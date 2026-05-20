import requests
import subprocess
import os
import json
import platform
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from hmpps.services.job_log_handling import (
  log_debug,
  log_error,
  log_info,
)
import processes.snyk_scans as snyk_scans


default_snyk_root = '/app/snyk_cache' if os.path.isdir('/app/snyk_cache') else '/tmp'
snyk_cache_dir = os.getenv(
  'SNYK_CACHE_DIR',
  os.path.join(default_snyk_root, '.snyk-cache'),
)
snyk_binary = os.getenv(
  'SNYK_BINARY_PATH',
  os.path.join(default_snyk_root, 'snyk-bin', 'snyk'),
)


def get_env_bool(name, default=False):
  value = os.getenv(name)
  if value is None:
    return default
  return value.strip().lower() in ('1', 'true', 'yes', 'on')


def get_env_int(name, default):
  value = os.getenv(name)
  if value is None:
    return default
  try:
    return int(value)
  except ValueError:
    log_error(f'Invalid integer value for {name}: {value}. Using default {default}.')
    return default


def get_thread_cache_dir():
  if not get_env_bool('SNYK_THREAD_CACHE_ENABLED', default=True):
    return snyk_cache_dir
  return os.path.join(snyk_cache_dir, f'thread-{threading.get_ident()}')


def cleanup_docker_after_scan(image_name):
  if not get_env_bool('SNYK_DOCKER_CLEANUP', default=True):
    return

  try:
    log_info(f'Running Docker cleanup for scanned image: {image_name}')
    subprocess.run(
      ['docker', 'image', 'rm', image_name],
      capture_output=True,
      text=True,
      check=False,
    )

    # Optional extra cleanup for high-pressure environments.
    if get_env_bool('SNYK_DOCKER_PRUNE', default=False):
      subprocess.run(
        ['docker', 'image', 'prune', '-f'],
        capture_output=True,
        text=True,
        check=False,
      )
      subprocess.run(
        ['docker', 'builder', 'prune', '-f'],
        capture_output=True,
        text=True,
        check=False,
      )
  except Exception as e:
    log_debug(f'Docker cleanup failed for {image_name}: {e}')


def cleanup_snyk_cache_after_scan(image_name, cache_dir=None):
  if not get_env_bool('SNYK_CACHE_CLEANUP', default=True):
    return

  target_cache_dir = cache_dir or snyk_cache_dir

  try:
    if os.path.isdir(target_cache_dir):
      shutil.rmtree(target_cache_dir, ignore_errors=True)
      os.makedirs(target_cache_dir, exist_ok=True)
      log_debug(
        f'Reset Snyk cache directory after scanning {image_name}: {target_cache_dir}'
      )
  except Exception as e:
    log_debug(f'Snyk cache cleanup failed for {image_name} at {target_cache_dir}: {e}')


def get_snyk_download_url():
  system = platform.system().lower()
  machine = platform.machine().lower()

  if system == 'linux':
    is_alpine = os.path.exists('/etc/alpine-release')
    if is_alpine:
      binary_name = (
        'snyk-alpine-arm64' if machine in ('aarch64', 'arm64') else 'snyk-alpine'
      )
    else:
      binary_name = (
        'snyk-linux-arm64' if machine in ('aarch64', 'arm64') else 'snyk-linux'
      )
  elif system == 'darwin':
    binary_name = (
      'snyk-macos-arm64' if machine in ('aarch64', 'arm64') else 'snyk-macos'
    )
  else:
    raise RuntimeError(f'Unsupported OS for Snyk install: {system}/{machine}')

  return f'https://github.com/snyk/cli/releases/latest/download/{binary_name}'


def install():
  global snyk_binary
  global snyk_cache_dir

  try:
    # Re-read env so runtime overrides are respected.
    snyk_cache_dir = os.getenv('SNYK_CACHE_DIR', snyk_cache_dir)
    snyk_binary = os.getenv('SNYK_BINARY_PATH', snyk_binary)
    os.makedirs(snyk_cache_dir, exist_ok=True)
    snyk_binary_dir = os.path.dirname(snyk_binary)
    if snyk_binary_dir:
      os.makedirs(snyk_binary_dir, exist_ok=True)
    log_debug(f'Using Snyk cache directory: {snyk_cache_dir}')
    log_debug(f'Using Snyk binary path: {snyk_binary}')

    # Prefer a pre-installed CLI (for example Homebrew on macOS).
    if installed_snyk := shutil.which('snyk'):
      snyk_binary = installed_snyk
      log_info(f'Using pre-installed Snyk binary: {snyk_binary}')
    else:
      snyk_url = get_snyk_download_url()
      log_info(f'Downloading Snyk from {snyk_url}...')
      response = requests.get(snyk_url, stream=True, timeout=30)
      response.raise_for_status()

      with open(snyk_binary, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
          f.write(chunk)
      os.chmod(snyk_binary, 0o755)

    version_result = subprocess.run(
      [snyk_binary, '--version'],
      capture_output=True,
      text=True,
      check=True,
    )
    log_info(f'Snyk installed successfully. Version: {version_result.stdout.strip()}')

  except Exception as e:  # Not a CalledProcess error - it could happen
    return f'Failed to install Snyk - {e}'

  if not os.getenv('SNYK_TOKEN'):
    return 'Failed to install Snyk - SNYK_TOKEN environment variable is missing'

  return 'Success'


def get_platform_fallbacks():
  configured_platforms = os.getenv('SNYK_PLATFORM_FALLBACKS', 'linux/amd64,linux/arm64')
  return [
    platform_name.strip()
    for platform_name in configured_platforms.split(',')
    if platform_name.strip()
  ]


def run_snyk_subprocess(command, cache_dir=None):
  target_cache_dir = cache_dir or get_thread_cache_dir()
  os.makedirs(target_cache_dir, exist_ok=True)
  process_env = os.environ.copy()
  process_env['SNYK_CACHE_PATH'] = target_cache_dir
  return subprocess.run(
    command,
    capture_output=True,
    text=True,
    check=False,
    env=process_env,
  )


def parse_snyk_json_output(output_text):
  if not output_text:
    raise ValueError('Snyk scan produced no JSON output')

  decoder = json.JSONDecoder()
  for marker in ('{', '['):
    start_idx = output_text.find(marker)
    if start_idx == -1:
      continue
    try:
      parsed, end_idx = decoder.raw_decode(output_text[start_idx:])
      trailing = output_text[start_idx + end_idx :].strip()
      if trailing:
        log_debug(
          'Snyk output contained trailing non-JSON content; '
          'parsed first JSON document successfully.'
        )
      return parsed
    except json.JSONDecodeError:
      continue

  raise ValueError('Unable to parse JSON from Snyk output')


def run_snyk_scan(image_name, retry_count=0, cache_dir=None):
  log_info(f'Running Snyk scan on {image_name}')
  command = [snyk_binary, 'container', 'test', image_name, '--json']
  target_cache_dir = cache_dir or get_thread_cache_dir()
  try:
    result = run_snyk_subprocess(command, cache_dir=target_cache_dir)
     # Snyk exits with code 1 when vulnerabilities are found, which is expected.
    if result.returncode in (0, 1):
      if not result.stdout:
        return {'error': 'Snyk scan produced no JSON output'}, image_name
      scan_output = parse_snyk_json_output(result.stdout)
      vulnerabilities = scan_output.get('vulnerabilities', [])
      log_debug(
        f'Snyk scan result for {image_name} complete: '
        f'{len(vulnerabilities)} vulnerabilities'
      )
      return scan_output, image_name

    error_output = result.stderr or result.stdout or 'Unknown Snyk error'
    error_output_lower = error_output.lower()

    if 'image does not exist for the current platform' in error_output_lower:
      for platform_name in get_platform_fallbacks():
        platform_command = command + [f'--platform={platform_name}']
        log_info(
          f'Image not available on current platform. Retrying {image_name} '
          f'with {platform_name}...'
        )
        platform_result = run_snyk_subprocess(
          platform_command,
          cache_dir=target_cache_dir,
        )
        if platform_result.returncode in (0, 1):
          if not platform_result.stdout:
            return {'error': 'Snyk scan produced no JSON output'}, image_name
          scan_output = parse_snyk_json_output(platform_result.stdout)
          vulnerabilities = scan_output.get('vulnerabilities', [])
          log_debug(
            f'Snyk scan result for {image_name} on {platform_name} complete: '
            f'{len(vulnerabilities)} vulnerabilities'
          )
          return scan_output, image_name

        error_output = platform_result.stderr or platform_result.stdout or error_output
        error_output_lower = error_output.lower()

    if 'no space left on device' in error_output_lower:
      log_error(
        'Snyk scan failed due to local Docker disk space exhaustion. '
        'Free Docker disk space and retry the job.'
      )
      log_error(f'Snyk scan failed for {image_name}: {error_output}')
      return {'error': error_output}, image_name

    retryable_error = (
      '429' in error_output
      or 'temporarily unavailable' in error_output_lower
      or 'http code 500' in error_output_lower
      or 'timeout' in error_output_lower
      or 'connection reset' in error_output_lower
    )

    if retryable_error and retry_count < 3:
      retry_count += 1
      backoff_seconds = retry_count * 5
      log_info(
        f'Retrying Snyk scan for {image_name} - attempt {retry_count} '
        f'after {backoff_seconds}s...'
      )
      sleep(backoff_seconds)
      return run_snyk_scan(image_name, retry_count, cache_dir=target_cache_dir)
    log_error(f'Snyk scan failed for {image_name}: {error_output}')
    return {'error': error_output}, image_name
  except Exception as e:
    log_error(f'Snyk scan failed for {image_name}: {e}')
    return {'error': str(e)}, image_name


def scan_component_image(services, component, retry_count):
  component_name = component['component_name']
  component_build_image_tag = component['build_image_tag']
  image_name = f'{component["container_image_repo"]}:{component_build_image_tag}'
  thread_cache_dir = get_thread_cache_dir()

  try:
    # Perform the Snyk scan
    result_json, image_id = run_snyk_scan(
      image_name,
      retry_count,
      cache_dir=thread_cache_dir,
    )

    # Summarize the scan results
    if not result_json or (isinstance(result_json, dict) and result_json.get('error')):
      scan_status = 'Failed'
      scan_summary = {}
    else:
      scan_status = 'Succeeded'
      scan_summary = scan_result_summary(result_json)

    # Update the scan results
    snyk_scans.update(
      services,
      component_name,
      component_build_image_tag,
      image_id,
      scan_summary,
      scan_status,
    )
  finally:
    cleanup_docker_after_scan(image_name)
    cleanup_snyk_cache_after_scan(image_name, cache_dir=thread_cache_dir)


def scan_result_summary(scan_result):
  severity_rank = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'UNKNOWN': 0,
  }

  scan_summary = {
    'scan_result': {},
    'summary': {
      'snyk': {
        'severity': {
          'CRITICAL': {
            'total': 0,
            'fixable': 0,
            'unfixable': 0,
          },
          'HIGH': {
            'total': 0,
            'fixable': 0,
            'unfixable': 0,
          },
          'MEDIUM': {
            'total': 0,
            'fixable': 0,
            'unfixable': 0,
          },
          'LOW': {
            'total': 0,
            'fixable': 0,
            'unfixable': 0,
          },
          'UNKNOWN': {
            'total': 0,
            'fixable': 0,
            'unfixable': 0,
          },
        },
        'total': 0,
      },
    },
  }

  aggregated_vulns = {}
  severity_mismatch_logged = set()

  def choose_earliest_iso(existing_value, new_value):
    if not new_value:
      return existing_value
    if not existing_value:
      return str(new_value)
    existing = str(existing_value)
    candidate = str(new_value)
    return candidate if candidate < existing else existing

  vulnerabilities = scan_result.get('vulnerabilities', [])
  for vuln in vulnerabilities:
    severity = str(vuln.get('severity', 'UNKNOWN')).upper()
    if severity not in severity_rank:
      severity = 'UNKNOWN'

    fixed_versions = vuln.get('fixedIn', [])
    normalized_fixed_in = []
    if isinstance(fixed_versions, list):
      normalized_fixed_in = [str(version) for version in fixed_versions if version]
    elif fixed_versions:
      normalized_fixed_in = [str(fixed_versions)]

    vulnerability_id = str(vuln.get('id', 'N/A'))
    cve_ids = vuln.get('identifiers', {}).get('CVE', [])
    snyk_publication_date = vuln.get('publicationTime')
    if not isinstance(cve_ids, list):
      cve_ids = []
    cve_ids = sorted({str(cve_id) for cve_id in cve_ids if cve_id})
    fixed_available = bool(normalized_fixed_in)

    if vulnerability_id not in aggregated_vulns:
      aggregated_vulns[vulnerability_id] = {
        'id': vulnerability_id,
        'title': str(vuln.get('title', '') or ''),
        'severity': severity,
        'packageName': str(vuln.get('packageName', 'N/A') or 'N/A'),
        'version': str(vuln.get('version', 'N/A') or 'N/A'),
        'fixedIn': sorted(set(normalized_fixed_in)),
        'fixable': fixed_available,
        'cve': cve_ids,
        'snykPublicationDate': str(snyk_publication_date)
        if snyk_publication_date
        else None,
      }
      continue

    existing = aggregated_vulns[vulnerability_id]
    existing_severity = existing['severity']
    if severity != existing_severity and vulnerability_id not in severity_mismatch_logged:
      log_info(
        'Severity mismatch detected for '
        f'{vulnerability_id}: existing={existing_severity}, incoming={severity}. '
        'Keeping highest severity for aggregated record.'
      )
      severity_mismatch_logged.add(vulnerability_id)

    if severity_rank[severity] > severity_rank[existing['severity']]:
      existing['severity'] = severity
    existing['cve'] = sorted(set(existing['cve']) | set(cve_ids))
    existing['fixedIn'] = sorted(set(existing['fixedIn']) | set(normalized_fixed_in))
    existing['fixable'] = existing['fixable'] or fixed_available
    existing['snykPublicationDate'] = choose_earliest_iso(
      existing.get('snykPublicationDate'),
      snyk_publication_date,
    )

  scan_summary['scan_result']['snyk-vulns'] = list(aggregated_vulns.values())
  for vuln in scan_summary['scan_result']['snyk-vulns']:
    severity = vuln.get('severity', 'UNKNOWN')
    severity_summary = scan_summary['summary']['snyk']['severity'].setdefault(
      severity,
      {
        'total': 0,
        'fixable': 0,
        'unfixable': 0,
      },
    )
    severity_summary['total'] += 1
    if vuln.get('fixable', False):
      severity_summary['fixable'] += 1
    else:
      severity_summary['unfixable'] += 1
    scan_summary['summary']['snyk']['total'] += 1

  return scan_summary


def scan_prod_image(sc, image_list):
  valid_components = [
    component
    for component in image_list
    if isinstance(component, dict) and component.get('build_image_tag')
  ]
  qty = len(valid_components)
  log_info(f'Starting scan for {qty} images...')

  max_workers = max(1, min(get_env_int('SNYK_MAX_WORKERS', 4), qty or 1))
  log_info(f'Running Snyk scans with {max_workers} worker threads.')

  if max_workers == 1:
    for count, component in enumerate(valid_components, start=1):
      log_info(
        f'Started Snyk scan for {component["component_name"]} - {count}/{qty} '
        f'images ({int((count / qty) * 100)}%)'
      )
      scan_component_image(sc, component, 1)
  else:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
      future_to_component = {
        executor.submit(scan_component_image, sc, component, 1): component
        for component in valid_components
      }
      completed = 0
      for future in as_completed(future_to_component):
        completed += 1
        component = future_to_component[future]
        try:
          future.result()
        except Exception as e:
          log_error(
            f'Scan worker failed for {component.get("component_name", "unknown")}: {e}'
          )
        log_info(
          f'Completed Snyk scans: {completed}/{qty} '
          f'({int((completed / qty) * 100)}%)'
        )

  log_info('Completed all Snyk scans.')


def scan_hmpps_base_container_images(sc):
  log_info('Starting scan for hmpps-base-container-images...')
  images = ['hmpps-python', 'hmpps-node', 'hmpps-eclipse-temurin']
  for image in images:
    log_info(f'Started Snyk scan for {image}')
    image_name = f'ghcr.io/ministryofjustice/{image}:latest'
    try:
      # Perform the Snyk scan
      result_json, image_id = run_snyk_scan(image_name, 1)

      # Summarize the scan results
      scan_failed = not result_json or (
        isinstance(result_json, dict) and result_json.get('error')
      )
      scan_summary = scan_result_summary(result_json) if not scan_failed else {}
      scan_status = 'Failed' if scan_failed else 'Succeeded'
      log_info(f'snyk scan summary for {image}: {scan_summary.get("summary", {})}')
      # Update the scan results
      snyk_scans.update(
        sc,
        f'hmpps-base-container-images:{image}',
        'latest',
        image_id,
        scan_summary,
        scan_status,
      )
    finally:
      cleanup_docker_after_scan(image_name)
      cleanup_snyk_cache_after_scan(image_name)
      