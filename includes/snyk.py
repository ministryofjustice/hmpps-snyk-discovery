import requests
import subprocess
import os
import json
import platform
import shutil
import re
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


def cleanup_snyk_cache_after_scan(image_name):
  if not get_env_bool('SNYK_CACHE_CLEANUP', default=True):
    return

  try:
    if os.path.isdir(snyk_cache_dir):
      shutil.rmtree(snyk_cache_dir, ignore_errors=True)
      os.makedirs(snyk_cache_dir, exist_ok=True)
      log_debug(
        f'Reset Snyk cache directory after scanning {image_name}: {snyk_cache_dir}'
      )
  except Exception as e:
    log_debug(f'Snyk cache cleanup failed for {image_name} at {snyk_cache_dir}: {e}')


def build_useful_description(vuln, fixed_version, cve_ids):
  raw_description = str(vuln.get('description', '') or '')

  # Remove common markdown boilerplate and keep readable text.
  cleaned = re.sub(r'#+\s*NVD Description\s*', '', raw_description, flags=re.IGNORECASE)
  cleaned = re.sub(
    r'\*\*_Note:_\*\*\s*_.*?_',
    '',
    cleaned,
    flags=re.IGNORECASE | re.DOTALL,
  )
  cleaned = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', cleaned)
  cleaned = re.sub(r'[`*_#>]', '', cleaned)
  cleaned = re.sub(r'\s+', ' ', cleaned).strip()

  title = str(vuln.get('title', '') or '').strip()
  package_name = str(vuln.get('packageName', 'N/A'))
  installed_version = str(vuln.get('version', 'N/A'))

  description_parts = []
  if title:
    description_parts.append(title)
  if cleaned and cleaned.lower() != title.lower():
    description_parts.append(cleaned)

  description_parts.append(f'Affected package: {package_name}@{installed_version}.')
  if fixed_version != 'N/A':
    description_parts.append(f'Fixed in: {fixed_version}.')
  else:
    description_parts.append('No fixed version currently available.')

  if cve_ids:
    description_parts.append(f'CVE: {", ".join(cve_ids)}.')

  description = ' '.join(part for part in description_parts if part)
  return description[:500]


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
    os.makedirs(os.path.dirname(snyk_binary), exist_ok=True)
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


def run_snyk_subprocess(command):
  os.makedirs(snyk_cache_dir, exist_ok=True)
  process_env = os.environ.copy()
  process_env['SNYK_CACHE_PATH'] = snyk_cache_dir
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


def run_snyk_scan(image_name, retry_count=0):
  log_info(f'Running Snyk scan on {image_name}')
  command = [snyk_binary, 'container', 'test', image_name, '--json']
  try:
    result = run_snyk_subprocess(command)
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
        platform_result = run_snyk_subprocess(platform_command)
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
      return run_snyk_scan(image_name, retry_count)
    log_error(f'Snyk scan failed for {image_name}: {error_output}')
    return {'error': error_output}, image_name
  except Exception as e:
    log_error(f'Snyk scan failed for {image_name}: {e}')
    return {'error': str(e)}, image_name


def scan_component_image(services, component, retry_count):
  component_name = component['component_name']
  component_build_image_tag = component['build_image_tag']
  image_name = f'{component["container_image_repo"]}:{component_build_image_tag}'

  try:
    # Perform the Snyk scan
    result_json, image_id = run_snyk_scan(image_name, retry_count)

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
    cleanup_snyk_cache_after_scan(image_name)


def scan_result_summary(scan_result):
  scan_summary = {
    'scan_result': {},
    'summary': {
      'snyk': {
        'severity': {},
        'fixable': {},
        'total': 0,
      },
    },
  }
  vulnerabilities = scan_result.get('vulnerabilities', [])
  for vuln in vulnerabilities:
    severity = str(vuln.get('severity', 'unknown')).upper()

    fixed_versions = vuln.get('fixedIn', [])
    if isinstance(fixed_versions, list):
      fixed_version = ', '.join(fixed_versions) if fixed_versions else 'N/A'
    else:
      fixed_version = str(fixed_versions) if fixed_versions else 'N/A'

    vulnerability_id = vuln.get('id', 'N/A')
    primary_url = f'https://security.snyk.io/vuln/{vulnerability_id}'
    cve_ids = vuln.get('identifiers', {}).get('CVE', [])
    if not isinstance(cve_ids, list):
      cve_ids = []
    cve_disclosure_date = vuln.get('disclosureTime')
    snyk_publication_date = vuln.get('publicationTime')
    description = build_useful_description(vuln, fixed_version, cve_ids)
    fixed_available = fixed_version != 'N/A'
    fixable_bucket = 'fixable' if fixed_available else 'not_fixable'

    # Store Snyk-native vulnerability payload for SC and developer portal consumers.
    normalized_fixed_in = fixed_versions if isinstance(fixed_versions, list) else []
    if not normalized_fixed_in and fixed_version != 'N/A':
      normalized_fixed_in = [fixed_version]

    scan_summary['scan_result'].setdefault('snyk-vulns', []).append(
      {
        'id': vulnerability_id,
        'title': vuln.get('title', ''),
        'severity': severity,
        'packageName': vuln.get('packageName', 'N/A'),
        'packageManager': vuln.get('packageManager', 'unknown'),
        'version': vuln.get('version', 'N/A'),
        'fixedIn': normalized_fixed_in,
        'description': description,
        'exploitMaturity': vuln.get('exploitMaturity', 'unknown'),
        'isUpgradable': bool(vuln.get('isUpgradable', False)),
        'isPatchable': bool(vuln.get('isPatchable', False)),
        'cvssScore': vuln.get('cvssScore'),
        'cve': cve_ids,
        'cveDisclosureDate': cve_disclosure_date,
        'snykPublicationDate': snyk_publication_date,
        'from': vuln.get('from', []),
        'url': primary_url,
      }
    )

    scan_summary['summary']['snyk']['severity'][severity] = (
      scan_summary['summary']['snyk']['severity'].get(severity, 0) + 1
    )
    scan_summary['summary']['snyk']['fixable'][fixable_bucket] = (
      scan_summary['summary']['snyk']['fixable'].get(fixable_bucket, 0) + 1
    )
    scan_summary['summary']['snyk']['total'] += 1

  return scan_summary


def scan_prod_image(sc, image_list):
  qty = len(image_list)
  log_info(f'Starting scan for {qty} images...')
  count = 1

  for component in image_list:
    if not isinstance(component, dict):
      log_error(f'Invalid component format: {component}')
      continue

    if 'build_image_tag' in component and component['build_image_tag']:
      log_info(
        f'Started Snyk scan for {component["component_name"]} - {count}/{qty} '
        f'images ({int((count / qty) * 100)}%)'
      )
      scan_component_image(sc, component, 1)
    count += 1

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
