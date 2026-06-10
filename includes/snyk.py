import requests
import subprocess
import os
import json
import base64
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
ghcr_login_attempted = False
ghcr_login_ok = False
ghcr_login_lock = threading.Lock()


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


def get_ghcr_credentials():
  auth_config_raw = os.getenv('GHCR_AUTH_CONFIG', '').strip()
  if not auth_config_raw:
    return (
      None,
      None,
      'GHCR credentials missing. Set GHCR_AUTH_CONFIG (.dockerconfigjson).',
    )

  try:
    auth_config = json.loads(auth_config_raw)
  except json.JSONDecodeError as e:
    return None, None, f'Invalid GHCR_AUTH_CONFIG JSON: {e}'

  auths = auth_config.get('auths', {}) if isinstance(auth_config, dict) else {}
  if not isinstance(auths, dict):
    return None, None, 'Invalid GHCR_AUTH_CONFIG: missing auths object.'

  candidate_hosts = ('ghcr.io', 'https://ghcr.io', 'https://ghcr.io/')
  ghcr_entry = None
  for host in candidate_hosts:
    value = auths.get(host)
    if isinstance(value, dict):
      ghcr_entry = value
      break

  if not ghcr_entry:
    for host, value in auths.items():
      if isinstance(host, str) and 'ghcr.io' in host and isinstance(value, dict):
        ghcr_entry = value
        break

  if not ghcr_entry:
    return None, None, 'Invalid GHCR_AUTH_CONFIG: no ghcr.io entry under auths.'

  ghcr_username = str(ghcr_entry.get('username', '')).strip()
  ghcr_password = str(ghcr_entry.get('password', '')).strip()
  if ghcr_username and ghcr_password:
    return ghcr_username, ghcr_password, None

  auth_b64 = str(ghcr_entry.get('auth', '')).strip()
  if not auth_b64:
    return None, None, 'Invalid GHCR_AUTH_CONFIG: ghcr.io entry missing credentials.'

  try:
    decoded_auth = base64.b64decode(auth_b64).decode('utf-8')
  except Exception as e:
    return None, None, f'Invalid GHCR_AUTH_CONFIG auth value: {e}'

  if ':' not in decoded_auth:
    return (
      None,
      None,
      'Invalid GHCR_AUTH_CONFIG auth value: expected username:password.',
    )

  ghcr_username, ghcr_password = decoded_auth.split(':', 1)
  ghcr_username = ghcr_username.strip()
  ghcr_password = ghcr_password.strip()
  if not (ghcr_username and ghcr_password):
    return (
      None,
      None,
      'Invalid GHCR_AUTH_CONFIG auth value: empty username or password.',
    )

  return ghcr_username, ghcr_password, None


def ensure_ghcr_login():
  global ghcr_login_attempted
  global ghcr_login_ok

  with ghcr_login_lock:
    if ghcr_login_attempted:
      return ghcr_login_ok, None if ghcr_login_ok else 'GHCR login already failed'

    ghcr_username, ghcr_password, credentials_error = get_ghcr_credentials()
    if credentials_error:
      ghcr_login_attempted = True
      ghcr_login_ok = False
      return False, credentials_error

    ghcr_login_attempted = True

    # Keep registry auth available for downstream tooling.
    os.environ['DOCKER_AUTH_CONFIG'] = os.getenv('GHCR_AUTH_CONFIG', '').strip()

    docker_path = shutil.which('docker')
    if docker_path:
      log_info('Using docker login for private/internal GHCR image scanning.')
      login_result = subprocess.run(
        ['docker', 'login', 'ghcr.io', '-u', ghcr_username, '--password-stdin'],
        input=ghcr_password,
        capture_output=True,
        text=True,
        check=False,
      )

      if login_result.returncode != 0:
        ghcr_login_ok = False
        error_text = (
          login_result.stderr
          or login_result.stdout
          or 'Unknown docker login error'
        )
        return False, f'Failed GHCR docker login: {error_text.strip()}'
    else:
      log_info(
        'Scanning private/internal GHCR images using DOCKER_AUTH_CONFIG registry auth.'
      )

    ghcr_login_ok = True
    return True, None


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


def inspect_image_manifest(image_name):
  inspect_result = subprocess.run(
    ['docker', 'manifest', 'inspect', image_name],
    capture_output=True,
    text=True,
    check=False,
  )

  if inspect_result.returncode != 0:
    error_text = inspect_result.stderr or inspect_result.stdout or 'Unknown error'
    return None, error_text.strip()

  try:
    return json.loads(inspect_result.stdout), None
  except json.JSONDecodeError as e:
    return None, f'Failed to parse image manifest for {image_name}: {e}'


def _matches_platform(manifest_platform, expected_platform):
  if not isinstance(manifest_platform, dict):
    return False

  expected_os, expected_arch, expected_variant = expected_platform
  manifest_os = str(manifest_platform.get('os', '')).lower()
  manifest_arch = str(manifest_platform.get('architecture', '')).lower()
  manifest_variant = str(manifest_platform.get('variant', '')).lower()

  if manifest_os != expected_os or manifest_arch != expected_arch:
    return False

  if expected_variant and manifest_variant != expected_variant:
    return False

  return True


def validate_image_exists_for_platforms(image_name, platforms):
  manifest_json, manifest_error = inspect_image_manifest(image_name)
  if manifest_json is None:
    return (
      False,
      f'Image validation failed for {image_name}: manifest lookup failed: '
      f'{manifest_error}',
    )

  manifests = (
    manifest_json.get('manifests')
    if isinstance(manifest_json, dict)
    else None
  )
  if not isinstance(manifests, list):
    return True, f'Image validation passed for {image_name}: manifest exists.'

  normalized_platforms = []
  for platform_name in platforms:
    parts = platform_name.lower().split('/', 2)
    if len(parts) < 2:
      continue
    expected_os = parts[0]
    expected_arch = parts[1]
    expected_variant = parts[2] if len(parts) > 2 else ''
    normalized_platforms.append((expected_os, expected_arch, expected_variant))

  if not normalized_platforms:
    return True, f'Image validation passed for {image_name}: manifest exists.'

  for manifest in manifests:
    platform_data = manifest.get('platform', {})
    if any(
      _matches_platform(platform_data, expected)
      for expected in normalized_platforms
    ):
      return (
        True,
        f'Image validation passed for {image_name}: platform manifest exists.',
      )

  platform_list = ', '.join(platforms)
  return (
    False,
    f'Image validation failed for {image_name}: image exists but no manifest '
    f'for configured fallback platform(s): {platform_list}',
  )


def parse_image_reference(image_name):
  if '@' in image_name:
    repo_part, ref = image_name.rsplit('@', 1)
  else:
    repo_part = image_name
    last_slash = repo_part.rfind('/')
    last_colon = repo_part.rfind(':')
    if last_colon > last_slash:
      repo_part, ref = repo_part[:last_colon], repo_part[last_colon + 1 :]
    else:
      ref = 'latest'

  if not repo_part.startswith('ghcr.io/'):
    return None, None, f'Unsupported registry for API validation: {image_name}'

  repo_path = repo_part[len('ghcr.io/'):]
  if not repo_path or not ref:
    return None, None, f'Invalid image reference: {image_name}'

  return repo_path, ref, None


def fetch_ghcr_manifest(image_name):
  repo_path, ref, ref_error = parse_image_reference(image_name)
  if ref_error:
    return None, ref_error

  ghcr_username, ghcr_password, credentials_error = get_ghcr_credentials()
  if credentials_error:
    return None, credentials_error

  token_url = 'https://ghcr.io/token'
  token_params = {
    'scope': f'repository:{repo_path}:pull',
    'service': 'ghcr.io',
  }
  token = None
  try:
    token_response = requests.get(
      token_url,
      params=token_params,
      auth=(ghcr_username, ghcr_password),
      timeout=20,
    )
    if token_response.status_code == 200:
      token = (token_response.json() or {}).get('token')
  except requests.RequestException as e:
    log_debug(f'GHCR token request failed for {image_name}: {e}')

  manifest_url = f'https://ghcr.io/v2/{repo_path}/manifests/{ref}'
  headers = {
    'Accept': (
      'application/vnd.oci.image.index.v1+json, '
      'application/vnd.docker.distribution.manifest.list.v2+json, '
      'application/vnd.oci.image.manifest.v1+json, '
      'application/vnd.docker.distribution.manifest.v2+json'
    )
  }
  if token:
    headers['Authorization'] = f'Bearer {token}'

  try:
    manifest_response = requests.get(
      manifest_url,
      headers=headers,
      auth=None if token else (ghcr_username, ghcr_password),
      timeout=20,
    )
  except requests.RequestException as e:
    return None, f'GHCR manifest request failed for {image_name}: {e}'

  if manifest_response.status_code == 404:
    return (
      None,
      f'Image validation failed for {image_name}: image/tag not found in GHCR.',
    )

  if manifest_response.status_code in (401, 403):
    return (
      None,
      f'Image validation failed for {image_name}: '
      f'unauthorized to access GHCR manifest.',
    )

  if manifest_response.status_code != 200:
    response_text = manifest_response.text.strip()[:300]
    return (
      None,
      f'Image validation failed for {image_name}: GHCR returned '
      f'{manifest_response.status_code}: {response_text}',
    )

  try:
    return manifest_response.json(), None
  except json.JSONDecodeError as e:
    return None, f'Image validation failed for {image_name}: invalid manifest JSON: {e}'


def validate_image_exists_for_platforms_via_registry(image_name, platforms):
  manifest_json, manifest_error = fetch_ghcr_manifest(image_name)
  if manifest_json is None:
    return False, manifest_error

  manifests = (
    manifest_json.get('manifests')
    if isinstance(manifest_json, dict)
    else None
  )
  if not isinstance(manifests, list):
    return True, f'Image validation passed for {image_name}: manifest exists.'

  normalized_platforms = []
  for platform_name in platforms:
    parts = platform_name.lower().split('/', 2)
    if len(parts) < 2:
      continue
    expected_os = parts[0]
    expected_arch = parts[1]
    expected_variant = parts[2] if len(parts) > 2 else ''
    normalized_platforms.append((expected_os, expected_arch, expected_variant))

  if not normalized_platforms:
    return True, f'Image validation passed for {image_name}: manifest exists.'

  for manifest in manifests:
    platform_data = manifest.get('platform', {})
    if any(
      _matches_platform(platform_data, expected)
      for expected in normalized_platforms
    ):
      return (
        True,
        f'Image validation passed for {image_name}: platform manifest exists.',
      )

  platform_list = ', '.join(platforms)
  return (
    False,
    f'Image validation failed for {image_name}: image exists but no manifest '
    f'for configured fallback platform(s): {platform_list}',
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
  command = [snyk_binary, 'container', 'test', image_name, '--json', '--app-vulns']
  target_cache_dir = cache_dir or get_thread_cache_dir()
  docker_cli_available = shutil.which('docker') is not None
  try:
    if image_name.lower().startswith('ghcr.io/'):
      log_info(f'Scanning private/internal GHCR image: {image_name}')
      logged_in, ghcr_login_error = ensure_ghcr_login()
      if not logged_in:
        log_error(
          f'Unable to authenticate to GHCR for {image_name}: {ghcr_login_error}'
        )
        return {'error': ghcr_login_error}, image_name

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
      if docker_cli_available:
        image_exists, existence_message = validate_image_exists_for_platforms(
          image_name,
          [],
        )
        if not image_exists:
          log_error(existence_message)
          return {'error': existence_message}, image_name
        log_info(existence_message)
      else:
        image_exists, existence_message = (
          validate_image_exists_for_platforms_via_registry(
            image_name,
            [],
          )
        )
        if not image_exists:
          log_error(existence_message)
          return {'error': existence_message}, image_name
        log_info(existence_message)

      platform_fallbacks = get_platform_fallbacks()
      for platform_name in platform_fallbacks:
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

      if docker_cli_available:
        image_exists, validation_message = validate_image_exists_for_platforms(
          image_name,
          platform_fallbacks,
        )
        if not image_exists:
          log_error(validation_message)
          return {'error': validation_message}, image_name
        log_info(validation_message)
      else:
        image_exists, validation_message = (
          validate_image_exists_for_platforms_via_registry(
            image_name,
            platform_fallbacks,
          )
        )
        if not image_exists:
          log_error(validation_message)
          return {'error': validation_message}, image_name
        log_info(validation_message)

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
    vulnerabilities = []

    # Summarize the scan results
    if not result_json or (isinstance(result_json, dict) and result_json.get('error')):
      scan_status = 'Failed'
      scan_data = {}
    else:
      scan_status = 'Succeeded'
      scan_data = scan_result_summary(result_json)
      vulnerabilities = scan_data.get('vulnerabilities', [])

    # Update the scan results
    snyk_scans.update(
      services,
      component_name,
      component_build_image_tag,
      image_id,
      scan_data,
      scan_status,
    )
    return vulnerabilities
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

  summary = {
    'critical_fixable': 0,
    'critical_unfixable': 0,
    'high_fixable': 0,
    'high_unfixable': 0,
    'medium_fixable': 0,
    'medium_unfixable': 0,
    'low_fixable': 0,
    'low_unfixable': 0,
    'unknown_fixable': 0,
    'unknown_unfixable': 0,
  }

  aggregated_vulns = {}

  all_vulnerabilities = list(scan_result.get('vulnerabilities', []))
  for application in scan_result.get('applications', []):
    application_vulns = application.get('vulnerabilities', [])
    if isinstance(application_vulns, list):
      all_vulnerabilities.extend(application_vulns)

  for vuln in all_vulnerabilities:
    log_debug(f'Results for vulnerability: {json.dumps(vuln, indent=2)}')
    snyk_id = str(vuln.get('id', ''))
    if not snyk_id:
      continue
    severity = str(vuln.get('severity', 'UNKNOWN')).upper()
    if severity not in severity_rank:
      severity = 'UNKNOWN'

    fixed_versions = vuln.get('fixedIn', [])
    is_fixable = bool(fixed_versions)
    cvss_score = vuln.get('cvssScore')
    if cvss_score is None:
      cvss_details = vuln.get('cvssDetails') or []
      cvss_sources = vuln.get('cvssSources') or []
      if cvss_details and isinstance(cvss_details[0], dict):
        cvss_score = cvss_details[0].get('cvssV3BaseScore')
      if cvss_score is None and cvss_sources and isinstance(cvss_sources[0], dict):
        cvss_score = cvss_sources[0].get('baseScore')

    exploit_maturity = vuln.get('exploitMaturity')
    if not exploit_maturity:
      maturity_levels = (vuln.get('exploitDetails') or {}).get('maturityLevels', [])
      primary_maturity = next(
        (
          level.get('level')
          for level in maturity_levels
          if isinstance(level, dict)
          and level.get('type') == 'primary'
          and level.get('level')
        ),
        None,
      )
      secondary_maturity = next(
        (
          level.get('level')
          for level in maturity_levels
          if isinstance(level, dict)
          and level.get('type') == 'secondary'
          and level.get('level')
        ),
        None,
      )
      exploit_maturity = primary_maturity or secondary_maturity or vuln.get('exploit')

    if snyk_id not in aggregated_vulns:
      aggregated_vulns[snyk_id] = {
        'id': snyk_id,
        'title': vuln.get('title'),
        'description': vuln.get('description'),
        'severity': severity,
        'language': vuln.get('language') or 'unknown',
        'name': vuln.get('name'),
        'packageName': vuln.get('packageName'),
        'version': vuln.get('version'),
        'fixedIn': fixed_versions,
        'fixable': is_fixable,
        'cvssScore': cvss_score,
        'exploitMaturity': exploit_maturity,
        'cve': vuln.get('identifiers', {}).get('CVE', []),
        'snykPublicationDate': vuln.get('publicationTime')
      }

  for v in aggregated_vulns.values():
    severity = v['severity'].lower()
    key = f"{severity}_{'fixable' if v['fixable'] else 'unfixable'}"
    if key not in summary:
      key = 'unknown_fixable' if v['fixable'] else 'unknown_unfixable'
    summary[key] += 1

  return {
    'counts': summary,
    'vulnerabilities': list(aggregated_vulns.values()),
    'snyk_ids': list(aggregated_vulns.keys())
  }

def scan_deployed_image(sc, image_list):
  valid_components = [
    component
    for component in image_list
    if isinstance(component, dict) and component.get('build_image_tag')
  ]
  qty = len(valid_components)
  log_info(f'Starting scan for {qty} images...')

  max_workers = max(1, min(get_env_int('SNYK_MAX_WORKERS', 2), qty or 1))
  log_info(f'Running Snyk scans with {max_workers} worker threads.')

  if max_workers == 1:
    for count, component in enumerate(valid_components, start=1):
      log_info(
        f'Started Snyk scan for {component["component_name"]} - {count}/{qty} '
        f'images ({int((count / qty) * 100)}%)'
      )
      component_vulnerabilities = scan_component_image(sc, component, 1) or []
      if component_vulnerabilities:
        snyk_scans.upsert_vulnerabilities(sc, component_vulnerabilities)
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
          component_vulnerabilities = future.result() or []
          if component_vulnerabilities:
            snyk_scans.upsert_vulnerabilities(sc, component_vulnerabilities)
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
      