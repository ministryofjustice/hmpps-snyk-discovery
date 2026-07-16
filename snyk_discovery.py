#!/usr/bin/env python
import base64
import binascii
import json
import os
import sys
from urllib.parse import urlparse

from hmpps import ServiceCatalogue, Slack
import processes.snyk_scans as snyk_scans
import includes.snyk as snyk
from hmpps.services.job_log_handling import (
  log_debug,
  log_error,
  log_info,
  log_critical,
  log_warning,
  job,
)

# Set maximum number of concurrent threads to run, try to avoid secondary
# github api limits.


def _normalise_service_catalogue_endpoint_for_local_testing():
  endpoint = os.getenv('SERVICE_CATALOGUE_API_ENDPOINT', '').strip()
  if not endpoint:
    return

  parsed = urlparse(endpoint)
  is_local = parsed.hostname in {'localhost', '127.0.0.1'}

  if parsed.scheme == 'https' and is_local:
    local_http_endpoint = endpoint.replace('https://', 'http://', 1)
    os.environ['SERVICE_CATALOGUE_API_ENDPOINT'] = local_http_endpoint
    log_warning(
      'Using HTTP for local Service Catalogue endpoint '
      f'({local_http_endpoint})'
    )


def _set_snyk_registry_credentials_from_ghcr_auth_config():
  raw_config = os.getenv('GHCR_AUTH_CONFIG', '').strip()
  if not raw_config:
    return

  config_data = None
  try:
    config_data = json.loads(raw_config)
  except json.JSONDecodeError:
    try:
      decoded = base64.b64decode(raw_config).decode('utf-8')
      config_data = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
      log_warning('GHCR_AUTH_CONFIG is not valid JSON; skipping registry env setup.')
      return

  auths = config_data.get('auths', {}) if isinstance(config_data, dict) else {}
  ghcr_auth_entry = (
    auths.get('ghcr.io')
    or auths.get('https://ghcr.io')
    or auths.get('https://ghcr.io/v1/')
  )
  if not isinstance(ghcr_auth_entry, dict):
    return

  username = ghcr_auth_entry.get('username')
  password = ghcr_auth_entry.get('password')

  if not username or not password:
    auth_value = ghcr_auth_entry.get('auth')
    if not auth_value:
      return
    try:
      decoded_auth = base64.b64decode(auth_value).decode('utf-8')
      username, password = decoded_auth.split(':', 1)
    except (binascii.Error, UnicodeDecodeError, ValueError):
      log_warning('Unable to decode GHCR auth token; skipping registry env setup.')
      return

  os.environ['SNYK_REGISTRY_USERNAME'] = username
  os.environ['SNYK_REGISTRY_PASSWORD'] = password
  log_debug('Set SNYK registry credentials from GHCR_AUTH_CONFIG.')


def main():
  if '-f' in sys.argv or '--full' in sys.argv:
    job.name = 'hmpps-snyk-discovery-full'
    log_info('Running Snyk scan on all container images in Service Catalogue')
    log_info('********************************************************************')
  elif '-i' in sys.argv or '--incremental' in sys.argv:
    job.name = 'hmpps-snyk-discovery-incremental'
    log_info('Running Snyk scan on new images only')
    log_info('********************************************************************')
  else:
    log_error(
      'Invalid argument. '
      'Use -i or --incremental for incremental scan '
      'or -f or --full for full scan.'
    )
    sys.exit(1)

  slack = Slack()
  _normalise_service_catalogue_endpoint_for_local_testing()
  _set_snyk_registry_credentials_from_ghcr_auth_config()
  sc = ServiceCatalogue()

  if not sc.connection_ok:
    log_error('Failed to connect to the Service Catalogue. Exiting...')
    slack.alert('hmpps-snyk-discovery: failed to connect to the Service Catalogue')
    sys.exit(1)

  # Install Snyk
  log_debug('Installing snyk')
  snyk_status = snyk.install()
  if snyk_status.startswith('Failed'):
    log_critical(f'{snyk_status}')
    slack.alert(f'{job.name} - {snyk_status}')
    sc.update_scheduled_job('Failed')
    sys.exit(1)
  log_debug('Snyk installed')

  image_list = snyk_scans.get_image_list(sc=sc)
  snyk_scans.delete_sc_snyk_scan_results(sc=sc)
  vulnerability_sync_state = snyk_scans.create_vulnerability_sync_state(sc=sc)
  snyk.scan_deployed_image(
    sc=sc,
    image_list=image_list,
    vulnerability_sync_state=vulnerability_sync_state,
  )
  snyk.scan_hmpps_base_container_images(sc=sc)
  snyk_scans.update_scan_cve_details(sc=sc)
  snyk_scans.delete_orphan_snyk_vulnerabilities(sc=sc)
  snyk_scans.send_summary_to_slack(sc=sc, slack=slack)
  if job.error_messages:
    sc.update_scheduled_job('Errors')
    log_info('Snyk discovery job completed  with errors.')
  else:
    sc.update_scheduled_job('Succeeded')
    log_info('Snyk discovery job completed successfully.')


if __name__ == '__main__':
  main()
