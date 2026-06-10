#!/usr/bin/env python
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
  snyk.scan_deployed_image(sc=sc, image_list=image_list)
  snyk.scan_hmpps_base_container_images(sc=sc)
  snyk_scans.update_scan_cve_details(sc=sc)
  snyk_scans.send_summary_to_slack(sc=sc, slack=slack)

  log_info('Snyk discovery job completed, processing results...')
  log_info(f'Before filtering, Error messages: {job.error_messages}')
  ignored_error = (
    "Error adding a record to snyk-vulnerabilities in service catalogue: 'name'"
  )
  filtered_messages = [
    message for message in job.error_messages if message != ignored_error
  ]
  deduplicated_messages = list(dict.fromkeys(filtered_messages))
  log_info(
    f'After filtering and deduplication, Error messages: {deduplicated_messages}'
  )
  job.error_messages = deduplicated_messages

  if deduplicated_messages:
    sc.update_scheduled_job('Errors')
    log_info('Snyk discovery job completed  with errors.')
  else:
    sc.update_scheduled_job('Succeeded')
    log_info('Snyk discovery job completed successfully.')


if __name__ == '__main__':
  main()
