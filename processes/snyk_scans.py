import requests
import json
from datetime import datetime
from hmpps.services.job_log_handling import (
  log_debug,
  log_error,
  log_info,
  log_warning,
  job,
)

def get_image_list(sc):
  environments_data = sc.get_all_records(sc.environments_get)
  if not environments_data:
    log_error('Errors occurred while fetching environment data from Service Catalogue')
    sc.update_scheduled_job('Failed')
    return None

  # Extract image list data from environments data
  image_list = extract_image_list(environments_data)
  if job.name == 'hmpps-snyk-discovery-incremental':
    image_list = get_new_container_image_list(sc, image_list)
  return image_list

def create_vulnerability_sync_state(sc):
  existing_records = sc.get_all_records('snyk-vulnerabilities') or []
  existing = {}

  for record in existing_records:
    snyk_id = record.get('snyk_id')
    document_id = record.get('documentId')
    normalized = _normalize_vulnerability_record(record)
    normalized['documentId'] = document_id
    existing[snyk_id] = normalized

  log_info(
    f'Loaded {len(existing)} existing vulnerability records into memory for sync.'
  )
  return {
    'existing': existing,
  }

def _normalize_vulnerability_record(record):
  return {
    'snyk_id': record.get('snyk_id'),
    'title': record.get('title'),
    'description': record.get('description') or record.get('title') or '',
    'severity': str(record.get('severity', 'UNKNOWN')).upper(),
    'language': str(record.get('language') or '').strip() or 'unknown',
    'cves': sorted(set(record.get('cves') or [])),
    'published_date': record.get('published_date'),
    'fix_available': str(record.get('fix_available', 'False')),
    'affected_package_name': record.get('affected_package_name'),
    'affected_versions': sorted(set(record.get('affected_versions') or [])),
    'cvss_score': record.get('cvss_score'),
    'exploit_maturity': record.get('exploit_maturity') or 'UNKNOWN',
    'fixed_versions': sorted(set(record.get('fixed_versions') or [])),
  }

def delete_sc_snyk_scan_results(sc):
  # Fetch the list of records
  snyk_data = sc.get_all_records('snyk-scans')
  for record in snyk_data:
    if job.name == 'hmpps-snyk-discovery-incremental':
      if not record.get('name', '').startswith('hmpps-base-container-images'):
        continue

    record_document_id = record.get('documentId')
    try:
      sc.delete('snyk-scans', record_document_id)
      log_info(f'Deleted Snyk scan record with ID: {record_document_id}')
    except requests.exceptions.RequestException as e:
      log_error(f'Error deleting Snyk scan record with ID {record_document_id}: {e}')
      job.error_messages.append(
        f'Error deleting Snyk scan record with ID {record_document_id}: {e}'
      )

def get_new_container_image_list(sc, image_list):
  new_image_list = []
  snyk_data = sc.get_all_records('snyk-scans?populate=*')
  filtered_snyk_data = [
    snyk
    for snyk in snyk_data
    if snyk.get('scan_status') == 'Succeeded'
    or (
      snyk.get('scan_status') == 'Failed'
      and all(
        'unable to find the specified image' in result.get('error', '').lower()
        for result in snyk.get('snyk_scan_results', [])
      )
    )
  ]
  for image in image_list:
    build_image_tag = image['build_image_tag']
    name = image['component_name']
    if not any(
      snyk.get('build_image_tag') == build_image_tag and snyk.get('name') == name
      for snyk in filtered_snyk_data
    ):
      new_image_list.append(image)
  log_info(f'Number of new images to scan: {len(new_image_list)}')
  return new_image_list


def extract_image_list(environments_data):
  filtered_components = []
  unique_component_keys = set()

  for environment in environments_data:
    if component := environment.get('component', {}):
      component_name = component.get('name')
      if component.get('archived'):
        log_debug(f'Skipping archived component: {component_name}')
        continue
      build_image_tag = environment.get('build_image_tag')
      if not build_image_tag:
        build_image_tag = 'latest'
        log_warning(
          f'Build image tag for {component_name} is "latest", '
          'this may cause issues with image identification.'
        )
      container_image_repo = component.get('container_image')
      if container_image_repo:
        raw_snyk_ignore = component.get('snyk_ignore')
        snyk_ignore = str(raw_snyk_ignore or '').strip()
        log_debug(
          f'environment build image tag for {component.get("name")}: '
          f'{environment.get("build_image_tag")}'
        )
        filtered_component = {
          'component_name': component_name,
          'container_image_repo': container_image_repo,
          'build_image_tag': build_image_tag,
          'snyk_ignore': snyk_ignore,
        }
        log_debug(f'filtered_component: {filtered_component}')
        component_key = (component_name, container_image_repo, build_image_tag)
        if component_key not in unique_component_keys:
          unique_component_keys.add(component_key)
          filtered_components.append(filtered_component)
      else:
        namespace = environment.get('namespace')
        env_name = environment.get('name')
        if component_name:
          log_warning(
            f'No container image repo for {component_name} - {env_name} - {namespace}'
          )
        else:
          log_info(
            f'Orphaned environment record for namespace {env_name} - {namespace}'
          )

  log_info(f'Number of environments records in SC: {len(environments_data)}')
  log_info(f'Number of images: {len(filtered_components)}')
  return filtered_components


def update(sc, component, image_tag, image_id, scan_data, scan_status='Succeeded'):
  counts = scan_data.get('counts', {})
  snyk_ids = list(set(scan_data.get('snyk_ids', [])))
  if component.startswith('hmpps-base-container-images'):
    log_info(f'Processing base container image: {component}')
    environments = []
  else:
    environments = (
      sc.get_filtered_records('environments', 'component][name', component) or []
    )
  environment_names = []
  environment_document_ids = []
  missing_images_environments_ids = []

  if image_tag == 'latest':
    environment_names.append('unknown')
    for environment in environments:
      missing_images_environments_ids.append(environment.get('documentId'))
  else:
    for environment in environments:
      if environment.get('build_image_tag') == image_tag:
        document_id = environment.get('documentId')
        environment_names.append(environment.get('name'))
        environment_document_ids.append(document_id)

  if not environment_names:
    environment_names = ['unknown']

  for env_name in environment_names:
    snyk_scan_data = {
      'name': component,
      'build_image_tag': image_tag,
      'image_id': image_id,
      'snyk_scan_timestamp': datetime.now().isoformat(),
      'scan_status': scan_status,
      'critical_fixable': counts.get('critical_fixable', 0),
      'critical_unfixable': counts.get('critical_unfixable', 0),
      'high_fixable': counts.get('high_fixable', 0),
      'high_unfixable': counts.get('high_unfixable', 0),
      'medium_fixable': counts.get('medium_fixable', 0),
      'medium_unfixable': counts.get('medium_unfixable', 0),
      'low_fixable': counts.get('low_fixable', 0),
      'low_unfixable': counts.get('low_unfixable', 0),
      'unknown_fixable': counts.get('unknown_fixable', 0),
      'unknown_unfixable': counts.get('unknown_unfixable', 0),
      'snyk_ids': snyk_ids,
      'environment_name': env_name,
    }
    if response := sc.add('snyk-scans', snyk_scan_data):
      snyk_scan_document_id = response.get('data', {}).get('documentId', '')
      
      if snyk_scan_document_id:
        for environment_document_id in environment_document_ids:
          sc.update(
            'environments',
            environment_document_id,
            {'snyk_scan': snyk_scan_document_id},
          )
          log_info(
            f'Updated environment {environment_document_id} with Snyk scan ID: '
            f'{snyk_scan_document_id}'
          )
        for environment_document_id in missing_images_environments_ids:
          sc.update(
            'environments',
            environment_document_id,
            {'snyk_scan': snyk_scan_document_id},
          )
          log_info(
            f'Updated environment {environment_document_id} with Snyk scan ID: '
            f'{snyk_scan_document_id}'
          )
      else:
        log_warning(f'No snyk_scan_document_id found for {component}')

def send_summary_to_slack(sc, slack):
  snyk_data = sc.get_all_records('snyk-scans?populate=*')
  if not snyk_data:
    log_warning('No Snyk scan data found to summarize.')
    return

  total_images = len(snyk_data)
  total_vulnerabilities = 0
  base_image_total_vulnerabilities = 0
  severity_count = {
    'CRITICAL': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0,
    'UNKNOWN': 0,
  }
  base_image_severity_count = {
    'CRITICAL': 0,
    'HIGH': 0,
    'MEDIUM': 0,
    'LOW': 0,
    'UNKNOWN': 0,
  }
  failed_scans = []
  error_messages = []

  for record in snyk_data:
    base_image_name = record.get('name', 'Unknown Image')
    scan_status = record.get('scan_status', 'Unknown')
    if scan_status == 'Succeeded':
      record_counts = {
        'CRITICAL': int(record.get('critical_fixable', 0) or 0)
        + int(record.get('critical_unfixable', 0) or 0),
        'HIGH': int(record.get('high_fixable', 0) or 0)
        + int(record.get('high_unfixable', 0) or 0),
        'MEDIUM': int(record.get('medium_fixable', 0) or 0)
        + int(record.get('medium_unfixable', 0) or 0),
        'LOW': int(record.get('low_fixable', 0) or 0)
        + int(record.get('low_unfixable', 0) or 0),
        'UNKNOWN': int(record.get('unknown_fixable', 0) or 0)
        + int(record.get('unknown_unfixable', 0) or 0),
      }

      for severity, count in record_counts.items():
        if severity in severity_count:
          severity_count[severity] += count
        else:
          severity_count['UNKNOWN'] += count
        total_vulnerabilities += count
        if base_image_name.startswith('hmpps-base-container-images'):
          if severity in base_image_severity_count:
            base_image_severity_count[severity] += count
          else:
            base_image_severity_count['UNKNOWN'] += count
          base_image_total_vulnerabilities += count

  summary_message = (
    f'*Snyk Scan Summary:*\n'
    f'- Total Images Scanned: {total_images}\n'
    f'- Total Vulnerabilities Found: {total_vulnerabilities}\n'
    f'  - Critical: {severity_count["CRITICAL"]}\n'
    f'  - High: {severity_count["HIGH"]}\n'
    f'  - Medium: {severity_count["MEDIUM"]}\n'
    f'  - Low: {severity_count["LOW"]}\n'
    f'  - Unknown: {severity_count["UNKNOWN"]}\n'
    f' Base container images vulnerabilities:\n'
    f'  - Total Vulnerabilities Found: {base_image_total_vulnerabilities}\n'
    f'    - Critical: {base_image_severity_count["CRITICAL"]}\n'
    f'    - High: {base_image_severity_count["HIGH"]}\n'
    f'    - Medium: {base_image_severity_count["MEDIUM"]}\n'
    f'    - Low: {base_image_severity_count["LOW"]}\n'
    f'    - Unknown: {base_image_severity_count["UNKNOWN"]}\n'
  )

  if failed_scans:
    summary_message += f'\n*Failed Scans:* {", ".join(failed_scans)}\n'

  if error_messages:
    summary_message += '\n*Error Messages:*\n' + '\n'.join(error_messages)
  log_info('Summary of Snyk scans prepared for Slack notification.')
  log_info('Summary message:\n' + summary_message)
  summary_message += (
    '\n_(generated by <https://github.com/ministryofjustice/'
    'hmpps-snyk-discovery|hmpps-snyk-discovery>)_'
  )
  if job.name == 'hmpps-snyk-discovery-full':
    slack.notify(summary_message)

  if base_image_severity_count['CRITICAL'] > 0:
    alert_message = (
      f'*Alert: Significant Vulnerabilities in Base Container Images!*\n'
      f'- Critical: {base_image_severity_count["CRITICAL"]}\n'
      f'- High: {base_image_severity_count["HIGH"]}\n'
      f'- Medium: {base_image_severity_count["MEDIUM"]}\n'
      f'- Low: {base_image_severity_count["LOW"]}\n'
      f'Immediate action is recommended to address these vulnerabilities.'
      f'\n_(generated by '
      '<https://github.com/ministryofjustice/hmpps-snyk-discovery|hmpps-snyk-discovery>)_'
    )
    slack.alert(alert_message)
    log_info('Sent slack alert for significant vulnerabilities in base images.')


def update_scan_cve_details(sc): # This will remain unchanged in feat/HEAT-1338-2 branch
  """Populate snyk-scans with CVE details for each snyk_id at end of job."""
  snyk_scan_records = sc.get_all_records('snyk-scans') or []
  if not snyk_scan_records:
    log_info('No snyk-scans records found for CVE enrichment.')
    return

  vulnerability_records = sc.get_all_records('snyk-vulnerabilities') or []
  snyk_id_to_cves = {
    record.get('snyk_id'): sorted(set(record.get('cves') or []))
    for record in vulnerability_records
    if record.get('snyk_id')
  }

  for scan_record in snyk_scan_records:
    document_id = scan_record.get('documentId')
    snyk_ids = scan_record.get('snyk_ids') or []
    if not document_id or not snyk_ids:
      continue

    snyk_cves = [
      {
        'snyk_id': snyk_id,
        'cves': snyk_id_to_cves.get(snyk_id, []),
      }
      for snyk_id in snyk_ids
    ]

    if scan_record.get('snyk_cves') == snyk_cves:
      continue

    try:
      sc.update('snyk-scans', document_id, {'snyk_cves': snyk_cves})
      log_info(f'Updated snyk_cves for snyk-scan record {document_id}')
    except Exception as e:
      log_error(f'Failed updating snyk_cves for snyk-scan record {document_id}: {e}')


def delete_orphan_snyk_vulnerabilities(sc):
  """Delete vulnerability records that are no longer referenced by any snyk-scan."""
  snyk_scan_records = sc.get_all_records('snyk-scans') or []
  active_snyk_ids = set()

  for scan_record in snyk_scan_records:
    for snyk_id in scan_record.get('snyk_ids') or []:
      if snyk_id:
        active_snyk_ids.add(snyk_id)

  vulnerability_records = sc.get_all_records('snyk-vulnerabilities') or []
  deleted_count = 0

  for vuln_record in vulnerability_records:
    snyk_id = vuln_record.get('snyk_id')
    document_id = vuln_record.get('documentId')
    if not snyk_id or not document_id:
      continue

    if snyk_id in active_snyk_ids:
      continue

    try:
      sc.delete('snyk-vulnerabilities', document_id)
      deleted_count += 1
      log_info(
        f'Deleted orphan snyk-vulnerabilities record {document_id} for {snyk_id}'
      )
    except Exception as e:
      log_error(
        'Failed deleting orphan snyk-vulnerabilities record '
        f'{document_id} for {snyk_id}: {e}'
      )

  log_info(
    'Orphan vulnerability cleanup complete: '
    f'{deleted_count} deleted, {len(active_snyk_ids)} '
    'active snyk_ids referenced by scans.'
  )

def upsert_vulnerabilities(sc, vulnerabilities, vulnerability_sync_state=None):
  severity_rank = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'UNKNOWN': 0,
  }
  exploit_maturity_rank = {
    'MATURE': 4,
    'PROOF_OF_CONCEPT': 3,
    'FUNCTIONAL': 2,
    'NO_KNOWN_EXPLOIT': 1,
    'UNKNOWN': 0,
  }

  for vuln in vulnerabilities:
    log_debug('Processing vulnerability: ' + json.dumps(vuln))
    snyk_id = vuln.get('id')
    if not snyk_id:
      continue

    state_existing_record = None
    if vulnerability_sync_state:
      state_existing_record = (vulnerability_sync_state.get('existing') or {}).get(
        snyk_id
      )

    if state_existing_record:
      existing_records = [state_existing_record]
    else:
      existing_records = sc.get_all_records(
        f'snyk-vulnerabilities?filters[snyk_id][$eq]={snyk_id}'
      )

    new_cves = vuln.get('cve', [])
    new_fixed_versions = sorted(set(vuln.get('fixedIn', [])))
    new_affected_versions = (
      sorted(set([vuln.get('version')])) if vuln.get('version') else []
    )
    new_severity = vuln.get('severity', 'UNKNOWN').upper()
    new_language = str(vuln.get('language') or '').strip()
    new_fix_available = str(bool(vuln.get('fixable')))
    new_package_name = vuln.get('name') or vuln.get('packageName')
    new_cvss_score = vuln.get('cvssScore')
    new_exploit_maturity = str(vuln.get('exploitMaturity') or 'UNKNOWN').upper()
    publication_date = vuln.get('snykPublicationDate')
    if isinstance(publication_date, str) and 'T' in publication_date:
      # Strapi `date` fields expect YYYY-MM-DD, not a full timestamp.
      publication_date = publication_date.split('T', 1)[0]

    snyk_vulnerability_payload = {
      'snyk_id': snyk_id,
      'title': vuln.get('title'),
      'description': vuln.get('description') or vuln.get('title') or '',
      'severity': new_severity,
      'language': new_language or 'unknown',
      'cves': new_cves,
      'published_date': publication_date,
      'fix_available': new_fix_available,
      'affected_package_name': new_package_name,
      'affected_versions': new_affected_versions,
      'cvss_score': new_cvss_score,
      'exploit_maturity': new_exploit_maturity,
      'fixed_versions': new_fixed_versions,
    }

    if not existing_records:
      log_info(f'Adding new vulnerability {snyk_id} to snyk-vulnerabilities collection')
      log_debug(
        f'Payload for new vulnerability {snyk_id}: '
        f'{json.dumps(snyk_vulnerability_payload)}'
      )
      response = sc.add('snyk-vulnerabilities', snyk_vulnerability_payload)

      if vulnerability_sync_state and response:
        log_info(f'Updating in-memory sync state for new vulnerability {snyk_id}')
        new_document_id = response.get('data', {}).get('documentId')
        in_memory_record = _normalize_vulnerability_record(snyk_vulnerability_payload)
        in_memory_record['documentId'] = new_document_id
        vulnerability_sync_state.setdefault('existing', {})[snyk_id] = in_memory_record
      continue

    existing = existing_records[0]

    existing_severity = str(existing.get('severity', 'UNKNOWN')).upper()
    existing_language = str(existing.get('language') or '').strip()
    existing_fix_available = str(existing.get('fix_available') or 'False')
    existing_package_name = existing.get('affected_package_name')
    existing_cvss_score = existing.get('cvss_score')
    existing_exploit_maturity = str(
      existing.get('exploit_maturity') or 'UNKNOWN'
    ).upper()
    existing_publication_date = existing.get('published_date')
    existing_cves = existing.get('cves') or []
    existing_fixed_versions = sorted(set(existing.get('fixed_versions') or []))
    existing_affected_versions = sorted(set(existing.get('affected_versions') or []))
    normalized_existing_cves = sorted(set(existing_cves))
    normalized_new_cves = sorted(set(new_cves))
    merged_cves = sorted(set(normalized_existing_cves) | set(normalized_new_cves))
    merged_fixed_versions = sorted(
      set(existing_fixed_versions) | set(new_fixed_versions)
    )
    merged_affected_versions = sorted(
      set(existing_affected_versions) | set(new_affected_versions)
    )

    final_severity = existing_severity
    final_language = existing_language or new_language or 'unknown'
    final_fix_available = (
      'True'
      if str(existing_fix_available).lower() == 'true'
      or str(new_fix_available).lower() == 'true'
      else 'False'
    )
    final_package_name = existing_package_name or new_package_name

    final_publication_date = existing_publication_date or publication_date
    if existing_publication_date and publication_date:
      final_publication_date = min(existing_publication_date, publication_date)

    final_cvss_score = existing_cvss_score
    if existing_cvss_score is None and new_cvss_score is not None:
      final_cvss_score = new_cvss_score
    elif existing_cvss_score is not None and new_cvss_score is not None:
      final_cvss_score = max(existing_cvss_score, new_cvss_score)

    final_exploit_maturity = existing_exploit_maturity
    if exploit_maturity_rank.get(new_exploit_maturity, 0) > exploit_maturity_rank.get(
      existing_exploit_maturity, 0
    ):
      final_exploit_maturity = new_exploit_maturity

    if severity_rank.get(new_severity, 0) > severity_rank.get(existing_severity, 0):
      final_severity = new_severity

    if (
      final_severity == existing_severity
      and final_language == existing_language
      and final_fix_available == existing_fix_available
      and final_package_name == existing_package_name
      and final_publication_date == existing_publication_date
      and final_cvss_score == existing_cvss_score
      and final_exploit_maturity == existing_exploit_maturity
      and merged_cves == normalized_existing_cves
      and merged_fixed_versions == existing_fixed_versions
      and merged_affected_versions == existing_affected_versions
    ):
      log_debug(
        f'No change for vulnerability {snyk_id}; skipping snyk-vulnerabilities update'
      )
      continue

    update_snyk_vulnerability_payload = {
      'severity': final_severity,
      'language': final_language,
      'fix_available': final_fix_available,
      'affected_package_name': final_package_name,
      'published_date': final_publication_date,
      'cvss_score': final_cvss_score,
      'exploit_maturity': final_exploit_maturity,
      'cves': merged_cves,
      'fixed_versions': merged_fixed_versions,
      'affected_versions': merged_affected_versions,
    }

    try:
      log_debug(
        f'Updating existing vulnerability {snyk_id} '
        'in snyk-vulnerabilities collection'
      )
      sc.update(
        'snyk-vulnerabilities',
        existing.get('documentId'),
        update_snyk_vulnerability_payload,
      )

      if vulnerability_sync_state:
        updated_in_memory_record = {
          **_normalize_vulnerability_record(existing),
          **_normalize_vulnerability_record(update_snyk_vulnerability_payload),
          'documentId': existing.get('documentId'),
        }
        vulnerability_sync_state.setdefault('existing', {})[
          snyk_id
        ] = updated_in_memory_record
    except Exception as e:
      log_error(f'Failed updating vuln {snyk_id}: {e}')
