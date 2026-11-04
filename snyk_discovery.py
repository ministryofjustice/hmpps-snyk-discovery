#!/usr/bin/env python
import base64
import binascii
import json
import os
import sys
import pathlib
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

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


def _setup_ghcr_authentication():
  """
  Set up GHCR authentication from GHCR_AUTH_CONFIG.
  
  Returns:
      bool: True if GHCR credentials were configured, False otherwise
  """
  raw_config = os.getenv('GHCR_AUTH_CONFIG', '').strip()
  if not raw_config:
    log_warning('GHCR_AUTH_CONFIG not found - GHCR images will not be accessible')
    return False

  config_data = None
  try:
    config_data = json.loads(raw_config)
  except json.JSONDecodeError:
    try:
      decoded = base64.b64decode(raw_config).decode('utf-8')
      config_data = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
      log_warning('GHCR_AUTH_CONFIG is not valid JSON; skipping GHCR setup.')
      return False

  auths = config_data.get('auths', {}) if isinstance(config_data, dict) else {}
  ghcr_auth_entry = (
    auths.get('ghcr.io')
    or auths.get('https://ghcr.io')
    or auths.get('https://ghcr.io/v1/')
  )
  if not isinstance(ghcr_auth_entry, dict):
    log_warning('No valid GHCR auth entry found in GHCR_AUTH_CONFIG')
    return False

  username = ghcr_auth_entry.get('username')
  password = ghcr_auth_entry.get('password')

  if not username or not password:
    auth_value = ghcr_auth_entry.get('auth')
    if not auth_value:
      log_warning('No credentials found in GHCR auth entry')
      return False
    try:
      decoded_auth = base64.b64decode(auth_value).decode('utf-8')
      username, password = decoded_auth.split(':', 1)
    except (binascii.Error, UnicodeDecodeError, ValueError):
      log_warning('Unable to decode GHCR auth token; skipping GHCR setup.')
      return False

  os.environ['SNYK_REGISTRY_USERNAME'] = username
  os.environ['SNYK_REGISTRY_PASSWORD'] = password
  log_info('✓ GHCR authentication configured from GHCR_AUTH_CONFIG')
  return True


def _setup_ecr_authentication_via_irsa():
  """
  Set up ECR authentication using IRSA (IAM Roles for Service Accounts).
  
  Uses boto3 to get ECR authorization tokens for multiple regions and writes
  credentials to ~/.docker/config.json (no docker-py needed).
  
  Supports images in different ECR regions (eu-west-2, us-east-1, etc).
  
  IRSA automatically provides:
  - AWS_ROLE_ARN: The ARN of the assumed IAM role
  - AWS_WEB_IDENTITY_TOKEN_FILE: Path to JWT token file
  
  Returns:
      bool: True if IRSA is configured and credentials written
            successfully, False otherwise
  """
  # Check if IRSA environment variables are present
  aws_role_arn = os.getenv('AWS_ROLE_ARN', '').strip()
  aws_token_file = os.getenv('AWS_WEB_IDENTITY_TOKEN_FILE', '').strip()
  
  if not aws_role_arn or not aws_token_file or not os.path.exists(aws_token_file):
    log_warning('IRSA is not configured - ECR images will not be accessible')
    log_info('Ensure ServiceAccount has eks.amazonaws.com/role-arn annotation')
    return False
  
  log_info('✓ IRSA is configured')
  log_debug(f'  Role ARN: {aws_role_arn}')
  log_debug(f'  Token File: {aws_token_file}')
  
  try:
    # Extract account ID from role ARN (arn:aws:iam::ACCOUNT_ID:role/...)
    try:
      account_id = aws_role_arn.split(':')[4]
    except (IndexError, ValueError):
      log_error(f'Unable to extract account ID from role ARN: {aws_role_arn}')
      return False
    
    # Support multiple ECR regions (images may be in different regions)
    ecr_regions = ['us-east-1', 'eu-west-2', 'eu-west-1']
    
    # Load or create docker config
    docker_config_dir = pathlib.Path.home() / '.docker'
    docker_config_dir.mkdir(mode=0o700, exist_ok=True)
    docker_config_file = docker_config_dir / 'config.json'
    
    if docker_config_file.exists():
      with open(docker_config_file, 'r') as f:
        config = json.load(f)
    else:
      config = {'auths': {}}
    
    # Ensure 'auths' section exists
    if 'auths' not in config:
      config['auths'] = {}
    
    # Get credentials for each region
    for region in ecr_regions:
      try:
        ecr_endpoint = f'{account_id}.dkr.ecr.{region}.amazonaws.com'
        
        # Create boto3 ECR client for this region
        ecr_client = boto3.client('ecr', region_name=region)
        
        # Get ECR authorization token from AWS
        response = ecr_client.get_authorization_token()
        auth_data = response['authorizationData'][0]
        
        # Decode authorization token (base64 encoded username:password)
        auth_token = base64.b64decode(
          auth_data['authorizationToken']
        ).decode('utf-8')
        username, password = auth_token.split(':')
        
        # Add ECR credentials for this region
        credentials = base64.b64encode(
          f'{username}:{password}'.encode()
        ).decode()
        config['auths'][ecr_endpoint] = {'auth': credentials}
        
        log_debug(f'  ✓ Got credentials for {region}')
        
      except ClientError as e:
        log_debug(f'  Could not get credentials for {region}: {e}')
        continue
      except Exception as e:
        log_debug(f'  Unexpected error for {region}: {e}')
        continue
    
    # Write config back to file
    with open(docker_config_file, 'w') as f:
      json.dump(config, f)
    
    # Restrict permissions on config file (contains credentials)
    docker_config_file.chmod(0o600)
    
    num_regions = len([k for k in config['auths'].keys() 
                       if '.dkr.ecr.' in k])
    log_info(f'✓ ECR credentials configured for {num_regions} region(s)')
    return True
    
  except (IOError, OSError) as e:
    log_error(f'Failed to write Docker config: {e}')
    return False
  except Exception as e:
    log_error(f'Unexpected error during ECR authentication: {e}')
    return False


def _print_registry_status(ghcr_available, ecr_available, quay_available=True):
  """
  Print a summary of available registries for debugging.
  
  Args:
      ghcr_available: Whether GHCR credentials are configured
      ecr_available: Whether IRSA/ECR setup is configured
      quay_available: Always True (public registry, no auth needed)
  """
  log_info('')
  log_info('Registry Authentication Status:')
  log_info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  quay_status = '✓ No auth required' if quay_available else '✗ Not accessible'
  log_info(f'  quay.io (Public):      {quay_status}')
  ghcr_status = '✓ Available' if ghcr_available else '✗ Not configured'
  log_info(f'  GHCR (ghcr.io):        {ghcr_status}')
  ecr_status = '✓ Available (IRSA)' if ecr_available else '✗ Not configured'
  log_info(f'  ECR (*.dkr.ecr.*):     {ecr_status}')
  log_info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  log_info('')
  
  # Fail only if NO registries are available
  if not quay_available and not ghcr_available and not ecr_available:
    log_critical('ERROR: No registries are accessible!')
    return False
  
  return True



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
  
  # Step 1: Normalize Service Catalogue endpoint (local testing support)
  _normalise_service_catalogue_endpoint_for_local_testing()
  
  # Step 2: Set up GHCR authentication (from GHCR_AUTH_CONFIG)
  ghcr_available = _setup_ghcr_authentication()
  
  # Step 3: Set up ECR authentication (from IRSA)
  ecr_available = _setup_ecr_authentication_via_irsa()
  
  # Step 4: Print registry status (quay.io is always available as public)
  quay_available = True  # quay.io is public, no auth needed
  if not _print_registry_status(ghcr_available, ecr_available, quay_available):
    log_critical('No registries are accessible!')
    slack.alert(
      'hmpps-snyk-discovery: No registries are accessible '
      '(quay.io, GHCR, ECR)'
    )
    sys.exit(1)
  
  # Step 5: Connect to Service Catalogue
  sc = ServiceCatalogue()

  if not sc.connection_ok:
    log_error('Failed to connect to the Service Catalogue. Exiting...')
    slack.alert('hmpps-snyk-discovery: failed to connect to the Service Catalogue')
    sys.exit(1)

  # Step 6: Install Snyk
  log_debug('Installing snyk')
  snyk_status = snyk.install()
  if snyk_status.startswith('Failed'):
    log_critical(f'{snyk_status}')
    slack.alert(f'{job.name} - {snyk_status}')
    sc.update_scheduled_job('Failed')
    sys.exit(1)
  log_debug('Snyk installed')

  # Step 7: Get image list and perform scans
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
  
  # Step 8: Final status
  if job.error_messages:
    sc.update_scheduled_job('Errors')
    log_info('Snyk discovery job completed with errors.')
  else:
    sc.update_scheduled_job('Succeeded')
    log_info('Snyk discovery job completed successfully.')


if __name__ == '__main__':
  main()
