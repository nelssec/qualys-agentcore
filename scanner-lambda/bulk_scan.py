import boto3
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sfn_client = boto3.client('stepfunctions')
sts_client = boto3.client('sts')
dynamodb = boto3.resource('dynamodb')

STATE_MACHINE_ARN = os.environ.get('STATE_MACHINE_ARN', '')
CROSS_ACCOUNT_ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', '')
SCANNER_EXTERNAL_ID = os.environ.get('SCANNER_EXTERNAL_ID', '')
INVENTORY_TABLE = os.environ.get('INVENTORY_TABLE', '')
EXCLUDE_PATTERNS = os.environ.get('EXCLUDE_PATTERNS', 'agentcore-scanner,bulk-scan').split(',')

try:
    INVOCATION_DELAY_MS = int(os.environ.get('INVOCATION_DELAY_MS', '100'))
except ValueError:
    logger.warning("Invalid INVOCATION_DELAY_MS, using default 100")
    INVOCATION_DELAY_MS = 100

try:
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '10'))
except ValueError:
    logger.warning("Invalid MAX_WORKERS, using default 10")
    MAX_WORKERS = 10

try:
    BATCH_SIZE = int(os.environ.get('BATCH_SIZE', '50'))
except ValueError:
    logger.warning("Invalid BATCH_SIZE, using default 50")
    BATCH_SIZE = 50

CURRENT_REGION = os.environ.get('AWS_REGION', 'us-east-1')
DEFAULT_REGIONS = [r.strip() for r in os.environ.get('DEFAULT_REGIONS', '').split(',') if r.strip()]

ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')
REGION_PATTERN = re.compile(r'^[a-z]{2}-[a-z]+-\d+$')


def validate_account_id(account_id: str) -> bool:
    return bool(ACCOUNT_ID_PATTERN.match(account_id))


def validate_region(region: str) -> bool:
    return bool(REGION_PATTERN.match(region))


def should_exclude(runtime_name: str, exclude_patterns: list) -> bool:
    for pattern in exclude_patterns:
        pattern = pattern.strip()
        if pattern and pattern in runtime_name:
            return True
    return False


def get_agentcore_client_for_account(account_id: str, region: str = None):
    """Assume role in spoke account and return an agentcore + ECR client."""
    if not CROSS_ACCOUNT_ROLE_NAME:
        return None, None

    if not validate_account_id(account_id):
        logger.error(f"Invalid account ID format: {account_id}")
        return None, None

    if region and not validate_region(region):
        logger.error(f"Invalid region format: {region}")
        return None, None

    try:
        role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='BulkScanSession',
            DurationSeconds=3600,
            ExternalId=SCANNER_EXTERNAL_ID
        )

        client_kwargs = {
            'aws_access_key_id': assumed_role['Credentials']['AccessKeyId'],
            'aws_secret_access_key': assumed_role['Credentials']['SecretAccessKey'],
            'aws_session_token': assumed_role['Credentials']['SessionToken']
        }
        if region:
            client_kwargs['region_name'] = region

        try:
            agentcore_client = boto3.client('bedrock-agentcore', **client_kwargs)
        except Exception:
            agentcore_client = None

        ecr_client = boto3.client('ecr', **client_kwargs)
        return agentcore_client, ecr_client
    except Exception as e:
        logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None, None


def get_local_agentcore_client(region: str = None):
    """Get agentcore client for the local account."""
    kwargs = {}
    if region and region != CURRENT_REGION:
        kwargs['region_name'] = region

    try:
        return boto3.client('bedrock-agentcore', **kwargs)
    except Exception:
        logger.warning(f"bedrock-agentcore client not available for region {region}")
        return None


def list_all_agent_runtimes(client, exclude_patterns: list) -> List[Dict[str, Any]]:
    """Paginate list-agent-runtimes. Returns runtime details with ECR URIs."""
    runtimes = []

    if not client:
        return runtimes

    try:
        response = client.list_agent_runtimes()
        items = response.get('agentRuntimes', response.get('agentRuntimeSummaries', []))

        while True:
            for runtime in items:
                runtime_name = runtime.get('agentRuntimeName', '')
                if should_exclude(runtime_name, exclude_patterns):
                    logger.debug(f"Excluding runtime: {runtime_name}")
                    continue

                ecr_uri = ''
                artifact = runtime.get('agentRuntimeArtifact', {})
                if isinstance(artifact, dict):
                    container_image = artifact.get('containerImage', {})
                    ecr_uri = container_image.get('uri', '')

                runtimes.append({
                    'agentRuntimeArn': runtime.get('agentRuntimeArn', ''),
                    'agentRuntimeId': runtime.get('agentRuntimeId', ''),
                    'agentRuntimeName': runtime_name,
                    'status': runtime.get('status', ''),
                    'ecrImageUri': ecr_uri,
                })

            next_token = response.get('nextToken')
            if not next_token:
                break
            response = client.list_agent_runtimes(nextToken=next_token)
            items = response.get('agentRuntimes', response.get('agentRuntimeSummaries', []))

    except Exception as e:
        logger.error(f"Error listing agent runtimes: {e}")

    return runtimes


def list_gateway_targets(client, agent_runtime_id: str) -> List[Dict[str, Any]]:
    """List gateway targets per runtime."""
    targets = []

    if not client:
        return targets

    try:
        response = client.list_gateway_targets(agentRuntimeId=agent_runtime_id)
        targets = response.get('gatewayTargets', [])

        while response.get('nextToken'):
            response = client.list_gateway_targets(
                agentRuntimeId=agent_runtime_id,
                nextToken=response['nextToken']
            )
            targets.extend(response.get('gatewayTargets', []))

    except Exception as e:
        logger.warning(f"Error listing gateway targets for {agent_runtime_id}: {e}")

    return targets


def get_inventory_items() -> Dict[str, Dict]:
    """Scan DynamoDB inventory table. Returns {arn: item}."""
    if not INVENTORY_TABLE:
        return {}

    try:
        table = dynamodb.Table(INVENTORY_TABLE)
        items = {}
        response = table.scan()

        for item in response.get('Items', []):
            arn = item.get('agent_runtime_arn')
            if arn:
                items[arn] = item

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            for item in response.get('Items', []):
                arn = item.get('agent_runtime_arn')
                if arn:
                    items[arn] = item

        return items

    except Exception as e:
        logger.error(f"Error scanning inventory table: {e}")
        return {}


def identify_stale_entries(discovered: List[Dict], inventory: Dict[str, Dict]) -> List[Dict]:
    """Compare API results against inventory. Returns runtimes needing scans."""
    needs_scan = []

    for runtime in discovered:
        arn = runtime.get('agentRuntimeArn')
        if not arn:
            continue

        existing = inventory.get(arn)

        if not existing:
            # Not in inventory — shadow/missed agent
            runtime['_scan_reason'] = 'not_in_inventory'
            needs_scan.append(runtime)
            continue

        # Check if ECR image changed
        current_uri = runtime.get('ecrImageUri', '')
        cached_uri = existing.get('ecr_image_uri', '')
        if current_uri and current_uri != cached_uri:
            runtime['_scan_reason'] = 'image_changed'
            needs_scan.append(runtime)
            continue

        # Check if last scan is stale
        last_scan = existing.get('last_scan_timestamp', '')
        if not last_scan:
            runtime['_scan_reason'] = 'never_scanned'
            needs_scan.append(runtime)
            continue

    return needs_scan


def mark_deleted_runtimes(discovered_arns: set, inventory: Dict[str, Dict]) -> None:
    """Mark inventory entries as DELETED if no longer in API response."""
    if not INVENTORY_TABLE:
        return

    try:
        table = dynamodb.Table(INVENTORY_TABLE)
        for arn, item in inventory.items():
            if arn not in discovered_arns and item.get('status') != 'DELETED':
                table.update_item(
                    Key={'agent_runtime_arn': arn},
                    UpdateExpression='SET #status = :status, updated_at = :ts',
                    ExpressionAttributeNames={'#status': 'status'},
                    ExpressionAttributeValues={
                        ':status': 'DELETED',
                        ':ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    }
                )
                logger.info(f"Marked as DELETED: {arn}")
    except Exception as e:
        logger.error(f"Error marking deleted runtimes: {e}")


def invoke_scanner(runtime: Dict[str, Any], source_account: str,
                   region: str = '') -> Tuple[bool, str]:
    """Start a Step Functions execution for a single agent runtime."""
    runtime_name = runtime.get('agentRuntimeName', 'unknown')

    if not STATE_MACHINE_ARN:
        logger.error("STATE_MACHINE_ARN not configured")
        return False, runtime_name

    scan_event = {
        'source': 'agentcore.bulk-scan',
        'detail-type': 'Bulk Scan Request',
        'region': region or CURRENT_REGION,
        'account': source_account,
        'detail': {
            'eventName': 'BulkScanRequest',
            'eventSource': 'bedrock-agentcore.amazonaws.com',
            'requestParameters': {
                'agentRuntimeId': runtime.get('agentRuntimeId', ''),
            },
            'responseElements': {
                'agentRuntimeArn': runtime.get('agentRuntimeArn', ''),
                'agentRuntimeName': runtime_name,
                'status': runtime.get('status', 'ACTIVE'),
            },
            'userIdentity': {
                'accountId': source_account,
            },
            'agentRuntimeArtifact': {
                'containerImage': {
                    'uri': runtime.get('ecrImageUri', ''),
                }
            },
        },
    }

    runtime_id = runtime.get('agentRuntimeId', 'unknown')
    timestamp = int(time.time())
    exec_name = f"bulk-{source_account}-{runtime_id[:20]}-{timestamp}"
    # Step Functions execution names max 80 chars, must match [a-zA-Z0-9-_]
    exec_name = re.sub(r'[^a-zA-Z0-9_-]', '-', exec_name)[:80]

    try:
        sfn_client.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=exec_name,
            input=json.dumps(scan_event)
        )
        return True, runtime_name
    except Exception as e:
        logger.error(f"Failed to start execution for {runtime_name}: {e}")
        return False, runtime_name


def invoke_batch_parallel(runtimes: List[Dict[str, Any]], account_id: str,
                          region: str = '') -> Tuple[int, int]:
    invoked = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_runtime = {
            executor.submit(invoke_scanner, runtime, account_id, region): runtime
            for runtime in runtimes
        }

        for future in as_completed(future_to_runtime):
            try:
                success, name = future.result()
                if success:
                    invoked += 1
                else:
                    failed += 1
            except Exception as e:
                runtime = future_to_runtime[future]
                logger.error(f"Exception invoking scanner for "
                             f"{runtime.get('agentRuntimeName', 'unknown')}: {e}")
                failed += 1

    return invoked, failed


def process_region(account_id: str, region: str, current_account: str,
                   exclude_patterns: list, dry_run: bool) -> Dict[str, Any]:
    result = {
        'region': region,
        'status': 'pending',
        'runtimes': 0,
        'invoked': 0,
        'failed': 0,
    }

    try:
        if account_id == current_account:
            agentcore_client = get_local_agentcore_client(region)
        else:
            agentcore_client, _ = get_agentcore_client_for_account(account_id, region)

        if not agentcore_client:
            result['status'] = 'failed'
            result['error'] = 'Could not create agentcore client'
            return result

        runtimes = list_all_agent_runtimes(agentcore_client, exclude_patterns)
        runtime_count = len(runtimes)
        result['runtimes'] = runtime_count

        logger.info(f"Found {runtime_count} agent runtimes in {account_id}/{region}")

        if dry_run:
            result['status'] = 'dry_run'
            return result

        if runtime_count == 0:
            result['status'] = 'success'
            return result

        # Get inventory for stale detection
        inventory = get_inventory_items()
        needs_scan = identify_stale_entries(runtimes, inventory)

        # Mark deleted runtimes
        discovered_arns = {r.get('agentRuntimeArn') for r in runtimes}
        mark_deleted_runtimes(discovered_arns, inventory)

        # Invoke scanner for runtimes needing scans
        if not needs_scan:
            logger.info(f"All runtimes in {account_id}/{region} are up-to-date")
            result['status'] = 'success'
            return result

        logger.info(f"{len(needs_scan)} runtimes need scanning in {account_id}/{region}")

        invoked = 0
        failed = 0

        for i in range(0, len(needs_scan), BATCH_SIZE):
            batch = needs_scan[i:i + BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            total_batches = (len(needs_scan) + BATCH_SIZE - 1) // BATCH_SIZE

            logger.info(f"Processing batch {batch_num}/{total_batches} in {region} "
                        f"({len(batch)} runtimes)")

            batch_invoked, batch_failed = invoke_batch_parallel(batch, account_id, region)
            invoked += batch_invoked
            failed += batch_failed

            if i + BATCH_SIZE < len(needs_scan) and INVOCATION_DELAY_MS > 0:
                pause_seconds = (INVOCATION_DELAY_MS * BATCH_SIZE) / 1000.0
                time.sleep(pause_seconds)

        result['invoked'] = invoked
        result['failed'] = failed
        result['status'] = 'success'

    except Exception as e:
        logger.error(f"Error processing {account_id}/{region}: {e}")
        result['status'] = 'error'
        result['error'] = str(e)

    return result


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    logger.info(f"Bulk scan triggered with event: {json.dumps(event)}")

    if not STATE_MACHINE_ARN:
        return {
            'statusCode': 500,
            'body': {'error': 'STATE_MACHINE_ARN not configured'}
        }

    account_ids = event.get('account_ids', [])
    event_regions = event.get('regions', [])
    dry_run = event.get('dry_run', False)
    additional_excludes = event.get('exclude_patterns', [])

    if event_regions:
        regions = [r.strip() for r in event_regions if r.strip()]
    elif DEFAULT_REGIONS:
        regions = DEFAULT_REGIONS
    else:
        regions = [CURRENT_REGION]

    invalid_regions = [r for r in regions if not validate_region(r)]
    if invalid_regions:
        return {
            'statusCode': 400,
            'body': {'error': f'Invalid regions: {invalid_regions}'}
        }

    exclude_patterns = list(EXCLUDE_PATTERNS) + additional_excludes

    results = {
        'accounts_processed': 0,
        'accounts_failed': 0,
        'regions_scanned': len(regions),
        'total_runtimes': 0,
        'invoked': 0,
        'failed': 0,
        'details': []
    }

    current_account = sts_client.get_caller_identity()['Account']

    if not account_ids:
        account_ids = [current_account]

    logger.info(f"Scanning {len(account_ids)} account(s) across {len(regions)} region(s): {regions}")

    for account_id in account_ids:
        account_id = str(account_id).strip()

        if not validate_account_id(account_id):
            logger.error(f"Invalid account ID: {account_id}")
            results['accounts_failed'] += 1
            continue

        logger.info(f"Processing account: {account_id}")

        account_detail = {
            'account': account_id,
            'status': 'success',
            'regions': [],
            'total_runtimes': 0,
            'total_invoked': 0,
            'total_failed': 0,
        }

        account_has_error = False

        for region in regions:
            region_result = process_region(
                account_id, region, current_account,
                exclude_patterns, dry_run
            )

            account_detail['regions'].append(region_result)
            account_detail['total_runtimes'] += region_result.get('runtimes', 0)
            account_detail['total_invoked'] += region_result.get('invoked', 0)
            account_detail['total_failed'] += region_result.get('failed', 0)

            results['total_runtimes'] += region_result.get('runtimes', 0)
            results['invoked'] += region_result.get('invoked', 0)
            results['failed'] += region_result.get('failed', 0)

            if region_result.get('status') == 'error':
                account_has_error = True

        if account_has_error:
            account_detail['status'] = 'partial'

        results['details'].append(account_detail)
        results['accounts_processed'] += 1

    logger.info(f"Bulk scan complete: {json.dumps(results)}")

    return {
        'statusCode': 200,
        'body': results
    }
