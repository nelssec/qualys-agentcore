"""Step Functions dispatch-pattern Lambda handler for AgentCore Scanner.

Replaces lambda_function.py — each action maps to a Step Functions state.
"""

import os
import json
import boto3
import logging
import re
import time
import random
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

secrets_manager = boto3.client('secretsmanager')
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
sts_client = boto3.client('sts')
cloudwatch = boto3.client('cloudwatch')
dynamodb = boto3.resource('dynamodb')

QUALYS_SECRET_ARN = os.environ.get('QUALYS_SECRET_ARN')
RESULTS_S3_BUCKET = os.environ.get('RESULTS_S3_BUCKET')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
SCAN_CACHE_TABLE = os.environ.get('SCAN_CACHE_TABLE')
INVENTORY_TABLE = os.environ.get('INVENTORY_TABLE')

EXISTING_ROLE_ARN = os.environ.get('EXISTING_ROLE_ARN')
EXISTING_ROLE_NAME = os.environ.get('EXISTING_ROLE_NAME', 'agentcore-qualys-ecr-reader')
STATE_MACHINE_ARN = os.environ.get('STATE_MACHINE_ARN')

try:
    CACHE_TTL_DAYS = int(os.environ.get('CACHE_TTL_DAYS', '30'))
except ValueError:
    logger.warning("Invalid CACHE_TTL_DAYS, using default 30")
    CACHE_TTL_DAYS = 30

SCANNER_EXTERNAL_ID = os.environ.get('SCANNER_EXTERNAL_ID')
CROSS_ACCOUNT_ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE_NAME')

ENABLE_MCP_DETECTION = os.environ.get('ENABLE_MCP_DETECTION', 'true').lower() == 'true'
ENABLE_AI_SERVICE_DETECTION = os.environ.get('ENABLE_AI_SERVICE_DETECTION', 'true').lower() == 'true'


class ScanException(Exception):
    pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_pod(pod: str) -> bool:
    return bool(re.match(r'^[A-Z0-9]+$', pod))


def validate_access_token(token: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_.-]{20,1000}$', token))


def validate_ecr_image_uri(uri: str) -> bool:
    if not uri or not isinstance(uri, str):
        return False
    pattern = r'^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9._/-]+(?::[a-zA-Z0-9._-]+|@sha256:[a-f0-9]{64})?$'
    return bool(re.match(pattern, uri))


def validate_agent_runtime_arn(arn: str) -> bool:
    if not arn or not isinstance(arn, str):
        return False
    pattern = r'^arn:aws:bedrock-agentcore:[a-z0-9-]+:\d{12}:runtime/[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, arn))


def validate_role_arn(arn: str) -> bool:
    if not arn or not isinstance(arn, str):
        return False
    return bool(re.match(r'^arn:aws:iam::\d{12}:role/[a-zA-Z0-9+=,.@_/-]{1,128}$', arn))


def sanitize_log_output(output: str) -> str:
    if not output:
        return ""
    output = re.sub(r'[a-zA-Z0-9]{32,}', '[REDACTED]', output)
    output = re.sub(r'(token|password|secret|key)[\s:=]+\S+', r'\1=[REDACTED]', output, flags=re.IGNORECASE)
    return output


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def publish_custom_metrics(metric_data: Dict[str, Any]) -> None:
    try:
        metrics = []
        namespace = 'AgentCoreScanner'

        if 'scan_success' in metric_data:
            metrics.append({
                'MetricName': 'ScanSuccess',
                'Value': 1 if metric_data['scan_success'] else 0,
                'Unit': 'Count'
            })

        if 'scan_partial' in metric_data:
            metrics.append({
                'MetricName': 'ScanPartialSuccess',
                'Value': 1 if metric_data['scan_partial'] else 0,
                'Unit': 'Count'
            })

        if 'scan_duration' in metric_data:
            metrics.append({
                'MetricName': 'ScanDuration',
                'Value': metric_data['scan_duration'],
                'Unit': 'Seconds'
            })

        if 'cache_hit' in metric_data:
            metrics.append({
                'MetricName': 'CacheHit',
                'Value': 1 if metric_data['cache_hit'] else 0,
                'Unit': 'Count'
            })

        if 'vulnerability_count' in metric_data:
            metrics.append({
                'MetricName': 'VulnerabilityCount',
                'Value': metric_data['vulnerability_count'],
                'Unit': 'Count'
            })

        if 'mcp_servers_detected' in metric_data:
            metrics.append({
                'MetricName': 'MCPServersDetected',
                'Value': metric_data['mcp_servers_detected'],
                'Unit': 'Count'
            })

        if 'ai_services_detected' in metric_data:
            metrics.append({
                'MetricName': 'AIServicesDetected',
                'Value': metric_data['ai_services_detected'],
                'Unit': 'Count'
            })

        if metrics:
            cloudwatch.put_metric_data(Namespace=namespace, MetricData=metrics)

    except Exception as e:
        logger.error(f"Failed to publish metrics: {e}")


# ---------------------------------------------------------------------------
# AWS retry decorator
# ---------------------------------------------------------------------------

def aws_retry(max_retries: int = 5, initial_delay: float = 0.5, max_delay: float = 30):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from botocore.exceptions import ClientError, BotoCoreError
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    retryable_codes = [
                        'Throttling', 'ThrottlingException', 'RequestThrottled',
                        'ProvisionedThroughputExceededException', 'ServiceUnavailable',
                        'InternalError', 'InternalServiceError', 'RequestLimitExceeded',
                        'TooManyRequestsException', 'TransactionConflictException'
                    ]
                    if error_code in retryable_codes and attempt < max_retries - 1:
                        delay = min(initial_delay * (2 ** attempt), max_delay)
                        delay = delay * (0.5 + random.random())
                        logger.warning(f"Retry {attempt + 1}/{max_retries} for {func.__name__}: {error_code}")
                        time.sleep(delay)
                        last_exception = e
                    else:
                        raise
                except BotoCoreError as e:
                    if attempt < max_retries - 1:
                        delay = min(initial_delay * (2 ** attempt), max_delay)
                        delay = delay * (0.5 + random.random())
                        logger.warning(f"Retry {attempt + 1}/{max_retries} for {func.__name__}: {type(e).__name__}")
                        time.sleep(delay)
                        last_exception = e
                    else:
                        raise
            if last_exception:
                raise last_exception
            raise ScanException(f"Max retries exceeded for {func.__name__}")
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Event parsing
# ---------------------------------------------------------------------------

def extract_agent_runtime_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse CloudTrail event for CreateAgentRuntime, UpdateAgentRuntime, CreateGatewayTarget."""
    if 'detail' not in event:
        raise ValueError("Invalid event structure: missing 'detail'")

    detail = event['detail']
    event_name = detail.get('eventName', '')
    account_id = event.get('account', detail.get('userIdentity', {}).get('accountId'))
    region = event.get('region', detail.get('awsRegion', 'us-east-1'))

    result = {
        'event_name': event_name,
        'account_id': account_id,
        'region': region,
    }

    response_elements = detail.get('responseElements', {}) or {}
    request_params = detail.get('requestParameters', {}) or {}

    if event_name == 'CreateGatewayTarget':
        result['gateway_target_id'] = response_elements.get('gatewayTargetId')
        result['gateway_target_name'] = request_params.get('name') or response_elements.get('name')
        result['gateway_identifier'] = request_params.get('gatewayIdentifier')
        result['target_configuration'] = request_params.get('targetConfiguration', {})
        result['status'] = response_elements.get('status')
        return result

    # CreateAgentRuntime or UpdateAgentRuntime
    agent_runtime_arn = response_elements.get('agentRuntimeArn')
    if not agent_runtime_arn:
        raise ValueError("Could not extract agentRuntimeArn from event")

    if not validate_agent_runtime_arn(agent_runtime_arn):
        raise ValueError(f"Invalid agent runtime ARN: {agent_runtime_arn}")

    result['agent_runtime_arn'] = agent_runtime_arn
    result['agent_runtime_id'] = response_elements.get('agentRuntimeId')
    result['agent_runtime_name'] = response_elements.get('agentRuntimeName') or request_params.get('agentRuntimeName')
    result['status'] = response_elements.get('status')

    # Extract ECR image URI from the artifact
    artifact = request_params.get('agentRuntimeArtifact', {})
    if not artifact:
        artifact = detail.get('agentRuntimeArtifact', {})

    container_image = artifact.get('containerImage', {})
    ecr_image_uri = container_image.get('uri')
    result['ecr_image_uri'] = ecr_image_uri

    role_arn = request_params.get('roleArn')
    result['role_arn'] = role_arn

    return result


# ---------------------------------------------------------------------------
# ECR helper
# ---------------------------------------------------------------------------

@aws_retry(max_retries=5, initial_delay=0.5)
def get_ecr_image_digest(image_uri: str, ecr_client=None) -> Optional[str]:
    """Resolve ECR tag to sha256 digest. Used as cache key."""
    if not image_uri:
        return None

    if '@sha256:' in image_uri:
        return image_uri.split('@sha256:')[1]

    parts = image_uri.split('/')
    repo_and_tag = '/'.join(parts[1:])

    if ':' in repo_and_tag:
        repo, tag = repo_and_tag.rsplit(':', 1)
    else:
        repo = repo_and_tag
        tag = 'latest'

    client = ecr_client or boto3.client('ecr')

    try:
        response = client.describe_images(
            repositoryName=repo,
            imageIds=[{'imageTag': tag}]
        )
        images = response.get('imageDetails', [])
        if images:
            return images[0].get('imageDigest', '').replace('sha256:', '')
    except Exception as e:
        logger.warning(f"Could not resolve ECR digest for {image_uri}: {e}")

    return None


def _get_ecr_client(account_id: str, region: str):
    """Get ECR client — assumes spoke role if cross-account."""
    if CROSS_ACCOUNT_ROLE_NAME and account_id:
        cross_account_role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
        if not validate_role_arn(cross_account_role_arn):
            raise ValueError(f"Invalid cross-account role ARN format: {cross_account_role_arn}")

        assumed_role = sts_client.assume_role(
            RoleArn=cross_account_role_arn,
            RoleSessionName='AgentCoreScannerSession',
            DurationSeconds=900,
            ExternalId=SCANNER_EXTERNAL_ID
        )

        return boto3.client('ecr',
                            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                            aws_session_token=assumed_role['Credentials']['SessionToken'],
                            region_name=region)
    else:
        return boto3.client('ecr', region_name=region)


# ---------------------------------------------------------------------------
# Scan cache
# ---------------------------------------------------------------------------

@aws_retry(max_retries=5, initial_delay=0.5)
def _get_cache_item(table, image_digest: str) -> Optional[Dict]:
    response = table.get_item(Key={'image_digest': image_digest})
    return response.get('Item')


def check_scan_cache(image_digest: str) -> bool:
    """Cache keyed on image_digest. Multiple runtimes may use the same image."""
    if not SCAN_CACHE_TABLE or not image_digest:
        return False

    try:
        table = dynamodb.Table(SCAN_CACHE_TABLE)
        item = _get_cache_item(table, image_digest)

        if not item:
            return False

        scan_timestamp = item.get('scan_timestamp')
        if scan_timestamp:
            scan_time = datetime.fromisoformat(scan_timestamp)
            cache_expiry = scan_time + timedelta(days=CACHE_TTL_DAYS)
            if datetime.utcnow() > cache_expiry:
                return False

        return True

    except Exception as e:
        logger.error(f"Cache check error: {e}")
        return False


@aws_retry(max_retries=5, initial_delay=0.5)
def _put_cache_item(table, item: Dict) -> None:
    table.put_item(Item=item)


def update_scan_cache(image_digest: str, ecr_image_uri: str,
                      agent_runtime_arn: str, scan_result: Dict[str, Any]) -> None:
    if not SCAN_CACHE_TABLE or not image_digest:
        return

    try:
        table = dynamodb.Table(SCAN_CACHE_TABLE)
        timestamp = datetime.utcnow()

        severity_summary = scan_result.get('summary', {'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
        vuln_count = severity_summary.get('total', sum(severity_summary.get(k, 0) for k in ['critical', 'high', 'medium', 'low']))

        item = {
            'image_digest': image_digest,
            'ecr_image_uri': ecr_image_uri,
            'scan_timestamp': timestamp.isoformat(),
            'scan_success': True,
            'vulnerability_count': vuln_count,
            'severity_summary': severity_summary,
            'agent_runtime_arns': set([agent_runtime_arn]),
            'ttl': int((timestamp + timedelta(days=CACHE_TTL_DAYS)).timestamp()),
        }

        _put_cache_item(table, item)

    except Exception as e:
        logger.error(f"Cache update error: {e}")


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

@aws_retry(max_retries=5, initial_delay=0.5)
def _update_inventory_item(table, item: Dict) -> None:
    table.put_item(Item=item)


def update_inventory(agent_runtime_arn: str, details: Dict[str, Any],
                     discovery_source: str = 'event-driven') -> None:
    if not INVENTORY_TABLE:
        return

    try:
        table = dynamodb.Table(INVENTORY_TABLE)
        timestamp = datetime.utcnow().isoformat()

        existing = None
        try:
            resp = table.get_item(Key={'agent_runtime_arn': agent_runtime_arn})
            existing = resp.get('Item')
        except Exception:
            pass

        item = {
            'agent_runtime_arn': agent_runtime_arn,
            'account_id': details.get('account_id', ''),
            'ecr_image_uri': details.get('ecr_image_uri', ''),
            'agent_runtime_name': details.get('agent_runtime_name', ''),
            'status': details.get('status', 'UNKNOWN'),
            'region': details.get('region', ''),
            'gateway_targets': details.get('gateway_targets', existing.get('gateway_targets', []) if existing else []),
            'mcp_servers': details.get('mcp_servers', existing.get('mcp_servers', []) if existing else []),
            'ai_services': details.get('ai_services', existing.get('ai_services', []) if existing else []),
            'risk_score': details.get('risk_score', existing.get('risk_score', 0) if existing else 0),
            'risk_factors': details.get('risk_factors', existing.get('risk_factors', []) if existing else []),
            'last_scan_timestamp': details.get('last_scan_timestamp', ''),
            'last_scan_status': details.get('last_scan_status', 'pending'),
            'last_scan_image_digest': details.get('last_scan_image_digest', ''),
            'discovery_source': discovery_source,
            'created_at': existing.get('created_at', timestamp) if existing else timestamp,
            'updated_at': timestamp,
        }

        _update_inventory_item(table, item)

    except Exception as e:
        logger.error(f"Inventory update error: {e}")


# ---------------------------------------------------------------------------
# Results storage
# ---------------------------------------------------------------------------

@aws_retry(max_retries=5, initial_delay=0.5)
def _s3_put_object(bucket: str, key: str, body: str) -> None:
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType='application/json'
    )


@aws_retry(max_retries=5, initial_delay=0.5)
def _sns_publish(topic_arn: str, subject: str, message: str) -> None:
    sns_client.publish(TopicArn=topic_arn, Subject=subject, Message=message)


def store_results(agent_runtime_details: Dict[str, Any],
                  scan_results: Dict[str, Any]) -> None:
    timestamp = datetime.utcnow().isoformat()

    full_results = {
        'scan_timestamp': timestamp,
        'agent_runtime': agent_runtime_details,
        'scan_results': scan_results
    }

    runtime_name = agent_runtime_details.get('agent_runtime_name', 'unknown')

    if RESULTS_S3_BUCKET:
        try:
            key = f"scans/{runtime_name}/{timestamp}.json"
            _s3_put_object(RESULTS_S3_BUCKET, key, json.dumps(full_results, indent=2, default=str))
        except Exception as e:
            logger.error(f"S3 storage error: {e}")

    if SNS_TOPIC_ARN:
        try:
            message = {
                'agent_runtime_name': runtime_name,
                'agent_runtime_arn': agent_runtime_details.get('agent_runtime_arn', 'N/A'),
                'ecr_image_uri': agent_runtime_details.get('ecr_image_uri', 'N/A'),
                'scan_timestamp': timestamp,
                'scan_success': True,
            }

            if 'summary' in scan_results:
                message['vulnerability_summary'] = scan_results['summary']

            _sns_publish(
                SNS_TOPIC_ARN,
                f"AgentCore Scan: {runtime_name}",
                json.dumps(message, indent=2, default=str)
            )
        except Exception as e:
            logger.error(f"SNS publish error: {e}")


# ---------------------------------------------------------------------------
# Action handlers (each maps to a Step Functions state)
# ---------------------------------------------------------------------------

def handle_parse_event(event, context=None):
    """Parse CloudTrail event, handle gateway targets inline."""
    runtime_details = extract_agent_runtime_from_event(event)
    event_name = runtime_details['event_name']
    account_id = runtime_details.get('account_id')
    region = runtime_details.get('region', 'us-east-1')

    logger.info(f"Processing {event_name}: account={account_id} region={region}")

    # Gateway target → MCP detection, return immediately (no images to scan)
    if event_name == 'CreateGatewayTarget':
        if ENABLE_MCP_DETECTION:
            try:
                from mcp_detector import classify_gateway_target
                target_config = runtime_details.get('target_configuration', {})
                mcp_info = classify_gateway_target(target_config)
                if mcp_info:
                    logger.info(f"MCP server detected: risk={mcp_info.risk_level}")
                    publish_custom_metrics({'mcp_servers_detected': 1})
            except Exception as e:
                logger.error(f"MCP detection error: {e}")

        return {
            'has_images': False,
            'event_name': event_name,
            'gateway_target_id': runtime_details.get('gateway_target_id'),
            'message': 'Gateway target processed',
        }

    agent_runtime_arn = runtime_details['agent_runtime_arn']
    ecr_image_uri = runtime_details.get('ecr_image_uri')

    if not ecr_image_uri or not validate_ecr_image_uri(ecr_image_uri):
        logger.warning(f"No valid ECR image URI for {agent_runtime_arn}")
        update_inventory(agent_runtime_arn, runtime_details, 'event-driven')
        return {
            'has_images': False,
            'event_name': event_name,
            'agent_runtime_arn': agent_runtime_arn,
            'message': 'No valid ECR image',
        }

    return {
        'has_images': True,
        'event_name': event_name,
        'agent_runtime_arn': agent_runtime_arn,
        'agent_runtime_name': runtime_details.get('agent_runtime_name', ''),
        'ecr_image_uri': ecr_image_uri,
        'account_id': account_id,
        'region': region,
        'role_arn': runtime_details.get('role_arn'),
        'status': runtime_details.get('status', 'ACTIVE'),
        'runtime_details': runtime_details,
    }


def handle_check_cache(payload):
    """Resolve ECR digest, check DynamoDB cache, update inventory."""
    ecr_image_uri = payload['ecr_image_uri']
    account_id = payload.get('account_id')
    region = payload.get('region', 'us-east-1')
    agent_runtime_arn = payload['agent_runtime_arn']
    runtime_details = payload.get('runtime_details', payload)

    # Resolve digest
    try:
        ecr_client = _get_ecr_client(account_id, region)
        image_digest = get_ecr_image_digest(ecr_image_uri, ecr_client)
    except Exception as e:
        logger.warning(f"Failed to get ECR client/digest: {e}")
        image_digest = None

    # Update inventory
    update_inventory(agent_runtime_arn, runtime_details, 'event-driven')

    # Check cache
    if image_digest and check_scan_cache(image_digest):
        logger.info(f"Cache hit for digest {image_digest[:12]}...")
        publish_custom_metrics({'cache_hit': True})
        return {
            **payload,
            'is_cached': True,
            'image_digest': image_digest,
        }

    # Parse ECR URI for repo/tag
    parts = ecr_image_uri.split('/')
    repo_and_tag = '/'.join(parts[1:])
    if ':' in repo_and_tag:
        repo, tag = repo_and_tag.rsplit(':', 1)
    else:
        repo = repo_and_tag
        tag = 'latest'

    return {
        **payload,
        'is_cached': False,
        'image_digest': image_digest,
        'repository': repo,
        'tag': tag,
    }


def handle_get_registry(payload):
    """Ensure AWS connector + registry exist in Qualys."""
    from qualys_api import get_qualys_credentials, get_or_create_registry

    creds = get_qualys_credentials(QUALYS_SECRET_ARN)

    account_id = payload.get('account_id')
    region = payload.get('region', 'us-east-1')
    registry_name = f"ecr-{account_id}-{region}"

    role_arn = EXISTING_ROLE_ARN or payload.get('role_arn')
    role_name = EXISTING_ROLE_NAME

    result = get_or_create_registry(
        creds, registry_name, account_id, region,
        role_arn=role_arn, role_name=role_name
    )

    if not result.get('registry_uuid'):
        raise ScanException(f"Registry for {account_id}/{region} not found: {result.get('error')}")

    logger.info(f"Registry: {result['registry_uuid'][:8]}... (created={result.get('created', False)})")

    return {
        **payload,
        'registry_uuid': result['registry_uuid'],
        'registry_name': registry_name,
        'qualys_secret_arn': QUALYS_SECRET_ARN,
    }


def handle_submit_scan(payload):
    """Submit on-demand scan to Qualys CS API."""
    from qualys_api import get_qualys_credentials, submit_on_demand_scan

    creds = get_qualys_credentials(QUALYS_SECRET_ARN)

    result = submit_on_demand_scan(
        creds,
        payload['registry_uuid'],
        payload['repository'],
        payload.get('tag', 'latest')
    )

    if result['status_code'] not in [200, 201, 202]:
        raise ScanException(f"Scan submit failed: HTTP {result['status_code']}")

    logger.info(f"Scan submitted for {payload['repository']}:{payload.get('tag', 'latest')}")
    return {
        **payload,
        'scan_submitted': True,
        'schedule_name': result['schedule_name'],
        'poll_count': 0,
    }


def handle_check_status(payload):
    """Poll Qualys for scan completion."""
    from qualys_api import get_qualys_credentials, get_image_scan_status

    creds = get_qualys_credentials(QUALYS_SECRET_ARN)
    image_id = payload.get('image_digest') or f"{payload['repository']}:{payload.get('tag', 'latest')}"
    status = get_image_scan_status(creds, image_id)

    poll_count = payload.get('poll_count', 0) + 1
    logger.info(f"Poll #{poll_count}: status={status['status']}")

    return {
        **payload,
        'scan_complete': status['status'] == 'complete',
        'scan_found': status.get('found', False),
        'poll_count': poll_count,
    }


def handle_get_results(payload):
    """Fetch vulnerability results and update cache."""
    from qualys_api import get_qualys_credentials, get_image_vulnerabilities

    creds = get_qualys_credentials(QUALYS_SECRET_ARN)
    image_id = payload.get('image_digest') or f"{payload['repository']}:{payload.get('tag', 'latest')}"
    results = get_image_vulnerabilities(creds, image_id)

    scan_result = {
        'summary': results['summary'],
        'scanned_at': datetime.utcnow().isoformat(),
        'vulnerabilities': results['vulnerabilities'][:10],
    }

    # Update scan cache
    image_digest = payload.get('image_digest')
    if image_digest:
        update_scan_cache(image_digest, payload.get('ecr_image_uri', ''),
                          payload.get('agent_runtime_arn', ''), scan_result)

    logger.info(f"Results for {payload['repository']}: {results['summary']}")
    return {
        **payload,
        'scan_result': scan_result,
    }


def handle_notify(payload):
    """Run AI service detection, update inventory with results, store and publish."""
    agent_runtime_arn = payload.get('agent_runtime_arn', '')
    runtime_details = payload.get('runtime_details', payload)
    scan_result = payload.get('scan_result', {})

    # AI service detection
    ai_services = []
    if ENABLE_AI_SERVICE_DETECTION:
        try:
            from ai_service_detector import detect_ai_services_from_runtime
            ai_services = detect_ai_services_from_runtime(agent_runtime_arn, runtime_details, None)
            if ai_services:
                logger.info(f"AI services detected: {len(ai_services)} for {agent_runtime_arn}")
        except Exception as e:
            logger.error(f"AI service detection error: {e}")

    # Update inventory with scan results
    inventory_update = {
        **runtime_details,
        'last_scan_timestamp': datetime.utcnow().isoformat(),
        'last_scan_status': 'success',
        'last_scan_image_digest': payload.get('image_digest', ''),
        'ai_services': [s if isinstance(s, dict) else vars(s) for s in ai_services] if ai_services else [],
    }
    update_inventory(agent_runtime_arn, inventory_update, 'event-driven')

    # Store results to S3 and SNS
    store_results(runtime_details, scan_result)

    # Publish metrics
    vuln_count = scan_result.get('summary', {}).get('total', 0)
    publish_custom_metrics({
        'cache_hit': False,
        'scan_success': True,
        'vulnerability_count': vuln_count,
        'ai_services_detected': len(ai_services),
    })

    return {
        **payload,
        'notified': True,
        'ai_services_count': len(ai_services),
    }


def handle_notify_failure(payload):
    """Update inventory with failure, publish failure metrics, send SNS."""
    agent_runtime_arn = payload.get('agent_runtime_arn', '')
    runtime_details = payload.get('runtime_details', payload)
    error_info = payload.get('error', {})

    # Update inventory with failure
    inventory_update = {
        **runtime_details,
        'last_scan_timestamp': datetime.utcnow().isoformat(),
        'last_scan_status': 'failed',
    }
    update_inventory(agent_runtime_arn, inventory_update, 'event-driven')

    # Publish failure metrics
    publish_custom_metrics({
        'scan_success': False,
    })

    # Send SNS failure notification
    if SNS_TOPIC_ARN:
        try:
            message = {
                'agent_runtime_arn': agent_runtime_arn,
                'agent_runtime_name': payload.get('agent_runtime_name', 'unknown'),
                'error': str(error_info),
                'status': 'failed',
            }
            _sns_publish(
                SNS_TOPIC_ARN,
                f"AgentCore Scan Failed: {payload.get('agent_runtime_name', 'unknown')}"[:100],
                json.dumps(message, indent=2, default=str)
            )
        except Exception as e:
            logger.error(f"SNS failure notification error: {e}")

    return {
        **payload,
        'notified': True,
        'status': 'failed',
    }


# ---------------------------------------------------------------------------
# Dispatch entry point
# ---------------------------------------------------------------------------

ACTION_HANDLERS = {
    'parse_event': handle_parse_event,
    'check_cache': handle_check_cache,
    'get_registry': handle_get_registry,
    'submit_scan': handle_submit_scan,
    'check_status': handle_check_status,
    'get_results': handle_get_results,
    'notify': handle_notify,
    'notify_failure': handle_notify_failure,
}


def lambda_handler(event, context):
    """Dispatch entry point — routes to action handlers."""
    action = event.get('action', 'parse_event')
    data = event.get('input', event)

    logger.info(f"Action: {action}")

    handler = ACTION_HANDLERS.get(action)
    if not handler:
        raise ValueError(f"Unknown action: {action}")

    if action == 'parse_event':
        return handler(data, context)
    return handler(data)
