"""Qualys Container Security API client.

Uses urllib.request (stdlib) to keep Lambda package small.
Module-level functions with creds dict pattern (matching qualys-fargate).
"""

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, Optional

import boto3

logger = logging.getLogger(__name__)

# Qualys POD to Container Security API base URL mapping
POD_URL_MAP = {
    'US1': 'https://gateway.qg1.apps.qualys.com',
    'US2': 'https://gateway.qg2.apps.qualys.com',
    'US3': 'https://gateway.qg3.apps.qualys.com',
    'US4': 'https://gateway.qg4.apps.qualys.com',
    'EU1': 'https://gateway.qg1.apps.qualys.eu',
    'EU2': 'https://gateway.qg2.apps.qualys.eu',
    'IN1': 'https://gateway.qg1.apps.qualys.in',
    'CA1': 'https://gateway.qg1.apps.qualys.ca',
    'AU1': 'https://gateway.qg1.apps.qualys.com.au',
    'UK1': 'https://gateway.qg1.apps.qualys.co.uk',
    'AE1': 'https://gateway.qg1.apps.qualys.ae',
    'KSA1': 'https://gateway.qg1.apps.qualys.sa',
}

API_TIMEOUT = int(os.environ.get('API_TIMEOUT_SECONDS', '30'))
SENSITIVE_PATTERNS = ['token', 'key', 'secret', 'password', 'credential', 'auth']


class QualysCSError(Exception):
    """Qualys Container Security API error."""
    def __init__(self, message: str, status_code: int = 0, response_body: str = ''):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def _sanitize_error(error_text: str, max_length: int = 100) -> str:
    if not error_text:
        return "Unknown error"

    logger.error(f"Full API error: {error_text[:500]}")

    error_lower = error_text.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in error_lower:
            return "API error (details logged to CloudWatch)"

    sanitized = error_text[:max_length]
    if len(error_text) > max_length:
        sanitized += "..."

    return sanitized


def _make_request(method: str, url: str, headers: Dict, body: Optional[Dict] = None,
                  timeout: int = None) -> Dict[str, Any]:
    """Make an HTTP request to the Qualys CS API."""
    if timeout is None:
        timeout = API_TIMEOUT

    data = None
    if body:
        data = json.dumps(body).encode('utf-8')

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_body = response.read().decode('utf-8')
            if response_body:
                return json.loads(response_body)
            return {}
    except urllib.error.HTTPError as e:
        response_body = ''
        try:
            response_body = e.read().decode('utf-8')
        except Exception:
            pass
        raise QualysCSError(
            f"HTTP {e.code}: {e.reason}",
            status_code=e.code,
            response_body=response_body
        )
    except urllib.error.URLError as e:
        raise QualysCSError(f"URL error: {e.reason}")
    except json.JSONDecodeError as e:
        raise QualysCSError(f"Invalid JSON response: {e}")


def get_headers(token: str) -> dict:
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


def get_qualys_credentials(secret_arn: str) -> dict:
    """Fetch Qualys credentials from Secrets Manager."""
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_arn)
    secret = json.loads(response['SecretString'])
    return {
        'token': secret['qualys_token'],
        'gateway_url': secret.get('qualys_gateway_url', 'https://gateway.qg2.apps.qualys.com')
    }


def get_qualys_aws_base(creds: dict) -> dict:
    """GET /csapi/v1.3/registry/aws-base — returns base_account_id and external_id."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/aws-base"
    headers = get_headers(creds['token'])

    data = _make_request('GET', url, headers)
    return {
        'base_account_id': data['accountId'],
        'external_id': str(data['externalId'])
    }


def create_aws_connector(creds: dict, role_arn: str, external_id: str,
                          connector_name: str = None) -> dict:
    """POST /csapi/v1.3/registry/aws/connector."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/aws/connector"
    headers = get_headers(creds['token'])

    if not connector_name:
        connector_name = f"ECR-Connector-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    payload = {
        "arn": role_arn,
        "description": "Auto-created connector for ECR scanning",
        "externalId": str(external_id),
        "name": connector_name,
        "accountType": "Global"
    }

    try:
        _make_request('POST', url, headers, body=payload)
        logger.info(f"Created AWS connector: {connector_name}")
        return {
            'created': True,
            'connector_name': connector_name,
            'connector_arn': role_arn
        }
    except QualysCSError as e:
        return {
            'created': False,
            'error': _sanitize_error(e.response_body or str(e)),
            'status_code': e.status_code
        }


def get_aws_connector(creds: dict, connector_name: str = None,
                       role_arn: str = None) -> Optional[dict]:
    """GET /csapi/v1.3/registry/aws/connectors — search by name or ARN."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/aws/connectors"
    headers = get_headers(creds['token'])

    try:
        connectors = _make_request('GET', url, headers)
    except QualysCSError:
        return None

    if not isinstance(connectors, list):
        connectors = connectors.get('data', connectors.get('connectors', []))

    for connector in connectors:
        if connector_name and connector.get('name') == connector_name:
            return connector
        if role_arn and connector.get('arn') == role_arn:
            return connector

    return None


def ensure_aws_connector(creds: dict, role_arn: str, role_name: str) -> dict:
    """Orchestrate get_qualys_aws_base + get/create connector."""
    base_info = get_qualys_aws_base(creds)
    external_id = base_info['external_id']

    logger.info(f"Qualys base account: {base_info['base_account_id'][:8]}..., external ID configured")

    existing = get_aws_connector(creds, role_arn=role_arn)
    if existing:
        logger.info(f"Found existing connector: {existing.get('name')}")
        return {
            'connector_name': existing.get('name'),
            'connector_arn': existing.get('arn'),
            'created': False,
        }

    connector_name = f"ecr-connector-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    result = create_aws_connector(creds, role_arn, external_id, connector_name)
    return result


def get_registry_uuid(creds: dict, registry_uri: str) -> Optional[str]:
    """GET /csapi/v1.3/registry with filter — return registry UUID."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry"
    headers = get_headers(creds['token'])

    filter_query = urllib.parse.quote(f'registryUri:"{registry_uri}"')
    full_url = f"{url}?filter={filter_query}&pageNumber=1&pageSize=50"

    try:
        data = _make_request('GET', full_url, headers)
    except QualysCSError as e:
        if e.status_code == 204:
            return None
        raise

    if 'data' in data and data['data']:
        return data['data'][0].get('registryUuid')

    return None


def get_registry_by_name(creds: dict, registry_name: str) -> Optional[str]:
    """GET /csapi/v1.3/registry with pagination — search by name."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry?pageNumber=1&pageSize=100"
    headers = get_headers(creds['token'])

    try:
        data = _make_request('GET', url, headers)
    except QualysCSError:
        return None

    for registry in data.get('data', []):
        if registry_name == registry.get('registryName'):
            return registry.get('registryUuid')

    return None


def create_ecr_registry(creds: dict, registry_name: str, account_id: str,
                         region: str, role_arn: str) -> dict:
    """POST /csapi/v1.3/registry — create ECR registry."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry"
    headers = get_headers(creds['token'])
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

    payload = {
        "aws": {
            "accountId": account_id,
            "arn": role_arn,
            "region": region,
            "accountType": "Global"
        },
        "credentialType": "AWS",
        "registryType": "AWS",
        "registryUri": registry_uri,
        "registryName": registry_name
    }

    try:
        data = _make_request('POST', url, headers, body=payload)
        registry_uuid = data.get('registryUuid')
        if not registry_uuid:
            registry_uuid = get_registry_uuid(creds, registry_uri)
        return {
            'created': True,
            'registry_uuid': registry_uuid,
            'registry_name': registry_name
        }
    except QualysCSError as e:
        return {
            'created': False,
            'error': _sanitize_error(e.response_body or str(e)),
            'status_code': e.status_code
        }


def get_or_create_registry(creds: dict, registry_name: str, account_id: str,
                            region: str, role_arn: str = None,
                            role_name: str = None) -> dict:
    """Orchestrate registry lookup + create."""
    registry_uri = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

    uuid = get_registry_uuid(creds, registry_uri)
    if uuid:
        logger.info(f"Found existing registry: {uuid[:8]}...")
        return {'registry_uuid': uuid, 'created': False, 'exists': True}

    uuid = get_registry_by_name(creds, registry_name)
    if uuid:
        logger.info(f"Found existing registry by name: {uuid[:8]}...")
        return {'registry_uuid': uuid, 'created': False, 'exists': True}

    if not role_arn:
        return {
            'registry_uuid': None,
            'created': False,
            'exists': False,
            'error': 'Registry not found and no IAM role ARN provided',
        }

    if role_name:
        logger.info(f"Ensuring AWS connector for role: {role_name}")
        connector_result = ensure_aws_connector(creds, role_arn, role_name)
        if connector_result.get('error'):
            logger.warning(f"Connector creation issue: {connector_result.get('error')}")

    logger.info(f"Creating registry: {registry_name}")
    result = create_ecr_registry(creds, registry_name, account_id, region, role_arn)

    if result.get('created'):
        return {
            'registry_uuid': result['registry_uuid'],
            'created': True,
            'exists': True,
        }
    else:
        return {
            'registry_uuid': None,
            'created': False,
            'exists': False,
            'error': _sanitize_error(result.get('error', 'Unknown registry error')),
        }


def submit_on_demand_scan(creds: dict, registry_uuid: str,
                           repo_name: str, image_tag: str) -> dict:
    """POST /csapi/v1.3/registry/{uuid}/schedule — submit on-demand scan."""
    url = f"{creds['gateway_url']}/csapi/v1.3/registry/{registry_uuid}/schedule"
    headers = get_headers(creds['token'])
    tag_filter = image_tag if image_tag != 'latest' else '.*'

    schedule_name = f"ECR-{repo_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    payload = {
        "filters": [{
            "repoTags": [{
                "repo": repo_name,
                "tag": tag_filter
            }],
            "days": None
        }],
        "name": schedule_name,
        "onDemand": True,
        "schedule": "00:00",
        "forceScan": True,
        "registryType": "AWS"
    }

    try:
        data = _make_request('POST', url, headers, body=payload)
        return {
            'status_code': 200,
            'schedule_id': data.get('scheduleId'),
            'schedule_name': schedule_name
        }
    except QualysCSError as e:
        return {
            'status_code': e.status_code,
            'schedule_id': None,
            'schedule_name': schedule_name,
            'error': _sanitize_error(e.response_body or str(e))
        }


def get_image_scan_status(creds: dict, image_id: str) -> dict:
    """GET /csapi/v1.3/images/{id} — returns status and found flag."""
    encoded_id = urllib.parse.quote(image_id, safe='')
    url = f"{creds['gateway_url']}/csapi/v1.3/images/{encoded_id}"
    headers = get_headers(creds['token'])

    try:
        data = _make_request('GET', url, headers)
        return {
            'status': 'complete' if data.get('scanStatus') == 'SUCCESS' else 'scanning',
            'found': True,
            'scan_status': data.get('scanStatus'),
            'vulnerabilities': data.get('vulnerabilities', {})
        }
    except QualysCSError as e:
        if e.status_code == 404:
            return {'status': 'pending', 'found': False}
        return {'status': 'error', 'found': False, 'error': _sanitize_error(e.response_body or str(e))}


def get_image_vulnerabilities(creds: dict, image_id: str) -> dict:
    """GET /csapi/v1.3/images/{id}/vuln — returns summary and vulnerabilities."""
    encoded_id = urllib.parse.quote(image_id, safe='')
    url = f"{creds['gateway_url']}/csapi/v1.3/images/{encoded_id}/vuln?pageNumber=1&pageSize=100"
    headers = get_headers(creds['token'])

    try:
        data = _make_request('GET', url, headers)
    except QualysCSError as e:
        return {
            'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'vulnerabilities': [],
            'error': _sanitize_error(e.response_body or str(e))
        }

    vulns = data.get('data', [])

    summary = {
        'total': len(vulns),
        'critical': sum(1 for v in vulns if v.get('severity') == 5),
        'high': sum(1 for v in vulns if v.get('severity') == 4),
        'medium': sum(1 for v in vulns if v.get('severity') == 3),
        'low': sum(1 for v in vulns if v.get('severity') in [1, 2])
    }

    return {
        'summary': summary,
        'vulnerabilities': vulns[:20]
    }
