"""Unit tests for scanner-lambda/qualys_api.py module-level functions."""

import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from qualys_api import (
    POD_URL_MAP,
    QualysCSError,
    _make_request,
    get_image_scan_status,
    get_image_vulnerabilities,
    get_or_create_registry,
    get_qualys_credentials,
    submit_on_demand_scan,
)

TEST_CREDS = {
    'token': 'test-token',
    'gateway_url': 'https://gateway.qg2.apps.qualys.com',
}


def _mock_urlopen_response(body_dict):
    """Create a MagicMock that behaves like a urllib response context manager."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(body_dict).encode('utf-8')
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)
    return mock_response


def _mock_urlopen_bytes(raw_bytes):
    """Create a MagicMock context-manager response returning raw bytes."""
    mock_response = MagicMock()
    mock_response.read.return_value = raw_bytes
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)
    return mock_response


@pytest.mark.unit
class TestPodUrlMap:
    """Verify that POD_URL_MAP contains expected pods with valid HTTPS URLs."""

    def test_all_expected_pods_present(self):
        expected_pods = [
            'US1', 'US2', 'US3', 'US4',
            'EU1', 'EU2',
            'IN1', 'CA1', 'AU1', 'UK1', 'AE1', 'KSA1',
        ]
        for pod in expected_pods:
            assert pod in POD_URL_MAP, f"Missing pod: {pod}"

    def test_all_urls_are_https(self):
        for pod, url in POD_URL_MAP.items():
            assert url.startswith('https://'), f"Pod {pod} URL does not start with https://"

    def test_all_urls_contain_gateway(self):
        for pod, url in POD_URL_MAP.items():
            assert 'gateway' in url, f"Pod {pod} URL does not contain 'gateway'"

    def test_pod_count(self):
        assert len(POD_URL_MAP) == 12


@pytest.mark.unit
class TestMakeRequest:
    """Tests for the _make_request HTTP helper."""

    @patch('qualys_api.urllib.request.urlopen')
    def test_successful_get(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({'key': 'value'})

        result = _make_request('GET', 'https://example.com/api', {'Authorization': 'Bearer tok'})

        assert result == {'key': 'value'}
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_method() == 'GET'
        assert req.full_url == 'https://example.com/api'

    @patch('qualys_api.urllib.request.urlopen')
    def test_successful_post_with_body(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({'id': '123'})

        result = _make_request(
            'POST',
            'https://example.com/api',
            {'Content-Type': 'application/json'},
            body={'name': 'test'},
        )

        assert result == {'id': '123'}
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_method() == 'POST'
        assert req.data == json.dumps({'name': 'test'}).encode('utf-8')

    @patch('qualys_api.urllib.request.urlopen')
    def test_empty_response_returns_empty_dict(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_bytes(b'')

        result = _make_request('GET', 'https://example.com/api', {})

        assert result == {}

    @patch('qualys_api.urllib.request.urlopen')
    def test_http_error_raises_qualys_cs_error(self, mock_urlopen):
        error_body = b'{"message": "Unauthorized"}'
        http_error = urllib.error.HTTPError(
            url='https://example.com/api',
            code=401,
            msg='Unauthorized',
            hdrs={},
            fp=BytesIO(error_body),
        )
        mock_urlopen.side_effect = http_error

        with pytest.raises(QualysCSError) as exc_info:
            _make_request('GET', 'https://example.com/api', {})

        assert exc_info.value.status_code == 401
        assert 'Unauthorized' in exc_info.value.response_body

    @patch('qualys_api.urllib.request.urlopen')
    def test_url_error_raises_qualys_cs_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError('Connection refused')

        with pytest.raises(QualysCSError, match='URL error'):
            _make_request('GET', 'https://example.com/api', {})

    @patch('qualys_api.urllib.request.urlopen')
    def test_json_decode_error_raises_qualys_cs_error(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_bytes(b'not-json-at-all')

        with pytest.raises(QualysCSError, match='Invalid JSON response'):
            _make_request('GET', 'https://example.com/api', {})


@pytest.mark.unit
class TestGetQualysCredentials:
    """Tests for get_qualys_credentials using moto for Secrets Manager."""

    @mock_aws
    def test_fetches_credentials_from_secrets_manager(self):
        sm = boto3.client('secretsmanager', region_name='us-east-1')
        secret_value = {
            'qualys_token': 'my-qualys-token',
            'qualys_gateway_url': 'https://gateway.qg3.apps.qualys.com',
        }
        response = sm.create_secret(
            Name='test-qualys-secret',
            SecretString=json.dumps(secret_value),
        )
        secret_arn = response['ARN']

        creds = get_qualys_credentials(secret_arn)

        assert creds['token'] == 'my-qualys-token'
        assert creds['gateway_url'] == 'https://gateway.qg3.apps.qualys.com'

    @mock_aws
    def test_defaults_gateway_url_when_missing(self):
        sm = boto3.client('secretsmanager', region_name='us-east-1')
        secret_value = {
            'qualys_token': 'token-no-url',
        }
        response = sm.create_secret(
            Name='test-qualys-secret-no-url',
            SecretString=json.dumps(secret_value),
        )
        secret_arn = response['ARN']

        creds = get_qualys_credentials(secret_arn)

        assert creds['token'] == 'token-no-url'
        assert creds['gateway_url'] == 'https://gateway.qg2.apps.qualys.com'


@pytest.mark.unit
class TestGetOrCreateRegistry:
    """Tests for get_or_create_registry orchestration function."""

    @patch('qualys_api.get_registry_uuid')
    def test_existing_registry_found_by_uri(self, mock_get_uuid):
        mock_get_uuid.return_value = 'uuid-existing-1234'

        result = get_or_create_registry(
            TEST_CREDS, 'my-registry', '123456789012', 'us-east-1',
        )

        assert result['registry_uuid'] == 'uuid-existing-1234'
        assert result['created'] is False
        assert result['exists'] is True
        mock_get_uuid.assert_called_once_with(
            TEST_CREDS, 'https://123456789012.dkr.ecr.us-east-1.amazonaws.com',
        )

    @patch('qualys_api.get_registry_by_name')
    @patch('qualys_api.get_registry_uuid')
    def test_existing_registry_found_by_name(self, mock_get_uuid, mock_get_by_name):
        mock_get_uuid.return_value = None
        mock_get_by_name.return_value = 'uuid-by-name-5678'

        result = get_or_create_registry(
            TEST_CREDS, 'my-registry', '123456789012', 'us-east-1',
        )

        assert result['registry_uuid'] == 'uuid-by-name-5678'
        assert result['created'] is False
        assert result['exists'] is True

    @patch('qualys_api.create_ecr_registry')
    @patch('qualys_api.ensure_aws_connector')
    @patch('qualys_api.get_registry_by_name')
    @patch('qualys_api.get_registry_uuid')
    def test_registry_created_successfully(
        self, mock_get_uuid, mock_get_by_name, mock_ensure_connector, mock_create,
    ):
        mock_get_uuid.return_value = None
        mock_get_by_name.return_value = None
        mock_ensure_connector.return_value = {'created': True, 'connector_name': 'c1'}
        mock_create.return_value = {
            'created': True,
            'registry_uuid': 'uuid-new-9999',
            'registry_name': 'my-registry',
        }

        result = get_or_create_registry(
            TEST_CREDS, 'my-registry', '123456789012', 'us-east-1',
            role_arn='arn:aws:iam::123456789012:role/MyRole',
            role_name='MyRole',
        )

        assert result['registry_uuid'] == 'uuid-new-9999'
        assert result['created'] is True
        assert result['exists'] is True
        mock_ensure_connector.assert_called_once()
        mock_create.assert_called_once()

    @patch('qualys_api.get_registry_by_name')
    @patch('qualys_api.get_registry_uuid')
    def test_no_role_arn_returns_error(self, mock_get_uuid, mock_get_by_name):
        mock_get_uuid.return_value = None
        mock_get_by_name.return_value = None

        result = get_or_create_registry(
            TEST_CREDS, 'my-registry', '123456789012', 'us-east-1',
            role_arn=None,
        )

        assert result['registry_uuid'] is None
        assert result['created'] is False
        assert result['exists'] is False
        assert 'no IAM role ARN' in result['error']

    @patch('qualys_api.create_ecr_registry')
    @patch('qualys_api.get_registry_by_name')
    @patch('qualys_api.get_registry_uuid')
    def test_create_registry_failure(self, mock_get_uuid, mock_get_by_name, mock_create):
        mock_get_uuid.return_value = None
        mock_get_by_name.return_value = None
        mock_create.return_value = {
            'created': False,
            'error': 'Registry limit exceeded',
            'status_code': 400,
        }

        result = get_or_create_registry(
            TEST_CREDS, 'my-registry', '123456789012', 'us-east-1',
            role_arn='arn:aws:iam::123456789012:role/MyRole',
        )

        assert result['registry_uuid'] is None
        assert result['created'] is False
        assert result['exists'] is False
        assert 'error' in result


@pytest.mark.unit
class TestSubmitOnDemandScan:
    """Tests for submit_on_demand_scan."""

    @patch('qualys_api.urllib.request.urlopen')
    def test_submit_scan_success(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({
            'scheduleId': 'sched-abc-123',
        })

        result = submit_on_demand_scan(
            TEST_CREDS, 'registry-uuid-1', 'my-repo', 'v1.0.0',
        )

        assert result['status_code'] == 200
        assert result['schedule_id'] == 'sched-abc-123'
        assert result['schedule_name'].startswith('ECR-my-repo-')

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_method() == 'POST'
        assert 'registry-uuid-1/schedule' in req.full_url

        payload = json.loads(req.data.decode('utf-8'))
        assert payload['onDemand'] is True
        assert payload['forceScan'] is True
        assert payload['filters'][0]['repoTags'][0]['repo'] == 'my-repo'
        assert payload['filters'][0]['repoTags'][0]['tag'] == 'v1.0.0'

    @patch('qualys_api.urllib.request.urlopen')
    def test_submit_scan_latest_tag_uses_wildcard(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({'scheduleId': 'sched-456'})

        submit_on_demand_scan(TEST_CREDS, 'registry-uuid-1', 'my-repo', 'latest')

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        payload = json.loads(req.data.decode('utf-8'))
        assert payload['filters'][0]['repoTags'][0]['tag'] == '.*'

    @patch('qualys_api.urllib.request.urlopen')
    def test_submit_scan_failure(self, mock_urlopen):
        http_error = urllib.error.HTTPError(
            url='https://example.com',
            code=500,
            msg='Internal Server Error',
            hdrs={},
            fp=BytesIO(b'{"message": "server error"}'),
        )
        mock_urlopen.side_effect = http_error

        result = submit_on_demand_scan(
            TEST_CREDS, 'registry-uuid-1', 'my-repo', 'v1.0.0',
        )

        assert result['status_code'] == 500
        assert result['schedule_id'] is None
        assert 'error' in result


@pytest.mark.unit
class TestGetImageScanStatus:
    """Tests for get_image_scan_status."""

    @patch('qualys_api.urllib.request.urlopen')
    def test_scan_complete(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({
            'scanStatus': 'SUCCESS',
            'vulnerabilities': {'total': 5},
        })

        result = get_image_scan_status(TEST_CREDS, 'sha256:abc123')

        assert result['status'] == 'complete'
        assert result['found'] is True
        assert result['scan_status'] == 'SUCCESS'
        assert result['vulnerabilities'] == {'total': 5}

    @patch('qualys_api.urllib.request.urlopen')
    def test_scan_in_progress(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({
            'scanStatus': 'IN_PROGRESS',
        })

        result = get_image_scan_status(TEST_CREDS, 'sha256:abc123')

        assert result['status'] == 'scanning'
        assert result['found'] is True
        assert result['scan_status'] == 'IN_PROGRESS'

    @patch('qualys_api.urllib.request.urlopen')
    def test_image_not_found_returns_pending(self, mock_urlopen):
        http_error = urllib.error.HTTPError(
            url='https://example.com',
            code=404,
            msg='Not Found',
            hdrs={},
            fp=BytesIO(b''),
        )
        mock_urlopen.side_effect = http_error

        result = get_image_scan_status(TEST_CREDS, 'sha256:notfound')

        assert result['status'] == 'pending'
        assert result['found'] is False

    @patch('qualys_api.urllib.request.urlopen')
    def test_api_error_returns_error_status(self, mock_urlopen):
        http_error = urllib.error.HTTPError(
            url='https://example.com',
            code=500,
            msg='Internal Server Error',
            hdrs={},
            fp=BytesIO(b'server error'),
        )
        mock_urlopen.side_effect = http_error

        result = get_image_scan_status(TEST_CREDS, 'sha256:abc123')

        assert result['status'] == 'error'
        assert result['found'] is False
        assert 'error' in result

    @patch('qualys_api.urllib.request.urlopen')
    def test_url_encodes_image_id(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({'scanStatus': 'SUCCESS'})

        get_image_scan_status(TEST_CREDS, 'sha256:abc/def:tag')

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert 'sha256%3Aabc%2Fdef%3Atag' in req.full_url


@pytest.mark.unit
class TestGetImageVulnerabilities:
    """Tests for get_image_vulnerabilities."""

    @patch('qualys_api.urllib.request.urlopen')
    def test_success_with_vulnerabilities(self, mock_urlopen):
        vulns = [
            {'qid': '1', 'severity': 5, 'title': 'Critical CVE'},
            {'qid': '2', 'severity': 4, 'title': 'High CVE'},
            {'qid': '3', 'severity': 3, 'title': 'Medium CVE'},
            {'qid': '4', 'severity': 2, 'title': 'Low CVE-1'},
            {'qid': '5', 'severity': 1, 'title': 'Low CVE-2'},
        ]
        mock_urlopen.return_value = _mock_urlopen_response({'data': vulns})

        result = get_image_vulnerabilities(TEST_CREDS, 'sha256:abc123')

        assert result['summary']['total'] == 5
        assert result['summary']['critical'] == 1
        assert result['summary']['high'] == 1
        assert result['summary']['medium'] == 1
        assert result['summary']['low'] == 2
        assert len(result['vulnerabilities']) == 5

    @patch('qualys_api.urllib.request.urlopen')
    def test_success_no_vulnerabilities(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({'data': []})

        result = get_image_vulnerabilities(TEST_CREDS, 'sha256:abc123')

        assert result['summary']['total'] == 0
        assert result['summary']['critical'] == 0
        assert result['summary']['high'] == 0
        assert result['summary']['medium'] == 0
        assert result['summary']['low'] == 0
        assert result['vulnerabilities'] == []

    @patch('qualys_api.urllib.request.urlopen')
    def test_error_response_returns_empty_summary(self, mock_urlopen):
        http_error = urllib.error.HTTPError(
            url='https://example.com',
            code=500,
            msg='Internal Server Error',
            hdrs={},
            fp=BytesIO(b'server error'),
        )
        mock_urlopen.side_effect = http_error

        result = get_image_vulnerabilities(TEST_CREDS, 'sha256:abc123')

        assert result['summary']['total'] == 0
        assert result['vulnerabilities'] == []
        assert 'error' in result

    @patch('qualys_api.urllib.request.urlopen')
    def test_truncates_vulnerabilities_to_20(self, mock_urlopen):
        vulns = [{'qid': str(i), 'severity': 3, 'title': f'CVE-{i}'} for i in range(30)]
        mock_urlopen.return_value = _mock_urlopen_response({'data': vulns})

        result = get_image_vulnerabilities(TEST_CREDS, 'sha256:abc123')

        assert result['summary']['total'] == 30
        assert len(result['vulnerabilities']) == 20
