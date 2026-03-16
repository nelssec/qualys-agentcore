"""Unit tests for scanner-lambda/handlers.py."""

import json
from unittest.mock import MagicMock
from datetime import datetime, timedelta

import pytest
from moto import mock_aws

from tests.fixtures.events import (
    SAMPLE_CREATE_AGENT_RUNTIME_EVENT,
    SAMPLE_UPDATE_AGENT_RUNTIME_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_EVENT,
    SAMPLE_BULK_SCAN_EVENT,
    INVALID_EVENT_MISSING_DETAIL,
    INVALID_EVENT_MISSING_ARTIFACT,
    INVALID_EVENT_BAD_ARN,
)


@pytest.mark.unit
class TestValidation:
    def test_validate_pod_valid(self):
        from handlers import validate_pod
        assert validate_pod("US2") is True
        assert validate_pod("EU1") is True
        assert validate_pod("IN1") is True

    def test_validate_pod_invalid(self):
        from handlers import validate_pod
        assert validate_pod("us2") is False
        assert validate_pod("US 2") is False
        assert validate_pod("") is False

    def test_validate_access_token_valid(self):
        from handlers import validate_access_token
        assert validate_access_token("a" * 20) is True
        assert validate_access_token("test_token_12345678901234567890") is True

    def test_validate_access_token_invalid(self):
        from handlers import validate_access_token
        assert validate_access_token("short") is False
        assert validate_access_token("") is False

    def test_validate_ecr_image_uri_valid(self):
        from handlers import validate_ecr_image_uri
        assert validate_ecr_image_uri(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest"
        ) is True
        assert validate_ecr_image_uri(
            "123456789012.dkr.ecr.eu-west-1.amazonaws.com/my-repo:v1.0"
        ) is True

    def test_validate_ecr_image_uri_invalid(self):
        from handlers import validate_ecr_image_uri
        assert validate_ecr_image_uri("") is False
        assert validate_ecr_image_uri(None) is False
        assert validate_ecr_image_uri("docker.io/library/nginx:latest") is False

    def test_validate_agent_runtime_arn_valid(self):
        from handlers import validate_agent_runtime_arn
        assert validate_agent_runtime_arn(
            "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123"
        ) is True

    def test_validate_agent_runtime_arn_invalid(self):
        from handlers import validate_agent_runtime_arn
        assert validate_agent_runtime_arn("not-a-valid-arn") is False
        assert validate_agent_runtime_arn("") is False
        assert validate_agent_runtime_arn(None) is False

    def test_sanitize_log_output(self):
        from handlers import sanitize_log_output
        assert "[REDACTED]" in sanitize_log_output("token: mysecrettoken12345678901234567890")
        assert sanitize_log_output("") == ""
        assert sanitize_log_output(None) == ""


@pytest.mark.unit
class TestExtractAgentRuntime:
    def test_extract_create_event(self):
        from handlers import extract_agent_runtime_from_event
        result = extract_agent_runtime_from_event(SAMPLE_CREATE_AGENT_RUNTIME_EVENT)

        assert result['event_name'] == 'CreateAgentRuntime'
        assert result['agent_runtime_arn'] == \
            'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456'
        assert result['ecr_image_uri'] == \
            '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest'
        assert result['account_id'] == '123456789012'
        assert result['region'] == 'us-east-1'
        assert result['status'] == 'CREATING'

    def test_extract_update_event(self):
        from handlers import extract_agent_runtime_from_event
        result = extract_agent_runtime_from_event(SAMPLE_UPDATE_AGENT_RUNTIME_EVENT)

        assert result['event_name'] == 'UpdateAgentRuntime'
        assert result['ecr_image_uri'] == \
            '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:v2'

    def test_extract_gateway_target_event(self):
        from handlers import extract_agent_runtime_from_event
        result = extract_agent_runtime_from_event(SAMPLE_CREATE_GATEWAY_TARGET_EVENT)

        assert result['event_name'] == 'CreateGatewayTarget'
        assert result['gateway_target_id'] == 'gt-xyz789'
        assert 'mcpServer' in result['target_configuration']

    def test_extract_bulk_scan_event(self):
        from handlers import extract_agent_runtime_from_event
        result = extract_agent_runtime_from_event(SAMPLE_BULK_SCAN_EVENT)

        assert result['event_name'] == 'BulkScanRequest'
        assert result['agent_runtime_arn'] == \
            'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456'
        assert result['ecr_image_uri'] == \
            '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest'

    def test_extract_missing_detail_raises(self):
        from handlers import extract_agent_runtime_from_event
        with pytest.raises(ValueError, match="missing 'detail'"):
            extract_agent_runtime_from_event(INVALID_EVENT_MISSING_DETAIL)

    def test_extract_missing_artifact(self):
        from handlers import extract_agent_runtime_from_event
        result = extract_agent_runtime_from_event(INVALID_EVENT_MISSING_ARTIFACT)
        # Should succeed but ecr_image_uri should be None
        assert result['ecr_image_uri'] is None

    def test_extract_bad_arn_raises(self):
        from handlers import extract_agent_runtime_from_event
        with pytest.raises(ValueError, match="Invalid agent runtime ARN"):
            extract_agent_runtime_from_event(INVALID_EVENT_BAD_ARN)


@pytest.mark.unit
class TestScanCache:
    @mock_aws
    def test_check_scan_cache_miss(self, monkeypatch):
        import boto3
        import handlers

        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='test-cache',
            KeySchema=[{'AttributeName': 'image_digest', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'image_digest', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        table.wait_until_exists()

        monkeypatch.setattr(handlers, 'SCAN_CACHE_TABLE', 'test-cache')
        monkeypatch.setattr(handlers, 'dynamodb', dynamodb)

        assert handlers.check_scan_cache('sha256:abc123') is False

    @mock_aws
    def test_check_scan_cache_hit(self, monkeypatch):
        import boto3
        import handlers

        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='test-cache',
            KeySchema=[{'AttributeName': 'image_digest', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'image_digest', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        table.wait_until_exists()
        table.put_item(Item={
            'image_digest': 'abc123digest',
            'scan_timestamp': datetime.utcnow().isoformat(),
        })

        monkeypatch.setattr(handlers, 'SCAN_CACHE_TABLE', 'test-cache')
        monkeypatch.setattr(handlers, 'dynamodb', dynamodb)

        assert handlers.check_scan_cache('abc123digest') is True

    @mock_aws
    def test_check_scan_cache_expired(self, monkeypatch):
        import boto3
        import handlers

        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='test-cache',
            KeySchema=[{'AttributeName': 'image_digest', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'image_digest', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        table.wait_until_exists()
        old_time = (datetime.utcnow() - timedelta(days=31)).isoformat()
        table.put_item(Item={
            'image_digest': 'abc123digest',
            'scan_timestamp': old_time,
        })

        monkeypatch.setattr(handlers, 'SCAN_CACHE_TABLE', 'test-cache')
        monkeypatch.setattr(handlers, 'dynamodb', dynamodb)
        monkeypatch.setattr(handlers, 'CACHE_TTL_DAYS', 30)

        assert handlers.check_scan_cache('abc123digest') is False

    def test_check_scan_cache_no_table(self, monkeypatch):
        import handlers

        monkeypatch.setattr(handlers, 'SCAN_CACHE_TABLE', '')
        assert handlers.check_scan_cache('any_digest') is False

    def test_check_scan_cache_no_digest(self, monkeypatch):
        import handlers

        monkeypatch.setattr(handlers, 'SCAN_CACHE_TABLE', 'some-table')
        assert handlers.check_scan_cache('') is False


@pytest.mark.unit
class TestInventory:
    @mock_aws
    def test_update_inventory(self, monkeypatch):
        import boto3
        import handlers

        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='test-inventory',
            KeySchema=[{'AttributeName': 'agent_runtime_arn', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'agent_runtime_arn', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        table.wait_until_exists()

        monkeypatch.setattr(handlers, 'INVENTORY_TABLE', 'test-inventory')
        monkeypatch.setattr(handlers, 'dynamodb', dynamodb)

        arn = 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test123'
        details = {
            'account_id': '123456789012',
            'ecr_image_uri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
            'agent_runtime_name': 'test-runtime',
            'status': 'ACTIVE',
            'region': 'us-east-1',
        }

        handlers.update_inventory(arn, details, 'event-driven')

        item = table.get_item(Key={'agent_runtime_arn': arn}).get('Item')
        assert item is not None
        assert item['agent_runtime_name'] == 'test-runtime'
        assert item['discovery_source'] == 'event-driven'


@pytest.mark.unit
class TestMetrics:
    def test_publish_custom_metrics(self, monkeypatch):
        import handlers

        mock_cw = MagicMock()
        monkeypatch.setattr(handlers, 'cloudwatch', mock_cw)

        handlers.publish_custom_metrics({
            'scan_success': True,
            'scan_duration': 42.5,
            'cache_hit': False,
            'vulnerability_count': 3,
            'mcp_servers_detected': 1,
        })

        mock_cw.put_metric_data.assert_called_once()
        call_args = mock_cw.put_metric_data.call_args
        assert call_args.kwargs['Namespace'] == 'AgentCoreScanner'
        assert len(call_args.kwargs['MetricData']) == 5


@pytest.mark.unit
class TestDispatch:
    def test_dispatch_parse_event_gateway(self, monkeypatch, lambda_context):
        import handlers

        monkeypatch.setattr(handlers, 'ENABLE_MCP_DETECTION', False)

        event = {
            'action': 'parse_event',
            'input': SAMPLE_CREATE_GATEWAY_TARGET_EVENT,
        }

        result = handlers.lambda_handler(event, lambda_context)

        assert result['has_images'] is False
        assert result['event_name'] == 'CreateGatewayTarget'
        assert result['message'] == 'Gateway target processed'

    def test_dispatch_invalid_event(self, lambda_context):
        import handlers

        event = {
            'action': 'parse_event',
            'input': INVALID_EVENT_MISSING_DETAIL,
        }

        with pytest.raises(ValueError, match="missing 'detail'"):
            handlers.lambda_handler(event, lambda_context)

    def test_dispatch_unknown_action(self, lambda_context):
        import handlers

        event = {
            'action': 'nonexistent_action',
            'input': {},
        }

        with pytest.raises(ValueError, match="Unknown action"):
            handlers.lambda_handler(event, lambda_context)
