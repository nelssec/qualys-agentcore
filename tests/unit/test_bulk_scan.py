"""Unit tests for scanner-lambda/bulk_scan.py."""

import json
from unittest.mock import patch, MagicMock

import pytest
from moto import mock_aws


@pytest.mark.unit
class TestValidation:
    def test_validate_account_id_valid(self):
        from bulk_scan import validate_account_id
        assert validate_account_id("123456789012") is True

    def test_validate_account_id_invalid(self):
        from bulk_scan import validate_account_id
        assert validate_account_id("1234") is False
        assert validate_account_id("12345678901a") is False
        assert validate_account_id("") is False

    def test_validate_region_valid(self):
        from bulk_scan import validate_region
        assert validate_region("us-east-1") is True
        assert validate_region("eu-west-1") is True
        assert validate_region("ap-southeast-2") is True

    def test_validate_region_invalid(self):
        from bulk_scan import validate_region
        assert validate_region("invalid") is False
        assert validate_region("us east 1") is False
        assert validate_region("") is False

    def test_should_exclude(self):
        from bulk_scan import should_exclude
        patterns = ['agentcore-scanner', 'bulk-scan']
        assert should_exclude('agentcore-scanner-dev', patterns) is True
        assert should_exclude('my-bulk-scan-func', patterns) is True
        assert should_exclude('my-agent-runtime', patterns) is False
        assert should_exclude('production-agent', []) is False


@pytest.mark.unit
class TestStaleDetection:
    def test_identify_stale_entries_new_runtime(self):
        from bulk_scan import identify_stale_entries

        discovered = [
            {
                'agentRuntimeArn': 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/new1',
                'agentRuntimeName': 'new-runtime',
                'ecrImageUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
            }
        ]
        inventory = {}

        needs_scan = identify_stale_entries(discovered, inventory)
        assert len(needs_scan) == 1
        assert needs_scan[0]['_scan_reason'] == 'not_in_inventory'

    def test_identify_stale_entries_image_changed(self):
        from bulk_scan import identify_stale_entries

        arn = 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123'
        discovered = [
            {
                'agentRuntimeArn': arn,
                'ecrImageUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v2',
            }
        ]
        inventory = {
            arn: {
                'agent_runtime_arn': arn,
                'ecr_image_uri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
                'last_scan_timestamp': '2025-01-01T00:00:00',
            }
        }

        needs_scan = identify_stale_entries(discovered, inventory)
        assert len(needs_scan) == 1
        assert needs_scan[0]['_scan_reason'] == 'image_changed'

    def test_identify_stale_entries_never_scanned(self):
        from bulk_scan import identify_stale_entries

        arn = 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123'
        discovered = [
            {
                'agentRuntimeArn': arn,
                'ecrImageUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
            }
        ]
        inventory = {
            arn: {
                'agent_runtime_arn': arn,
                'ecr_image_uri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
                'last_scan_timestamp': '',
            }
        }

        needs_scan = identify_stale_entries(discovered, inventory)
        assert len(needs_scan) == 1
        assert needs_scan[0]['_scan_reason'] == 'never_scanned'

    def test_identify_stale_entries_up_to_date(self):
        from bulk_scan import identify_stale_entries

        arn = 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123'
        discovered = [
            {
                'agentRuntimeArn': arn,
                'ecrImageUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
            }
        ]
        inventory = {
            arn: {
                'agent_runtime_arn': arn,
                'ecr_image_uri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
                'last_scan_timestamp': '2025-01-15T00:00:00',
            }
        }

        needs_scan = identify_stale_entries(discovered, inventory)
        assert len(needs_scan) == 0


@pytest.mark.unit
class TestInvokeScanner:
    @mock_aws
    def test_invoke_scanner_success(self, monkeypatch):
        import boto3
        import bulk_scan

        mock_sfn = MagicMock()
        mock_sfn.start_execution.return_value = {'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:test'}
        monkeypatch.setattr(bulk_scan, 'sfn_client', mock_sfn)
        monkeypatch.setattr(bulk_scan, 'STATE_MACHINE_ARN', 'arn:aws:states:us-east-1:123456789012:stateMachine:test')

        runtime = {
            'agentRuntimeArn': 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test',
            'agentRuntimeId': 'test',
            'agentRuntimeName': 'test-runtime',
            'status': 'ACTIVE',
            'ecrImageUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1',
        }

        success, name = bulk_scan.invoke_scanner(runtime, '123456789012', 'us-east-1')
        assert success is True
        assert name == 'test-runtime'

    def test_invoke_scanner_no_function_name(self, monkeypatch):
        import bulk_scan
        monkeypatch.setattr(bulk_scan, 'STATE_MACHINE_ARN', '')

        runtime = {'agentRuntimeName': 'test'}
        success, name = bulk_scan.invoke_scanner(runtime, '123456789012')
        assert success is False


@pytest.mark.unit
class TestLambdaHandler:
    @mock_aws
    def test_handler_no_scanner_function(self, monkeypatch):
        import bulk_scan
        monkeypatch.setattr(bulk_scan, 'STATE_MACHINE_ARN', '')

        result = bulk_scan.lambda_handler({}, None)
        assert result['statusCode'] == 500

    @mock_aws
    def test_handler_invalid_regions(self, monkeypatch):
        import bulk_scan
        monkeypatch.setattr(bulk_scan, 'STATE_MACHINE_ARN', 'arn:aws:states:us-east-1:123456789012:stateMachine:test')

        result = bulk_scan.lambda_handler({'regions': ['invalid-region']}, None)
        assert result['statusCode'] == 400

    @mock_aws
    def test_handler_dry_run(self, monkeypatch):
        import boto3
        import bulk_scan

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        monkeypatch.setattr(bulk_scan, 'sts_client', mock_sts)
        monkeypatch.setattr(bulk_scan, 'STATE_MACHINE_ARN', 'arn:aws:states:us-east-1:123456789012:stateMachine:test')

        # Mock agentcore client
        mock_ac = MagicMock()
        mock_ac.list_agent_runtimes.return_value = {
            'agentRuntimes': [
                {
                    'agentRuntimeArn': 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt1',
                    'agentRuntimeId': 'rt1',
                    'agentRuntimeName': 'runtime-1',
                    'status': 'ACTIVE',
                }
            ]
        }
        monkeypatch.setattr(bulk_scan, 'get_local_agentcore_client', lambda region=None: mock_ac)

        result = bulk_scan.lambda_handler({
            'dry_run': True,
            'regions': ['us-east-1'],
        }, None)

        assert result['statusCode'] == 200
        assert result['body']['total_runtimes'] == 1
        assert result['body']['details'][0]['regions'][0]['status'] == 'dry_run'
