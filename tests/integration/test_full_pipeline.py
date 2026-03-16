"""Integration tests for the full AgentCore Scanner pipeline.

Uses moto to simulate the complete flow end-to-end:
- CloudTrail event -> parse -> cache check -> registry -> scan -> results -> notify
- MCP detection on gateway target events
- AI service detection on runtime configs
- Bulk scan stale detection and inventory reconciliation

Tests the handlers.py dispatch pattern with mocked Qualys API calls.
"""

import json
import os
import importlib
from copy import deepcopy
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import boto3
import pytest
from moto import mock_aws

from tests.fixtures.events import (
    SAMPLE_CREATE_AGENT_RUNTIME_EVENT,
    SAMPLE_UPDATE_AGENT_RUNTIME_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_HTTP_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_LAMBDA_EVENT,
    SAMPLE_BULK_SCAN_EVENT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockContext:
    function_name = "agentcore-scanner"
    function_version = "$LATEST"
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:agentcore-scanner"
    memory_limit_in_mb = 2048
    aws_request_id = "integ-test-request-id"
    log_group_name = "/aws/lambda/agentcore-scanner"
    log_stream_name = "2025/01/15/[$LATEST]integ"
    identity = None
    client_context = None

    def get_remaining_time_in_millis(self):
        return 300000


def _setup_ecr(ecr_client, repo_name="my-agent", tags=None):
    """Create an ECR repo and push fake images for each tag."""
    if tags is None:
        tags = ["latest"]

    try:
        ecr_client.create_repository(repositoryName=repo_name)
    except ecr_client.exceptions.RepositoryAlreadyExistsException:
        pass

    for i, tag in enumerate(tags):
        # Each tag gets a unique manifest so moto computes distinct imageDigest values
        digest_char = chr(ord("a") + i)
        ecr_client.put_image(
            repositoryName=repo_name,
            imageManifest=json.dumps({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                           "size": 7023 + i, "digest": "sha256:" + digest_char * 64},
                "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                             "size": 1000 + i, "digest": "sha256:" + str(i) * 64}],
            }),
            imageTag=tag,
        )


# Mock Qualys API credentials
MOCK_QUALYS_CREDS = {
    'token': 'test-token-abcdef1234567890',
    'gateway_url': 'https://gateway.qg2.apps.qualys.com',
}

# Mock Qualys API responses
MOCK_REGISTRY_RESULT = {
    'registry_uuid': 'uuid-registry-123456',
    'created': False,
    'exists': True,
}

MOCK_SCAN_SUBMIT_RESULT = {
    'status_code': 200,
    'schedule_id': 'sched-001',
    'schedule_name': 'ECR-my-agent-20250115120000',
}

MOCK_SCAN_STATUS_COMPLETE = {
    'status': 'complete',
    'found': True,
    'scan_status': 'SUCCESS',
    'vulnerabilities': {},
}

MOCK_VULN_RESULTS = {
    'summary': {
        'total': 19,
        'critical': 1,
        'high': 3,
        'medium': 10,
        'low': 5,
    },
    'vulnerabilities': [
        {'qid': 10001, 'severity': 5, 'title': 'Critical CVE-2025-0001', 'cveids': ['CVE-2025-0001']},
        {'qid': 10002, 'severity': 4, 'title': 'High CVE-2025-0002', 'cveids': ['CVE-2025-0002']},
        {'qid': 10003, 'severity': 4, 'title': 'High CVE-2025-0003', 'cveids': ['CVE-2025-0003']},
        {'qid': 10004, 'severity': 4, 'title': 'High CVE-2025-0004', 'cveids': ['CVE-2025-0004']},
        {'qid': 10005, 'severity': 3, 'title': 'Medium CVE-2025-0005', 'cveids': ['CVE-2025-0005']},
    ],
}


# ---------------------------------------------------------------------------
# Pipeline integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestCreateAgentRuntimePipeline:
    """Full flow: CreateAgentRuntime event -> scan -> inventory + cache update."""

    def test_create_runtime_full_flow(self, scanner_env_vars, mock_aws_services):
        """Chain handlers: parse_event -> check_cache -> get_registry -> submit_scan ->
        check_status -> get_results -> notify. Mock qualys_api functions.
        Assert inventory and cache updated.
        """
        ecr = boto3.client("ecr", region_name="us-east-1")
        _setup_ecr(ecr)

        import handlers
        importlib.reload(handlers)

        ctx = MockContext()
        event = deepcopy(SAMPLE_CREATE_AGENT_RUNTIME_EVENT)

        # Step 1: parse_event
        payload = handlers.handle_parse_event(event, ctx)
        assert payload["has_images"] is True
        assert payload["event_name"] == "CreateAgentRuntime"
        assert payload["agent_runtime_arn"] == (
            "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456"
        )
        assert payload["ecr_image_uri"] == (
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest"
        )

        # Step 2: check_cache — mock get_ecr_image_digest to return a digest
        test_digest = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        with patch("handlers.get_ecr_image_digest", return_value=test_digest):
            payload = handlers.handle_check_cache(payload)
        assert payload["is_cached"] is False
        assert payload["image_digest"] == test_digest
        assert payload["repository"] == "my-agent"
        assert payload["tag"] == "latest"

        # Step 3: get_registry — mock qualys_api functions
        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.get_or_create_registry", return_value=MOCK_REGISTRY_RESULT):
            payload = handlers.handle_get_registry(payload)
        assert payload["registry_uuid"] == "uuid-registry-123456"

        # Step 4: submit_scan
        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.submit_on_demand_scan", return_value=MOCK_SCAN_SUBMIT_RESULT):
            payload = handlers.handle_submit_scan(payload)
        assert payload["scan_submitted"] is True
        assert payload["schedule_name"] == "ECR-my-agent-20250115120000"
        assert payload["poll_count"] == 0

        # Step 5: check_status — scan is complete
        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.get_image_scan_status", return_value=MOCK_SCAN_STATUS_COMPLETE):
            payload = handlers.handle_check_status(payload)
        assert payload["scan_complete"] is True
        assert payload["scan_found"] is True
        assert payload["poll_count"] == 1

        # Step 6: get_results — fetch vulnerabilities and update cache
        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.get_image_vulnerabilities", return_value=MOCK_VULN_RESULTS):
            payload = handlers.handle_get_results(payload)
        assert "scan_result" in payload
        assert payload["scan_result"]["summary"]["critical"] == 1
        assert payload["scan_result"]["summary"]["total"] == 19

        # Step 7: notify — update inventory, store results to S3 and SNS
        payload = handlers.handle_notify(payload)
        assert payload["notified"] is True

        # Verify inventory was populated
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        inv_table = ddb.Table(handlers.INVENTORY_TABLE)
        inv_item = inv_table.get_item(
            Key={"agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456"}
        ).get("Item")
        assert inv_item is not None
        assert inv_item["account_id"] == "123456789012"
        assert inv_item["last_scan_status"] == "success"
        assert inv_item["discovery_source"] == "event-driven"

        # Verify scan cache was populated
        cache_table = ddb.Table(handlers.SCAN_CACHE_TABLE)
        scan_resp = cache_table.scan()
        cache_items = scan_resp.get("Items", [])
        assert len(cache_items) == 1
        assert cache_items[0]["scan_success"] is True
        assert cache_items[0]["image_digest"] == test_digest

        # Verify S3 results were stored
        s3 = boto3.client("s3", region_name="us-east-1")
        objs = s3.list_objects_v2(Bucket=handlers.RESULTS_S3_BUCKET)
        assert objs["KeyCount"] == 1
        assert "my-agent-runtime" in objs["Contents"][0]["Key"]

    def test_cache_hit_skips_rescan(self, scanner_env_vars, mock_aws_services):
        """First run populates cache, second run hits cache in check_cache handler."""
        ecr = boto3.client("ecr", region_name="us-east-1")
        _setup_ecr(ecr)

        import handlers
        importlib.reload(handlers)

        ctx = MockContext()
        event = deepcopy(SAMPLE_CREATE_AGENT_RUNTIME_EVENT)
        test_digest = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        # --- First run: full pipeline populates cache ---
        payload = handlers.handle_parse_event(event, ctx)
        assert payload["has_images"] is True

        with patch("handlers.get_ecr_image_digest", return_value=test_digest):
            payload = handlers.handle_check_cache(payload)
        assert payload["is_cached"] is False

        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.get_or_create_registry", return_value=MOCK_REGISTRY_RESULT):
            payload = handlers.handle_get_registry(payload)

        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.submit_on_demand_scan", return_value=MOCK_SCAN_SUBMIT_RESULT):
            payload = handlers.handle_submit_scan(payload)

        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.get_image_scan_status", return_value=MOCK_SCAN_STATUS_COMPLETE):
            payload = handlers.handle_check_status(payload)

        with patch("qualys_api.get_qualys_credentials", return_value=MOCK_QUALYS_CREDS), \
             patch("qualys_api.get_image_vulnerabilities", return_value=MOCK_VULN_RESULTS):
            payload = handlers.handle_get_results(payload)

        handlers.handle_notify(payload)

        # Verify cache was populated
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        cache_table = ddb.Table(handlers.SCAN_CACHE_TABLE)
        cache_items = cache_table.scan().get("Items", [])
        assert len(cache_items) == 1

        # --- Second run: same image digest -> cache hit ---
        payload2 = handlers.handle_parse_event(deepcopy(SAMPLE_CREATE_AGENT_RUNTIME_EVENT), ctx)
        assert payload2["has_images"] is True

        with patch("handlers.get_ecr_image_digest", return_value=test_digest):
            payload2 = handlers.handle_check_cache(payload2)

        # check_cache should report cache hit
        assert payload2["is_cached"] is True
        assert payload2["image_digest"] == test_digest


@pytest.mark.integration
class TestGatewayTargetPipeline:
    """CreateGatewayTarget events trigger MCP detection."""

    def test_mcp_server_detected(self, scanner_env_vars, mock_aws_services):
        """Gateway target with MCP server config is detected via handle_parse_event."""
        import handlers
        importlib.reload(handlers)

        ctx = MockContext()
        event = deepcopy(SAMPLE_CREATE_GATEWAY_TARGET_EVENT)
        result = handlers.handle_parse_event(event, ctx)

        assert result["has_images"] is False
        assert result["event_name"] == "CreateGatewayTarget"
        assert result["gateway_target_id"] == "gt-xyz789"
        assert result["message"] == "Gateway target processed"

    def test_http_mcp_detected_as_critical(self, scanner_env_vars, mock_aws_services):
        """External HTTP MCP server should be classified as CRITICAL risk."""
        from mcp_detector import classify_gateway_target

        target_config = SAMPLE_CREATE_GATEWAY_TARGET_HTTP_EVENT["detail"]["requestParameters"]["targetConfiguration"]
        info = classify_gateway_target(target_config)

        assert info is not None
        assert info.transport == "http"
        assert info.is_internal is False
        assert info.risk_level == "CRITICAL"
        assert any("Unencrypted" in f for f in info.risk_factors)

    def test_lambda_target_not_classified_as_mcp(self, scanner_env_vars, mock_aws_services):
        """Lambda-backed gateway target returns None from MCP classifier."""
        from mcp_detector import classify_gateway_target

        target_config = SAMPLE_CREATE_GATEWAY_TARGET_LAMBDA_EVENT["detail"]["requestParameters"]["targetConfiguration"]
        info = classify_gateway_target(target_config)
        assert info is None


@pytest.mark.integration
class TestAIServiceDetectionPipeline:
    """AI service detection from runtime configs, endpoints, and IAM policies."""

    def test_bedrock_model_detected(self, mock_aws_services):
        """Bedrock model_id in runtime config is detected."""
        from ai_service_detector import detect_bedrock_models, AI_SERVICE_BEDROCK

        details = {"model_id": "anthropic.claude-3-sonnet-20240229-v1:0"}
        services = detect_bedrock_models(details)

        assert len(services) == 1
        assert services[0].service_type == AI_SERVICE_BEDROCK
        assert services[0].provider == "anthropic"
        assert "text" in services[0].modalities

    def test_external_ai_from_gateway_endpoint(self, mock_aws_services):
        """External AI endpoint detected from gateway target URI."""
        from ai_service_detector import detect_external_ai_services, AI_SERVICE_EXTERNAL

        targets = [{"uri": "https://api.openai.com/v1/chat/completions"}]
        services = detect_external_ai_services(targets)

        assert len(services) == 1
        assert services[0].service_type == AI_SERVICE_EXTERNAL
        assert services[0].provider == "openai"

    def test_iam_policy_reveals_bedrock_access(self, mock_aws_services):
        """IAM policy with bedrock:InvokeModel is detected."""
        from ai_service_detector import detect_ai_from_iam_policy, AI_SERVICE_BEDROCK

        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="agent-runtime-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
                                "Action": "sts:AssumeRole"}],
            }),
        )
        iam.put_role_policy(
            RoleName="agent-runtime-role",
            PolicyName="BedrockAccess",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["bedrock:InvokeModel", "bedrock:Converse"],
                    "Resource": "*",
                }],
            }),
        )

        services = detect_ai_from_iam_policy(
            "arn:aws:iam::123456789012:role/agent-runtime-role", iam
        )
        assert len(services) >= 1
        assert any(s.service_type == AI_SERVICE_BEDROCK for s in services)

    def test_combined_risk_scoring(self, mock_aws_services):
        """Risk scoring combines multiple factors correctly."""
        from ai_service_detector import AIServiceInfo, AI_SERVICE_EXTERNAL, assess_ai_service_risk

        info = AIServiceInfo(
            service_type=AI_SERVICE_EXTERNAL,
            is_custom_model=True,
            endpoint_config={"uri": "http://insecure-ai.example.com/predict"},
        )
        score, factors = assess_ai_service_risk(info)
        assert score >= 75  # external(30) + custom(25) + unencrypted(20)
        assert any("External" in f for f in factors)
        assert any("Unencrypted" in f for f in factors)
        assert any("Custom" in f or "proprietary" in f for f in factors)


@pytest.mark.integration
class TestMCPClassificationMatrix:
    """Test the full MCP classification matrix across endpoint types."""

    def test_classification_matrix(self):
        """Comprehensive classification of different MCP endpoint types."""
        from mcp_detector import classify_gateway_target

        scenarios = [
            ("Internal HTTPS", {"mcpServer": {"uri": "https://10.0.1.50:8443/sse", "transportType": "SSE"}}, "LOW", "https"),
            ("External HTTPS", {"mcpServer": {"uri": "https://mcp.example.com/sse", "transportType": "SSE"}}, "MEDIUM", "https"),
            ("External HTTP (critical)", {"mcpServer": {"uri": "http://mcp.example.com:9090/mcp", "transportType": "STREAMABLE_HTTP"}}, "CRITICAL", "http"),
            ("AWS service endpoint", {"mcpServer": {"uri": "https://bedrock-agentcore.us-east-1.amazonaws.com/mcp", "transportType": "SSE"}}, "LOW", "https"),
            ("VPC endpoint", {"mcpServer": {"uri": "https://vpce-1234.bedrock.us-east-1.vpce.amazonaws.com/mcp", "transportType": "SSE"}}, "LOW", "https"),
            ("Localhost", {"mcpServer": {"uri": "http://localhost:3000/mcp", "transportType": "STDIO"}}, "MEDIUM", "http"),
        ]

        for desc, config, expected_risk, expected_transport in scenarios:
            info = classify_gateway_target(config)
            assert info is not None, f"Failed to classify: {desc}"
            assert info.risk_level == expected_risk, f"{desc}: expected risk={expected_risk}, got={info.risk_level}"
            assert info.transport == expected_transport, f"{desc}: expected transport={expected_transport}, got={info.transport}"


@pytest.mark.integration
class TestBulkScanInventoryReconciliation:
    """Bulk scan discovers stale entries and reconciles inventory."""

    def test_stale_detection_full_cycle(self, scanner_env_vars, mock_aws_services):
        """Stale detection correctly identifies new, changed, and current runtimes."""
        from bulk_scan import identify_stale_entries, mark_deleted_runtimes

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        inv_table = ddb.Table(os.environ["INVENTORY_TABLE"])

        # Runtime A: exists and up-to-date
        inv_table.put_item(Item={
            "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/aaa",
            "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-a:v1",
            "last_scan_timestamp": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        })
        # Runtime B: exists but image will change
        inv_table.put_item(Item={
            "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/bbb",
            "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-b:v1",
            "last_scan_timestamp": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        })
        # Runtime D: in inventory but no longer discovered (will be marked deleted)
        inv_table.put_item(Item={
            "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/ddd",
            "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-d:v1",
            "last_scan_timestamp": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        })

        inventory = {item["agent_runtime_arn"]: item for item in inv_table.scan()["Items"]}

        discovered = [
            {"agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/aaa",
             "agentRuntimeName": "agent-a",
             "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-a:v1"},
            {"agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/bbb",
             "agentRuntimeName": "agent-b",
             "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-b:v2"},  # changed
            {"agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/ccc",
             "agentRuntimeName": "agent-c",
             "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-c:v1"},  # new
        ]

        needs_scan = identify_stale_entries(discovered, inventory)
        arns_needing_scan = {r["agentRuntimeArn"] for r in needs_scan}

        assert "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/bbb" in arns_needing_scan
        assert "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/ccc" in arns_needing_scan
        assert "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/aaa" not in arns_needing_scan

        reasons = {r["agentRuntimeArn"]: r["_scan_reason"] for r in needs_scan}
        assert reasons["arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/bbb"] == "image_changed"
        assert reasons["arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/ccc"] == "not_in_inventory"

        # Mark deleted runtimes (D is no longer discovered)
        import bulk_scan
        importlib.reload(bulk_scan)

        discovered_arns = {r["agentRuntimeArn"] for r in discovered}
        bulk_scan.mark_deleted_runtimes(discovered_arns, inventory)

        d_item = inv_table.get_item(
            Key={"agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/ddd"}
        )["Item"]
        assert d_item["status"] == "DELETED"
