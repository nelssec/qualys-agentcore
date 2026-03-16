"""Unit tests for scanner-lambda/mcp_detector.py."""

import pytest

from mcp_detector import (
    MCPServerInfo,
    classify_gateway_target,
    assess_mcp_risk,
    build_mcp_inventory_entry,
    _is_private_ip,
    _is_internal_hostname,
    _is_aws_service,
)


@pytest.mark.unit
class TestHelpers:
    def test_is_private_ip(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.2.3.4") is False

    def test_is_internal_hostname(self):
        assert _is_internal_hostname("10.0.0.1") is True
        assert _is_internal_hostname("localhost") is True
        assert _is_internal_hostname("my-service.internal") is True
        assert _is_internal_hostname("my-service.local") is True
        assert _is_internal_hostname("vpce-abc123.execute-api.us-east-1.vpce.amazonaws.com") is True
        assert _is_internal_hostname("example.com") is False

    def test_is_aws_service(self):
        assert _is_aws_service("bedrock-runtime.us-east-1.amazonaws.com") is True
        assert _is_aws_service("sagemaker.us-east-1.amazonaws.com") is True
        assert _is_aws_service("example.com") is False


@pytest.mark.unit
class TestClassifyGatewayTarget:
    def test_classify_mcp_server_https(self):
        config = {
            'mcpServer': {
                'uri': 'https://mcp.internal.example.com:8443/sse',
                'transportType': 'SSE',
            }
        }
        result = classify_gateway_target(config)
        assert result is not None
        assert result.server_type == 'SSE'
        assert result.transport == 'https'
        assert result.hostname == 'mcp.internal.example.com'
        assert result.port == 8443

    def test_classify_mcp_server_http(self):
        config = {
            'mcpServer': {
                'uri': 'http://external-mcp.example.com:9090/mcp',
                'transportType': 'STREAMABLE_HTTP',
            }
        }
        result = classify_gateway_target(config)
        assert result is not None
        assert result.server_type == 'STREAMABLE_HTTP'
        assert result.transport == 'http'
        assert result.port == 9090
        assert result.is_internal is False

    def test_classify_mcp_server_internal(self):
        config = {
            'mcpServer': {
                'uri': 'https://10.0.0.5:8443/mcp',
                'transportType': 'SSE',
            }
        }
        result = classify_gateway_target(config)
        assert result is not None
        assert result.is_internal is True

    def test_classify_mcp_server_aws_endpoint(self):
        config = {
            'mcpServer': {
                'uri': 'https://bedrock-runtime.us-east-1.amazonaws.com/invoke',
                'transportType': 'STREAMABLE_HTTP',
            }
        }
        result = classify_gateway_target(config)
        assert result is not None
        assert result.is_aws_service is True

    def test_classify_lambda_target_returns_none(self):
        config = {
            'lambdaTarget': {
                'functionArn': 'arn:aws:lambda:us-east-1:123456789012:function:my-func'
            }
        }
        result = classify_gateway_target(config)
        assert result is None

    def test_classify_empty_config(self):
        assert classify_gateway_target({}) is None
        assert classify_gateway_target(None) is None

    def test_classify_mcp_no_uri(self):
        config = {
            'mcpServer': {
                'transportType': 'SSE',
            }
        }
        result = classify_gateway_target(config)
        assert result is None

    def test_classify_mcp_with_tools(self):
        config = {
            'mcpServer': {
                'uri': 'https://mcp.example.com/sse',
                'transportType': 'SSE',
                'tools': [
                    {'name': 'read_file'},
                    {'name': 'write_file'},
                    {'name': 'execute_command'},
                ],
            }
        }
        result = classify_gateway_target(config)
        assert result is not None
        assert len(result.tools_declared) == 3
        assert 'read_file' in result.tools_declared


@pytest.mark.unit
class TestAssessMCPRisk:
    def test_critical_external_http(self):
        info = MCPServerInfo(
            uri='http://external.example.com/mcp',
            transport='http',
            hostname='external.example.com',
            is_internal=False,
        )
        level, factors = assess_mcp_risk(info)
        assert level == 'CRITICAL'
        assert any('Unencrypted' in f for f in factors)

    def test_low_internal_https(self):
        info = MCPServerInfo(
            uri='https://10.0.0.5:8443/mcp',
            transport='https',
            hostname='10.0.0.5',
            is_internal=True,
        )
        level, factors = assess_mcp_risk(info)
        assert level == 'LOW'

    def test_low_aws_service(self):
        info = MCPServerInfo(
            uri='https://bedrock-runtime.us-east-1.amazonaws.com',
            transport='https',
            hostname='bedrock-runtime.us-east-1.amazonaws.com',
            is_aws_service=True,
        )
        level, factors = assess_mcp_risk(info)
        assert level == 'LOW'

    def test_medium_internal_http(self):
        info = MCPServerInfo(
            uri='http://10.0.0.5:8080/mcp',
            transport='http',
            hostname='10.0.0.5',
            is_internal=True,
        )
        level, factors = assess_mcp_risk(info)
        assert level == 'MEDIUM'

    def test_high_external_many_tools(self):
        info = MCPServerInfo(
            uri='https://mcp.external.com/sse',
            transport='https',
            hostname='mcp.external.com',
            is_internal=False,
            is_aws_service=False,
            tools_declared=[f'tool_{i}' for i in range(15)],
        )
        level, factors = assess_mcp_risk(info)
        assert level == 'HIGH'
        assert any('Broad tool surface' in f for f in factors)

    def test_medium_external_https(self):
        info = MCPServerInfo(
            uri='https://mcp.external.com/sse',
            transport='https',
            hostname='mcp.external.com',
            is_internal=False,
            is_aws_service=False,
            tools_declared=['read', 'write'],
        )
        level, factors = assess_mcp_risk(info)
        assert level == 'MEDIUM'


@pytest.mark.unit
class TestBuildInventoryEntry:
    def test_build_entry(self):
        info = MCPServerInfo(
            uri='https://mcp.example.com/sse',
            server_type='SSE',
            transport='https',
            hostname='mcp.example.com',
            port=443,
            is_internal=False,
            is_aws_service=False,
            risk_level='MEDIUM',
            risk_factors=['External MCP endpoint'],
            tools_declared=['read_file'],
        )
        entry = build_mcp_inventory_entry(info, 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test')
        assert entry['uri'] == 'https://mcp.example.com/sse'
        assert entry['server_type'] == 'SSE'
        assert entry['risk_level'] == 'MEDIUM'
        assert entry['agent_runtime_arn'] == 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test'
