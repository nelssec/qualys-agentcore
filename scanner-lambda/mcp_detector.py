"""MCP (Model Context Protocol) server detection and classification."""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# RFC 1918 private IP ranges
PRIVATE_IP_PATTERNS = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^fd[0-9a-f]{2}:'),  # IPv6 ULA
    re.compile(r'^::1$'),             # IPv6 loopback
]

AWS_ENDPOINT_PATTERN = re.compile(r'.*\.amazonaws\.com$')
VPC_ENDPOINT_PATTERN = re.compile(r'.*\.vpce\.amazonaws\.com$')


@dataclass
class MCPServerInfo:
    """Classified MCP server metadata."""
    uri: str = ''
    server_type: str = 'UNKNOWN'        # STDIO, SSE, STREAMABLE_HTTP
    transport: str = 'unknown'           # http, https, stdio
    hostname: str = ''
    port: int = 0
    is_internal: bool = False
    is_aws_service: bool = False
    protocol_version: str = ''
    tools_declared: List[str] = field(default_factory=list)
    risk_level: str = 'UNKNOWN'          # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'uri': self.uri,
            'server_type': self.server_type,
            'transport': self.transport,
            'hostname': self.hostname,
            'port': self.port,
            'is_internal': self.is_internal,
            'is_aws_service': self.is_aws_service,
            'protocol_version': self.protocol_version,
            'tools_declared': self.tools_declared,
            'risk_level': self.risk_level,
            'risk_factors': self.risk_factors,
        }


def _is_private_ip(hostname: str) -> bool:
    """Check if hostname is a private/internal IP address."""
    for pattern in PRIVATE_IP_PATTERNS:
        if pattern.match(hostname):
            return True
    return False


def _is_internal_hostname(hostname: str) -> bool:
    """Check if hostname is internal (private IP, VPC endpoint, localhost)."""
    if _is_private_ip(hostname):
        return True
    if hostname in ('localhost', '127.0.0.1', '::1'):
        return True
    if VPC_ENDPOINT_PATTERN.match(hostname):
        return True
    if hostname.endswith('.internal') or hostname.endswith('.local'):
        return True
    return False


def _is_aws_service(hostname: str) -> bool:
    """Check if hostname is an AWS service endpoint."""
    return bool(AWS_ENDPOINT_PATTERN.match(hostname))


def classify_gateway_target(target_config: Dict[str, Any]) -> Optional[MCPServerInfo]:
    """Classify a gateway target from CreateGatewayTarget event.

    Parses targetConfiguration to identify MCP servers vs other endpoint types.
    Returns MCPServerInfo if target is an MCP server, None otherwise.
    """
    if not target_config:
        return None

    # Check for MCP server target
    mcp_config = target_config.get('mcpServer')
    if not mcp_config:
        # Not an MCP server target (could be Lambda, API Gateway, etc.)
        return None

    uri = mcp_config.get('uri', '')
    transport_type = mcp_config.get('transportType', 'UNKNOWN')

    if not uri:
        logger.warning("MCP server target has no URI")
        return None

    info = MCPServerInfo(uri=uri, server_type=transport_type)

    # Parse URI
    parsed = urlparse(uri)
    info.hostname = parsed.hostname or ''
    info.port = parsed.port or (443 if parsed.scheme == 'https' else 80 if parsed.scheme == 'http' else 0)
    info.transport = parsed.scheme or 'unknown'

    # Classify internal vs external
    info.is_internal = _is_internal_hostname(info.hostname)
    info.is_aws_service = _is_aws_service(info.hostname)

    # Extract protocol version if available
    info.protocol_version = mcp_config.get('protocolVersion', '')

    # Extract declared tools if available
    tools = mcp_config.get('tools', [])
    if isinstance(tools, list):
        info.tools_declared = [t.get('name', str(t)) if isinstance(t, dict) else str(t) for t in tools]

    # Assess risk
    info.risk_level, info.risk_factors = assess_mcp_risk(info)

    return info


def detect_mcp_from_runtime(agent_runtime_details: Dict[str, Any],
                            agentcore_client) -> List[MCPServerInfo]:
    """Given an agent runtime, list gateway targets and classify each.

    Calls list-gateway-targets API for the runtime.
    Returns list of detected MCP servers.
    """
    mcp_servers = []

    if not agentcore_client:
        logger.warning("No agentcore client available for MCP detection")
        return mcp_servers

    runtime_id = agent_runtime_details.get('agent_runtime_id')
    if not runtime_id:
        # Try to extract from ARN
        arn = agent_runtime_details.get('agent_runtime_arn', '')
        if '/runtime/' in arn:
            runtime_id = arn.split('/runtime/')[-1]

    if not runtime_id:
        logger.warning("No runtime ID available for gateway target listing")
        return mcp_servers

    try:
        paginator_params = {'agentRuntimeId': runtime_id}
        targets = []

        # Try to paginate through targets
        try:
            response = agentcore_client.list_gateway_targets(**paginator_params)
            targets = response.get('gatewayTargets', [])
            while response.get('nextToken'):
                response = agentcore_client.list_gateway_targets(
                    **paginator_params, nextToken=response['nextToken']
                )
                targets.extend(response.get('gatewayTargets', []))
        except Exception as e:
            logger.warning(f"Could not list gateway targets for {runtime_id}: {e}")
            return mcp_servers

        for target in targets:
            target_config = target.get('targetConfiguration', {})
            mcp_info = classify_gateway_target(target_config)
            if mcp_info:
                mcp_servers.append(mcp_info)

    except Exception as e:
        logger.error(f"Error detecting MCP servers: {e}")

    return mcp_servers


def assess_mcp_risk(mcp_info: MCPServerInfo) -> Tuple[str, List[str]]:
    """Risk assessment for MCP server connections.

    - CRITICAL: External HTTP (unencrypted) MCP endpoint
    - HIGH: External HTTPS endpoint with broad tool declarations
    - MEDIUM: External HTTPS with limited scope
    - LOW: Internal/VPC endpoint or AWS service endpoint
    """
    risk_factors = []

    # Transport security
    if mcp_info.transport == 'http' and not mcp_info.is_internal:
        risk_factors.append('Unencrypted HTTP transport to external endpoint')
        return 'CRITICAL', risk_factors

    if mcp_info.transport == 'http' and mcp_info.is_internal:
        risk_factors.append('Unencrypted HTTP transport (internal)')

    # Internal vs external
    if mcp_info.is_internal or mcp_info.is_aws_service:
        if mcp_info.transport == 'http':
            risk_factors.append('Internal endpoint using HTTP')
            return 'MEDIUM', risk_factors
        return 'LOW', risk_factors

    # External HTTPS endpoints
    risk_factors.append('External MCP endpoint')

    # Broad tools
    if len(mcp_info.tools_declared) > 10:
        risk_factors.append(f'Broad tool surface: {len(mcp_info.tools_declared)} tools declared')
        return 'HIGH', risk_factors

    if len(mcp_info.tools_declared) == 0:
        risk_factors.append('No tools declared (unknown scope)')

    # Default for external HTTPS
    if not risk_factors or risk_factors == ['External MCP endpoint']:
        risk_factors.append('External HTTPS endpoint with limited scope')

    return 'MEDIUM', risk_factors


def build_mcp_inventory_entry(mcp_info: MCPServerInfo,
                               agent_runtime_arn: str) -> Dict[str, Any]:
    """Build DynamoDB item for the inventory table's gateway_targets list."""
    return {
        'agent_runtime_arn': agent_runtime_arn,
        'uri': mcp_info.uri,
        'server_type': mcp_info.server_type,
        'transport': mcp_info.transport,
        'hostname': mcp_info.hostname,
        'port': mcp_info.port,
        'is_internal': mcp_info.is_internal,
        'is_aws_service': mcp_info.is_aws_service,
        'risk_level': mcp_info.risk_level,
        'risk_factors': mcp_info.risk_factors,
        'tools_declared': mcp_info.tools_declared,
    }
