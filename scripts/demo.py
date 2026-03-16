#!/usr/bin/env python3
"""AgentCore Scanner - Capability Demo

Demonstrates all scanner capabilities using sample data.
No AWS credentials required - runs entirely locally.

Usage:
    python3 scripts/demo.py
"""

import json
import os
import sys

# Add scanner-lambda to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner-lambda"))

from mcp_detector import classify_gateway_target, assess_mcp_risk, MCPServerInfo, build_mcp_inventory_entry
from ai_service_detector import (
    AIServiceInfo, AI_SERVICE_BEDROCK, AI_SERVICE_SAGEMAKER, AI_SERVICE_EXTERNAL,
    detect_bedrock_models, detect_external_ai_services, detect_external_ai_services_from_uri,
    assess_ai_service_risk, _identify_model_provider, _classify_model_type, _infer_modalities,
    _extract_ai_actions_from_policy,
)
from handlers import (
    extract_agent_runtime_from_event, validate_ecr_image_uri,
    validate_agent_runtime_arn, sanitize_log_output,
)
from bulk_scan import identify_stale_entries

# Reuse test fixtures
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
from fixtures.events import (
    SAMPLE_CREATE_AGENT_RUNTIME_EVENT,
    SAMPLE_UPDATE_AGENT_RUNTIME_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_HTTP_EVENT,
    SAMPLE_CREATE_GATEWAY_TARGET_LAMBDA_EVENT,
    SAMPLE_BULK_SCAN_EVENT,
)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def header(title):
    width = 70
    print()
    print(f"{BOLD}{BLUE}{'=' * width}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'=' * width}{RESET}")
    print()


def subheader(title):
    print(f"\n{BOLD}{CYAN}--- {title} ---{RESET}\n")


def risk_color(level):
    colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
    return colors.get(level, RESET)


def score_color(score):
    if score >= 75:
        return RED
    if score >= 50:
        return RED
    if score >= 25:
        return YELLOW
    return GREEN


def print_field(label, value, indent=2):
    print(f"{' ' * indent}{DIM}{label}:{RESET} {value}")


def print_risk(level, factors, indent=2):
    color = risk_color(level)
    print(f"{' ' * indent}{DIM}Risk Level:{RESET} {color}{BOLD}{level}{RESET}")
    for f in factors:
        print(f"{' ' * indent}  - {f}")


def print_score(score, factors, indent=2):
    color = score_color(score)
    print(f"{' ' * indent}{DIM}Risk Score:{RESET} {color}{BOLD}{score}/100{RESET}")
    for f in factors:
        print(f"{' ' * indent}  - {f}")


# ---------------------------------------------------------------------------
# Demo sections
# ---------------------------------------------------------------------------

def demo_event_parsing():
    header("1. CloudTrail Event Parsing")
    print("AgentCore Scanner intercepts CloudTrail events via EventBridge.")
    print("It parses CreateAgentRuntime, UpdateAgentRuntime, and CreateGatewayTarget.\n")

    events = [
        ("CreateAgentRuntime", SAMPLE_CREATE_AGENT_RUNTIME_EVENT),
        ("UpdateAgentRuntime", SAMPLE_UPDATE_AGENT_RUNTIME_EVENT),
        ("CreateGatewayTarget", SAMPLE_CREATE_GATEWAY_TARGET_EVENT),
        ("BulkScanRequest (synthetic)", SAMPLE_BULK_SCAN_EVENT),
    ]

    for name, event in events:
        subheader(f"Event: {name}")
        try:
            details = extract_agent_runtime_from_event(event)
            print_field("Event Name", details["event_name"])
            print_field("Account", details.get("account_id", "N/A"))
            print_field("Region", details.get("region", "N/A"))

            if details["event_name"] == "CreateGatewayTarget":
                print_field("Gateway Target ID", details.get("gateway_target_id", "N/A"))
                print_field("Target Name", details.get("gateway_target_name", "N/A"))
                config = details.get("target_configuration", {})
                if "mcpServer" in config:
                    print_field("MCP Server URI", config["mcpServer"].get("uri", "N/A"))
                    print_field("Transport", config["mcpServer"].get("transportType", "N/A"))
                elif "lambdaTarget" in config:
                    print_field("Lambda ARN", config["lambdaTarget"].get("functionArn", "N/A"))
            else:
                print_field("Runtime ARN", details.get("agent_runtime_arn", "N/A"))
                print_field("Runtime Name", details.get("agent_runtime_name", "N/A"))
                print_field("ECR Image", details.get("ecr_image_uri", "N/A"))
                print_field("Status", details.get("status", "N/A"))

        except Exception as e:
            print(f"  {RED}Parse error: {e}{RESET}")


def demo_mcp_detection():
    header("2. MCP Server Detection & Risk Classification")
    print("When a CreateGatewayTarget event arrives, the scanner classifies")
    print("MCP server endpoints and assesses their security risk.\n")

    scenarios = [
        ("Internal HTTPS (VPC)",
         {"mcpServer": {"uri": "https://10.0.1.50:8443/sse", "transportType": "SSE"}}),

        ("AWS Service Endpoint",
         {"mcpServer": {"uri": "https://bedrock-agentcore.us-east-1.amazonaws.com/mcp",
                         "transportType": "SSE"}}),

        ("VPC Endpoint",
         {"mcpServer": {"uri": "https://vpce-1234.bedrock.us-east-1.vpce.amazonaws.com/mcp",
                         "transportType": "SSE"}}),

        ("External HTTPS (production)",
         {"mcpServer": {"uri": "https://mcp.enterprise-tools.com:443/sse",
                         "transportType": "SSE"}}),

        ("External HTTPS with Many Tools",
         {"mcpServer": {"uri": "https://tools.example.com/sse", "transportType": "SSE",
                         "tools": [{"name": f"tool_{i}"} for i in range(15)]}}),

        ("External HTTP (CRITICAL)",
         {"mcpServer": {"uri": "http://insecure-mcp.example.com:9090/mcp",
                         "transportType": "STREAMABLE_HTTP"}}),

        ("Lambda Target (non-MCP)",
         {"lambdaTarget": {"functionArn": "arn:aws:lambda:us-east-1:123456789012:function:handler"}}),
    ]

    for desc, config in scenarios:
        subheader(desc)
        info = classify_gateway_target(config)
        if info is None:
            print(f"  {DIM}Not an MCP server target - skipped{RESET}")
            continue

        print_field("URI", info.uri)
        print_field("Server Type", info.server_type)
        print_field("Transport", info.transport)
        print_field("Hostname", info.hostname)
        print_field("Port", info.port)
        print_field("Internal", info.is_internal)
        print_field("AWS Service", info.is_aws_service)
        if info.tools_declared:
            print_field("Tools Declared", f"{len(info.tools_declared)} tools")
        print_risk(info.risk_level, info.risk_factors)


def demo_ai_service_detection():
    header("3. AI Service Detection")
    print("The scanner identifies AI/ML services used by agent runtimes from")
    print("three sources: runtime config, gateway targets, and IAM policies.\n")

    # --- Bedrock model detection ---
    subheader("3a. Bedrock Model Detection")
    models = [
        ("anthropic.claude-3-sonnet-20240229-v1:0", "Claude 3 Sonnet"),
        ("meta.llama3-70b-instruct-v1:0", "Llama 3 70B"),
        ("amazon.titan-text-express-v1", "Titan Text Express"),
        ("stability.stable-diffusion-xl-v1", "Stable Diffusion XL"),
        ("cohere.embed-english-v3", "Cohere Embed v3"),
        ("arn:aws:bedrock:us-east-1:123:custom-model/my-finetuned", "Custom fine-tuned"),
    ]

    for model_id, label in models:
        provider = _identify_model_provider(model_id)
        model_type = _classify_model_type(model_id)
        modalities = _infer_modalities(model_id)

        services = detect_bedrock_models({"model_id": model_id})
        svc = services[0] if services else None

        print(f"  {BOLD}{label}{RESET}")
        print_field("Model ID", model_id, indent=4)
        print_field("Provider", provider, indent=4)
        print_field("Type", model_type, indent=4)
        print_field("Modalities", ", ".join(modalities), indent=4)
        if svc:
            score, factors = assess_ai_service_risk(svc)
            print_score(score, factors, indent=4)
        print()

    # --- External AI endpoint detection ---
    subheader("3b. External AI Endpoint Detection")
    endpoints = [
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
        "https://generativelanguage.googleapis.com/v1/models",
        "https://api.cohere.ai/v1/generate",
        "https://api.mistral.ai/v1/chat/completions",
        "https://api.replicate.com/v1/predictions",
        "https://api.groq.com/openai/v1/chat/completions",
        "https://runtime.sagemaker.us-east-1.amazonaws.com/endpoints/my-model",
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke",
        "https://my-custom-api.example.com/predict",
    ]

    for uri in endpoints:
        services = detect_external_ai_services_from_uri(uri)
        if services:
            svc = services[0]
            color = RED if svc.service_type == "EXTERNAL" else YELLOW if svc.service_type == "SAGEMAKER" else GREEN
            print(f"  {color}{svc.service_type:10}{RESET} {DIM}provider={RESET}{svc.provider:12} {DIM}uri={RESET}{uri}")
        else:
            print(f"  {DIM}{'UNKNOWN':10} {'':16} uri={uri}{RESET}")

    # --- IAM policy analysis ---
    subheader("3c. IAM Policy Analysis")
    print("  The scanner analyzes IAM role policies to detect AI service permissions:\n")

    policies = [
        ("Bedrock InvokeModel", {
            "Statement": [{"Effect": "Allow",
                           "Action": ["bedrock:InvokeModel", "bedrock:Converse"],
                           "Resource": "*"}],
        }),
        ("SageMaker InvokeEndpoint", {
            "Statement": [{"Effect": "Allow",
                           "Action": "sagemaker:InvokeEndpoint",
                           "Resource": "*"}],
        }),
        ("Wildcard bedrock:*", {
            "Statement": [{"Effect": "Allow",
                           "Action": "bedrock:*",
                           "Resource": "*"}],
        }),
        ("Deny (ignored)", {
            "Statement": [{"Effect": "Deny",
                           "Action": "bedrock:InvokeModel",
                           "Resource": "*"}],
        }),
    ]

    for desc, policy_doc in policies:
        services = _extract_ai_actions_from_policy(policy_doc)
        count = len(services)
        if count > 0:
            types = ", ".join(set(s.service_type for s in services))
            print(f"  {GREEN}DETECTED{RESET}  {desc} -> {count} service(s): {types}")
            for svc in services:
                for rf in svc.risk_factors:
                    print(f"            {DIM}{rf}{RESET}")
        else:
            print(f"  {DIM}NONE      {desc}{RESET}")


def demo_risk_scoring():
    header("4. Risk Scoring Matrix")
    print("AI service risk scores (0-100) combine multiple weighted factors.")
    print("Scoring is adapted from the qualys-dspm AI tracking module.\n")

    scenarios = [
        ("Bedrock Foundation Model (low risk)",
         AIServiceInfo(service_type=AI_SERVICE_BEDROCK, provider="anthropic",
                       model_id="anthropic.claude-3-sonnet", is_custom_model=False)),

        ("Custom Fine-tuned Model",
         AIServiceInfo(service_type=AI_SERVICE_BEDROCK, provider="aws",
                       model_id="arn:aws:bedrock:us-east-1:123:custom-model/x",
                       is_custom_model=True)),

        ("External AI (OpenAI)",
         AIServiceInfo(service_type=AI_SERVICE_EXTERNAL, provider="openai",
                       endpoint_config={"uri": "https://api.openai.com/v1/chat"})),

        ("External AI + Unencrypted",
         AIServiceInfo(service_type=AI_SERVICE_EXTERNAL, provider="unknown",
                       endpoint_config={"uri": "http://insecure-ai.example.com/predict"})),

        ("SageMaker Endpoint",
         AIServiceInfo(service_type=AI_SERVICE_SAGEMAKER, provider="aws")),

        ("Bedrock + Broad IAM Permissions",
         AIServiceInfo(service_type=AI_SERVICE_BEDROCK, provider="aws",
                       risk_factors=["IAM permission: bedrock:*"])),

        ("Worst Case: External + Custom + HTTP + Broad Perms",
         AIServiceInfo(service_type=AI_SERVICE_EXTERNAL, is_custom_model=True,
                       endpoint_config={"uri": "http://insecure.example.com"},
                       risk_factors=["IAM permission: bedrock:*"])),
    ]

    # Table header
    print(f"  {'Scenario':<50} {'Score':>5}  Factors")
    print(f"  {'-' * 50} {'-' * 5}  {'-' * 40}")

    for desc, info in scenarios:
        score, factors = assess_ai_service_risk(info)
        color = score_color(score)
        factors_str = "; ".join(f for f in factors if f not in info.risk_factors) or "(baseline)"
        print(f"  {desc:<50} {color}{score:>5}{RESET}  {DIM}{factors_str}{RESET}")


def demo_bulk_scan():
    header("5. Bulk Scan - Stale Entry Detection")
    print("The periodic sync Lambda compares discovered runtimes against")
    print("the DynamoDB inventory to identify entries needing (re-)scan.\n")

    from datetime import datetime, timedelta

    inventory = {
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-a": {
            "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-a",
            "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-a:v1",
            "last_scan_timestamp": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        },
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-b": {
            "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-b",
            "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-b:v1",
            "last_scan_timestamp": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        },
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-c": {
            "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-c",
            "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-c:v1",
            "last_scan_timestamp": "",
            "status": "ACTIVE",
        },
    }

    discovered = [
        {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-a",
            "agentRuntimeName": "agent-a",
            "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-a:v1",
        },
        {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-b",
            "agentRuntimeName": "agent-b",
            "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-b:v2",  # CHANGED
        },
        {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-c",
            "agentRuntimeName": "agent-c",
            "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-c:v1",
        },
        {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-d",
            "agentRuntimeName": "agent-d",
            "ecrImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-d:v1",
        },
    ]

    print(f"  {BOLD}Inventory:{RESET} {len(inventory)} runtimes tracked")
    print(f"  {BOLD}Discovered:{RESET} {len(discovered)} runtimes from API\n")

    needs_scan = identify_stale_entries(discovered, inventory)

    # Table
    print(f"  {'Runtime':<12} {'Status':<20} {'Action'}")
    print(f"  {'-' * 12} {'-' * 20} {'-' * 30}")

    scanned_arns = {r["agentRuntimeArn"] for r in needs_scan}

    for runtime in discovered:
        arn = runtime["agentRuntimeArn"]
        name = runtime["agentRuntimeName"]
        if arn in scanned_arns:
            reason = next(r["_scan_reason"] for r in needs_scan if r["agentRuntimeArn"] == arn)
            reason_labels = {
                "not_in_inventory": f"{RED}NEW - Shadow agent{RESET}",
                "image_changed": f"{YELLOW}RESCAN - Image changed{RESET}",
                "never_scanned": f"{YELLOW}SCAN - Never scanned{RESET}",
            }
            print(f"  {name:<12} {reason:<20} {reason_labels.get(reason, reason)}")
        else:
            print(f"  {name:<12} {'up_to_date':<20} {GREEN}SKIP - Cache valid{RESET}")

    # Missing from discovered (would be marked DELETED)
    deleted_arns = set(inventory.keys()) - {r["agentRuntimeArn"] for r in discovered}
    # (none in this demo, but show the concept)
    print(f"\n  {DIM}Runtimes in inventory but not discovered (would be marked DELETED): {len(deleted_arns)}{RESET}")


def demo_validation():
    header("6. Input Validation")
    print("All inputs are validated before processing to prevent injection.\n")

    uri_tests = [
        ("123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest", True),
        ("123456789012.dkr.ecr.us-east-1.amazonaws.com/org/repo:v2.1", True),
        ("123456789012.dkr.ecr.us-east-1.amazonaws.com/repo@sha256:" + "a" * 64, True),
        ("docker.io/malicious/image:latest", False),
        ("'; DROP TABLE agents; --", False),
        ("", False),
    ]

    print(f"  {BOLD}ECR Image URI Validation:{RESET}")
    for uri, expected in uri_tests:
        result = validate_ecr_image_uri(uri)
        status = f"{GREEN}PASS{RESET}" if result == expected else f"{RED}FAIL{RESET}"
        valid = f"{GREEN}valid{RESET}" if result else f"{RED}invalid{RESET}"
        print(f"    {status} {valid:>20}  {uri[:65]}")

    print()

    arn_tests = [
        ("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123", True),
        ("arn:aws:bedrock-agentcore:eu-west-1:987654321098:runtime/xyz_789", True),
        ("not-a-valid-arn", False),
        ("arn:aws:lambda:us-east-1:123456789012:function:my-func", False),
    ]

    print(f"  {BOLD}Agent Runtime ARN Validation:{RESET}")
    for arn, expected in arn_tests:
        result = validate_agent_runtime_arn(arn)
        status = f"{GREEN}PASS{RESET}" if result == expected else f"{RED}FAIL{RESET}"
        valid = f"{GREEN}valid{RESET}" if result else f"{RED}invalid{RESET}"
        print(f"    {status} {valid:>20}  {arn[:65]}")

    print()

    print(f"  {BOLD}Log Sanitization:{RESET}")
    sensitive = "Error connecting with token=abc123456789012345678901234567890xyz password=s3cr3t"
    sanitized = sanitize_log_output(sensitive)
    print(f"    Input:     {sensitive}")
    print(f"    Sanitized: {sanitized}")


def demo_inventory_entry():
    header("7. DynamoDB Inventory Entry (Sample)")
    print("Each agent runtime gets a comprehensive inventory record:\n")

    entry = {
        "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456",
        "account_id": "123456789012",
        "ecr_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest",
        "agent_runtime_name": "my-agent-runtime",
        "status": "ACTIVE",
        "region": "us-east-1",
        "mcp_servers": [
            {
                "uri": "https://mcp.internal.example.com:8443/sse",
                "server_type": "SSE",
                "transport": "https",
                "risk_level": "LOW",
                "is_internal": True,
            },
            {
                "uri": "http://external-mcp.example.com:9090/mcp",
                "server_type": "STREAMABLE_HTTP",
                "transport": "http",
                "risk_level": "CRITICAL",
                "is_internal": False,
            },
        ],
        "ai_services": [
            {
                "service_type": "BEDROCK",
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "provider": "anthropic",
                "risk_score": 0,
            },
            {
                "service_type": "EXTERNAL",
                "provider": "openai",
                "endpoint_config": {"uri": "https://api.openai.com/v1/chat"},
                "risk_score": 30,
            },
        ],
        "risk_score": 45,
        "risk_factors": [
            "External AI service - data leaves AWS boundary",
            "Unencrypted HTTP transport to external MCP endpoint",
        ],
        "last_scan_timestamp": "2025-01-15T12:30:00",
        "last_scan_status": "success",
        "last_scan_image_digest": "a" * 64,
        "discovery_source": "event-driven",
    }

    print(f"  {json.dumps(entry, indent=4)}")


def demo_summary():
    header("Summary: AgentCore Scanner Capabilities")

    capabilities = [
        ("Event-Driven Scanning", "Intercepts CreateAgentRuntime, UpdateAgentRuntime, CreateGatewayTarget via CloudTrail + EventBridge"),
        ("Container Image Scanning", "Submits ECR images to Qualys CS API for server-side vulnerability scanning via Step Functions"),
        ("MCP Server Detection", "Classifies MCP endpoints: transport, internal/external, risk level (LOW/MEDIUM/HIGH/CRITICAL)"),
        ("AI Service Detection", "Identifies Bedrock models, external AI APIs (OpenAI/Anthropic/etc), and SageMaker endpoints"),
        ("IAM Policy Analysis", "Detects AI service permissions from IAM role policies attached to runtimes"),
        ("Risk Scoring", "Weighted risk scores (0-100) combining external exposure, custom models, encryption, permissions"),
        ("Scan Cache", "Image-digest-based cache prevents redundant scans when multiple runtimes share the same image"),
        ("Real-time Inventory", "DynamoDB-backed inventory with MCP servers, AI services, risk factors per runtime"),
        ("Periodic Sync", "Bulk scan Lambda discovers shadow agents, detects stale entries, reconciles inventory"),
        ("Hub-Spoke Architecture", "Cross-account scanning with STS role assumption and external ID validation"),
    ]

    for i, (name, desc) in enumerate(capabilities, 1):
        print(f"  {BOLD}{i:2}. {name}{RESET}")
        print(f"      {DIM}{desc}{RESET}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{BOLD}{BLUE}")
    print("    ___                    __  ______                ")
    print("   /   | ____ ____  ____  / /_/ ____/___  __________ ")
    print("  / /| |/ __ `/ _ \\/ __ \\/ __/ /   / __ \\/ ___/ _ \\\\")
    print(" / ___ / /_/ /  __/ / / / /_/ /___/ /_/ / /  /  __/")
    print("/_/  |_\\__, /\\___/_/ /_/\\__/\\____/\\____/_/   \\___/ ")
    print("      /____/                                        ")
    print(f"           Scanner - Capability Demo{RESET}")

    demo_event_parsing()
    demo_mcp_detection()
    demo_ai_service_detection()
    demo_risk_scoring()
    demo_bulk_scan()
    demo_validation()
    demo_inventory_entry()
    demo_summary()


if __name__ == "__main__":
    main()
