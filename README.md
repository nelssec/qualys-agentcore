# AgentCore Scanner

Real-time inventory, vulnerability scanning, and AI/MCP detection for AWS Bedrock AgentCore runtimes.

## Overview

AgentCore Scanner provides:

- **Event-driven scanning** — Detects AgentCore deployments via CloudTrail + EventBridge (CreateAgentRuntime, UpdateAgentRuntime, CreateGatewayTarget)
- **Container image scanning** — Scans ECR images for vulnerabilities using QScanner and Qualys CS API
- **MCP server detection** — Detects and classifies MCP servers connected via gateway targets
- **AI service detection** — Identifies Bedrock models, external AI APIs, and SageMaker endpoints used by runtimes
- **Real-time inventory** — DynamoDB-backed inventory of all agent runtimes, images, MCP servers, and AI services
- **Periodic sync** — Bulk scan every 4-12 hours to catch shadow agents missed during CloudTrail gaps
- **Hub-spoke architecture** — Multi-account scanning from day 1

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Spoke Account(s)                                       │
│  ┌──────────────┐  ┌──────────────┐                     │
│  │  CloudTrail   │→│  EventBridge  │──→ Central Bus ─┐  │
│  └──────────────┘  └──────────────┘                  │  │
│  ┌──────────────┐                                    │  │
│  │ IAM Spoke    │  (for cross-account scanning)      │  │
│  │ Role         │                                    │  │
│  └──────────────┘                                    │  │
└──────────────────────────────────────────────────────┼──┘
                                                       │
┌──────────────────────────────────────────────────────┼──┐
│  Hub Account (Security)                              ▼  │
│  ┌──────────────┐     ┌─────────────────────────────┐   │
│  │Central Event │────→│ Scanner Lambda              │   │
│  │Bus           │     │  - QScanner (vuln scan)     │   │
│  └──────────────┘     │  - MCP detection            │   │
│                       │  - AI service detection     │   │
│                       └──────────┬──────────────────┘   │
│                                  │                      │
│  ┌──────────┐  ┌──────────┐  ┌──┴───────┐  ┌────────┐  │
│  │ Scan     │  │Inventory │  │ S3 Scan  │  │  SNS   │  │
│  │ Cache    │  │ Table    │  │ Results  │  │ Alerts │  │
│  │(DynamoDB)│  │(DynamoDB)│  └──────────┘  └────────┘  │
│  └──────────┘  └──────────┘                             │
│                                                         │
│  ┌──────────────────────┐                               │
│  │ Bulk Scan Lambda     │  (periodic sync every N hrs)  │
│  └──────────────────────┘                               │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- AWS CLI configured
- Qualys QScanner binary and access token

### Install Development Dependencies

```bash
make install-dev
```

### Run Tests

```bash
make test
```

### Deploy Hub (Security Account)

```bash
# 1. Create Qualys secret and upload artifacts
# 2. Deploy hub stack
make deploy-hub QUALYS_ACCESS_TOKEN=your-token EXTERNAL_ID=your-external-id
```

### Deploy Spokes (Member Accounts)

```bash
# Via StackSet (recommended for organizations)
make deploy-spoke-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx

# Or for org-level CloudTrail (no new trails in member accounts)
make deploy-org-forwarder HUB_ACCOUNT_ID=123456789012
make deploy-spoke-minimal-stackset ORG_UNIT_IDS=ou-xxxx HUB_ACCOUNT_ID=123456789012
```

## Project Structure

```
agentcore/
├── scanner-lambda/
│   ├── handlers.py                 # Dispatch-pattern Lambda handler (Step Functions)
│   ├── bulk_scan.py                # Periodic sync Lambda
│   ├── qualys_api.py               # Qualys Container Security REST API
│   ├── mcp_detector.py             # MCP server detection & classification
│   └── ai_service_detector.py      # AI service detection from runtime configs
├── cloudformation/
│   ├── centralized-hub.yaml        # Hub account infrastructure
│   ├── centralized-spoke.yaml      # Spoke account (with CloudTrail)
│   ├── centralized-spoke-minimal.yaml  # Spoke (IAM role only)
│   └── org-cloudtrail-forwarder.yaml   # Org-level event forwarding
├── tests/
│   ├── fixtures/events.py          # Sample CloudTrail events
│   └── unit/                       # Unit tests
├── scripts/
│   ├── config_loader.py            # Configuration management
│   └── validate.py                 # Pre-flight validation
├── pyproject.toml
├── Makefile
└── README.md
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QUALYS_SECRET_ARN` | — | Secrets Manager ARN for Qualys credentials |
| `RESULTS_S3_BUCKET` | — | S3 bucket for scan results |
| `SNS_TOPIC_ARN` | — | SNS topic for notifications |
| `SCAN_CACHE_TABLE` | — | DynamoDB table for scan cache |
| `INVENTORY_TABLE` | — | DynamoDB table for runtime inventory |
| `SCAN_TIMEOUT` | 300 | QScanner timeout (seconds) |
| `CACHE_TTL_DAYS` | 30 | Scan cache TTL |
| `ENABLE_MCP_DETECTION` | true | Enable MCP server detection |
| `ENABLE_AI_SERVICE_DETECTION` | true | Enable AI service detection |
| `ENABLE_QUALYS_CS_API` | false | Enable Qualys CS API integration |
| `ENABLE_SECURITY_HUB` | false | Enable Security Hub findings |

### Secrets Manager Schema

```json
{
  "qualys_pod": "US2",
  "qualys_access_token": "your-token",
  "qualys_cs_api_key": "(optional)"
}
```

## Cleanup

```bash
# Preview what will be deleted
make clean-dry-run

# Full cleanup
make clean-all-hub ORG_UNIT_IDS=ou-xxxx
```
