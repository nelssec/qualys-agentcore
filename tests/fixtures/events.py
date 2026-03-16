"""Sample CloudTrail events for Bedrock AgentCore."""

SAMPLE_CREATE_AGENT_RUNTIME_EVENT = {
    "version": "0",
    "id": "12345678-1234-1234-1234-123456789012",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "time": "2025-01-15T12:00:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.09",
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "CreateAgentRuntime",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/admin/user",
        },
        "requestParameters": {
            "agentRuntimeName": "my-agent-runtime",
            "agentRuntimeArtifact": {
                "containerImage": {
                    "uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest"
                }
            },
            "roleArn": "arn:aws:iam::123456789012:role/agent-runtime-role",
            "networkConfiguration": {
                "networkMode": "PUBLIC",
            },
        },
        "responseElements": {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456",
            "agentRuntimeId": "abc123def456",
            "agentRuntimeName": "my-agent-runtime",
            "status": "CREATING",
        },
    },
}

SAMPLE_UPDATE_AGENT_RUNTIME_EVENT = {
    "version": "0",
    "id": "22345678-1234-1234-1234-123456789012",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "time": "2025-01-15T14:00:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.09",
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "UpdateAgentRuntime",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/admin/user",
        },
        "requestParameters": {
            "agentRuntimeId": "abc123def456",
            "agentRuntimeArtifact": {
                "containerImage": {
                    "uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:v2"
                }
            },
        },
        "responseElements": {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456",
            "agentRuntimeId": "abc123def456",
            "agentRuntimeName": "my-agent-runtime",
            "status": "UPDATING",
        },
    },
}

SAMPLE_CREATE_GATEWAY_TARGET_EVENT = {
    "version": "0",
    "id": "32345678-1234-1234-1234-123456789012",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "time": "2025-01-15T15:00:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.09",
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "CreateGatewayTarget",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/admin/user",
        },
        "requestParameters": {
            "gatewayIdentifier": "gw-abc123",
            "name": "my-mcp-server",
            "targetConfiguration": {
                "mcpServer": {
                    "uri": "https://mcp.internal.example.com:8443/sse",
                    "transportType": "SSE",
                }
            },
        },
        "responseElements": {
            "gatewayTargetId": "gt-xyz789",
            "name": "my-mcp-server",
            "status": "CREATING",
        },
    },
}

SAMPLE_CREATE_GATEWAY_TARGET_LAMBDA_EVENT = {
    "version": "0",
    "id": "42345678-1234-1234-1234-123456789012",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "time": "2025-01-15T16:00:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.09",
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "CreateGatewayTarget",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/admin/user",
        },
        "requestParameters": {
            "gatewayIdentifier": "gw-abc123",
            "name": "my-lambda-target",
            "targetConfiguration": {
                "lambdaTarget": {
                    "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-tool-handler"
                }
            },
        },
        "responseElements": {
            "gatewayTargetId": "gt-lam456",
            "name": "my-lambda-target",
            "status": "CREATING",
        },
    },
}

SAMPLE_CREATE_GATEWAY_TARGET_HTTP_EVENT = {
    "version": "0",
    "id": "52345678-1234-1234-1234-123456789012",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "time": "2025-01-15T17:00:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.09",
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "CreateGatewayTarget",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/admin/user",
        },
        "requestParameters": {
            "gatewayIdentifier": "gw-abc123",
            "name": "my-external-mcp",
            "targetConfiguration": {
                "mcpServer": {
                    "uri": "http://external-mcp.example.com:9090/mcp",
                    "transportType": "STREAMABLE_HTTP",
                }
            },
        },
        "responseElements": {
            "gatewayTargetId": "gt-ext123",
            "name": "my-external-mcp",
            "status": "CREATING",
        },
    },
}

SAMPLE_BULK_SCAN_EVENT = {
    "source": "agentcore.bulk-scan",
    "detail-type": "Bulk Scan Request",
    "region": "us-east-1",
    "account": "123456789012",
    "detail": {
        "eventName": "BulkScanRequest",
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "requestParameters": {
            "agentRuntimeId": "abc123def456",
        },
        "responseElements": {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/abc123def456",
            "agentRuntimeName": "my-agent-runtime",
            "status": "ACTIVE",
        },
        "userIdentity": {
            "accountId": "123456789012",
        },
        "agentRuntimeArtifact": {
            "containerImage": {
                "uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest"
            }
        },
    },
}

INVALID_EVENT_MISSING_DETAIL = {
    "version": "0",
    "id": "bad-event-1",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "region": "us-east-1",
}

INVALID_EVENT_MISSING_ARTIFACT = {
    "version": "0",
    "id": "bad-event-2",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "CreateAgentRuntime",
        "requestParameters": {
            "agentRuntimeName": "no-artifact-runtime",
        },
        "responseElements": {
            "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/noart123",
            "agentRuntimeId": "noart123",
            "status": "CREATING",
        },
        "userIdentity": {
            "accountId": "123456789012",
        },
    },
}

INVALID_EVENT_BAD_ARN = {
    "version": "0",
    "id": "bad-event-3",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.bedrock-agentcore",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventSource": "bedrock-agentcore.amazonaws.com",
        "eventName": "CreateAgentRuntime",
        "requestParameters": {
            "agentRuntimeName": "bad-arn-runtime",
            "agentRuntimeArtifact": {
                "containerImage": {
                    "uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-agent:latest"
                }
            },
        },
        "responseElements": {
            "agentRuntimeArn": "not-a-valid-arn",
            "agentRuntimeId": "badarn123",
            "status": "CREATING",
        },
        "userIdentity": {
            "accountId": "123456789012",
        },
    },
}
