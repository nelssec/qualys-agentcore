import json
import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def mock_aws_services():
    with mock_aws():
        yield


@pytest.fixture
def secrets_manager_client(mock_aws_services):
    return boto3.client("secretsmanager", region_name="us-east-1")


@pytest.fixture
def s3_client(mock_aws_services):
    return boto3.client("s3", region_name="us-east-1")


@pytest.fixture
def dynamodb_resource(mock_aws_services):
    return boto3.resource("dynamodb", region_name="us-east-1")


@pytest.fixture
def sns_client(mock_aws_services):
    return boto3.client("sns", region_name="us-east-1")


@pytest.fixture
def iam_client(mock_aws_services):
    return boto3.client("iam", region_name="us-east-1")


@pytest.fixture
def qualys_secret(secrets_manager_client):
    secret_value = {
        "qualys_pod": "US2",
        "qualys_access_token": "test_token_12345678901234567890"
    }
    response = secrets_manager_client.create_secret(
        Name="agentcore-scanner-credentials",
        SecretString=json.dumps(secret_value)
    )
    return response["ARN"]


@pytest.fixture
def s3_bucket(s3_client):
    bucket_name = "agentcore-scan-results-test"
    s3_client.create_bucket(Bucket=bucket_name)
    return bucket_name


@pytest.fixture
def sns_topic(sns_client):
    response = sns_client.create_topic(Name="agentcore-scan-notifications")
    return response["TopicArn"]


@pytest.fixture
def scan_cache_table(dynamodb_resource):
    table_name = "agentcore-scan-cache-test"
    table = dynamodb_resource.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "image_digest", "KeyType": "HASH"}
        ],
        AttributeDefinitions=[
            {"AttributeName": "image_digest", "AttributeType": "S"}
        ],
        BillingMode="PAY_PER_REQUEST"
    )
    table.wait_until_exists()
    return table_name


@pytest.fixture
def inventory_table(dynamodb_resource):
    table_name = "agentcore-inventory-test"
    table = dynamodb_resource.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "agent_runtime_arn", "KeyType": "HASH"}
        ],
        AttributeDefinitions=[
            {"AttributeName": "agent_runtime_arn", "AttributeType": "S"}
        ],
        BillingMode="PAY_PER_REQUEST"
    )
    table.wait_until_exists()
    return table_name


@pytest.fixture
def scanner_env_vars(monkeypatch, qualys_secret, s3_bucket, sns_topic,
                     scan_cache_table, inventory_table):
    monkeypatch.setenv("QUALYS_SECRET_ARN", qualys_secret)
    monkeypatch.setenv("RESULTS_S3_BUCKET", s3_bucket)
    monkeypatch.setenv("SNS_TOPIC_ARN", sns_topic)
    monkeypatch.setenv("SCAN_CACHE_TABLE", scan_cache_table)
    monkeypatch.setenv("INVENTORY_TABLE", inventory_table)
    monkeypatch.setenv("CACHE_TTL_DAYS", "30")
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "agentcore-scanner")
    monkeypatch.setenv("ENABLE_MCP_DETECTION", "true")
    monkeypatch.setenv("ENABLE_AI_SERVICE_DETECTION", "true")


class MockLambdaContext:
    def __init__(self):
        self.function_name = "agentcore-scanner"
        self.function_version = "$LATEST"
        self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:agentcore-scanner"
        self.memory_limit_in_mb = 2048
        self.aws_request_id = "test-request-id-12345"
        self.log_group_name = "/aws/lambda/agentcore-scanner"
        self.log_stream_name = "2025/01/15/[$LATEST]abc123"
        self.identity = None
        self.client_context = None

    def get_remaining_time_in_millis(self):
        return 300000


@pytest.fixture
def lambda_context():
    return MockLambdaContext()
