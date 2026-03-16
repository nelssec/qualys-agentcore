.PHONY: help package deploy-hub deploy-spoke deploy-spoke-stackset \
       deploy-org-forwarder deploy-spoke-minimal deploy-spoke-minimal-stackset \
       delete delete-hub delete-spoke-stackset delete-org-forwarder \
       delete-bucket delete-buckets delete-artifacts-bucket delete-secret \
       delete-dynamodb delete-dlq delete-sns delete-log-groups delete-alarms delete-eventbridge-rules delete-kms-key \
       clean clean-all clean-all-hub clean-dry-run \
       test test-unit test-integration test-smoke test-coverage \
       validate validate-config validate-cfn config-init config-show install-dev

AWS_REGION ?= us-east-1
STACK_NAME ?= agentcore-scanner
QUALYS_POD ?= US2
S3_BUCKET ?= $(STACK_NAME)-artifacts-$(shell aws sts get-caller-identity --query Account --output text)
QUALYS_ACCESS_TOKEN ?= $(shell echo $$QUALYS_ACCESS_TOKEN)
EXISTING_ROLE_ARN ?=
EXISTING_ROLE_NAME ?= agentcore-qualys-ecr-reader

REGIONS ?= $(AWS_REGION)
EXTERNAL_ID ?= $(shell openssl rand -hex 16)
ORG_ID ?= $(shell aws organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null)
ORG_UNIT_IDS ?=
ADMIN_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text)

help:
	@echo "AgentCore Scanner - Makefile"
	@echo ""
	@echo "=== Centralized Hub-Spoke Deployment ==="
	@echo "  deploy-hub           - Deploy hub scanner in security account"
	@echo "  deploy-spoke-stackset - Deploy spoke template via StackSet"
	@echo "  delete-hub           - Delete hub stack"
	@echo "  delete-spoke-stackset - Delete spoke StackSet"
	@echo ""
	@echo "=== Hub-Spoke with Org CloudTrail (no new CloudTrails) ==="
	@echo "  deploy-org-forwarder - Deploy EventBridge forwarder in management account"
	@echo "  deploy-spoke-minimal - Deploy minimal spoke (IAM role only) to single account"
	@echo "  deploy-spoke-minimal-stackset - Deploy minimal spoke via StackSet"
	@echo "  delete-org-forwarder - Delete org forwarder stack"
	@echo ""
	@echo "=== Build ==="
	@echo "  package              - Package Lambda function code"
	@echo ""
	@echo "=== Cleanup ==="
	@echo "  clean                - Clean local build artifacts only"
	@echo "  clean-dry-run        - Show what AWS resources would be deleted"
	@echo "  clean-all-hub        - FULL cleanup for hub-spoke deployment"
	@echo ""
	@echo "Variables:"
	@echo "  AWS_REGION              - AWS region (default: us-east-1)"
	@echo "  STACK_NAME              - CloudFormation stack name (default: agentcore-scanner)"
	@echo "  QUALYS_POD              - Qualys POD (default: US2)"
	@echo "  QUALYS_ACCESS_TOKEN     - Qualys access token (required, or set env var)"
	@echo "  ORG_UNIT_IDS            - Comma-separated OU IDs for StackSet deployment"
	@echo "  EXISTING_ROLE_ARN       - ARN of Qualys connector role with ECR read"
	@echo "  EXISTING_ROLE_NAME      - Name of Qualys connector role (default: agentcore-qualys-ecr-reader)"
	@echo "  HUB_ACCOUNT_ID          - Hub account ID (for org forwarder and minimal spoke)"
	@echo "  EXTERNAL_ID             - External ID for cross-account role (auto-generated if not set)"
	@echo "  REGIONS                 - Comma-separated regions for multi-region StackSet"
	@echo ""
	@echo "=== Testing ==="
	@echo "  test               - Run all unit tests (no AWS required)"
	@echo "  test-unit          - Run unit tests only"
	@echo "  test-integration   - Run integration tests (requires AWS)"
	@echo "  test-coverage      - Run tests with coverage report"
	@echo ""
	@echo "=== Validation ==="
	@echo "  validate           - Run pre-flight validation before deploy"
	@echo "  validate-cfn       - Lint CloudFormation templates"

package:
	@echo "Packaging Lambda function code..."
	@mkdir -p build/function build/bulk-scan
	@cp scanner-lambda/handlers.py scanner-lambda/qualys_api.py \
	    scanner-lambda/mcp_detector.py scanner-lambda/ai_service_detector.py \
	    build/function/
	@cp scanner-lambda/bulk_scan.py build/bulk-scan/
	@cd build/function && zip -r ../scanner-function.zip .
	@cd build/bulk-scan && zip -r ../bulk-scan.zip .
	@echo "Function packages created"

create-bucket:
	@echo "Creating S3 bucket for artifacts..."
	@aws s3 mb s3://$(S3_BUCKET) --region $(AWS_REGION) 2>/dev/null || true

upload-function: package create-bucket
	@echo "Uploading Lambda function code to S3..."
	@aws s3 cp build/scanner-function.zip s3://$(S3_BUCKET)/scanner-function.zip
	@aws s3 cp build/bulk-scan.zip s3://$(S3_BUCKET)/bulk-scan.zip

create-secret:
	@echo "Creating Secrets Manager secret..."
	@if [ -z "$(QUALYS_ACCESS_TOKEN)" ]; then \
		echo "ERROR: QUALYS_ACCESS_TOKEN environment variable not set"; \
		exit 1; \
	fi
	@mkdir -p build
	@SECRET_JSON='{"qualys_pod":"$(QUALYS_POD)","qualys_token":"$(QUALYS_ACCESS_TOKEN)"}'; \
	SECRET_ARN=$$(aws secretsmanager create-secret \
		--name "$(STACK_NAME)-qualys-credentials" \
		--description "Qualys credentials for AgentCore scanner" \
		--secret-string "$$SECRET_JSON" \
		--region $(AWS_REGION) \
		--query ARN \
		--output text 2>/dev/null || \
		aws secretsmanager describe-secret \
		--secret-id "$(STACK_NAME)-qualys-credentials" \
		--region $(AWS_REGION) \
		--query ARN \
		--output text); \
	echo $$SECRET_ARN > build/secret-arn.txt
	@echo "Secret ARN: $$(cat build/secret-arn.txt)"

create-artifacts-bucket:
	@echo "Creating artifacts bucket for cross-account distribution..."
	@mkdir -p build
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	BUCKET_NAME=agentcore-scanner-artifacts-$$ACCOUNT_ID; \
	aws s3 mb s3://$$BUCKET_NAME --region $(AWS_REGION) 2>/dev/null || true; \
	if [ -n "$(ORG_ID)" ] && [ "$(ORG_ID)" != "None" ]; then \
		echo "Applying org-wide bucket policy for $(ORG_ID)..."; \
		aws s3api put-bucket-policy --bucket $$BUCKET_NAME --policy '{"Version":"2012-10-17","Statement":[{"Sid":"AllowOrgAccess","Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::'$$BUCKET_NAME'/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"$(ORG_ID)"}}}]}'; \
	fi; \
	echo $$BUCKET_NAME > build/artifacts-bucket.txt
	@echo "Artifacts bucket: $$(cat build/artifacts-bucket.txt)"

upload-artifacts: package create-artifacts-bucket
	@echo "Uploading artifacts to S3..."
	@BUCKET=$$(cat build/artifacts-bucket.txt); \
	aws s3 cp build/scanner-function.zip s3://$$BUCKET/agentcore-scanner/lambda-code.zip; \
	aws s3 cp build/bulk-scan.zip s3://$$BUCKET/agentcore-scanner/bulk-scan.zip

deploy-hub: upload-artifacts create-secret
	@echo "Deploying centralized hub scanner..."
	@BUCKET=$$(cat build/artifacts-bucket.txt); \
	aws cloudformation deploy \
		--template-file cloudformation/centralized-hub.yaml \
		--stack-name $(STACK_NAME)-hub \
		--parameter-overrides \
			QualysSecretArn=$$(cat build/secret-arn.txt) \
			ArtifactsBucket=$$BUCKET \
			OrganizationId=$(ORG_ID) \
			ScannerExternalId=$(EXTERNAL_ID) \
			ExistingRoleArn=$(EXISTING_ROLE_ARN) \
			ExistingRoleName=$(EXISTING_ROLE_NAME) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)
	@echo ""
	@echo "Hub deployment complete!"
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query 'Stacks[0].Outputs' \
		--region $(AWS_REGION) \
		--output table
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-hub \
		--query "Stacks[0].Outputs[?OutputKey=='CentralEventBusArn'].OutputValue" \
		--output text \
		--region $(AWS_REGION) > build/central-bus-arn.txt
	@echo ""
	@echo "Next: make deploy-spoke-stackset ORG_UNIT_IDS=ou-xxxx-xxxxxxxx"

deploy-spoke-stackset:
	@echo "Deploying spoke StackSet to member accounts..."
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required"; \
		exit 1; \
	fi
	@if [ ! -f build/central-bus-arn.txt ]; then \
		echo "ERROR: Deploy hub first: make deploy-hub"; \
		exit 1; \
	fi
	@SECURITY_ACCT=$$(aws sts get-caller-identity --query Account --output text); \
	CENTRAL_BUS_ARN=$$(cat build/central-bus-arn.txt); \
	CENTRAL_BUS_NAME=$$(echo $$CENTRAL_BUS_ARN | awk -F'/' '{print $$NF}'); \
	aws cloudformation create-stack-set \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--template-body file://cloudformation/centralized-spoke.yaml \
		--parameters \
			ParameterKey=SecurityAccountId,ParameterValue=$$SECURITY_ACCT \
			ParameterKey=CentralEventBusName,ParameterValue=$$CENTRAL_BUS_NAME \
			ParameterKey=CentralEventBusArn,ParameterValue=$$CENTRAL_BUS_ARN \
		--capabilities CAPABILITY_NAMED_IAM \
		--permission-model SERVICE_MANAGED \
		--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
		--region $(AWS_REGION) 2>/dev/null || \
		aws cloudformation update-stack-set \
			--stack-set-name $(STACK_NAME)-spoke-stackset \
			--template-body file://cloudformation/centralized-spoke.yaml \
			--parameters \
				ParameterKey=SecurityAccountId,ParameterValue=$$SECURITY_ACCT \
				ParameterKey=CentralEventBusName,ParameterValue=$$CENTRAL_BUS_NAME \
				ParameterKey=CentralEventBusArn,ParameterValue=$$CENTRAL_BUS_ARN \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION)
	@echo "Creating spoke instances in OUs: $(ORG_UNIT_IDS)..."
	@aws cloudformation create-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25 \
		--region $(AWS_REGION)
	@echo "Spoke StackSet deployment initiated!"

delete-spoke-stackset:
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required"; \
		exit 1; \
	fi
	@aws cloudformation delete-stack-instances \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
		--regions $(AWS_REGION) \
		--no-retain-stacks \
		--region $(AWS_REGION) || true
	@sleep 60
	@aws cloudformation delete-stack-set \
		--stack-set-name $(STACK_NAME)-spoke-stackset \
		--region $(AWS_REGION)
	@echo "Spoke StackSet deleted"

HUB_ACCOUNT_ID ?=
HUB_EVENT_BUS_NAME ?= $(STACK_NAME)-hub-central-bus

deploy-org-forwarder:
	@echo "Deploying org CloudTrail EventBridge forwarder..."
	@if [ -z "$(HUB_ACCOUNT_ID)" ]; then \
		echo "ERROR: HUB_ACCOUNT_ID required"; \
		exit 1; \
	fi
	aws cloudformation deploy \
		--template-file cloudformation/org-cloudtrail-forwarder.yaml \
		--stack-name $(STACK_NAME)-org-forwarder \
		--parameter-overrides \
			HubAccountId=$(HUB_ACCOUNT_ID) \
			HubEventBusName=$(HUB_EVENT_BUS_NAME) \
			HubRegion=$(AWS_REGION) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)
	@echo "Org forwarder deployed!"

delete-org-forwarder:
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME)-org-forwarder \
		--region $(AWS_REGION)
	@aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK_NAME)-org-forwarder \
		--region $(AWS_REGION)
	@echo "Org forwarder deleted"

deploy-spoke-minimal:
	@echo "Deploying minimal spoke (IAM role only, no CloudTrail)..."
	@if [ -z "$(HUB_ACCOUNT_ID)" ]; then \
		echo "ERROR: HUB_ACCOUNT_ID required"; \
		exit 1; \
	fi
	aws cloudformation deploy \
		--template-file cloudformation/centralized-spoke-minimal.yaml \
		--stack-name $(STACK_NAME)-spoke \
		--parameter-overrides \
			SecurityAccountId=$(HUB_ACCOUNT_ID) \
			ScannerExternalId=$(EXTERNAL_ID) \
		--capabilities CAPABILITY_NAMED_IAM \
		--region $(AWS_REGION)
	@echo "Minimal spoke deployed!"

deploy-spoke-minimal-stackset:
	@echo "Deploying minimal spoke StackSet..."
	@if [ -z "$(ORG_UNIT_IDS)" ]; then \
		echo "ERROR: ORG_UNIT_IDS required"; \
		exit 1; \
	fi
	@if [ -z "$(HUB_ACCOUNT_ID)" ]; then \
		echo "ERROR: HUB_ACCOUNT_ID required"; \
		exit 1; \
	fi
	@aws cloudformation create-stack-set \
		--stack-set-name $(STACK_NAME)-spoke-minimal-stackset \
		--template-body file://cloudformation/centralized-spoke-minimal.yaml \
		--parameters \
			ParameterKey=SecurityAccountId,ParameterValue=$(HUB_ACCOUNT_ID) \
			ParameterKey=ScannerExternalId,ParameterValue=$(EXTERNAL_ID) \
		--capabilities CAPABILITY_NAMED_IAM \
		--permission-model SERVICE_MANAGED \
		--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
		--region $(AWS_REGION) 2>/dev/null || \
		aws cloudformation update-stack-set \
			--stack-set-name $(STACK_NAME)-spoke-minimal-stackset \
			--template-body file://cloudformation/centralized-spoke-minimal.yaml \
			--parameters \
				ParameterKey=SecurityAccountId,ParameterValue=$(HUB_ACCOUNT_ID) \
				ParameterKey=ScannerExternalId,ParameterValue=$(EXTERNAL_ID) \
			--capabilities CAPABILITY_NAMED_IAM \
			--region $(AWS_REGION)
	@echo "Creating stack instances in OUs: $(ORG_UNIT_IDS)..."
	@for region in $$(echo "$(REGIONS)" | tr ',' ' '); do \
		aws cloudformation create-stack-instances \
			--stack-set-name $(STACK_NAME)-spoke-minimal-stackset \
			--deployment-targets OrganizationalUnitIds=$(ORG_UNIT_IDS) \
			--regions $$region \
			--operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25 \
			--region $(AWS_REGION); \
	done
	@echo "Minimal spoke StackSet deployment initiated!"

delete-hub:
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME)-hub \
		--region $(AWS_REGION)
	@aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK_NAME)-hub \
		--region $(AWS_REGION)
	@echo "Hub deleted"

clean:
	@rm -rf build/
	@echo "Build artifacts cleaned"

delete-secret:
	@aws secretsmanager delete-secret \
		--secret-id "$(STACK_NAME)-qualys-credentials" \
		--force-delete-without-recovery \
		--region $(AWS_REGION) 2>/dev/null && \
		echo "Secret deleted" || echo "Secret not found"

clean-all-hub:
	@echo "=========================================="
	@echo "COMPLETE CLEANUP - Hub-Spoke Deployment"
	@echo "=========================================="
	@if [ -n "$(ORG_UNIT_IDS)" ]; then \
		$(MAKE) delete-spoke-stackset 2>/dev/null || echo "Spoke StackSet not found"; \
	fi
	-@$(MAKE) delete-hub 2>/dev/null || echo "Hub stack already deleted"
	-@$(MAKE) delete-secret 2>/dev/null || true
	@$(MAKE) clean
	@echo "CLEANUP COMPLETE"

clean-dry-run:
	@echo "=========================================="
	@echo "DRY RUN - Resources that would be deleted"
	@echo "=========================================="
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text); \
	echo "Account: $$ACCOUNT_ID  Region: $(AWS_REGION)  Stack: $(STACK_NAME)"
	@aws cloudformation describe-stacks --stack-name $(STACK_NAME)-hub --region $(AWS_REGION) \
		--query 'Stacks[0].StackName' --output text 2>/dev/null && \
		echo "  [FOUND] $(STACK_NAME)-hub" || echo "  [NOT FOUND] $(STACK_NAME)-hub"

# =============================================================================
# Testing Targets
# =============================================================================

install-dev:
	@echo "Installing development dependencies..."
	pip3 install -e ".[dev]"
	@echo "Development dependencies installed"

test: test-unit
	@echo "All tests completed"

test-unit:
	@echo "Running unit tests..."
	python3 -m pytest tests/unit -v -m unit --tb=short

test-integration:
	@echo "Running integration tests (requires AWS credentials)..."
	python3 -m pytest tests/integration -v -m integration --tb=short

test-coverage:
	@echo "Running tests with coverage..."
	python3 -m pytest tests/unit -v --cov=scanner-lambda --cov-report=term-missing --cov-report=html
	@echo "Coverage report generated in htmlcov/"

# =============================================================================
# Validation Targets
# =============================================================================

validate:
	@echo "Running pre-flight validation..."
	@python3 scripts/validate.py

validate-cfn:
	@echo "Linting CloudFormation templates..."
	@if command -v cfn-lint >/dev/null 2>&1; then \
		cfn-lint cloudformation/*.yaml; \
		echo "All templates passed validation"; \
	else \
		echo "cfn-lint not installed. Install with: pip install cfn-lint"; \
		exit 1; \
	fi

validate-config:
	@echo "Validating configuration..."
	@python3 scripts/config_loader.py --config .agentcore-scanner.yml 2>/dev/null || \
		echo "No .agentcore-scanner.yml found (using defaults)"

config-init:
	@if [ -f .agentcore-scanner.yml ]; then \
		echo "ERROR: .agentcore-scanner.yml already exists"; \
		exit 1; \
	fi
	@cp .agentcore-scanner.yml.example .agentcore-scanner.yml
	@echo "Created .agentcore-scanner.yml from example"

config-show:
	@echo "Current configuration:"
	@python3 scripts/config_loader.py 2>/dev/null || echo "Using defaults"
