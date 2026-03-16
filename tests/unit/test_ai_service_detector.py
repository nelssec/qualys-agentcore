"""Unit tests for scanner-lambda/ai_service_detector.py."""

import pytest

from ai_service_detector import (
    AIServiceInfo,
    AI_SERVICE_BEDROCK,
    AI_SERVICE_SAGEMAKER,
    AI_SERVICE_EXTERNAL,
    MODEL_TYPE_FOUNDATION,
    MODEL_TYPE_CUSTOM,
    detect_bedrock_models,
    detect_external_ai_services,
    detect_external_ai_services_from_uri,
    assess_ai_service_risk,
    _identify_model_provider,
    _classify_model_type,
    _infer_modalities,
    _action_matches,
    _extract_ai_actions_from_policy,
)


@pytest.mark.unit
class TestModelIdentification:
    def test_identify_anthropic(self):
        assert _identify_model_provider("anthropic.claude-3-sonnet-20240229-v1:0") == "anthropic"
        assert _identify_model_provider("anthropic.claude-v2") == "anthropic"

    def test_identify_meta(self):
        assert _identify_model_provider("meta.llama3-70b-instruct-v1:0") == "meta"

    def test_identify_amazon(self):
        assert _identify_model_provider("amazon.titan-text-express-v1") == "amazon"

    def test_identify_cohere(self):
        assert _identify_model_provider("cohere.command-r-plus-v1:0") == "cohere"

    def test_identify_mistral(self):
        assert _identify_model_provider("mistral.mistral-large-2402-v1:0") == "mistral"

    def test_identify_stability(self):
        assert _identify_model_provider("stability.stable-diffusion-xl-v1") == "stability"

    def test_identify_unknown(self):
        assert _identify_model_provider("some-unknown-model") == "unknown"

    def test_identify_arn(self):
        assert _identify_model_provider("arn:aws:bedrock:us-east-1::foundation-model/test") == "aws"

    def test_identify_dotted(self):
        assert _identify_model_provider("newprovider.somemodel-v1") == "newprovider"


@pytest.mark.unit
class TestModelClassification:
    def test_foundation_model(self):
        assert _classify_model_type("anthropic.claude-3-sonnet") == MODEL_TYPE_FOUNDATION

    def test_custom_model(self):
        assert _classify_model_type("arn:aws:bedrock:us-east-1:123:custom-model/my-model") == MODEL_TYPE_CUSTOM

    def test_fine_tuned_model(self):
        from ai_service_detector import MODEL_TYPE_FINE_TUNED
        assert _classify_model_type("arn:aws:bedrock:us-east-1:123:fine-tuning-job/my-job") == MODEL_TYPE_FINE_TUNED


@pytest.mark.unit
class TestInferModalities:
    def test_text_model(self):
        modalities = _infer_modalities("anthropic.claude-3-sonnet")
        assert 'text' in modalities

    def test_image_model(self):
        modalities = _infer_modalities("stability.stable-diffusion-xl")
        assert 'image' in modalities

    def test_embedding_model(self):
        modalities = _infer_modalities("cohere.embed-english-v3")
        assert 'embedding' in modalities

    def test_default_text(self):
        modalities = _infer_modalities("unknown-model-xyz")
        assert 'text' in modalities


@pytest.mark.unit
class TestDetectBedrockModels:
    def test_detect_from_model_id(self):
        details = {
            'model_id': 'anthropic.claude-3-sonnet-20240229-v1:0',
        }
        services = detect_bedrock_models(details)
        assert len(services) == 1
        assert services[0].service_type == AI_SERVICE_BEDROCK
        assert services[0].provider == 'anthropic'
        assert 'text' in services[0].modalities

    def test_detect_from_foundation_model(self):
        details = {
            'foundationModel': 'meta.llama3-70b-instruct-v1:0',
        }
        services = detect_bedrock_models(details)
        assert len(services) == 1
        assert services[0].provider == 'meta'

    def test_detect_from_agent_configuration(self):
        details = {
            'agentConfiguration': {
                'foundationModel': 'anthropic.claude-3-sonnet-20240229-v1:0',
            },
        }
        services = detect_bedrock_models(details)
        assert len(services) == 1

    def test_detect_no_model(self):
        details = {}
        services = detect_bedrock_models(details)
        assert len(services) == 0

    def test_detect_duplicate_model(self):
        """Same model in both top-level and agent config should not duplicate."""
        model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        details = {
            'model_id': model_id,
            'agentConfiguration': {
                'foundationModel': model_id,
            },
        }
        services = detect_bedrock_models(details)
        assert len(services) == 1  # Should deduplicate


@pytest.mark.unit
class TestDetectExternalAIServices:
    def test_detect_openai(self):
        targets = [{'uri': 'https://api.openai.com/v1/chat/completions'}]
        services = detect_external_ai_services(targets)
        assert len(services) == 1
        assert services[0].service_type == AI_SERVICE_EXTERNAL
        assert services[0].provider == 'openai'

    def test_detect_anthropic(self):
        targets = [{'uri': 'https://api.anthropic.com/v1/messages'}]
        services = detect_external_ai_services(targets)
        assert len(services) == 1
        assert services[0].provider == 'anthropic'

    def test_detect_google(self):
        targets = [{'uri': 'https://generativelanguage.googleapis.com/v1/models'}]
        services = detect_external_ai_services(targets)
        assert len(services) == 1
        assert services[0].provider == 'google'

    def test_detect_cohere(self):
        services = detect_external_ai_services_from_uri('https://api.cohere.ai/v1/generate')
        assert len(services) == 1
        assert services[0].provider == 'cohere'

    def test_detect_sagemaker(self):
        services = detect_external_ai_services_from_uri(
            'https://runtime.sagemaker.us-east-1.amazonaws.com/endpoints/my-endpoint/invocations'
        )
        assert len(services) == 1
        assert services[0].service_type == AI_SERVICE_SAGEMAKER

    def test_detect_bedrock_runtime(self):
        services = detect_external_ai_services_from_uri(
            'https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke'
        )
        assert len(services) == 1
        assert services[0].service_type == AI_SERVICE_BEDROCK

    def test_detect_unknown_uri(self):
        services = detect_external_ai_services_from_uri('https://my-custom-api.example.com/predict')
        assert len(services) == 0

    def test_detect_from_target_configuration(self):
        targets = [{
            'targetConfiguration': {
                'mcpServer': {
                    'uri': 'https://api.openai.com/v1/chat',
                }
            }
        }]
        services = detect_external_ai_services(targets)
        assert len(services) == 1
        assert services[0].provider == 'openai'

    def test_detect_empty_uri(self):
        services = detect_external_ai_services_from_uri('')
        assert len(services) == 0


@pytest.mark.unit
class TestActionMatches:
    def test_exact_match(self):
        assert _action_matches('bedrock:InvokeModel', 'bedrock:InvokeModel') is True

    def test_wildcard_all(self):
        assert _action_matches('*', 'bedrock:InvokeModel') is True

    def test_service_wildcard(self):
        assert _action_matches('bedrock:*', 'bedrock:InvokeModel') is True

    def test_no_match(self):
        assert _action_matches('s3:GetObject', 'bedrock:InvokeModel') is False

    def test_partial_wildcard(self):
        assert _action_matches('bedrock:Invoke*', 'bedrock:InvokeModel') is True


@pytest.mark.unit
class TestExtractAIActionsFromPolicy:
    def test_extract_bedrock_actions(self):
        policy = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': ['bedrock:InvokeModel', 'bedrock:Converse'],
                'Resource': '*',
            }]
        }
        services = _extract_ai_actions_from_policy(policy)
        assert len(services) >= 1
        assert any(s.service_type == AI_SERVICE_BEDROCK for s in services)

    def test_extract_sagemaker_actions(self):
        policy = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': 'sagemaker:InvokeEndpoint',
                'Resource': '*',
            }]
        }
        services = _extract_ai_actions_from_policy(policy)
        assert len(services) >= 1
        assert any(s.service_type == AI_SERVICE_SAGEMAKER for s in services)

    def test_ignore_deny_statements(self):
        policy = {
            'Statement': [{
                'Effect': 'Deny',
                'Action': 'bedrock:InvokeModel',
                'Resource': '*',
            }]
        }
        services = _extract_ai_actions_from_policy(policy)
        assert len(services) == 0

    def test_extract_wildcard_service(self):
        policy = {
            'Statement': [{
                'Effect': 'Allow',
                'Action': 'bedrock:*',
                'Resource': '*',
            }]
        }
        services = _extract_ai_actions_from_policy(policy)
        assert len(services) >= 1


@pytest.mark.unit
class TestRiskAssessment:
    def test_external_service_risk(self):
        info = AIServiceInfo(service_type=AI_SERVICE_EXTERNAL, provider='openai')
        score, factors = assess_ai_service_risk(info)
        assert score >= 30
        assert any('External' in f for f in factors)

    def test_custom_model_risk(self):
        info = AIServiceInfo(service_type=AI_SERVICE_BEDROCK, is_custom_model=True)
        score, factors = assess_ai_service_risk(info)
        assert score >= 25
        assert any('Custom' in f or 'proprietary' in f for f in factors)

    def test_unencrypted_endpoint_risk(self):
        info = AIServiceInfo(
            service_type=AI_SERVICE_EXTERNAL,
            endpoint_config={'uri': 'http://api.example.com/predict'}
        )
        score, factors = assess_ai_service_risk(info)
        assert score >= 50  # External (30) + unencrypted (20)

    def test_sagemaker_risk(self):
        info = AIServiceInfo(service_type=AI_SERVICE_SAGEMAKER)
        score, factors = assess_ai_service_risk(info)
        assert score >= 15

    def test_foundation_model_lower_risk(self):
        info = AIServiceInfo(
            service_type=AI_SERVICE_BEDROCK,
            is_custom_model=False,
        )
        score, factors = assess_ai_service_risk(info)
        assert score <= 10  # Foundation models have reduced risk

    def test_broad_permissions_risk(self):
        info = AIServiceInfo(
            service_type=AI_SERVICE_BEDROCK,
            risk_factors=['IAM permission: bedrock:*'],
        )
        score, factors = assess_ai_service_risk(info)
        assert score >= 10
        assert any('Broad' in f for f in factors)

    def test_risk_capped_at_100(self):
        info = AIServiceInfo(
            service_type=AI_SERVICE_EXTERNAL,
            is_custom_model=True,
            endpoint_config={'uri': 'http://insecure.example.com'},
            risk_factors=['IAM permission: bedrock:*', 'Managed policy: AmazonBedrockFullAccess'],
        )
        score, factors = assess_ai_service_risk(info)
        assert score <= 100
