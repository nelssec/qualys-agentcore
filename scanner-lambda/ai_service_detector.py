"""AI service detection from agent runtime configurations.

Identifies AI/ML services used by agent runtimes. Adapts risk scoring
patterns from qualys-dspm aitracking module.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# AI service type constants
AI_SERVICE_BEDROCK = "BEDROCK"
AI_SERVICE_SAGEMAKER = "SAGEMAKER"
AI_SERVICE_EXTERNAL = "EXTERNAL"

# Model type constants
MODEL_TYPE_FOUNDATION = "FOUNDATION"
MODEL_TYPE_CUSTOM = "CUSTOM"
MODEL_TYPE_FINE_TUNED = "FINE_TUNED"

# Known AI service endpoint patterns
AI_ENDPOINT_PATTERNS = {
    r'api\.openai\.com': ('EXTERNAL', 'openai'),
    r'api\.anthropic\.com': ('EXTERNAL', 'anthropic'),
    r'generativelanguage\.googleapis\.com': ('EXTERNAL', 'google'),
    r'api\.cohere\.(ai|com)': ('EXTERNAL', 'cohere'),
    r'api\.mistral\.ai': ('EXTERNAL', 'mistral'),
    r'api\.replicate\.com': ('EXTERNAL', 'replicate'),
    r'api\.together\.xyz': ('EXTERNAL', 'together'),
    r'api\.groq\.com': ('EXTERNAL', 'groq'),
    r'api\.perplexity\.ai': ('EXTERNAL', 'perplexity'),
    r'.*\.sagemaker\..*\.amazonaws\.com': ('SAGEMAKER', 'aws'),
    r'bedrock-runtime\..*\.amazonaws\.com': ('BEDROCK', 'aws'),
    r'bedrock-agentcore\..*\.amazonaws\.com': ('BEDROCK', 'aws'),
    r'bedrock\..*\.amazonaws\.com': ('BEDROCK', 'aws'),
}

# Known Bedrock model ID patterns
BEDROCK_MODEL_PROVIDERS = {
    'anthropic': ['claude'],
    'amazon': ['titan'],
    'meta': ['llama'],
    'mistral': ['mistral', 'mixtral'],
    'cohere': ['command', 'embed'],
    'stability': ['stable-diffusion'],
    'ai21': ['jamba', 'jurassic'],
}

# AWS AI service actions for IAM policy analysis
AWS_AI_SERVICE_ACTIONS = {
    'bedrock:InvokeModel': (AI_SERVICE_BEDROCK, 'Invoke Bedrock model'),
    'bedrock:InvokeModelWithResponseStream': (AI_SERVICE_BEDROCK, 'Invoke Bedrock model (streaming)'),
    'bedrock:Converse': (AI_SERVICE_BEDROCK, 'Bedrock Converse API'),
    'sagemaker:InvokeEndpoint': (AI_SERVICE_SAGEMAKER, 'Invoke SageMaker endpoint'),
    'sagemaker:InvokeEndpointAsync': (AI_SERVICE_SAGEMAKER, 'Invoke SageMaker endpoint (async)'),
    'comprehend:DetectSentiment': (AI_SERVICE_BEDROCK, 'Amazon Comprehend'),
    'comprehend:DetectEntities': (AI_SERVICE_BEDROCK, 'Amazon Comprehend'),
    'rekognition:DetectLabels': (AI_SERVICE_BEDROCK, 'Amazon Rekognition'),
    'rekognition:DetectFaces': (AI_SERVICE_BEDROCK, 'Amazon Rekognition'),
    'textract:AnalyzeDocument': (AI_SERVICE_BEDROCK, 'Amazon Textract'),
    'textract:DetectDocumentText': (AI_SERVICE_BEDROCK, 'Amazon Textract'),
    'transcribe:StartTranscriptionJob': (AI_SERVICE_BEDROCK, 'Amazon Transcribe'),
    'polly:SynthesizeSpeech': (AI_SERVICE_BEDROCK, 'Amazon Polly'),
}


@dataclass
class AIServiceInfo:
    """Detected AI service metadata."""
    service_type: str = ''              # BEDROCK, SAGEMAKER, EXTERNAL
    service_arn: str = ''               # ARN if AWS service
    model_id: str = ''                  # Model identifier
    provider: str = ''                  # anthropic, openai, aws, etc.
    modalities: List[str] = field(default_factory=list)   # text, image, video, embedding
    is_custom_model: bool = False       # Custom/fine-tuned vs foundation
    endpoint_config: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0                 # 0-100
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'service_type': self.service_type,
            'service_arn': self.service_arn,
            'model_id': self.model_id,
            'provider': self.provider,
            'modalities': self.modalities,
            'is_custom_model': self.is_custom_model,
            'endpoint_config': self.endpoint_config,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
        }


def detect_ai_services_from_runtime(agent_runtime_arn: str,
                                     runtime_details: Dict[str, Any],
                                     agentcore_client=None) -> List[AIServiceInfo]:
    """Detect AI services connected to an agent runtime.

    1. Check runtime config for Bedrock model associations
    2. Check gateway targets for AI service endpoints
    3. Check IAM role policies for Bedrock/SageMaker permissions
    """
    services = []

    # 1. Detect Bedrock models from runtime config
    bedrock_services = detect_bedrock_models(runtime_details)
    services.extend(bedrock_services)

    # 2. Detect external AI services from gateway targets
    if agentcore_client:
        try:
            from mcp_detector import detect_mcp_from_runtime
            mcp_servers = detect_mcp_from_runtime(runtime_details, agentcore_client)
            for mcp in mcp_servers:
                endpoint = mcp.uri if hasattr(mcp, 'uri') else mcp.get('uri', '')
                external_services = detect_external_ai_services_from_uri(endpoint)
                services.extend(external_services)
        except Exception as e:
            logger.warning(f"Could not check gateway targets for AI services: {e}")

    # 3. Detect from IAM role policies
    role_arn = runtime_details.get('role_arn')
    if role_arn:
        try:
            iam_services = detect_ai_from_iam_policy(role_arn)
            # Deduplicate: only add services not already detected
            existing_types = {(s.service_type, s.provider) for s in services}
            for svc in iam_services:
                if (svc.service_type, svc.provider) not in existing_types:
                    services.append(svc)
        except Exception as e:
            logger.warning(f"Could not analyze IAM policies for AI services: {e}")

    # Assess risk for each service
    for svc in services:
        svc.risk_score, svc.risk_factors = assess_ai_service_risk(svc)

    return services


def detect_bedrock_models(runtime_details: Dict[str, Any]) -> List[AIServiceInfo]:
    """Identify Bedrock models used by the runtime from config."""
    services = []

    # Check for model references in runtime configuration
    model_id = runtime_details.get('model_id') or runtime_details.get('foundationModel')
    if model_id:
        provider = _identify_model_provider(model_id)
        model_type = _classify_model_type(model_id)

        service = AIServiceInfo(
            service_type=AI_SERVICE_BEDROCK,
            model_id=model_id,
            provider=provider,
            modalities=_infer_modalities(model_id),
            is_custom_model=(model_type != MODEL_TYPE_FOUNDATION),
        )
        services.append(service)

    # Check for agent runtime artifact configs that reference models
    agent_config = runtime_details.get('agentConfiguration', {})
    if isinstance(agent_config, dict):
        agent_model = agent_config.get('foundationModel') or agent_config.get('modelId')
        if agent_model and agent_model != model_id:
            provider = _identify_model_provider(agent_model)
            service = AIServiceInfo(
                service_type=AI_SERVICE_BEDROCK,
                model_id=agent_model,
                provider=provider,
                modalities=_infer_modalities(agent_model),
                is_custom_model=False,
            )
            services.append(service)

    return services


def detect_external_ai_services(gateway_targets: List[Dict[str, Any]]) -> List[AIServiceInfo]:
    """Identify non-AWS AI services from gateway target endpoints."""
    services = []
    for target in gateway_targets:
        uri = target.get('uri', '')
        if not uri:
            target_config = target.get('targetConfiguration', {})
            mcp_config = target_config.get('mcpServer', {})
            uri = mcp_config.get('uri', '')

        if uri:
            found = detect_external_ai_services_from_uri(uri)
            services.extend(found)

    return services


def detect_external_ai_services_from_uri(uri: str) -> List[AIServiceInfo]:
    """Identify AI services from a single URI."""
    services = []
    if not uri:
        return services

    for pattern, (service_type, provider) in AI_ENDPOINT_PATTERNS.items():
        if re.search(pattern, uri):
            service = AIServiceInfo(
                service_type=service_type,
                provider=provider,
                endpoint_config={'uri': uri},
            )
            services.append(service)
            break

    return services


def detect_ai_from_iam_policy(role_arn: str, iam_client=None) -> List[AIServiceInfo]:
    """Analyze runtime IAM role for AI service permissions."""
    services = []

    if not role_arn:
        return services

    try:
        import boto3
        client = iam_client or boto3.client('iam')

        # Extract role name from ARN
        role_name = role_arn.split('/')[-1]

        # List inline policies
        try:
            policy_response = client.list_role_policies(RoleName=role_name)
            policy_names = policy_response.get('PolicyNames', [])

            for policy_name in policy_names:
                policy_doc = client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                document = policy_doc.get('PolicyDocument', {})
                found = _extract_ai_actions_from_policy(document)
                services.extend(found)
        except Exception as e:
            logger.warning(f"Could not list inline policies for {role_name}: {e}")

        # List attached managed policies
        try:
            attached = client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                # Check for known AI-related managed policies
                if any(svc in policy_arn for svc in ['Bedrock', 'SageMaker', 'Comprehend', 'Rekognition', 'Textract']):
                    service_type = AI_SERVICE_BEDROCK
                    if 'SageMaker' in policy_arn:
                        service_type = AI_SERVICE_SAGEMAKER
                    services.append(AIServiceInfo(
                        service_type=service_type,
                        provider='aws',
                        risk_factors=[f'Managed policy: {policy_arn}'],
                    ))
        except Exception as e:
            logger.warning(f"Could not list attached policies for {role_name}: {e}")

    except Exception as e:
        logger.error(f"IAM policy analysis error for {role_arn}: {e}")

    return services


def _extract_ai_actions_from_policy(document: Dict[str, Any]) -> List[AIServiceInfo]:
    """Extract AI service usage from an IAM policy document."""
    services = []
    seen = set()

    statements = document.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue

        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            for known_action, (service_type, description) in AWS_AI_SERVICE_ACTIONS.items():
                # Handle wildcards like bedrock:*
                if _action_matches(action, known_action):
                    key = (service_type, description)
                    if key not in seen:
                        seen.add(key)
                        services.append(AIServiceInfo(
                            service_type=service_type,
                            provider='aws',
                            risk_factors=[f'IAM permission: {action}'],
                        ))

    return services


def _action_matches(policy_action: str, target_action: str) -> bool:
    """Check if a policy action (possibly with wildcards) matches a target action."""
    if policy_action == '*':
        return True
    if policy_action == target_action:
        return True

    # Handle service:* patterns
    if ':*' in policy_action:
        service_prefix = policy_action.split(':')[0]
        target_prefix = target_action.split(':')[0]
        return service_prefix == target_prefix

    # Handle wildcards in action name
    pattern = policy_action.replace('*', '.*')
    try:
        return bool(re.match(f'^{pattern}$', target_action))
    except re.error:
        return False


def assess_ai_service_risk(ai_info: AIServiceInfo) -> Tuple[int, List[str]]:
    """Risk scoring adapted from qualys-dspm aitracking.go.

    Weights:
    - Sensitive data access potential: 30%
    - Custom/fine-tuned model (may contain proprietary data): 25%
    - Unencrypted endpoints: 20%
    - Cross-account access: 15%
    - Broad permissions: 10%
    """
    score = 0
    factors = list(ai_info.risk_factors)  # Preserve existing factors

    # External AI services have higher baseline risk (data leaves AWS)
    if ai_info.service_type == AI_SERVICE_EXTERNAL:
        score += 30
        factors.append('External AI service - data leaves AWS boundary')

    # Custom/fine-tuned models may contain proprietary training data
    if ai_info.is_custom_model:
        score += 25
        factors.append('Custom/fine-tuned model may contain proprietary data')

    # Check endpoint encryption
    endpoint_uri = ai_info.endpoint_config.get('uri', '')
    if endpoint_uri and endpoint_uri.startswith('http://'):
        score += 20
        factors.append('Unencrypted endpoint connection')

    # SageMaker endpoints may expose custom models
    if ai_info.service_type == AI_SERVICE_SAGEMAKER:
        score += 15
        factors.append('SageMaker endpoint - custom model deployment')

    # Broad IAM permissions
    for factor in ai_info.risk_factors:
        if ':*' in factor or 'Managed policy' in factor:
            score += 10
            if 'Broad IAM permissions' not in factors:
                factors.append('Broad IAM permissions for AI services')
            break

    # Foundation models have lower risk than custom (only reduce if no other risk factors added)
    has_other_risk = (ai_info.service_type == AI_SERVICE_EXTERNAL
                      or ai_info.is_custom_model
                      or (endpoint_uri and endpoint_uri.startswith('http://'))
                      or any(':*' in f or 'Managed policy' in f for f in ai_info.risk_factors))
    if ai_info.service_type == AI_SERVICE_BEDROCK and not ai_info.is_custom_model and not has_other_risk:
        score = max(score - 10, 0)

    return min(score, 100), factors


def _identify_model_provider(model_id: str) -> str:
    """Identify the provider from a Bedrock model ID."""
    model_lower = model_id.lower()
    for provider, keywords in BEDROCK_MODEL_PROVIDERS.items():
        for keyword in keywords:
            if keyword in model_lower:
                return provider
    # Check for ARN-style model IDs
    if model_id.startswith('arn:'):
        return 'aws'
    # Try prefix-based detection (e.g., "anthropic.claude-3")
    if '.' in model_id:
        return model_id.split('.')[0]
    return 'unknown'


def _classify_model_type(model_id: str) -> str:
    """Classify model as foundation, custom, or fine-tuned."""
    if model_id.startswith('arn:'):
        if ':custom-model/' in model_id or ':provisioned-model/' in model_id:
            return MODEL_TYPE_CUSTOM
        if ':fine-tuning-job/' in model_id:
            return MODEL_TYPE_FINE_TUNED
    return MODEL_TYPE_FOUNDATION


def _infer_modalities(model_id: str) -> List[str]:
    """Infer model modalities from model ID."""
    model_lower = model_id.lower()
    modalities = []

    if any(kw in model_lower for kw in ['claude', 'llama', 'mistral', 'command', 'jamba', 'jurassic', 'titan-text', 'gpt']):
        modalities.append('text')
    if any(kw in model_lower for kw in ['stable-diffusion', 'titan-image', 'dall-e', 'imagen']):
        modalities.append('image')
    if any(kw in model_lower for kw in ['embed', 'titan-embed']):
        modalities.append('embedding')
    if any(kw in model_lower for kw in ['whisper', 'transcribe']):
        modalities.append('audio')

    if not modalities:
        modalities.append('text')  # Default assumption

    return modalities
