"""Configuration loader for AgentCore Scanner."""

import os
import sys
import json
from typing import Dict, Any


DEFAULT_CONFIG = {
    'qualys_pod': 'US2',
    'aws_region': 'us-east-1',
    'stack_name': 'agentcore-scanner',
    'scanner_memory_size': 2048,
    'scanner_timeout': 900,
    'cache_ttl_days': 30,
    'enable_s3_results': True,
    'enable_sns_notifications': True,
    'enable_scan_cache': True,
    'enable_inventory_table': True,
    'enable_bulk_scan': True,
    'enable_mcp_detection': True,
    'enable_ai_service_detection': True,
    'enable_qualys_cs_api': False,
    'enable_security_hub': False,
    'sync_interval_hours': 8,
    'exclude_patterns': ['agentcore-scanner', 'bulk-scan'],
}


def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from YAML file or use defaults."""
    config = dict(DEFAULT_CONFIG)

    if config_path and os.path.exists(config_path):
        try:
            import yaml
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
                if file_config and isinstance(file_config, dict):
                    config.update(file_config)
        except ImportError:
            print("WARNING: PyYAML not installed, using defaults")
        except Exception as e:
            print(f"WARNING: Could not load config: {e}")

    # Override from environment variables
    env_mappings = {
        'QUALYS_POD': 'qualys_pod',
        'AWS_REGION': 'aws_region',
        'STACK_NAME': 'stack_name',
    }
    for env_var, config_key in env_mappings.items():
        value = os.environ.get(env_var)
        if value:
            config[config_key] = value

    return config


def show_config(config: Dict[str, Any]) -> None:
    """Display configuration."""
    print("AgentCore Scanner Configuration")
    print("=" * 40)
    for key, value in sorted(config.items()):
        print(f"  {key}: {value}")
    print()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='AgentCore Scanner Configuration')
    parser.add_argument('--config', default='.agentcore-scanner.yml',
                        help='Path to config file')
    args = parser.parse_args()

    config = load_config(args.config)
    show_config(config)
