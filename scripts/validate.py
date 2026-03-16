"""Pre-flight validation for AgentCore Scanner deployment."""

import os
import sys
import json
import subprocess


def check_aws_credentials():
    """Verify AWS credentials are configured."""
    try:
        result = subprocess.run(
            ['aws', 'sts', 'get-caller-identity'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            print("FAIL: AWS credentials not configured")
            return False
        identity = json.loads(result.stdout)
        print(f"  OK: AWS Account: {identity['Account']}")
        print(f"      ARN: {identity['Arn']}")
        return True
    except FileNotFoundError:
        print("FAIL: AWS CLI not installed")
        return False
    except Exception as e:
        print(f"FAIL: Could not verify AWS credentials: {e}")
        return False


def check_cfn_lint():
    """Check if cfn-lint is available."""
    try:
        result = subprocess.run(
            ['cfn-lint', '--version'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"  OK: cfn-lint {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    print("WARN: cfn-lint not installed (pip install cfn-lint)")
    return False


def check_templates():
    """Validate CloudFormation templates exist."""
    templates = [
        'cloudformation/centralized-hub.yaml',
        'cloudformation/centralized-spoke.yaml',
        'cloudformation/centralized-spoke-minimal.yaml',
        'cloudformation/org-cloudtrail-forwarder.yaml',
    ]
    all_ok = True
    for template in templates:
        if os.path.exists(template):
            print(f"  OK: {template}")
        else:
            print(f"FAIL: {template} not found")
            all_ok = False
    return all_ok


def check_lambda_code():
    """Verify Lambda function code exists."""
    files = [
        'scanner-lambda/handlers.py',
        'scanner-lambda/bulk_scan.py',
        'scanner-lambda/mcp_detector.py',
        'scanner-lambda/ai_service_detector.py',
        'scanner-lambda/qualys_api.py',
    ]
    all_ok = True
    for f in files:
        if os.path.exists(f):
            print(f"  OK: {f}")
        else:
            print(f"FAIL: {f} not found")
            all_ok = False
    return all_ok


def main():
    print("AgentCore Scanner - Pre-flight Validation")
    print("=" * 50)
    print()

    checks = [
        ("AWS Credentials", check_aws_credentials),
        ("CloudFormation Templates", check_templates),
        ("Lambda Function Code", check_lambda_code),
        ("cfn-lint", check_cfn_lint),
    ]

    results = {}
    for name, check_fn in checks:
        print(f"\n{name}:")
        results[name] = check_fn()

    print("\n" + "=" * 50)
    failures = [name for name, ok in results.items() if not ok]
    if not failures:
        print("All checks passed!")
        return 0
    else:
        print(f"Failed checks: {', '.join(failures)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
