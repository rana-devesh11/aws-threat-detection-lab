#!/usr/bin/env python3
"""
Credential Attack Simulations

Simulates credential-based attack scenarios including root account usage
and suspicious console login patterns.

WARNING: Only run in dedicated lab AWS account. Never in production.
"""

import boto3
import argparse
import time
from botocore.exceptions import ClientError

sts_client = boto3.client('sts')
iam_client = boto3.client('iam')

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_scenario(name, description, mitre_technique):
    """Print scenario header"""
    print(f"\n{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.YELLOW}Scenario: {name}{Colors.END}")
    print(f"Description: {description}")
    print(f"MITRE ATT&CK: {mitre_technique}")
    print(f"{Colors.BLUE}{'='*70}{Colors.END}\n")

def scenario_root_api_usage():
    """
    Simulate root account API usage

    MITRE ATT&CK: T1078.004 (Cloud Accounts)
    Tactic: Privilege Escalation
    """
    print_scenario(
        "Root Account API Usage",
        "Making API calls with root account credentials",
        "T1078.004 - Cloud Accounts"
    )

    try:
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking caller identity...")
        identity = sts_client.get_caller_identity()

        if ':root' in identity.get('Arn', ''):
            print(f"{Colors.RED}[WARNING]{Colors.END} Running as root account!")

            # Make various API calls as root (THIS TRIGGERS ALERT)
            print(f"\n{Colors.RED}[ATTACK]{Colors.END} Making API calls as root account...")

            # List users
            iam_client.list_users(MaxItems=1)
            print(f"{Colors.GREEN}✓{Colors.END} ListUsers called")

            # Get account summary
            iam_client.get_account_summary()
            print(f"{Colors.GREEN}✓{Colors.END} GetAccountSummary called")

            print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END}")
            print("  - EventBridge detects root account API calls")
            print("  - Lambda detector flags root usage")
            print("  - SNS critical alert sent")
        else:
            print(f"{Colors.BLUE}[INFO]{Colors.END} Not running as root account")
            print(f"Current identity: {identity.get('Arn')}")
            print(f"\n{Colors.YELLOW}Note:{Colors.END} To test root detection:")
            print("  1. Create root access keys (not recommended)")
            print("  2. Configure AWS CLI with root credentials")
            print("  3. Run this script")
            print("  OR use AWS Console with root account instead")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_cross_account_assume_role():
    """
    Simulate cross-account role assumption attempt

    MITRE ATT&CK: T1550.001 (Use Alternate Authentication Material)
    Tactic: Lateral Movement
    """
    print_scenario(
        "Cross-Account Role Assumption",
        "Attempting to assume role in another account",
        "T1550.001 - Use Alternate Authentication Material"
    )

    try:
        # This will fail but generates suspicious CloudTrail activity
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Attempting cross-account role assumption...")

        fake_role_arn = "arn:aws:iam::123456789012:role/AdminRole"

        try:
            sts_client.assume_role(
                RoleArn=fake_role_arn,
                RoleSessionName="suspicious-session"
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print(f"{Colors.YELLOW}✓{Colors.END} AssumeRole denied (expected)")
                print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END}")
                print("  - CloudTrail logs failed AssumeRole attempt")
                print("  - GuardDuty may flag suspicious IAM activity")
            else:
                raise

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_credential_enumeration(test_user):
    """
    Simulate credential enumeration

    MITRE ATT&CK: T1087 (Account Discovery)
    Tactic: Discovery
    """
    print_scenario(
        "Credential Enumeration",
        "Enumerating IAM users and their access keys",
        "T1087 - Account Discovery"
    )

    try:
        # Create test user
        try:
            iam_client.get_user(UserName=test_user)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                iam_client.create_user(UserName=test_user)
                print(f"{Colors.GREEN}✓{Colors.END} Created test user '{test_user}'")

        # Enumerate credentials (THIS GENERATES SUSPICIOUS ACTIVITY)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Enumerating credentials...")

        # List all users
        response = iam_client.list_users()
        user_count = len(response.get('Users', []))
        print(f"{Colors.GREEN}✓{Colors.END} Enumerated {user_count} users")

        # List access keys for test user
        keys_response = iam_client.list_access_keys(UserName=test_user)
        key_count = len(keys_response.get('AccessKeyMetadata', []))
        print(f"{Colors.GREEN}✓{Colors.END} Enumerated {key_count} access keys for {test_user}")

        # Get user policies
        policies = iam_client.list_attached_user_policies(UserName=test_user)
        print(f"{Colors.GREEN}✓{Colors.END} Enumerated user policies")

        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END}")
        print("  - High volume IAM List* API calls")
        print("  - GuardDuty may detect reconnaissance behavior")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_password_policy_weakening():
    """
    Attempt to weaken account password policy

    MITRE ATT&CK: T1531 (Account Access Removal)
    Tactic: Impact
    """
    print_scenario(
        "Password Policy Weakening",
        "Attempting to weaken account password requirements",
        "T1531 - Account Access Removal"
    )

    try:
        # Get current policy
        try:
            current_policy = iam_client.get_account_password_policy()
            print(f"{Colors.BLUE}[INFO]{Colors.END} Current password policy retrieved")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print(f"{Colors.YELLOW}[INFO]{Colors.END} No password policy currently set")

        # Attempt to set weak policy (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Attempting to set weak password policy...")

        try:
            iam_client.update_account_password_policy(
                MinimumPasswordLength=6,
                RequireSymbols=False,
                RequireNumbers=False,
                RequireUppercaseCharacters=False,
                RequireLowercaseCharacters=False,
                AllowUsersToChangePassword=True,
                MaxPasswordAge=180,
                PasswordReusePrevention=1
            )
            print(f"{Colors.GREEN}✓{Colors.END} Weak password policy set")
            print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END}")
            print("  - EventBridge detects UpdateAccountPasswordPolicy")
            print("  - Alert for security policy weakening")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print(f"{Colors.YELLOW}✓{Colors.END} Access denied (insufficient permissions)")
            else:
                raise

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def cleanup(test_user):
    """
    Clean up test resources
    """
    print(f"\n{Colors.BLUE}Cleaning up...{Colors.END}")

    try:
        # Delete test user
        try:
            # Delete access keys first
            keys = iam_client.list_access_keys(UserName=test_user)
            for key in keys['AccessKeyMetadata']:
                iam_client.delete_access_key(
                    UserName=test_user,
                    AccessKeyId=key['AccessKeyId']
                )

            # Delete user
            iam_client.delete_user(UserName=test_user)
            print(f"{Colors.GREEN}✓{Colors.END} Deleted test user '{test_user}'")
        except:
            pass

    except Exception as e:
        print(f"{Colors.RED}✗{Colors.END} Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Credential attack simulations for threat detection lab',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--scenario',
        choices=['root-usage', 'cross-account', 'enumeration', 'password-policy', 'all'],
        required=True,
        help='Attack scenario to simulate'
    )
    parser.add_argument(
        '--test-user',
        default='test-recon-user',
        help='Test user name for enumeration scenario'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up test resources after running'
    )

    args = parser.parse_args()

    print(f"\n{Colors.RED}{'='*70}")
    print("  AWS THREAT DETECTION LAB - CREDENTIAL ATTACK SIMULATIONS")
    print("  WARNING: Only run in dedicated lab AWS account!")
    print(f"{'='*70}{Colors.END}\n")

    time.sleep(2)

    # Run scenarios
    if args.scenario == 'root-usage' or args.scenario == 'all':
        scenario_root_api_usage()
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'cross-account' or args.scenario == 'all':
        scenario_cross_account_assume_role()
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'enumeration' or args.scenario == 'all':
        scenario_credential_enumeration(args.test_user)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'password-policy' or args.scenario == 'all':
        scenario_password_policy_weakening()

    # Cleanup if requested
    if args.cleanup:
        time.sleep(2)
        cleanup(args.test_user)

    print(f"\n{Colors.GREEN}Simulation complete!{Colors.END}")
    print(f"Check your email for alerts in 1-2 minutes.\n")

if __name__ == '__main__':
    main()
