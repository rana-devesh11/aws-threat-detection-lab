#!/usr/bin/env python3
"""
IAM Attack Simulations

Simulates various IAM-based attack scenarios to test detection rules.
These are intentionally malicious actions in a controlled lab environment.

WARNING: Only run in dedicated lab AWS account. Never in production.
"""

import boto3
import argparse
import time
from botocore.exceptions import ClientError

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

def scenario_privilege_escalation(target_user):
    """
    Simulate privilege escalation by attaching admin policy

    MITRE ATT&CK: T1078 (Valid Accounts)
    Tactic: Privilege Escalation
    """
    print_scenario(
        "IAM Privilege Escalation",
        "Attaching AdministratorAccess policy to compromised user",
        "T1078 - Valid Accounts"
    )

    try:
        # Create test user if doesn't exist
        try:
            iam_client.get_user(UserName=target_user)
            print(f"{Colors.GREEN}✓{Colors.END} User '{target_user}' already exists")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                iam_client.create_user(UserName=target_user)
                print(f"{Colors.GREEN}✓{Colors.END} Created user '{target_user}'")

        # Attach admin policy (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Attaching AdministratorAccess policy...")
        iam_client.attach_user_policy(
            UserName=target_user,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        print(f"{Colors.GREEN}✓{Colors.END} Policy attached successfully")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END}")
        print("  - EventBridge rule triggers")
        print("  - Lambda detector analyzes event")
        print("  - SNS alert sent (check email in 1-2 minutes)")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_inline_admin_policy(target_user):
    """
    Create inline policy with admin permissions

    MITRE ATT&CK: T1078 (Valid Accounts)
    Tactic: Privilege Escalation
    """
    print_scenario(
        "Inline Admin Policy Creation",
        "Creating inline policy with wildcard permissions",
        "T1078 - Valid Accounts"
    )

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    try:
        # Create test user if doesn't exist
        try:
            iam_client.get_user(UserName=target_user)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                iam_client.create_user(UserName=target_user)
                print(f"{Colors.GREEN}✓{Colors.END} Created user '{target_user}'")

        # Put inline policy (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Creating inline admin policy...")
        iam_client.put_user_policy(
            UserName=target_user,
            PolicyName='AdminPolicy',
            PolicyDocument=str(policy_document)
        )
        print(f"{Colors.GREEN}✓{Colors.END} Inline policy created")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END} SNS alert for inline admin policy")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_access_key_creation(target_user):
    """
    Create access key for persistence

    MITRE ATT&CK: T1078 (Valid Accounts)
    Tactic: Persistence
    """
    print_scenario(
        "Access Key Creation for Persistence",
        "Creating programmatic access credentials",
        "T1078 - Valid Accounts"
    )

    try:
        # Create test user if doesn't exist
        try:
            iam_client.get_user(UserName=target_user)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                iam_client.create_user(UserName=target_user)
                print(f"{Colors.GREEN}✓{Colors.END} Created user '{target_user}'")

        # Create access key (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Creating access key...")
        response = iam_client.create_access_key(UserName=target_user)
        access_key_id = response['AccessKey']['AccessKeyId']
        print(f"{Colors.GREEN}✓{Colors.END} Access key created: {access_key_id}")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END} SNS alert for key creation")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_add_to_admin_group(target_user):
    """
    Add user to admin group

    MITRE ATT&CK: T1078 (Valid Accounts)
    Tactic: Privilege Escalation
    """
    print_scenario(
        "Admin Group Addition",
        "Adding user to administrators group",
        "T1078 - Valid Accounts"
    )

    group_name = "test-admins"

    try:
        # Create test group
        try:
            iam_client.create_group(GroupName=group_name)
            print(f"{Colors.GREEN}✓{Colors.END} Created group '{group_name}'")
        except ClientError as e:
            if e.response['Error']['Code'] != 'EntityAlreadyExists':
                raise

        # Create test user if doesn't exist
        try:
            iam_client.get_user(UserName=target_user)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                iam_client.create_user(UserName=target_user)
                print(f"{Colors.GREEN}✓{Colors.END} Created user '{target_user}'")

        # Add to group (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Adding user to admin group...")
        iam_client.add_user_to_group(
            UserName=target_user,
            GroupName=group_name
        )
        print(f"{Colors.GREEN}✓{Colors.END} User added to group")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END} SNS alert for admin group addition")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def cleanup(target_user):
    """
    Clean up test resources
    """
    print(f"\n{Colors.BLUE}Cleaning up...{Colors.END}")

    try:
        # Detach policies
        try:
            iam_client.detach_user_policy(
                UserName=target_user,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            print(f"{Colors.GREEN}✓{Colors.END} Detached admin policy")
        except:
            pass

        # Delete inline policies
        try:
            iam_client.delete_user_policy(
                UserName=target_user,
                PolicyName='AdminPolicy'
            )
            print(f"{Colors.GREEN}✓{Colors.END} Deleted inline policy")
        except:
            pass

        # Remove from groups
        try:
            iam_client.remove_user_from_group(
                UserName=target_user,
                GroupName='test-admins'
            )
            print(f"{Colors.GREEN}✓{Colors.END} Removed from admin group")
        except:
            pass

        # Delete access keys
        try:
            keys = iam_client.list_access_keys(UserName=target_user)
            for key in keys['AccessKeyMetadata']:
                iam_client.delete_access_key(
                    UserName=target_user,
                    AccessKeyId=key['AccessKeyId']
                )
                print(f"{Colors.GREEN}✓{Colors.END} Deleted access key {key['AccessKeyId']}")
        except:
            pass

        # Delete user
        try:
            iam_client.delete_user(UserName=target_user)
            print(f"{Colors.GREEN}✓{Colors.END} Deleted user '{target_user}'")
        except:
            pass

        # Delete test group
        try:
            iam_client.delete_group(GroupName='test-admins')
            print(f"{Colors.GREEN}✓{Colors.END} Deleted test group")
        except:
            pass

    except Exception as e:
        print(f"{Colors.RED}✗{Colors.END} Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='IAM attack simulations for threat detection lab',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--scenario',
        choices=['privilege-escalation', 'inline-policy', 'access-key', 'admin-group', 'all'],
        required=True,
        help='Attack scenario to simulate'
    )
    parser.add_argument(
        '--target-user',
        default='test-victim-user',
        help='Target IAM user name (default: test-victim-user)'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up test resources after running'
    )

    args = parser.parse_args()

    print(f"\n{Colors.RED}{'='*70}")
    print("  AWS THREAT DETECTION LAB - IAM ATTACK SIMULATIONS")
    print("  WARNING: Only run in dedicated lab AWS account!")
    print(f"{'='*70}{Colors.END}\n")

    time.sleep(2)

    # Run scenarios
    if args.scenario == 'privilege-escalation' or args.scenario == 'all':
        scenario_privilege_escalation(args.target_user)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'inline-policy' or args.scenario == 'all':
        scenario_inline_admin_policy(args.target_user)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'access-key' or args.scenario == 'all':
        scenario_access_key_creation(args.target_user)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'admin-group' or args.scenario == 'all':
        scenario_add_to_admin_group(args.target_user)

    # Cleanup if requested
    if args.cleanup:
        time.sleep(2)
        cleanup(args.target_user)

    print(f"\n{Colors.GREEN}Simulation complete!{Colors.END}")
    print(f"Check your email for alerts in 1-2 minutes.\n")

if __name__ == '__main__':
    main()
