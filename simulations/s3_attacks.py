#!/usr/bin/env python3
"""
S3 Attack Simulations

Simulates S3 data exfiltration and public exposure scenarios.

WARNING: Only run in dedicated lab AWS account. Never in production.
"""

import boto3
import argparse
import time
import json
from botocore.exceptions import ClientError

s3_client = boto3.client('s3')

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

def scenario_public_acl(bucket_name):
    """
    Make bucket public via ACL

    MITRE ATT&CK: T1530 (Data from Cloud Storage Object)
    Tactic: Collection
    """
    print_scenario(
        "S3 Bucket Public via ACL",
        "Making S3 bucket public by modifying ACL to allow AllUsers",
        "T1530 - Data from Cloud Storage Object"
    )

    try:
        # Create test bucket
        try:
            s3_client.create_bucket(Bucket=bucket_name)
            print(f"{Colors.GREEN}✓{Colors.END} Created bucket '{bucket_name}'")
            time.sleep(2)  # Wait for bucket creation
        except ClientError as e:
            if e.response['Error']['Code'] != 'BucketAlreadyOwnedByYou':
                raise

        # Make bucket public via ACL (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Making bucket public via ACL...")
        s3_client.put_bucket_acl(
            Bucket=bucket_name,
            ACL='public-read'
        )
        print(f"{Colors.GREEN}✓{Colors.END} Bucket ACL set to public-read")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END}")
        print("  - EventBridge rule triggers")
        print("  - Lambda detector analyzes ACL change")
        print("  - SNS alert sent for public bucket exposure")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_public_policy(bucket_name):
    """
    Make bucket public via bucket policy

    MITRE ATT&CK: T1530 (Data from Cloud Storage Object)
    Tactic: Collection
    """
    print_scenario(
        "S3 Bucket Public via Policy",
        "Making S3 bucket public using bucket policy with wildcard principal",
        "T1530 - Data from Cloud Storage Object"
    )

    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

    try:
        # Ensure bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
        except ClientError:
            s3_client.create_bucket(Bucket=bucket_name)
            print(f"{Colors.GREEN}✓{Colors.END} Created bucket '{bucket_name}'")
            time.sleep(2)

        # Apply public policy (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Applying public bucket policy...")
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(public_policy)
        )
        print(f"{Colors.GREEN}✓{Colors.END} Public policy applied")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END} SNS alert for public bucket policy")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_disable_block_public_access(bucket_name):
    """
    Disable S3 Block Public Access

    MITRE ATT&CK: T1530 (Data from Cloud Storage Object)
    Tactic: Defense Evasion
    """
    print_scenario(
        "Disable S3 Block Public Access",
        "Removing S3 Block Public Access protection",
        "T1530 - Data from Cloud Storage Object"
    )

    try:
        # Ensure bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
        except ClientError:
            s3_client.create_bucket(Bucket=bucket_name)
            print(f"{Colors.GREEN}✓{Colors.END} Created bucket '{bucket_name}'")
            time.sleep(2)

        # Disable block public access (THIS TRIGGERS ALERT)
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Disabling Block Public Access...")
        s3_client.delete_public_access_block(Bucket=bucket_name)
        print(f"{Colors.GREEN}✓{Colors.END} Block Public Access disabled")
        print(f"\n{Colors.YELLOW}Expected Detection:{Colors.END} SNS alert for public access protection removal")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def scenario_exfiltration_simulation(bucket_name):
    """
    Simulate data exfiltration by copying data

    MITRE ATT&CK: T1537 (Transfer Data to Cloud Account)
    Tactic: Exfiltration
    """
    print_scenario(
        "Data Exfiltration Simulation",
        "Simulating bulk data download (exfiltration pattern)",
        "T1537 - Transfer Data to Cloud Account"
    )

    try:
        # Ensure bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
        except ClientError:
            s3_client.create_bucket(Bucket=bucket_name)
            print(f"{Colors.GREEN}✓{Colors.END} Created bucket '{bucket_name}'")
            time.sleep(2)

        # Upload test files
        print(f"{Colors.BLUE}[INFO]{Colors.END} Uploading test data files...")
        for i in range(5):
            key = f"sensitive-data-{i}.txt"
            s3_client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=f"FAKE TEST DATA {i}"
            )
        print(f"{Colors.GREEN}✓{Colors.END} Test files uploaded")

        # Simulate bulk download
        print(f"\n{Colors.RED}[ATTACK]{Colors.END} Simulating bulk data download...")
        for i in range(5):
            key = f"sensitive-data-{i}.txt"
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            response['Body'].read()
        print(f"{Colors.GREEN}✓{Colors.END} Bulk download completed")
        print(f"\n{Colors.YELLOW}Note:{Colors.END} High volume S3 GetObject calls may trigger GuardDuty alerts")

    except ClientError as e:
        print(f"{Colors.RED}✗{Colors.END} Error: {e}")

def cleanup(bucket_name):
    """
    Clean up test resources
    """
    print(f"\n{Colors.BLUE}Cleaning up...{Colors.END}")

    try:
        # Delete objects
        try:
            response = s3_client.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                for obj in response['Contents']:
                    s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
                    print(f"{Colors.GREEN}✓{Colors.END} Deleted object {obj['Key']}")
        except:
            pass

        # Delete bucket policy
        try:
            s3_client.delete_bucket_policy(Bucket=bucket_name)
            print(f"{Colors.GREEN}✓{Colors.END} Deleted bucket policy")
        except:
            pass

        # Delete bucket
        try:
            s3_client.delete_bucket(Bucket=bucket_name)
            print(f"{Colors.GREEN}✓{Colors.END} Deleted bucket '{bucket_name}'")
        except:
            pass

    except Exception as e:
        print(f"{Colors.RED}✗{Colors.END} Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='S3 attack simulations for threat detection lab',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--scenario',
        choices=['public-acl', 'public-policy', 'disable-block', 'exfiltration', 'all'],
        required=True,
        help='Attack scenario to simulate'
    )
    parser.add_argument(
        '--bucket',
        default='threat-lab-test-bucket-12345',
        help='Test bucket name (must be globally unique)'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up test resources after running'
    )

    args = parser.parse_args()

    print(f"\n{Colors.RED}{'='*70}")
    print("  AWS THREAT DETECTION LAB - S3 ATTACK SIMULATIONS")
    print("  WARNING: Only run in dedicated lab AWS account!")
    print(f"{'='*70}{Colors.END}\n")

    time.sleep(2)

    # Run scenarios
    if args.scenario == 'public-acl' or args.scenario == 'all':
        scenario_public_acl(args.bucket)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'public-policy' or args.scenario == 'all':
        scenario_public_policy(args.bucket)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'disable-block' or args.scenario == 'all':
        scenario_disable_block_public_access(args.bucket)
        if args.scenario == 'all':
            time.sleep(5)

    if args.scenario == 'exfiltration' or args.scenario == 'all':
        scenario_exfiltration_simulation(args.bucket)

    # Cleanup if requested
    if args.cleanup:
        time.sleep(2)
        cleanup(args.bucket)

    print(f"\n{Colors.GREEN}Simulation complete!{Colors.END}")
    print(f"Check your email for alerts in 1-2 minutes.\n")

if __name__ == '__main__':
    main()
