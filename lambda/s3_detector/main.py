import json
import boto3
import os
from datetime import datetime

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def lambda_handler(event, context):
    """
    Detects S3 buckets made public
    """
    try:
        detail = event['detail']
        event_name = detail['eventName']
        request_params = detail.get('requestParameters', {})
        bucket_name = request_params.get('bucketName')

        if not bucket_name:
            return {
                'statusCode': 200,
                'body': json.dumps({'alert_sent': False, 'reason': 'No bucket name'})
            }

        # Detect public access changes
        detection = detect_public_access(detail, bucket_name)

        if detection:
            alert = create_alert(detection, detail)
            send_alert(alert)

            return {
                'statusCode': 200,
                'body': json.dumps({'alert_sent': True, 'detection': detection['type']})
            }

        return {
            'statusCode': 200,
            'body': json.dumps({'alert_sent': False})
        }

    except Exception as e:
        print(f"Error processing event: {str(e)}")
        raise

def detect_public_access(detail, bucket_name):
    """
    Detect S3 bucket made public
    """
    event_name = detail['eventName']
    request_params = detail.get('requestParameters', {})

    # Check for dangerous public access changes
    if event_name == 'PutBucketAcl':
        acl = request_params.get('AccessControlPolicy', {})
        if is_public_acl(acl):
            return {
                'type': 'S3 Bucket Made Public - ACL',
                'severity': 'CRITICAL',
                'technique': 'T1530',
                'tactic': 'Collection',
                'bucket': bucket_name,
                'method': 'ACL'
            }

    elif event_name == 'PutBucketPolicy':
        policy = request_params.get('bucketPolicy')
        if policy and is_public_policy(policy):
            return {
                'type': 'S3 Bucket Made Public - Policy',
                'severity': 'CRITICAL',
                'technique': 'T1530',
                'tactic': 'Collection',
                'bucket': bucket_name,
                'method': 'Bucket Policy'
            }

    elif event_name == 'DeleteBucketPublicAccessBlock':
        return {
            'type': 'S3 Public Access Block Disabled',
            'severity': 'HIGH',
            'technique': 'T1530',
            'tactic': 'Collection',
            'bucket': bucket_name,
            'method': 'Public Access Block Removal'
        }

    elif event_name == 'PutBucketPublicAccessBlock':
        # Check if settings actually make bucket more public
        block_config = request_params.get('PublicAccessBlockConfiguration', {})
        if not all([
            block_config.get('BlockPublicAcls', False),
            block_config.get('BlockPublicPolicy', False),
            block_config.get('IgnorePublicAcls', False),
            block_config.get('RestrictPublicBuckets', False)
        ]):
            return {
                'type': 'S3 Public Access Block Weakened',
                'severity': 'HIGH',
                'technique': 'T1530',
                'tactic': 'Collection',
                'bucket': bucket_name,
                'method': 'Public Access Block Configuration'
            }

    return None

def is_public_acl(acl):
    """
    Check if ACL grants public access
    """
    grants = acl.get('AccessControlList', {}).get('Grant', [])
    for grant in grants:
        grantee = grant.get('Grantee', {})
        uri = grantee.get('URI', '')
        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
            return True
    return False

def is_public_policy(policy_str):
    """
    Check if bucket policy allows public access
    """
    try:
        policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
        statements = policy.get('Statement', [])

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or principal.get('AWS') == '*':
                    return True
    except:
        pass
    return False

def create_alert(detection, detail):
    """
    Format alert message
    """
    user_identity = detail['userIdentity']
    source_ip = detail.get('sourceIPAddress', 'Unknown')

    alert = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'detection_type': detection['type'],
        'severity': detection['severity'],
        'mitre_attack': {
            'technique': detection['technique'],
            'tactic': detection['tactic']
        },
        'event_details': {
            'event_name': detail['eventName'],
            'event_time': detail['eventTime'],
            'source_ip': source_ip,
            'user_agent': detail.get('userAgent', 'Unknown')
        },
        'actor': {
            'type': user_identity.get('type'),
            'name': user_identity.get('userName', user_identity.get('principalId')),
            'arn': user_identity.get('arn')
        },
        'target': {
            'bucket': detection['bucket'],
            'method': detection['method']
        },
        'recommendation': 'Review S3 bucket permissions. Enable Public Access Block unless public access is explicitly required.'
    }

    return alert

def send_alert(alert):
    """
    Send alert to SNS
    """
    subject = f"[{alert['severity']}] {alert['detection_type']}"

    message = f"""
AWS Threat Detection Alert

Detection: {alert['detection_type']}
Severity: {alert['severity']}
Timestamp: {alert['timestamp']}

MITRE ATT&CK:
  Technique: {alert['mitre_attack']['technique']}
  Tactic: {alert['mitre_attack']['tactic']}

Event Details:
  Event: {alert['event_details']['event_name']}
  Time: {alert['event_details']['event_time']}
  Source IP: {alert['event_details']['source_ip']}

Actor:
  Type: {alert['actor']['type']}
  Name: {alert['actor']['name']}
  ARN: {alert['actor']['arn']}

Target:
  Bucket: {alert['target']['bucket']}
  Method: {alert['target']['method']}

Recommendation:
{alert['recommendation']}

---
This alert was generated by AWS Threat Detection Lab
"""

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message
    )

    print(f"Alert sent: {subject}")
