import json
import boto3
import os
from datetime import datetime

sns_client = boto3.client('sns')
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# High-risk IAM operations and policies
DANGEROUS_POLICIES = [
    'AdministratorAccess',
    'IAMFullAccess',
    'SecurityAudit',
    'PowerUserAccess'
]

PRIVILEGE_ESCALATION_EVENTS = [
    'AttachUserPolicy',
    'PutUserPolicy',
    'AddUserToGroup',
    'CreateAccessKey',
    'UpdateAssumeRolePolicy'
]

def lambda_handler(event, context):
    """
    Detects IAM privilege escalation attempts
    """
    try:
        # Parse CloudTrail event
        detail = event['detail']
        event_name = detail['eventName']
        user_identity = detail['userIdentity']
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        user_agent = detail.get('userAgent', 'Unknown')

        # Detect privilege escalation
        detection = detect_privilege_escalation(detail)

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

def detect_privilege_escalation(detail):
    """
    Apply detection logic
    """
    event_name = detail['eventName']
    request_params = detail.get('requestParameters', {})

    # Detect dangerous policy attachments
    if event_name == 'AttachUserPolicy':
        policy_arn = request_params.get('policyArn', '')
        if any(policy in policy_arn for policy in DANGEROUS_POLICIES):
            return {
                'type': 'Privilege Escalation - Admin Policy Attachment',
                'severity': 'HIGH',
                'technique': 'T1078',
                'tactic': 'Privilege Escalation',
                'policy': policy_arn,
                'target_user': request_params.get('userName')
            }

    # Detect inline policy with admin permissions
    if event_name == 'PutUserPolicy':
        policy_document = request_params.get('policyDocument', '')
        if '"Effect":"Allow"' in policy_document and '"Action":"*"' in policy_document:
            return {
                'type': 'Privilege Escalation - Inline Admin Policy',
                'severity': 'HIGH',
                'technique': 'T1078',
                'tactic': 'Privilege Escalation',
                'target_user': request_params.get('userName')
            }

    # Detect adding user to admin group
    if event_name == 'AddUserToGroup':
        group_name = request_params.get('groupName', '')
        if 'admin' in group_name.lower() or 'power' in group_name.lower():
            return {
                'type': 'Privilege Escalation - Admin Group Addition',
                'severity': 'MEDIUM',
                'technique': 'T1078',
                'tactic': 'Privilege Escalation',
                'group': group_name,
                'target_user': request_params.get('userName')
            }

    # Detect suspicious access key creation
    if event_name == 'CreateAccessKey':
        return {
            'type': 'IAM Access Key Created',
            'severity': 'MEDIUM',
            'technique': 'T1078',
            'tactic': 'Persistence',
            'target_user': request_params.get('userName')
        }

    return None

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
        'target': detection.get('target_user', 'N/A'),
        'additional_context': {
            k: v for k, v in detection.items()
            if k not in ['type', 'severity', 'technique', 'tactic']
        }
    }

    return alert

def send_alert(alert):
    """
    Send alert to SNS
    """
    subject = f"[{alert['severity']}] {alert['detection_type']}"

    # Format message
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

Target: {alert['target']}

Additional Context:
{json.dumps(alert['additional_context'], indent=2)}

---
This alert was generated by AWS Threat Detection Lab
"""

    # Publish to SNS
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message
    )

    print(f"Alert sent: {subject}")
