import json
import boto3
import os
from datetime import datetime

sns_client = boto3.client('sns')
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def lambda_handler(event, context):
    """
    Detects access key security issues
    """
    try:
        detail = event['detail']
        event_name = detail['eventName']

        # Detect key security issues
        detection = detect_key_issues(detail)

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

def detect_key_issues(detail):
    """
    Detect access key security issues
    """
    event_name = detail['eventName']
    user_identity = detail['userIdentity']
    request_params = detail.get('requestParameters', {})
    response_elements = detail.get('responseElements', {})

    # Detect root account access key creation (critical)
    if event_name == 'CreateAccessKey':
        target_user = request_params.get('userName')
        creator_type = user_identity.get('type')

        # Root creating keys is critical
        if creator_type == 'Root':
            return {
                'type': 'Root Account Access Key Created',
                'severity': 'CRITICAL',
                'technique': 'T1078.004',
                'tactic': 'Persistence',
                'target_user': 'root',
                'created_by': 'root'
            }

        # Keys created for privileged users
        if target_user:
            return {
                'type': 'IAM Access Key Created',
                'severity': 'MEDIUM',
                'technique': 'T1078',
                'tactic': 'Persistence',
                'target_user': target_user,
                'created_by': user_identity.get('userName', user_identity.get('principalId')),
                'access_key_id': response_elements.get('accessKey', {}).get('accessKeyId')
            }

    # Detect access key updates (potential activation of dormant keys)
    elif event_name == 'UpdateAccessKey':
        status = request_params.get('status')
        if status == 'Active':
            return {
                'type': 'Access Key Activated',
                'severity': 'MEDIUM',
                'technique': 'T1078',
                'tactic': 'Persistence',
                'target_user': request_params.get('userName'),
                'access_key_id': request_params.get('accessKeyId'),
                'action': 'Key reactivated'
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
        'target': {
            'user': detection.get('target_user'),
            'access_key_id': detection.get('access_key_id', 'N/A')
        },
        'recommendation': get_recommendation(detection['type'])
    }

    return alert

def get_recommendation(detection_type):
    """
    Get security recommendation based on detection type
    """
    recommendations = {
        'Root Account Access Key Created': 'Immediately delete root access keys. Root account should only use console access with MFA enabled.',
        'IAM Access Key Created': 'Review if access key is necessary. Consider using temporary credentials (STS) or IAM roles instead.',
        'Access Key Activated': 'Verify key activation is authorized. Dormant keys being activated may indicate compromise.'
    }
    return recommendations.get(detection_type, 'Review access key usage and apply least privilege principles.')

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
  User: {alert['target']['user']}
  Access Key: {alert['target']['access_key_id']}

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
