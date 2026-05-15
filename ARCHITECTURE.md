# Architecture Documentation

## Design Overview

This lab implements a serverless, event-driven threat detection pipeline using AWS native services. The architecture follows cloud security best practices and demonstrates production-grade detection engineering.

### Design Principles

- **Serverless**: No servers to manage, scales automatically
- **Event-Driven**: Real-time detection using CloudTrail + EventBridge
- **Cost-Effective**: Minimal infrastructure, pay-per-use
- **Auditable**: All activities logged, immutable audit trail
- **Modular**: Each detection is independent Lambda function

## Component Architecture

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AWS Account Activities                        │
│  (Console logins, API calls, Resource changes, IAM operations)      │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   CloudTrail    │
                    │                 │
                    │ - Captures all  │
                    │   API events    │
                    │ - Management    │
                    │   events        │
                    │ - Data events   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌───────────┐  ┌───────────┐  ┌───────────┐
       │ S3 Bucket │  │EventBridge│  │ GuardDuty │
       │  (Logs)   │  │  (Rules)  │  │(Findings) │
       └───────────┘  └─────┬─────┘  └─────┬─────┘
                            │              │
                            │              │
            ┌───────────────┼──────────────┘
            │               │
            ▼               ▼
     ┌─────────────────────────────┐
     │    Detection Rules          │
     │  (EventBridge Patterns)     │
     │                             │
     │  - IAM policy changes       │
     │  - Root account activity    │
     │  - S3 public access         │
     │  - Console login failures   │
     │  - Access key operations    │
     └──────────────┬──────────────┘
                    │
        ┌───────────┼───────────┬──────────┐
        │           │           │          │
        ▼           ▼           ▼          ▼
   ┌────────┐ ┌────────┐  ┌────────┐ ┌────────┐
   │Lambda  │ │Lambda  │  │Lambda  │ │Lambda  │
   │  IAM   │ │  S3    │  │  Root  │ │  Keys  │
   │Detector│ │Detector│  │Detector│ │Detector│
   └───┬────┘ └───┬────┘  └───┬────┘ └───┬────┘
       │          │           │          │
       └──────────┼───────────┼──────────┘
                  │           │
                  ▼           ▼
           ┌────────────────────┐
           │   SNS Topic        │
           │  (Notifications)   │
           └─────────┬──────────┘
                     │
           ┌─────────┴─────────┐
           │                   │
           ▼                   ▼
      ┌─────────┐        ┌─────────┐
      │  Email  │        │  Slack  │
      └─────────┘        └─────────┘
```

## Core Components

### 1. CloudTrail

**Purpose:** Comprehensive API activity logging

**Configuration:**
- Organization trail (multi-region)
- Management events: Read + Write
- Data events: S3 object-level operations
- Log file validation: Enabled
- S3 encryption: Enabled (SSE-S3)

**Log Format:**
```json
{
  "eventTime": "2026-05-10T17:30:00Z",
  "eventName": "AttachUserPolicy",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "attacker"
  },
  "requestParameters": {
    "userName": "target-user",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  },
  "sourceIPAddress": "198.51.100.42"
}
```

**Why CloudTrail:**
- Immutable audit log
- Captures ALL AWS API activity
- Native integration with EventBridge
- Compliance requirement for most frameworks

### 2. EventBridge (CloudWatch Events)

**Purpose:** Event routing and pattern matching

**Event Pattern Example:**
```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "AttachUserPolicy",
      "PutUserPolicy",
      "AddUserToGroup",
      "CreateAccessKey"
    ]
  }
}
```

**Rule Types:**

| Rule Name | Pattern | Target Lambda |
|-----------|---------|---------------|
| iam-privilege-escalation | IAM policy attachments | iam_detector |
| root-account-activity | Root user actions | root_detector |
| s3-public-access | S3 bucket policy changes | s3_detector |
| access-key-operations | IAM key creation/rotation | key_detector |

**Why EventBridge:**
- Real-time event processing
- Declarative pattern matching
- Native CloudTrail integration
- No polling required

### 3. Lambda Detection Functions

**Architecture Pattern:**

```
Lambda Function
├── Handler (main.py)
│   ├── Parse CloudTrail event
│   ├── Apply detection logic
│   ├── Enrich with context
│   └── Send alert if match
├── Detection Rules (rules.py)
│   ├── Severity scoring
│   ├── False positive filtering
│   └── MITRE ATT&CK mapping
└── Alert Formatting (alerts.py)
    ├── SNS message formatting
    └── Metadata enrichment
```

**Example: IAM Privilege Escalation Detector**

```python
def detect_privilege_escalation(event):
    """
    Detects IAM privilege escalation attempts
    
    Indicators:
    - Attaching admin policies
    - Creating inline admin policies
    - Adding users to admin groups
    """
    
    event_name = event['detail']['eventName']
    
    # High-risk policy attachments
    dangerous_policies = [
        'AdministratorAccess',
        'IAMFullAccess',
        'SecurityAudit'
    ]
    
    if event_name == 'AttachUserPolicy':
        policy_arn = event['detail']['requestParameters']['policyArn']
        if any(policy in policy_arn for policy in dangerous_policies):
            return {
                'severity': 'HIGH',
                'technique': 'T1078',  # Valid Accounts
                'tactic': 'Privilege Escalation',
                'description': 'Admin policy attached to user'
            }
    
    return None
```

**Lambda Configuration:**
- Runtime: Python 3.9
- Memory: 256 MB (sufficient for event processing)
- Timeout: 30 seconds
- Environment variables: SNS_TOPIC_ARN, LOG_LEVEL

**Why Lambda:**
- No infrastructure management
- Automatic scaling
- Pay per invocation
- Easy to test and update

### 4. GuardDuty

**Purpose:** ML-based threat intelligence

**Detection Categories:**
- Reconnaissance (port scans, unusual API calls)
- Instance compromise (crypto mining, backdoors)
- Account compromise (credential exposure, impossible travel)
- Bucket compromise (data exfiltration patterns)

**Integration:**
```
GuardDuty Finding
      ↓
EventBridge Rule
      ↓
Lambda Processor
      ↓
SNS Alert
```

**Why GuardDuty:**
- Pre-built threat intelligence
- Machine learning detections
- Covers network and DNS analysis
- Complements CloudTrail-based detections

### 5. SNS (Simple Notification Service)

**Purpose:** Alert distribution

**Topic Configuration:**
- Encryption: AWS managed key
- Subscriptions: Email, HTTPS (Slack webhook)
- Delivery policy: Retry with exponential backoff

**Alert Format:**
```json
{
  "severity": "HIGH",
  "detection": "IAM Privilege Escalation",
  "user": "attacker",
  "action": "AttachUserPolicy",
  "resource": "target-user",
  "policy": "AdministratorAccess",
  "source_ip": "198.51.100.42",
  "timestamp": "2026-05-10T17:30:00Z",
  "mitre_attack": {
    "technique": "T1078",
    "tactic": "Privilege Escalation"
  }
}
```

## Detection Logic

### IAM Privilege Escalation Detection

**Threat Model:**
Attacker gains access to low-privilege IAM user and attempts to escalate privileges.

**Detection Indicators:**

1. **Policy Attachment**
   ```
   Event: AttachUserPolicy
   High-Risk Policies: Administrator*, IAMFullAccess
   ```

2. **Inline Policy Creation**
   ```
   Event: PutUserPolicy
   Policy Contains: iam:*, sts:AssumeRole, *:*
   ```

3. **Group Membership**
   ```
   Event: AddUserToGroup
   Group Name: *Admin*, *Power*
   ```

**False Positive Filtering:**
- Whitelist legitimate admin users
- Ignore service-linked roles
- Time-based filtering (e.g., maintenance windows)

**MITRE ATT&CK Mapping:**
- Technique: T1078 (Valid Accounts)
- Tactic: Privilege Escalation, Persistence

### Root Account Activity Detection

**Threat Model:**
Root account credentials compromised or used inappropriately.

**Detection Indicators:**

1. **Any Root Activity**
   ```
   UserIdentity.type == "Root"
   EventName != ConsoleLogin with MFA
   ```

2. **Root API Calls**
   ```
   All API calls from root account
   Exception: Account setup activities
   ```

3. **Root MFA Changes**
   ```
   Event: DeactivateMFADevice
   User: Root
   ```

**Risk Scoring:**
- Root login without MFA: CRITICAL
- Root API call: HIGH
- Root MFA change: CRITICAL

**MITRE ATT&CK Mapping:**
- Technique: T1078.004 (Cloud Accounts)
- Tactic: Persistence, Privilege Escalation

### S3 Public Access Detection

**Threat Model:**
Sensitive data exposed via misconfigured S3 bucket.

**Detection Indicators:**

1. **Bucket Policy Changes**
   ```
   Event: PutBucketPolicy
   Policy Contains: "Principal": "*"
   Condition: No IP restrictions
   ```

2. **ACL Changes**
   ```
   Event: PutBucketAcl
   Grantee: AllUsers or AuthenticatedUsers
   ```

3. **Public Access Block Removal**
   ```
   Event: DeletePublicAccessBlock
   ```

**Severity Assessment:**
```python
if bucket_contains_pii():
    severity = "CRITICAL"
elif bucket_is_logging_bucket():
    severity = "HIGH"
else:
    severity = "MEDIUM"
```

**MITRE ATT&CK Mapping:**
- Technique: T1530 (Data from Cloud Storage Object)
- Tactic: Collection

### Access Key Security Detection

**Threat Model:**
Access keys exposed in public repositories or used inappropriately.

**Detection Indicators:**

1. **Key Age**
   ```
   Key older than 90 days: MEDIUM
   Key never used: LOW
   ```

2. **Unusual Key Usage**
   ```
   New geographic location
   Multiple failed auth attempts
   API calls from known malicious IPs
   ```

3. **Key Creation Pattern**
   ```
   Multiple keys created in short time
   Keys created outside business hours
   Keys created for service accounts
   ```

**Integration Points:**
- GitHub secret scanning API
- GuardDuty findings (credential exposure)
- VPC Flow Logs (unusual source IPs)

## Security Considerations

### Lab Security

**Isolation:**
- Use dedicated AWS account for lab
- No production data or workloads
- Proper IAM permissions (least privilege)

**Cleanup:**
- Terraform destroy removes all resources
- CloudTrail logs retained for audit
- No persistent credentials

### Detection Limitations

**What We Detect:**
- AWS API activity (CloudTrail)
- IAM-based attacks
- Resource misconfigurations
- Console/API authentication

**What We Don't Detect:**
- Application-layer attacks
- Network traffic analysis (requires VPC Flow Logs)
- OS-level compromise (requires agent)
- Data exfiltration via approved channels

### False Positives

**Common Sources:**
- Automated tools (CI/CD, IaC)
- Legitimate admin operations
- AWS service actions

**Mitigation:**
- Whitelist trusted users/roles
- Time-based filtering
- Severity thresholds
- Alert aggregation

## Performance Characteristics

**Latency:**
- CloudTrail event delivery: 5-15 minutes average
- EventBridge processing: < 1 second
- Lambda execution: < 1 second
- SNS delivery: < 5 seconds
- **Total detection time: 5-15 minutes**

**Throughput:**
- EventBridge: Unlimited
- Lambda: 1000 concurrent executions (default)
- SNS: 30,000 messages/second

**Scalability:**
- Serverless auto-scaling
- No capacity planning required
- Handles burst traffic
- Cost scales with usage

## Cost Optimization

**Free Tier Usage:**
- CloudTrail: First trail free
- Lambda: 1M requests/month free
- SNS: 1,000 notifications/month free
- GuardDuty: 30-day free trial

**Cost Reduction Strategies:**
- Filter EventBridge rules (reduce Lambda invocations)
- Aggregate alerts (reduce SNS messages)
- Use S3 lifecycle policies (delete old logs)
- Disable GuardDuty after testing

## Deployment Considerations

**Prerequisites:**
- AWS account with admin access
- Terraform installed locally
- Python 3.9+ for simulations
- AWS CLI configured

**Deployment Steps:**
1. Configure Terraform variables
2. Deploy infrastructure (`terraform apply`)
3. Verify EventBridge rules active
4. Test with simulations
5. Monitor SNS for alerts

**Cleanup:**
```bash
terraform destroy
# Manually delete S3 bucket contents if needed
```

## Extension Points

**Additional Detections:**
- EC2 instance modifications
- Security group changes
- VPC configuration changes
- Secrets Manager access patterns
- Lambda function updates
- RDS public exposure

**Advanced Features:**
- Automated remediation (e.g., revoke keys, disable users)
- Threat intelligence integration
- SIEM integration (Splunk, Elasticsearch)
- Slack bot for interactive response
- Metrics and dashboards (CloudWatch)

## References

### AWS Documentation
- [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [EventBridge User Guide](https://docs.aws.amazon.com/eventbridge/latest/userguide/)
- [GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/)

### Security Frameworks
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)

---

**Author:** Devesh Rana  
**Last Updated:** May 2026
