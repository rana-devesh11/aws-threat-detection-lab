# Detection Rules

Detailed documentation of all detection rules, detection logic, and alert criteria.

## Detection Categories

1. **IAM Privilege Escalation**
2. **Root Account Activity**
3. **S3 Data Exposure**
4. **Access Key Security**
5. **GuardDuty Findings** (if enabled)

---

## 1. IAM Privilege Escalation Detection

**Lambda Function**: `iam_detector/main.py`  
**EventBridge Rule**: `iam_privilege_escalation`  
**MITRE ATT&CK**: T1078 (Valid Accounts)

### Monitored Events

- `AttachUserPolicy`
- `PutUserPolicy`
- `AddUserToGroup`
- `CreateAccessKey`
- `UpdateAssumeRolePolicy`
- `AttachGroupPolicy`
- `AttachRolePolicy`

### Detection Logic

#### 1.1 Admin Policy Attachment
```python
if event_name == 'AttachUserPolicy':
    policy_arn = request_parameters['policyArn']
    if 'AdministratorAccess' in policy_arn or 'IAMFullAccess' in policy_arn:
        ALERT: HIGH severity
```

**Triggers on**: Attaching AWS managed admin policies  
**Severity**: HIGH  
**False Positives**: Legitimate admin user creation (review context)

#### 1.2 Inline Admin Policy
```python
if event_name == 'PutUserPolicy':
    policy_document = request_parameters['policyDocument']
    if '"Effect":"Allow"' and '"Action":"*"' in policy_document:
        ALERT: HIGH severity
```

**Triggers on**: Inline policies with wildcard permissions (`"Action":"*"`)  
**Severity**: HIGH  
**False Positives**: Service accounts requiring broad permissions

#### 1.3 Admin Group Addition
```python
if event_name == 'AddUserToGroup':
    group_name = request_parameters['groupName']
    if 'admin' in group_name.lower() or 'power' in group_name.lower():
        ALERT: MEDIUM severity
```

**Triggers on**: Adding users to groups with 'admin' or 'power' in name  
**Severity**: MEDIUM  
**False Positives**: Legitimate group assignments

#### 1.4 Access Key Creation
```python
if event_name == 'CreateAccessKey':
    ALERT: MEDIUM severity
```

**Triggers on**: Any IAM access key creation  
**Severity**: MEDIUM  
**Rationale**: Keys provide programmatic access and enable persistence  
**False Positives**: Service account setup, CI/CD credential rotation

### Alert Format

```
Detection: Privilege Escalation - Admin Policy Attachment
Severity: HIGH
MITRE ATT&CK: T1078 - Privilege Escalation
Event: AttachUserPolicy
Actor: arn:aws:iam::123456789012:user/attacker
Target: test-victim-user
Policy: arn:aws:iam::aws:policy/AdministratorAccess
Source IP: 203.0.113.42
```

---

## 2. Root Account Activity Detection

**Lambda Function**: `root_detector/main.py`  
**EventBridge Rule**: `root_account_usage`  
**MITRE ATT&CK**: T1078.004 (Cloud Accounts)

### Monitored Events

All CloudTrail events where `userIdentity.type == "Root"`

### Detection Logic

#### 2.1 Root Account API Usage
```python
if user_identity['type'] == 'Root':
    if event_name not in ALLOWED_ROOT_ACTIONS:
        severity = 'CRITICAL' if is_dangerous_action(event_name) else 'HIGH'
        ALERT: severity
```

**Allowed Actions** (no alert):
- `GetAccountSummary`
- `GetServiceLastAccessedDetails`
- `ListAccountAliases`

**Dangerous Actions** (CRITICAL severity):
- `CreateAccessKey` / `DeleteAccessKey`
- `PutUserPolicy` / `AttachUserPolicy`
- `CreateUser` / `DeleteUser`
- `DeactivateMFADevice`
- `DeleteAccountPasswordPolicy`

**Other Actions** (HIGH severity):
- Any other root account activity

### Alert Format

```
Detection: Root Account Activity Detected
Severity: CRITICAL
MITRE ATT&CK: T1078.004 - Privilege Escalation / Persistence
Event: CreateAccessKey
Actor: Root Account (123456789012)
MFA Used: false
Source IP: 203.0.113.42
Recommendation: Root account should only be used for account setup.
```

### False Positives

- Initial account setup (first 24 hours)
- Account recovery procedures
- Billing/support access

**Mitigation**: Review context and timing. Root usage should be exceptional.

---

## 3. S3 Data Exposure Detection

**Lambda Function**: `s3_detector/main.py`  
**EventBridge Rule**: `s3_public_access`  
**MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)

### Monitored Events

- `PutBucketAcl`
- `PutBucketPolicy`
- `PutBucketPublicAccessBlock`
- `DeleteBucketPublicAccessBlock`

### Detection Logic

#### 3.1 Public ACL
```python
if event_name == 'PutBucketAcl':
    if 'AllUsers' in ACL or 'AuthenticatedUsers' in ACL:
        ALERT: CRITICAL severity
```

**Triggers on**: ACL grants to `http://acs.amazonaws.com/groups/global/AllUsers`  
**Severity**: CRITICAL

#### 3.2 Public Bucket Policy
```python
if event_name == 'PutBucketPolicy':
    policy = request_parameters['bucketPolicy']
    if principal == '*' and effect == 'Allow':
        ALERT: CRITICAL severity
```

**Triggers on**: Bucket policies with wildcard principal (`"Principal": "*"`)  
**Severity**: CRITICAL

#### 3.3 Public Access Block Removal
```python
if event_name == 'DeleteBucketPublicAccessBlock':
    ALERT: HIGH severity
```

**Triggers on**: Deleting Block Public Access settings  
**Severity**: HIGH

#### 3.4 Public Access Block Weakening
```python
if event_name == 'PutBucketPublicAccessBlock':
    if not all([BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets]):
        ALERT: HIGH severity
```

**Triggers on**: Disabling any Block Public Access option  
**Severity**: HIGH

### Alert Format

```
Detection: S3 Bucket Made Public - ACL
Severity: CRITICAL
MITRE ATT&CK: T1530 - Collection
Event: PutBucketAcl
Bucket: sensitive-data-bucket
Method: ACL
Actor: arn:aws:iam::123456789012:user/attacker
Recommendation: Enable Public Access Block unless public access explicitly required.
```

---

## 4. Access Key Security Detection

**Lambda Function**: `key_detector/main.py`  
**EventBridge Rule**: `access_key_security`  
**MITRE ATT&CK**: T1078 / T1078.004

### Monitored Events

- `CreateAccessKey`
- `UpdateAccessKey`

### Detection Logic

#### 4.1 Root Access Key Creation
```python
if event_name == 'CreateAccessKey' and user_identity['type'] == 'Root':
    ALERT: CRITICAL severity
```

**Triggers on**: Creating access keys for root account  
**Severity**: CRITICAL  
**Recommendation**: Immediately delete root access keys

#### 4.2 IAM Access Key Creation
```python
if event_name == 'CreateAccessKey':
    ALERT: MEDIUM severity
```

**Triggers on**: Any IAM user access key creation  
**Severity**: MEDIUM  
**Recommendation**: Use temporary credentials (STS) or IAM roles instead

#### 4.3 Access Key Activation
```python
if event_name == 'UpdateAccessKey' and status == 'Active':
    ALERT: MEDIUM severity
```

**Triggers on**: Reactivating dormant access keys  
**Severity**: MEDIUM  
**Rationale**: Dormant key activation may indicate compromise

### Alert Format

```
Detection: Root Account Access Key Created
Severity: CRITICAL
MITRE ATT&CK: T1078.004 - Persistence
Event: CreateAccessKey
Actor: Root
Access Key: AKIAIOSFODNN7EXAMPLE
Recommendation: Immediately delete root access keys. Use IAM users with MFA.
```

---

## 5. GuardDuty Findings (Optional)

**EventBridge Rule**: `guardduty_findings`  
**Integrated**: GuardDuty → EventBridge → SNS

### Monitored Findings

All GuardDuty findings with severity ≥ 4.0 (Medium and above)

### Finding Types Detected

#### Reconnaissance
- `Recon:IAMUser/MaliciousIPCaller`
- `Recon:IAMUser/TorIPCaller`

#### Credential Access
- `CredentialAccess:IAMUser/AnomalousAPIActivity`
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`

#### Persistence
- `Persistence:IAMUser/NetworkPermissions`
- `Persistence:IAMUser/ResourcePermissions`

#### Data Exfiltration
- `Exfiltration:S3/ObjectRead.Unusual`
- `Exfiltration:S3/AnomalousBehavior`

### Alert Format

```
GuardDuty Finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
Severity: 7.5
Description: Credentials obtained via compromised EC2 instance
Resource: EC2 Instance (i-1234567890abcdef0)
Account: 123456789012
Region: us-east-1
```

### GuardDuty vs Custom Detection

| Feature | GuardDuty | Custom Lambda |
|---------|-----------|---------------|
| Detection Method | ML-based anomaly detection | Rule-based signatures |
| Latency | 5-15 minutes | 1-2 minutes |
| Customization | Limited | Full control |
| Cost | ~$5-10/month | Free tier eligible |
| Coverage | Broad behavioral analysis | Specific attack patterns |

**Recommendation**: Use both for defense in depth. GuardDuty catches anomalies; Lambda catches known attack patterns immediately.

---

## Detection Tuning

### Reducing False Positives

#### IAM Privilege Escalation
- Whitelist service accounts in Lambda code
- Add business hours filtering
- Correlate with change management tickets

#### Root Account Activity
- Exclude first 24 hours after account creation
- Whitelist specific read-only actions for monitoring tools

#### S3 Public Access
- Whitelist buckets hosting public static websites
- Validate against asset inventory

#### Access Key Creation
- Whitelist CI/CD service accounts
- Implement approval workflow integration

### Adding Custom Detections

1. **Create EventBridge Pattern**
   ```hcl
   event_pattern = jsonencode({
     source      = ["aws.iam"]
     detail-type = ["AWS API Call via CloudTrail"]
     detail = {
       eventName = ["YourEventName"]
     }
   })
   ```

2. **Write Detection Logic**
   ```python
   def detect_threat(detail):
       if suspicious_condition:
           return {
               'type': 'Detection Name',
               'severity': 'HIGH',
               'technique': 'T1234',
               'tactic': 'Attack Tactic'
           }
   ```

3. **Deploy and Test**
   ```bash
   terraform apply
   python3 simulations/test_detection.py
   ```

---

## Performance Metrics

- **Detection Latency**: 1-2 minutes (CloudTrail → EventBridge → Lambda → SNS)
- **Lambda Execution Time**: 100-500ms per event
- **Alert Delivery**: <30 seconds (SNS email)
- **False Positive Rate**: <5% with default rules
- **Cost per Alert**: ~$0.0001 (mostly SNS)
