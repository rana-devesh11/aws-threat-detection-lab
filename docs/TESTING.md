# Testing Guide

Comprehensive guide for testing all detection rules using attack simulations.

## Prerequisites

- AWS Threat Detection Lab deployed (see [SETUP.md](SETUP.md))
- SNS email subscription confirmed
- Python 3.9+ with boto3 installed
- AWS CLI configured with credentials

## Test Overview

| Simulation Script | Scenarios | Expected Alerts | Time |
|------------------|-----------|-----------------|------|
| `iam_attacks.py` | 4 IAM privilege escalation scenarios | 4 HIGH severity | 5 min |
| `s3_attacks.py` | 4 S3 exposure scenarios | 3 CRITICAL, 1 HIGH | 5 min |
| `credential_attacks.py` | 4 credential abuse scenarios | 1 CRITICAL, 2 MEDIUM | 5 min |

**Total Test Duration**: 15 minutes  
**Expected Alerts**: 10-12 email alerts

---

## IAM Attack Simulations

**Script**: `simulations/iam_attacks.py`

### Test 1: Admin Policy Attachment

Simulates attacker attaching AdministratorAccess policy to compromised user.

```bash
python3 simulations/iam_attacks.py \
    --scenario privilege-escalation \
    --target-user test-victim-user \
    --cleanup
```

**Expected Alert**:
```
Subject: [HIGH] Privilege Escalation - Admin Policy Attachment
Detection: AttachUserPolicy
Target: test-victim-user
Policy: arn:aws:iam::aws:policy/AdministratorAccess
MITRE ATT&CK: T1078
```

**Alert Timing**: 1-2 minutes  
**Cleanup**: User and policy removed automatically

---

### Test 2: Inline Admin Policy

Creates inline policy with wildcard permissions.

```bash
python3 simulations/iam_attacks.py \
    --scenario inline-policy \
    --target-user test-victim-user \
    --cleanup
```

**Expected Alert**:
```
Subject: [HIGH] Privilege Escalation - Inline Admin Policy
Detection: PutUserPolicy
Action: "*"
Resource: "*"
```

**Alert Timing**: 1-2 minutes

---

### Test 3: Access Key Creation

Creates programmatic access credentials for persistence.

```bash
python3 simulations/iam_attacks.py \
    --scenario access-key \
    --target-user test-victim-user \
    --cleanup
```

**Expected Alert**:
```
Subject: [MEDIUM] IAM Access Key Created
Detection: CreateAccessKey
Target: test-victim-user
Access Key: AKIAIOSFODNN7EXAMPLE
```

**Alert Timing**: 1-2 minutes

---

### Test 4: Admin Group Addition

Adds user to administrative group.

```bash
python3 simulations/iam_attacks.py \
    --scenario admin-group \
    --target-user test-victim-user \
    --cleanup
```

**Expected Alert**:
```
Subject: [MEDIUM] Privilege Escalation - Admin Group Addition
Detection: AddUserToGroup
Group: test-admins
Target: test-victim-user
```

**Alert Timing**: 1-2 minutes

---

### Test All IAM Scenarios

Run all IAM attacks sequentially:

```bash
python3 simulations/iam_attacks.py --scenario all --cleanup
```

**Expected**: 4 email alerts over 3-4 minutes

---

## S3 Attack Simulations

**Script**: `simulations/s3_attacks.py`

### Test 5: Public ACL

Makes bucket public using ACL.

```bash
python3 simulations/s3_attacks.py \
    --scenario public-acl \
    --bucket threat-lab-test-bucket-12345 \
    --cleanup
```

**Expected Alert**:
```
Subject: [CRITICAL] S3 Bucket Made Public - ACL
Detection: PutBucketAcl
Bucket: threat-lab-test-bucket-12345
Method: ACL (AllUsers)
MITRE ATT&CK: T1530
```

**Alert Timing**: 1-2 minutes  
**Note**: Bucket name must be globally unique

---

### Test 6: Public Bucket Policy

Makes bucket public using bucket policy with wildcard principal.

```bash
python3 simulations/s3_attacks.py \
    --scenario public-policy \
    --bucket threat-lab-test-bucket-12345 \
    --cleanup
```

**Expected Alert**:
```
Subject: [CRITICAL] S3 Bucket Made Public - Policy
Detection: PutBucketPolicy
Principal: "*"
```

**Alert Timing**: 1-2 minutes

---

### Test 7: Disable Block Public Access

Removes S3 Block Public Access protection.

```bash
python3 simulations/s3_attacks.py \
    --scenario disable-block \
    --bucket threat-lab-test-bucket-12345 \
    --cleanup
```

**Expected Alert**:
```
Subject: [HIGH] S3 Public Access Block Disabled
Detection: DeleteBucketPublicAccessBlock
```

**Alert Timing**: 1-2 minutes

---

### Test 8: Data Exfiltration

Simulates bulk data download pattern.

```bash
python3 simulations/s3_attacks.py \
    --scenario exfiltration \
    --bucket threat-lab-test-bucket-12345 \
    --cleanup
```

**Expected Behavior**:
- No immediate Lambda alert (not in EventBridge pattern)
- May trigger GuardDuty alert after 5-15 minutes if enabled
- CloudTrail logs high volume S3 GetObject calls

**GuardDuty Finding** (if enabled):
```
Finding: Exfiltration:S3/ObjectRead.Unusual
Severity: Medium
Description: Unusual volume of S3 object reads
```

---

### Test All S3 Scenarios

```bash
python3 simulations/s3_attacks.py --scenario all --cleanup
```

**Expected**: 3 immediate alerts + optional GuardDuty alert

---

## Credential Attack Simulations

**Script**: `simulations/credential_attacks.py`

### Test 9: Root Account API Usage

**WARNING**: This test requires root account credentials. Only run if you understand the security implications.

```bash
# Configure AWS CLI with root credentials (not recommended)
aws configure --profile root

# Run test
AWS_PROFILE=root python3 simulations/credential_attacks.py \
    --scenario root-usage
```

**Expected Alert**:
```
Subject: [CRITICAL] Root Account Activity Detected
Detection: ListUsers (or other root action)
Actor: Root Account
MFA Used: false
MITRE ATT&CK: T1078.004
```

**Alert Timing**: 1-2 minutes  
**Recommendation**: Use IAM user for testing instead. Root detection can be validated by reviewing CloudTrail console login events.

---

### Test 10: Credential Enumeration

Simulates attacker enumerating IAM users and credentials.

```bash
python3 simulations/credential_attacks.py \
    --scenario enumeration \
    --test-user test-recon-user \
    --cleanup
```

**Expected Behavior**:
- Multiple IAM List* API calls logged in CloudTrail
- No immediate Lambda alert (reconnaissance pattern)
- May trigger GuardDuty alert after 5-15 minutes

**GuardDuty Finding** (if enabled):
```
Finding: Recon:IAMUser/MaliciousIPCaller
Severity: Medium
Description: Suspicious reconnaissance activity detected
```

---

### Test 11: Cross-Account Role Assumption

Attempts to assume role in different account.

```bash
python3 simulations/credential_attacks.py \
    --scenario cross-account
```

**Expected Behavior**:
- AssumeRole fails with AccessDenied (expected)
- CloudTrail logs failed attempt
- No immediate alert (failed attempts not configured)
- May trigger GuardDuty behavioral analysis

---

### Test All Credential Scenarios

```bash
python3 simulations/credential_attacks.py --scenario all --cleanup
```

**Note**: Root usage test skipped unless running as root.

---

## Validation Checklist

After running simulations, verify:

### CloudTrail
```bash
# Check CloudTrail is logging events
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --max-results 5
```

### Lambda Execution
```bash
# Check Lambda detector logs
aws logs tail /aws/lambda/threat-detection-lab-iam-detector --since 10m

# Should show: "Alert sent: [HIGH] Privilege Escalation..."
```

### EventBridge Rules
```bash
# Check EventBridge invocation metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/Events \
    --metric-name Invocations \
    --dimensions Name=RuleName,Value=threat-detection-lab-iam-privilege-escalation \
    --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Sum
```

### SNS Delivery
```bash
# Check SNS publish metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/SNS \
    --metric-name NumberOfMessagesPublished \
    --dimensions Name=TopicName,Value=threat-detection-lab-alerts \
    --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Sum
```

### Email Alerts
- Check inbox for alerts (may take 1-2 minutes)
- Check spam folder if no alerts received
- Verify SNS subscription is "Confirmed" status

---

## Troubleshooting

### No Alerts Received

**1. Check SNS Subscription Status**
```bash
aws sns get-subscription-attributes --subscription-arn <SUBSCRIPTION_ARN>
```

If status is "PendingConfirmation", check email for confirmation link.

**2. Check Lambda Errors**
```bash
aws logs filter-log-events \
    --log-group-name /aws/lambda/threat-detection-lab-iam-detector \
    --filter-pattern "ERROR"
```

**3. Check EventBridge Permissions**
```bash
aws lambda get-policy --function-name threat-detection-lab-iam-detector
```

Should show EventBridge invoke permission.

---

### Alerts Delayed

Normal detection latency: 1-2 minutes (CloudTrail → EventBridge → Lambda → SNS)

If alerts take >5 minutes:
- Check CloudTrail processing delay
- Verify EventBridge rule is enabled
- Check Lambda execution time in CloudWatch

---

### Wrong Alert Content

If alert content is incorrect or missing fields:

```bash
# Test Lambda function directly
aws lambda invoke \
    --function-name threat-detection-lab-iam-detector \
    --payload file://test_event.json \
    response.json

cat response.json
```

Sample test event (`test_event.json`):
```json
{
  "detail": {
    "eventName": "AttachUserPolicy",
    "userIdentity": {
      "type": "IAMUser",
      "userName": "test-attacker"
    },
    "requestParameters": {
      "userName": "test-victim",
      "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    },
    "sourceIPAddress": "203.0.113.42",
    "eventTime": "2026-05-10T12:00:00Z"
  }
}
```

---

## Performance Testing

### Measure Detection Latency

```bash
#!/bin/bash
# Test detection latency

echo "Starting test at $(date)"
START_TIME=$(date +%s)

# Trigger detection
python3 simulations/iam_attacks.py --scenario privilege-escalation --cleanup

# Wait for alert
echo "Waiting for alert..."
sleep 120

# Check Lambda logs for execution time
END_TIME=$(aws logs filter-log-events \
    --log-group-name /aws/lambda/threat-detection-lab-iam-detector \
    --filter-pattern "Alert sent" \
    --query 'events[0].timestamp' \
    --output text)

LATENCY=$((END_TIME/1000 - START_TIME))
echo "Detection latency: ${LATENCY} seconds"
```

Typical results:
- CloudTrail ingestion: 30-60 seconds
- EventBridge processing: <1 second
- Lambda execution: 0.1-0.5 seconds
- SNS delivery: <30 seconds
- **Total latency**: 60-120 seconds

---

## Advanced Testing

### Stress Test Detection Rules

Run multiple attacks simultaneously:

```bash
# Terminal 1
python3 simulations/iam_attacks.py --scenario all &

# Terminal 2
python3 simulations/s3_attacks.py --scenario all &

# Terminal 3
python3 simulations/credential_attacks.py --scenario all &

# Wait for completion
wait

# Check Lambda concurrent executions
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name ConcurrentExecutions \
    --dimensions Name=FunctionName,Value=threat-detection-lab-iam-detector \
    --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 60 \
    --statistics Maximum
```

Expected: All alerts delivered, no Lambda throttling

---

### Integration Testing

Test integration with SIEM or ticketing system:

```bash
# Add HTTPS endpoint to SNS topic
aws sns subscribe \
    --topic-arn <SNS_TOPIC_ARN> \
    --protocol https \
    --notification-endpoint https://your-siem.example.com/webhook

# Run test
python3 simulations/iam_attacks.py --scenario privilege-escalation

# Verify alert received in SIEM
```

---

## Test Report Template

After testing, document results:

```markdown
# Test Report - AWS Threat Detection Lab

**Date**: 2026-05-10
**Tester**: Devesh Rana
**Lab Version**: 1.0

## Test Results

| Test ID | Scenario | Status | Alert Received | Latency |
|---------|----------|--------|----------------|---------|
| 1 | Admin Policy Attachment | ✓ Pass | Yes | 68s |
| 2 | Inline Admin Policy | ✓ Pass | Yes | 72s |
| 3 | Access Key Creation | ✓ Pass | Yes | 65s |
| 4 | Admin Group Addition | ✓ Pass | Yes | 70s |
| 5 | S3 Public ACL | ✓ Pass | Yes | 75s |
| 6 | S3 Public Policy | ✓ Pass | Yes | 68s |
| 7 | Disable Block Public Access | ✓ Pass | Yes | 71s |
| 8 | Data Exfiltration | ✓ Pass | GuardDuty | 8m |
| 9 | Root Account Usage | ✗ Skip | N/A | N/A |
| 10 | Credential Enumeration | ✓ Pass | GuardDuty | 12m |

## Summary

- **Total Tests**: 10
- **Passed**: 9
- **Failed**: 0
- **Skipped**: 1 (root account test)
- **Average Latency**: 71 seconds
- **False Positives**: 0

## Issues Found

None

## Recommendations

- All detection rules working as expected
- Latency within acceptable range (60-120s)
- Ready for production deployment
```

---

## Continuous Testing

Set up automated testing:

```bash
# Create cron job for weekly testing
crontab -e

# Add line (runs every Monday at 2 AM)
0 2 * * 1 cd /path/to/aws-threat-detection-lab && python3 simulations/iam_attacks.py --scenario all --cleanup >> /var/log/threat-lab-test.log 2>&1
```

Monitor test results in `/var/log/threat-lab-test.log`
