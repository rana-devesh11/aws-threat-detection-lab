# Setup Guide

Complete setup guide for deploying the AWS Threat Detection Lab.

## Prerequisites

1. **AWS Account**
   - Dedicated lab/sandbox account (not production)
   - IAM user with administrative permissions
   - AWS CLI configured with credentials

2. **Tools**
   - Terraform >= 1.0
   - Python 3.9+
   - AWS CLI v2
   - Boto3 library: `pip install boto3`

3. **Cost Awareness**
   - CloudTrail: First trail free
   - Lambda: 1M requests/month free tier
   - EventBridge: First 14M events/month free
   - SNS: 1,000 email notifications/month free
   - GuardDuty: 30-day free trial, then ~$5-10/month
   - Estimated monthly cost: $5-10 after free tier

## Step 1: Clone and Configure

```bash
# Clone repository
git clone https://github.com/yourusername/aws-threat-detection-lab.git
cd aws-threat-detection-lab

# Configure Terraform variables
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
aws_region         = "us-east-1"
owner_email        = "your.email@example.com"
alert_email        = "your.email@example.com"
enable_guardduty   = true
```

## Step 2: Package Lambda Functions

Create deployment packages for Lambda detectors:

```bash
cd lambda

# Package IAM detector
cd iam_detector
zip -r ../iam_detector.zip main.py
cd ..

# Package root account detector
cd root_detector
zip -r ../root_detector.zip main.py
cd ..

# Package S3 detector
cd s3_detector
zip -r ../s3_detector.zip main.py
cd ..

# Package access key detector
cd key_detector
zip -r ../key_detector.zip main.py
cd ..

cd ..
```

## Step 3: Deploy Infrastructure

```bash
cd terraform

# Initialize Terraform
terraform init

# Review deployment plan
terraform plan

# Deploy (confirm when prompted)
terraform apply
```

Deployment takes 2-3 minutes. Terraform will output:
- CloudTrail name
- SNS topic ARN
- Lambda function names
- EventBridge rule names

## Step 4: Confirm SNS Subscription

1. Check your email for "AWS Notification - Subscription Confirmation"
2. Click "Confirm subscription" link
3. You should see "Subscription confirmed!"

Without this step, you won't receive alerts.

## Step 5: Verify Deployment

Check that resources are active:

```bash
# Verify CloudTrail is logging
aws cloudtrail get-trail-status --name threat-detection-lab-trail

# List Lambda functions
aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `threat-detection-lab`)].FunctionName'

# Check EventBridge rules
aws events list-rules --name-prefix threat-detection-lab

# Verify GuardDuty (if enabled)
aws guardduty list-detectors
```

## Step 6: Run Test Simulations

Test detection rules with attack simulations:

```bash
# Make simulation scripts executable
chmod +x simulations/*.py

# Test IAM privilege escalation detection
python3 simulations/iam_attacks.py --scenario privilege-escalation --cleanup

# Wait 1-2 minutes and check your email for alert
```

Expected alert:
- Subject: `[HIGH] Privilege Escalation - Admin Policy Attachment`
- Contains: MITRE ATT&CK mapping, event details, actor information

## Troubleshooting

### No alerts received

1. **Check SNS subscription**
   ```bash
   aws sns list-subscriptions-by-topic --topic-arn <SNS_TOPIC_ARN>
   ```
   Status should be "Confirmed", not "PendingConfirmation"

2. **Check Lambda logs**
   ```bash
   aws logs tail /aws/lambda/threat-detection-lab-iam-detector --follow
   ```

3. **Verify EventBridge rules**
   ```bash
   aws events list-targets-by-rule --rule threat-detection-lab-iam-privilege-escalation
   ```

### Lambda permission errors

Ensure Lambda execution role has:
- CloudWatch Logs write permissions
- SNS publish permissions
- S3/IAM read permissions (for detectors)

```bash
aws iam get-role-policy --role-name threat-detection-lab-lambda-detector-role --policy-name threat-detection-lab-lambda-sns
```

### CloudTrail not logging

Check CloudTrail status:
```bash
aws cloudtrail get-trail-status --name threat-detection-lab-trail
```

Should show `"IsLogging": true`

### High AWS costs

To reduce costs:
1. Disable GuardDuty: Set `enable_guardduty = false` in terraform.tfvars
2. Reduce CloudTrail retention: Set `cloudtrail_retention_days = 30`
3. Run `terraform apply` to update

## Cleanup

To destroy all resources and stop charges:

```bash
cd terraform
terraform destroy
```

This removes:
- CloudTrail and S3 bucket (with logs)
- Lambda functions
- EventBridge rules
- SNS topic
- GuardDuty detector
- IAM roles and policies

**Note**: S3 bucket must be empty to delete. Terraform handles this automatically.

## Next Steps

- Read [DETECTIONS.md](DETECTIONS.md) for detection rule details
- Read [TESTING.md](TESTING.md) for comprehensive testing guide
- Review Lambda detector code in `lambda/` for customization
- Modify EventBridge patterns in `terraform/eventbridge.tf` to add detections
