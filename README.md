# AWS Threat Detection Lab

A practical AWS security monitoring and threat detection lab demonstrating detection engineering, event-driven security automation, and cloud security architecture.

**Author:** Devesh Rana  
**Focus:** Cloud Security, Threat Detection, Security Engineering

## Overview

This lab implements a production-style threat detection pipeline in AWS, simulating real-world attack scenarios and demonstrating automated detection capabilities. The project maps detections to MITRE ATT&CK framework and implements event-driven response workflows.

## Architecture

The lab uses AWS native services to create a centralized security monitoring pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│                      AWS Account                            │
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                   │
│  │  CloudTrail  │─────▶│      S3      │                   │
│  │  (Logging)   │      │   (Storage)  │                   │
│  └──────────────┘      └──────────────┘                   │
│         │                                                   │
│         │ Events                                           │
│         ▼                                                   │
│  ┌──────────────┐                                          │
│  │ EventBridge  │                                          │
│  │   (Rules)    │                                          │
│  └──────┬───────┘                                          │
│         │                                                   │
│    ┌────┴────┬────────┬────────┐                          │
│    │         │        │        │                           │
│    ▼         ▼        ▼        ▼                           │
│  Lambda   Lambda   Lambda   Lambda                         │
│  (IAM)    (S3)     (Root)    (Key)                        │
│    │         │        │        │                           │
│    └────┬────┴────────┴────────┘                          │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐      ┌──────────────┐                   │
│  │     SNS      │─────▶│   Email /    │                   │
│  │   (Alerts)   │      │    Slack     │                   │
│  └──────────────┘      └──────────────┘                   │
│                                                             │
│  ┌──────────────┐                                          │
│  │  GuardDuty   │──────────────┐                          │
│  │  (Findings)  │              │                          │
│  └──────────────┘              │                          │
│         │                       │                          │
│         └───────────────────────┘                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Detection Sources

- **CloudTrail**: Captures all API calls and management events
- **GuardDuty**: ML-based threat intelligence and anomaly detection
- **EventBridge**: Event routing and pattern matching

### Detection Logic

Lambda functions implement detection rules for:

1. **IAM Abuse Detection**
   - Privilege escalation attempts
   - Policy modifications
   - Role assumption patterns
   - User creation/deletion

2. **Access Key Security**
   - Key exposure in public repositories
   - Unused access keys
   - Key rotation violations
   - Abnormal key usage

3. **Root Account Activity**
   - Root login detection
   - Root API usage
   - MFA status changes

4. **S3 Security**
   - Public bucket detection
   - Bucket policy changes
   - Data exfiltration patterns

### Response Actions

- SNS notifications (Email/Slack)
- Automated remediation (optional)
- Logging to CloudWatch
- Metrics generation

## Threat Scenarios

The lab includes simulation scripts for:

| Scenario | MITRE ATT&CK | Description |
|----------|--------------|-------------|
| IAM Privilege Escalation | T1078 | Attach admin policies to compromised user |
| Access Key Exposure | T1552.001 | Simulate credential leak scenario |
| Root Account Usage | T1078.004 | Root account login attempts |
| Public S3 Bucket | T1530 | Bucket made publicly accessible |
| Suspicious Console Login | T1078 | Login from unusual location |
| IAM Enumeration | T1087 | Discovery of users and roles |

## Project Structure

```
aws-threat-detection-lab/
├── README.md                    # This file
├── ARCHITECTURE.md              # Detailed design
├── terraform/                   # Infrastructure as Code
│   ├── main.tf
│   ├── cloudtrail.tf
│   ├── eventbridge.tf
│   ├── lambda.tf
│   ├── sns.tf
│   ├── iam.tf
│   └── variables.tf
├── lambda/                      # Detection functions
│   ├── iam_detector/
│   ├── s3_detector/
│   ├── root_detector/
│   └── key_detector/
├── simulations/                 # Attack scenarios
│   ├── iam_attacks.py
│   ├── s3_attacks.py
│   └── credential_attacks.py
├── docs/                        # Documentation
│   ├── SETUP.md
│   ├── DETECTIONS.md
│   └── TESTING.md
└── examples/                    # Screenshots, outputs
```

## Prerequisites

- AWS Account (Free tier compatible)
- AWS CLI configured
- Terraform >= 1.0
- Python 3.9+
- Basic understanding of AWS services

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/rana-devesh11/aws-threat-detection-lab.git
cd aws-threat-detection-lab
```

### 2. Configure Variables

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your settings
```

### 3. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

### 4. Run Attack Simulations

```bash
cd simulations
python3 iam_attacks.py --scenario privilege-escalation
```

### 5. Monitor Alerts

Check your email/Slack for detection alerts within 1-2 minutes.

## Detection Examples

### IAM Privilege Escalation

**Trigger:**
```bash
aws iam attach-user-policy \
  --user-name test-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Detection:**
```
Alert: IAM Privilege Escalation Detected
User: test-user
Action: AttachUserPolicy
Policy: AdministratorAccess
Time: 2026-05-10 17:30:45 UTC
Risk: HIGH
```

### Root Account Usage

**Trigger:**
```bash
aws s3 ls --profile root
```

**Detection:**
```
Alert: Root Account Activity Detected
Action: ListBuckets
Source IP: 203.0.113.42
Time: 2026-05-10 17:31:12 UTC
Risk: CRITICAL
```

## Cost Estimation

Based on minimal usage (testing/demo):

| Service | Monthly Cost |
|---------|-------------|
| CloudTrail | $0 (first trail free) |
| GuardDuty | ~$5-10 (30-day free trial) |
| Lambda | $0 (within free tier) |
| SNS | $0 (within free tier) |
| S3 | < $1 |
| **Total** | **~$5-10/month** |

**Note:** Costs are minimal if used for learning/testing. Remember to run `terraform destroy` when done.

## Key Features

- **Event-Driven Architecture**: Real-time detection using EventBridge
- **Infrastructure as Code**: Fully automated deployment with Terraform
- **MITRE ATT&CK Mapping**: Industry-standard threat framework alignment
- **Realistic Scenarios**: Based on actual cloud security incidents
- **Production Patterns**: Demonstrates real-world security engineering practices

## Learning Outcomes

This lab demonstrates:

- AWS security service integration
- Detection engineering principles
- Event-driven security automation
- Cloud security monitoring architecture
- Infrastructure as Code for security
- Threat modeling and simulation
- Incident detection and response workflows

## Limitations

- Focuses on AWS API activity (not network traffic)
- Detection rules are signature-based (not ML)
- Simulations run in same account (not adversary emulation)
- No persistent threat hunting capabilities
- Limited to AWS native services

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [CloudTrail Log Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)

## License

MIT License - see [LICENSE](LICENSE)

## Contact

Devesh Rana  
Cyber Security Engineer  
[LinkedIn](https://www.linkedin.com/in/devesh-rana11/)
