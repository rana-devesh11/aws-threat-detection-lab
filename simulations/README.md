# Attack Simulations

Python scripts for simulating attack scenarios to test detection rules.

## Scripts

| Script | Purpose | Scenarios | MITRE Techniques |
|--------|---------|-----------|------------------|
| `iam_attacks.py` | IAM privilege escalation | 4 | T1078 |
| `s3_attacks.py` | S3 data exposure | 4 | T1530, T1537 |
| `credential_attacks.py` | Credential abuse | 4 | T1078.004, T1087, T1550.001 |

## Quick Start

```bash
# Test single scenario
python3 iam_attacks.py --scenario privilege-escalation --cleanup

# Test all scenarios in a script
python3 iam_attacks.py --scenario all --cleanup

# Check email for alerts (1-2 minutes)
```

## IAM Attacks

```bash
# Admin policy attachment
python3 iam_attacks.py --scenario privilege-escalation --cleanup

# Inline admin policy creation
python3 iam_attacks.py --scenario inline-policy --cleanup

# Access key creation
python3 iam_attacks.py --scenario access-key --cleanup

# Admin group addition
python3 iam_attacks.py --scenario admin-group --cleanup

# All IAM scenarios
python3 iam_attacks.py --scenario all --cleanup
```

## S3 Attacks

```bash
# Make bucket public via ACL
python3 s3_attacks.py --scenario public-acl --bucket your-test-bucket --cleanup

# Make bucket public via policy
python3 s3_attacks.py --scenario public-policy --bucket your-test-bucket --cleanup

# Disable Block Public Access
python3 s3_attacks.py --scenario disable-block --bucket your-test-bucket --cleanup

# Data exfiltration simulation
python3 s3_attacks.py --scenario exfiltration --bucket your-test-bucket --cleanup

# All S3 scenarios
python3 s3_attacks.py --scenario all --bucket your-test-bucket --cleanup
```

**Note**: Bucket names must be globally unique. Change `your-test-bucket` to something unique.

## Credential Attacks

```bash
# Root account API usage (requires root credentials)
python3 credential_attacks.py --scenario root-usage

# Cross-account role assumption attempt
python3 credential_attacks.py --scenario cross-account

# Credential enumeration
python3 credential_attacks.py --scenario enumeration --cleanup

# Password policy weakening
python3 credential_attacks.py --scenario password-policy

# All credential scenarios
python3 credential_attacks.py --scenario all --cleanup
```

## Options

All scripts support:

- `--scenario`: Choose specific scenario or `all`
- `--cleanup`: Remove test resources after execution
- `--help`: Show full usage

## Expected Behavior

After running a simulation:

1. **CloudTrail** logs the malicious API call (30-60 seconds)
2. **EventBridge** matches the event pattern (<1 second)
3. **Lambda** detector analyzes and creates alert (0.1-0.5 seconds)
4. **SNS** delivers email notification (<30 seconds)

**Total time**: 1-2 minutes from execution to email alert

## Safety

These scripts are designed for lab environments only:

- Use `--cleanup` flag to remove test resources
- Never run in production AWS accounts
- All test data marked as FAKE/TEST
- Scripts create minimal resources (users, buckets, keys)
- No actual malicious actions taken

## Troubleshooting

**No alerts received:**
- Verify SNS subscription is confirmed
- Check Lambda logs: `aws logs tail /aws/lambda/threat-detection-lab-iam-detector`
- Ensure EventBridge rules are enabled

**Permission errors:**
- Ensure AWS credentials have necessary IAM permissions
- Check IAM user/role has rights to create test resources

**Bucket name conflicts:**
- S3 bucket names are globally unique
- Use unique suffix: `--bucket threat-lab-test-$(date +%s)`
