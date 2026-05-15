#!/bin/bash
# AWS Threat Detection Lab Demo Recording Script
# Creates terminal recording showing attack simulations and real-time detection

set -e

echo "======================================================================"
echo "  AWS Threat Detection Lab Demo - Recording Terminal Session"
echo "======================================================================"
echo ""
echo "This will demonstrate:"
echo "  1. Deploying infrastructure with Terraform"
echo "  2. Running IAM privilege escalation attack"
echo "  3. Showing real-time detection and alerts"
echo "  4. Verifying Lambda detector logs"
echo ""
echo "Prerequisites:"
echo "  - AWS credentials configured"
echo "  - Terraform installed"
echo "  - Infrastructure deployed (terraform apply)"
echo ""
echo "Recording in 3 seconds..."
sleep 3

clear

# Demo script
cat << 'DEMO_SCRIPT' > /tmp/threat_lab_demo.sh
#!/bin/bash
set -e

echo "======================================================================"
echo "  AWS Threat Detection Lab Demo"
echo "======================================================================"
echo ""
echo "Architecture: CloudTrail → EventBridge → Lambda → SNS"
echo ""
sleep 2

echo "Step 1: Verify infrastructure deployment"
echo "----------------------------------------------------------------------"
echo ""
echo "$ cd terraform && terraform output"
cd terraform
terraform output
cd ..

echo ""
sleep 2

echo "Step 2: Run IAM privilege escalation attack simulation"
echo "----------------------------------------------------------------------"
echo ""
echo "$ python3 simulations/iam_attacks.py --scenario privilege-escalation --cleanup"
echo ""
sleep 2

python3 simulations/iam_attacks.py --scenario privilege-escalation --target-user demo-victim-user --cleanup

echo ""
sleep 3

echo "Step 3: Check Lambda detector logs (real-time detection)"
echo "----------------------------------------------------------------------"
echo ""
echo "$ aws logs tail /aws/lambda/threat-detection-lab-iam-detector --since 2m"
echo ""
sleep 2

aws logs tail /aws/lambda/threat-detection-lab-iam-detector --since 2m

echo ""
sleep 2

echo "Step 4: Verify CloudTrail logged the attack"
echo "----------------------------------------------------------------------"
echo ""
echo "$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy --max-results 1"
echo ""
sleep 2

aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --max-results 1 \
    --query 'Events[0].[Username,CloudTrailEvent]' \
    --output text | jq '.'

echo ""
sleep 2

echo "======================================================================"
echo "  Demo Complete!"
echo "======================================================================"
echo ""
echo "Detection Flow Demonstrated:"
echo "  1. ✓ Attacker attaches AdministratorAccess policy"
echo "  2. ✓ CloudTrail logs API call (30-60s)"
echo "  3. ✓ EventBridge matches attack pattern (<1s)"
echo "  4. ✓ Lambda detector analyzes and creates alert (0.5s)"
echo "  5. ✓ SNS sends email notification (<30s)"
echo ""
echo "Total Detection Time: ~60-120 seconds"
echo ""
echo "MITRE ATT&CK: T1078 (Valid Accounts) - Privilege Escalation"
echo ""
DEMO_SCRIPT

chmod +x /tmp/threat_lab_demo.sh
cd /Users/deveshrana/PersonalProjectPortfolio/secengineeringprojects/aws-threat-detection-lab
bash /tmp/threat_lab_demo.sh

rm /tmp/threat_lab_demo.sh
