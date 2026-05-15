#!/bin/bash
# Deployment script for AWS Threat Detection Lab

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LAMBDA_DIR="$PROJECT_DIR/lambda"
TERRAFORM_DIR="$PROJECT_DIR/terraform"

echo "======================================================================"
echo "  AWS Threat Detection Lab - Deployment Script"
echo "======================================================================"
echo ""

# Check prerequisites
check_prerequisites() {
    echo "[1/5] Checking prerequisites..."

    if ! command -v terraform &> /dev/null; then
        echo "ERROR: terraform not found. Install from https://www.terraform.io/downloads"
        exit 1
    fi

    if ! command -v aws &> /dev/null; then
        echo "ERROR: aws CLI not found. Install from https://aws.amazon.com/cli/"
        exit 1
    fi

    if ! command -v python3 &> /dev/null; then
        echo "ERROR: python3 not found"
        exit 1
    fi

    if ! command -v zip &> /dev/null; then
        echo "ERROR: zip not found"
        exit 1
    fi

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "ERROR: AWS credentials not configured. Run 'aws configure'"
        exit 1
    fi

    echo "✓ All prerequisites satisfied"
    echo ""
}

# Package Lambda functions
package_lambdas() {
    echo "[2/5] Packaging Lambda functions..."

    cd "$LAMBDA_DIR"

    # IAM Detector
    echo "  - Packaging iam_detector..."
    cd iam_detector
    zip -q -r ../iam_detector.zip main.py
    cd ..

    # Root Detector
    echo "  - Packaging root_detector..."
    cd root_detector
    zip -q -r ../root_detector.zip main.py
    cd ..

    # S3 Detector
    echo "  - Packaging s3_detector..."
    cd s3_detector
    zip -q -r ../s3_detector.zip main.py
    cd ..

    # Key Detector
    echo "  - Packaging key_detector..."
    cd key_detector
    zip -q -r ../key_detector.zip main.py
    cd ..

    echo "✓ Lambda functions packaged"
    echo ""
}

# Check terraform configuration
check_terraform_config() {
    echo "[3/5] Checking Terraform configuration..."

    if [ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]; then
        echo "ERROR: terraform.tfvars not found"
        echo ""
        echo "Please create terraform.tfvars from example:"
        echo "  cd $TERRAFORM_DIR"
        echo "  cp terraform.tfvars.example terraform.tfvars"
        echo "  nano terraform.tfvars"
        echo ""
        exit 1
    fi

    echo "✓ Terraform configuration found"
    echo ""
}

# Deploy infrastructure
deploy_infrastructure() {
    echo "[4/5] Deploying infrastructure..."

    cd "$TERRAFORM_DIR"

    # Initialize Terraform
    echo "  - Initializing Terraform..."
    terraform init -upgrade > /dev/null

    # Plan deployment
    echo "  - Planning deployment..."
    terraform plan -out=tfplan

    echo ""
    read -p "Review the plan above. Deploy infrastructure? (yes/no): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        echo "Deployment cancelled"
        rm -f tfplan
        exit 0
    fi

    # Apply deployment
    echo "  - Applying Terraform configuration..."
    terraform apply tfplan
    rm -f tfplan

    echo "✓ Infrastructure deployed"
    echo ""
}

# Post-deployment verification
verify_deployment() {
    echo "[5/5] Verifying deployment..."

    cd "$TERRAFORM_DIR"

    # Get outputs
    SNS_TOPIC_ARN=$(terraform output -raw sns_topic_arn)
    CLOUDTRAIL_NAME=$(terraform output -raw cloudtrail_name)

    echo "  - CloudTrail: $CLOUDTRAIL_NAME"

    # Check CloudTrail status
    TRAIL_STATUS=$(aws cloudtrail get-trail-status --name "$CLOUDTRAIL_NAME" --query 'IsLogging' --output text)
    if [ "$TRAIL_STATUS" == "True" ]; then
        echo "    ✓ CloudTrail is logging"
    else
        echo "    ✗ CloudTrail is not logging"
    fi

    echo "  - SNS Topic: $SNS_TOPIC_ARN"

    # Check SNS subscription
    SUB_STATUS=$(aws sns list-subscriptions-by-topic --topic-arn "$SNS_TOPIC_ARN" --query 'Subscriptions[0].SubscriptionArn' --output text)
    if [[ "$SUB_STATUS" == arn:* ]]; then
        echo "    ✓ SNS subscription confirmed"
    elif [ "$SUB_STATUS" == "PendingConfirmation" ]; then
        echo "    ! SNS subscription pending - check your email"
    else
        echo "    ✗ No SNS subscription found"
    fi

    # List Lambda functions
    echo "  - Lambda Functions:"
    terraform output -json lambda_functions | python3 -c "import sys, json; [print(f'    ✓ {v}') for v in json.load(sys.stdin).values()]"

    echo ""
    echo "✓ Deployment verification complete"
    echo ""
}

# Print next steps
print_next_steps() {
    echo "======================================================================"
    echo "  Deployment Complete!"
    echo "======================================================================"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "1. Confirm SNS Subscription:"
    echo "   Check your email for 'AWS Notification - Subscription Confirmation'"
    echo "   Click 'Confirm subscription' link"
    echo ""
    echo "2. Test Detection Rules:"
    echo "   cd $PROJECT_DIR/simulations"
    echo "   python3 iam_attacks.py --scenario privilege-escalation --cleanup"
    echo ""
    echo "3. Check for alerts in your email (1-2 minutes after test)"
    echo ""
    echo "4. Review documentation:"
    echo "   - docs/DETECTIONS.md - Detection rule details"
    echo "   - docs/TESTING.md - Comprehensive testing guide"
    echo ""
    echo "To destroy infrastructure later:"
    echo "   cd $TERRAFORM_DIR && terraform destroy"
    echo ""
}

# Main execution
main() {
    check_prerequisites
    package_lambdas
    check_terraform_config
    deploy_infrastructure
    verify_deployment
    print_next_steps
}

main
