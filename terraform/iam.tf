# IAM roles and policies for Lambda detectors

# Lambda execution role
resource "aws_iam_role" "lambda_detector" {
  name = "${var.project_name}-lambda-detector-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "Lambda Detector Role"
  })
}

# CloudWatch Logs policy
resource "aws_iam_role_policy" "lambda_logging" {
  name = "${var.project_name}-lambda-logging"
  role = aws_iam_role.lambda_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:*"
      }
    ]
  })
}

# SNS publish policy
resource "aws_iam_role_policy" "lambda_sns" {
  name = "${var.project_name}-lambda-sns"
  role = aws_iam_role.lambda_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# S3 read policy for detector functions
resource "aws_iam_role_policy" "lambda_s3_read" {
  name = "${var.project_name}-lambda-s3-read"
  role = aws_iam_role.lambda_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::*"
      }
    ]
  })
}

# IAM read policy for detector functions
resource "aws_iam_role_policy" "lambda_iam_read" {
  name = "${var.project_name}-lambda-iam-read"
  role = aws_iam_role.lambda_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:GetGroup",
          "iam:GetRole",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = "*"
      }
    ]
  })
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Local variables
locals {
  account_id = data.aws_caller_identity.current.account_id
  common_tags = {
    Project     = var.project_name
    ManagedBy   = "Terraform"
    Environment = "lab"
    Owner       = var.owner_email
  }
}
