# Lambda functions for threat detection

# IAM Detector Lambda
resource "aws_lambda_function" "iam_detector" {
  filename         = "${path.module}/../lambda/iam_detector.zip"
  function_name    = "${var.project_name}-iam-detector"
  role            = aws_iam_role.lambda_detector.arn
  handler         = "main.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/../lambda/iam_detector.zip")
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "IAM Detector"
  })
}

# Root Account Detector Lambda
resource "aws_lambda_function" "root_detector" {
  filename         = "${path.module}/../lambda/root_detector.zip"
  function_name    = "${var.project_name}-root-detector"
  role            = aws_iam_role.lambda_detector.arn
  handler         = "main.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/../lambda/root_detector.zip")
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "Root Account Detector"
  })
}

# S3 Public Access Detector Lambda
resource "aws_lambda_function" "s3_detector" {
  filename         = "${path.module}/../lambda/s3_detector.zip"
  function_name    = "${var.project_name}-s3-detector"
  role            = aws_iam_role.lambda_detector.arn
  handler         = "main.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/../lambda/s3_detector.zip")
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "S3 Public Access Detector"
  })
}

# Access Key Security Detector Lambda
resource "aws_lambda_function" "key_detector" {
  filename         = "${path.module}/../lambda/key_detector.zip"
  function_name    = "${var.project_name}-key-detector"
  role            = aws_iam_role.lambda_detector.arn
  handler         = "main.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/../lambda/key_detector.zip")
  runtime         = "python3.11"
  timeout         = 60
  memory_size     = 256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "Access Key Detector"
  })
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "iam_detector" {
  name              = "/aws/lambda/${aws_lambda_function.iam_detector.function_name}"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "root_detector" {
  name              = "/aws/lambda/${aws_lambda_function.root_detector.function_name}"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "s3_detector" {
  name              = "/aws/lambda/${aws_lambda_function.s3_detector.function_name}"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "key_detector" {
  name              = "/aws/lambda/${aws_lambda_function.key_detector.function_name}"
  retention_in_days = 30

  tags = local.common_tags
}
