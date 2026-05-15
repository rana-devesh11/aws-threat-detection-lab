# EventBridge rules for real-time threat detection

# IAM Privilege Escalation Detection
resource "aws_cloudwatch_event_rule" "iam_privilege_escalation" {
  name        = "${var.project_name}-iam-privilege-escalation"
  description = "Detect IAM privilege escalation attempts"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AttachUserPolicy",
        "PutUserPolicy",
        "AddUserToGroup",
        "CreateAccessKey",
        "UpdateAssumeRolePolicy",
        "AttachGroupPolicy",
        "AttachRolePolicy"
      ]
    }
  })

  tags = merge(local.common_tags, {
    Name = "IAM Privilege Escalation Rule"
  })
}

resource "aws_cloudwatch_event_target" "iam_privilege_escalation" {
  rule      = aws_cloudwatch_event_rule.iam_privilege_escalation.name
  target_id = "IAMDetectorLambda"
  arn       = aws_lambda_function.iam_detector.arn
}

# Root Account Activity Detection
resource "aws_cloudwatch_event_rule" "root_account_usage" {
  name        = "${var.project_name}-root-account-usage"
  description = "Detect root account activity"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })

  tags = merge(local.common_tags, {
    Name = "Root Account Usage Rule"
  })
}

resource "aws_cloudwatch_event_target" "root_account_usage" {
  rule      = aws_cloudwatch_event_rule.root_account_usage.name
  target_id = "RootDetectorLambda"
  arn       = aws_lambda_function.root_detector.arn
}

# S3 Public Access Detection
resource "aws_cloudwatch_event_rule" "s3_public_access" {
  name        = "${var.project_name}-s3-public-access"
  description = "Detect S3 buckets made public"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock"
      ]
    }
  })

  tags = merge(local.common_tags, {
    Name = "S3 Public Access Rule"
  })
}

resource "aws_cloudwatch_event_target" "s3_public_access" {
  rule      = aws_cloudwatch_event_rule.s3_public_access.name
  target_id = "S3DetectorLambda"
  arn       = aws_lambda_function.s3_detector.arn
}

# Access Key Security Detection
resource "aws_cloudwatch_event_rule" "access_key_security" {
  name        = "${var.project_name}-access-key-security"
  description = "Detect access key creation and exposure"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateAccessKey",
        "UpdateAccessKey"
      ]
    }
  })

  tags = merge(local.common_tags, {
    Name = "Access Key Security Rule"
  })
}

resource "aws_cloudwatch_event_target" "access_key_security" {
  rule      = aws_cloudwatch_event_rule.access_key_security.name
  target_id = "KeyDetectorLambda"
  arn       = aws_lambda_function.key_detector.arn
}

# Lambda permissions for EventBridge
resource "aws_lambda_permission" "iam_detector_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_privilege_escalation.arn
}

resource "aws_lambda_permission" "root_detector_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.root_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.root_account_usage.arn
}

resource "aws_lambda_permission" "s3_detector_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_access.arn
}

resource "aws_lambda_permission" "key_detector_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.key_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.access_key_security.arn
}
