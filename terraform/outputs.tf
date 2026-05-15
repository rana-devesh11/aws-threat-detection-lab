# Terraform outputs

output "cloudtrail_name" {
  description = "CloudTrail trail name"
  value       = aws_cloudtrail.main.name
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "lambda_functions" {
  description = "Deployed Lambda detector functions"
  value = {
    iam_detector  = aws_lambda_function.iam_detector.function_name
    root_detector = aws_lambda_function.root_detector.function_name
    s3_detector   = aws_lambda_function.s3_detector.function_name
    key_detector  = aws_lambda_function.key_detector.function_name
  }
}

output "eventbridge_rules" {
  description = "EventBridge detection rules"
  value = {
    iam_privilege_escalation = aws_cloudwatch_event_rule.iam_privilege_escalation.name
    root_account_usage       = aws_cloudwatch_event_rule.root_account_usage.name
    s3_public_access         = aws_cloudwatch_event_rule.s3_public_access.name
    access_key_security      = aws_cloudwatch_event_rule.access_key_security.name
  }
}

output "alert_email" {
  description = "Email receiving security alerts"
  value       = var.alert_email
}

output "aws_region" {
  description = "AWS region"
  value       = var.aws_region
}

output "aws_account_id" {
  description = "AWS account ID"
  value       = local.account_id
}
