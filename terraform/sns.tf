# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-alerts"
  display_name      = "Security Alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(local.common_tags, {
    Name = "Security Alerts Topic"
  })
}

# Email subscription
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Slack subscription (optional)
resource "aws_sns_topic_subscription" "slack" {
  count     = var.slack_webhook_url != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "https"
  endpoint  = var.slack_webhook_url
}

# SNS topic policy
resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}
