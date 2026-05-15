variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "owner_email" {
  description = "Email address for notifications and tagging"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "threat-detection-lab"
}

variable "alert_email" {
  description = "Email address to receive security alerts"
  type        = string
}

variable "enable_guardduty" {
  description = "Enable GuardDuty (costs apply after 30-day trial)"
  type        = bool
  default     = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "cloudtrail_retention_days" {
  description = "CloudTrail log retention in days"
  type        = number
  default     = 90
}
