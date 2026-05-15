# GuardDuty for ML-based threat detection

resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false # Disabled to reduce costs
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = false # Disabled to reduce costs
        }
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "Main GuardDuty Detector"
  })
}

# EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.project_name}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=" : 4.0] } # Medium and above
      ]
    }
  })

  tags = merge(local.common_tags, {
    Name = "GuardDuty Findings Rule"
  })
}

# Send GuardDuty findings directly to SNS
resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "GuardDutySNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      description = "$.detail.description"
      resource    = "$.detail.resource.resourceType"
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      time        = "$.detail.updatedAt"
    }

    input_template = <<TEMPLATE
{
  "GuardDuty_Finding": "<type>",
  "Severity": "<severity>",
  "Description": "<description>",
  "Resource_Type": "<resource>",
  "Account": "<account>",
  "Region": "<region>",
  "Time": "<time>"
}
TEMPLATE
  }
}

# Output GuardDuty detector ID
output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : "Not enabled"
}
