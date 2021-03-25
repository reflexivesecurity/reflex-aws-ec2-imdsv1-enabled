module "cwe" {
  source           = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/cwe?ref=v2.1.3"
  name        = "ReflexAwsEc2Imdsv1Enabled"
  description = "Detect when RunInstances is called with IMDSv1 allowed."

  event_pattern = <<PATTERN
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "source": [
    "aws.ec2"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "RunInstances"
    ]
  }
}

PATTERN
}
