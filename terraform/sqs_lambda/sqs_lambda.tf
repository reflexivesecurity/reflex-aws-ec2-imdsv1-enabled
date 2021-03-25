module "sqs_lambda" {
  source           = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/sqs_lambda?ref=v2.1.3"
  cloudwatch_event_rule_id  = var.cloudwatch_event_rule_id
  cloudwatch_event_rule_arn = var.cloudwatch_event_rule_arn
  function_name             = "ReflexAwsEc2Imdsv1Enabled"
  package_location          = var.package_location
  handler                   = "reflex_aws_ec2_imdsv1_enabled.lambda_handler"
  lambda_runtime            = "python3.7"
  environment_variable_map  = {
    SNS_TOPIC = var.sns_topic_arn,
    
  }
  custom_lambda_policy = <<EOF
# TODO: Provide required lambda permissions policy
EOF

  queue_name    = "ReflexAwsEc2Imdsv1Enabled"
  delay_seconds = 0

  target_id = "ReflexAwsEc2Imdsv1Enabled"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}