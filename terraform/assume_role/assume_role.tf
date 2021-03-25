data "aws_caller_identity" "current" {}

module "assume_role" {
  source = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/sqs_lambda/modules/iam_assume_role?ref=v2.1.3"

  function_name        = "ReflexAwsEc2Imdsv1Enabled"
  custom_lambda_policy = <<EOF
# TODO: Provide required lambda permissions policy
EOF

  lambda_execution_role_arn = "arn:aws:iam::${var.parent_account}:role/ReflexReflexAwsEc2Imdsv1EnabledLambdaExecution"

}