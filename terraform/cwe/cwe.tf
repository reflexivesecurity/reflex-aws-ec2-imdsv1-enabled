module "cwe" {
  source           = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/cwe?ref=v2.1.3"
  name        = "ReflexAwsEc2Imdsv1Enabled"
  description = "TODO: Provide rule description"

  event_pattern = <<PATTERN
# TODO: Provide event pattern
PATTERN
}