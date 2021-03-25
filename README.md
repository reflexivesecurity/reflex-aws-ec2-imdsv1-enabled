# reflex-aws-ec2-imdsv1-enabled

Reflex rule to detect when less secure IMDSv1 setting is allowed. 

## Usage

To use this rule either add it to your `reflex.yaml` configuration file:

```
rules:
  - reflex-aws-ec2-imdsv1-enabled:
      version: latest
```

or add it directly to your Terraform:

```
...

module "reflex-aws-ec2-imdsv1-enabled-cwe" {
  source            = "git::https://github.com/reflexivesecurity/reflex-aws-ec2-imdsv1-enabled.git//terraform/cwe?ref=latest"
}

module "reflex-aws-ec2-imdsv1-enabled" {
  source            = "git::https://github.com/reflexivesecurity/reflex-aws-ec2-imdsv1-enabled.git?ref=latest"
  sns_topic_arn     = module.central-sns-topic.arn
  reflex_kms_key_id = module.reflex-kms-key.key_id
}

...
```

Note: The `sns_topic_arn` and `reflex_kms_key_id` example values shown here assume you generated resources with `reflex build`. If you are using the Terraform on its own you need to provide your own valid values.

## Contributing
If you are interested in contributing, please review [our contribution guide](https://docs.reflexivesecurity.com/about/contributing.html).

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view
the [LICENSE](https://github.com/reflexivesecurity/reflex-aws-ec2-imdsv1-enabled/blob/master/LICENSE)
