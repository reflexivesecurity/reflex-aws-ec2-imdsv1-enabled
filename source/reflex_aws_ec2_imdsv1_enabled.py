""" Module for ReflexAwsEc2Imdsv1Enabled """

import json

import boto3
from reflex_core import AWSRule, subscription_confirmation


class ReflexAwsEc2Imdsv1Enabled(AWSRule):
    """ Rule to detect when a ec2 instance is launched allowing IMDSv1. """

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.instance_items = event["detail"]["responseElements"]["items"]

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        # TODO: Implement a check for determining if the resource is compliant

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        # TODO: Provide a human readable message describing what occured. This
        # message is sent in all notifications.
        #
        # Example:
        # return f"The S3 bucket {self.bucket_name} was unencrypted. AES-256 encryption was enabled."


def lambda_handler(event, _):
    """ Handles the incoming event """
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = ReflexAwsEc2Imdsv1Enabled(event_payload)
    rule.run_compliance_rule()
