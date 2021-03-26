""" Module for ReflexAwsEc2Imdsv1Enabled """

import datetime
import json

import boto3
from reflex_core import AWSRule, subscription_confirmation


class ReflexAwsEc2Imdsv1Enabled(AWSRule):
    """ Rule to detect when a ec2 instance is launched allowing IMDSv1. """

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.instance_items = event["detail"]["responseElements"].get(
            "instancesSet", []
        )
        self.non_compliant_instance_ids = []

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        compliant = True

        instance_ids = []

        if self.instance_items:
            for item in self.instance_items["items"]:
                instance_ids.append(item["instanceId"])
        else:
            date_filter = (
                datetime.datetime.now() - datetime.timedelta(days=1)
            ).strftime("%Y-%m-%d") + "*"
            instance_ids = self.get_filtered_instances(date_filter)

        response = self.client.describe_instances(InstanceIds=instance_ids)

        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                if (
                    instance["MetadataOptions"]["HttpEndpoint"] == "enabled"
                    and instance["MetadataOptions"]["HttpTokens"] != "required"
                ):
                    compliant = False
                    self.non_compliant_instance_ids.append(instance["InstanceId"])

        return compliant

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The following EC2 instances were launched allowing IMDSv1: {self.non_compliant_instance_ids}"

    def get_filtered_instances(self, date_filter):
        instance_ids = []

        filters = [
            {"Name": "launch-time", "Values": [date_filter]},
            {"Name": "instance-state-name", "Values": ["pending", "running"]},
        ]

        response = self.client.describe_instances(Filters=filters)
        next_token = response.get("NextToken")

        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                instance_ids.append(instance["InstanceId"])

        while next_token:
            response = self.client.describe_instances(Filters=filters)
            next_token = response.get("NextToken")

            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_ids.append(instance["InstanceId"])

        return instance_ids


def lambda_handler(event, _):
    """ Handles the incoming event """
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = ReflexAwsEc2Imdsv1Enabled(event_payload)
    rule.run_compliance_rule()
