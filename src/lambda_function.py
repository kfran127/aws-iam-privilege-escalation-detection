
import base64
import gzip
import json
import os

import boto3

sns = boto3.client("sns")


def analyze_event(detail):
    # Only inspect successful IAM API calls.
    if detail.get("eventSource") != "iam.amazonaws.com":
        return False

    if detail.get("errorCode"):
        return False

    event_name = detail.get("eventName", "")
    request = detail.get("requestParameters") or {}
    identity = detail.get("userIdentity") or {}

    finding = None

    if event_name == "AttachUserPolicy":
        if request.get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess":
            finding = {
                "severity": "CRITICAL",
                "reason": "AdministratorAccess attached to IAM user",
                "target": request.get("userName", "unknown"),
            }

    elif event_name == "AddUserToGroup":
        if request.get("groupName") == "lab-privileged-admins":
            finding = {
                "severity": "HIGH",
                "reason": "User added to designated privileged group",
                "target": request.get("userName", "unknown"),
            }

    elif event_name == "CreatePolicyVersion":
        if (
            request.get("setAsDefault") in (True, "true")
            and request.get("policyArn", "").endswith(":policy/lab-privileged-policy")
        ):
            finding = {
                "severity": "HIGH",
                "reason": "Privileged IAM policy default version changed",
                "target": request.get("policyArn", "unknown"),
            }

    if finding is None:
        return False

    alert = {
        "alert_type": "IAM Privilege Change",
        "severity": finding["severity"],
        "reason": finding["reason"],
        "target": finding["target"],
        "event_name": event_name,
        "actor": identity.get("arn", "unknown"),
        "source_ip": detail.get("sourceIPAddress", "unknown"),
        "event_time": detail.get("eventTime", "unknown"),
        "aws_region": detail.get("awsRegion", "unknown"),
        "event_id": detail.get("eventID", "unknown"),
        "classification": "Potentially risky permission change",
    }

    print(json.dumps(alert))

    sns.publish(
        TopicArn=os.environ["SNS_TOPIC_ARN"],
        Subject=f"[{finding['severity']}] AWS IAM Privilege Change",
        Message=json.dumps(alert, indent=2),
    )

    return True


def lambda_handler(event, context):
    # CloudWatch Logs subscription delivery
    if "awslogs" in event:
        compressed = base64.b64decode(event["awslogs"]["data"])
        payload = json.loads(gzip.decompress(compressed))

        if payload.get("messageType") == "CONTROL_MESSAGE":
            return {"statusCode": 200, "body": "Control message ignored"}

        processed = 0
        alerts = 0

        for log_event in payload.get("logEvents", []):
            detail = json.loads(log_event["message"])
            processed += 1

            if analyze_event(detail):
                alerts += 1

        return {
            "statusCode": 200,
            "body": json.dumps({
                "processed_events": processed,
                "alerts_published": alerts,
            }),
        }

    # Keep compatibility with existing EventBridge tests
    if "detail" in event:
        matched = analyze_event(event["detail"])
        return {
            "statusCode": 200,
            "body": "Security alert published" if matched else "No matching high-risk IAM activity",
        }

    return {"statusCode": 400, "body": "Unsupported event format"}
