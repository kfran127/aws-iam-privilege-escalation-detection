"""Offline simulated tests of the unchanged export; no AWS SDK/network access."""
import base64
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((Path(__file__).parent / 'fixtures' / 'simulated_attach_user_policy.json').read_text())
TOPIC = 'arn:aws:sns:us-east-2:123456789012:simulated-alert-topic'


def subscription(records=(), message_type='DATA_MESSAGE'):
    payload = {
        'messageType': message_type,
        'owner': '123456789012',
        'logGroup': 'simulated-log-group',
        'logStream': 'simulated-log-stream',
        'subscriptionFilters': ['simulated-filter'],
        'logEvents': [{'id': f'simulated-log-{i}', 'timestamp': 0,
                       'message': json.dumps(record)} for i, record in enumerate(records)],
    }
    return {'awslogs': {'data': base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.sns = Mock()
        sdk = types.ModuleType('boto3')
        sdk.client = Mock(return_value=self.sns)
        spec = importlib.util.spec_from_file_location('export_under_test', ROOT / 'src' / 'lambda_function.py')
        self.detector = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'boto3': sdk}):
            spec.loader.exec_module(self.detector)
        sdk.client.assert_called_once_with('sns')
        self.env = patch.dict(os.environ, {'SNS_TOPIC_ARN': TOPIC})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.output = redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.record = copy.deepcopy(FIXTURE)

    def analyze(self, event_name=None, **parameters):
        if event_name:
            self.record['eventName'] = event_name
            self.record['requestParameters'] = parameters
        return self.detector.analyze_event(self.record)

    def assert_no_match(self):
        self.assertFalse(self.analyze())
        self.sns.publish.assert_not_called()

    def test_admin_attachment_publishes_complete_finding(self):
        self.assertTrue(self.analyze())
        args = self.sns.publish.call_args.kwargs
        self.assertEqual(args['TopicArn'], TOPIC)
        self.assertEqual(args['Subject'], '[CRITICAL] AWS IAM Privilege Change')
        self.assertEqual(json.loads(args['Message']), {
            'alert_type': 'IAM Privilege Change', 'severity': 'CRITICAL',
            'reason': 'AdministratorAccess attached to IAM user', 'target': 'simulated-user',
            'event_name': 'AttachUserPolicy', 'actor': self.record['userIdentity']['arn'],
            'source_ip': '192.0.2.10', 'event_time': self.record['eventTime'],
            'aws_region': 'us-east-1', 'event_id': 'simulated-unit-event-001',
            'classification': 'Potentially risky permission change',
        })

    def test_other_user_also_matches(self):
        self.record['requestParameters']['userName'] = 'other-simulated-user'
        self.assertTrue(self.analyze())

    def test_other_policy_does_not_match(self):
        self.record['requestParameters']['policyArn'] = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
        self.assert_no_match()

    def test_failed_iam_call_ignored(self):
        self.record['errorCode'] = 'AccessDenied'
        self.assert_no_match()

    def test_non_iam_ignored(self):
        self.record['eventSource'] = 'ec2.amazonaws.com'
        self.assert_no_match()

    def test_detachment_not_alerted(self):
        self.record['eventName'] = 'DetachUserPolicy'
        self.assert_no_match()

    def test_group_match(self):
        self.assertTrue(self.analyze('AddUserToGroup', groupName='lab-privileged-admins', userName='simulated-user'))
        self.assertEqual(self.sns.publish.call_args.kwargs['Subject'], '[HIGH] AWS IAM Privilege Change')

    def test_other_group_not_alerted(self):
        self.assertFalse(self.analyze('AddUserToGroup', groupName='ordinary-group'))
        self.sns.publish.assert_not_called()

    def test_default_policy_version_matches_boolean_and_string(self):
        for value in (True, 'true'):
            with self.subTest(value=value):
                self.sns.reset_mock()
                self.assertTrue(self.analyze('CreatePolicyVersion', setAsDefault=value,
                    policyArn='arn:aws:iam::123456789012:policy/lab-privileged-policy'))
                self.assertEqual(self.sns.publish.call_args.kwargs['Subject'], '[HIGH] AWS IAM Privilege Change')

    def test_policy_version_negative_cases(self):
        for value, arn in (
            (False, 'arn:aws:iam::123456789012:policy/lab-privileged-policy'),
            ('false', 'arn:aws:iam::123456789012:policy/lab-privileged-policy'),
            (True, 'arn:aws:iam::123456789012:policy/ordinary-policy'),
            (True, 'arn:aws:iam::123456789012:policy/path/lab-privileged-policy'),
        ):
            with self.subTest(default=value, arn=arn):
                self.assertFalse(self.analyze('CreatePolicyVersion', setAsDefault=value, policyArn=arn))
        self.sns.publish.assert_not_called()

    def test_missing_request_ignored(self):
        self.record['requestParameters'] = None
        self.assert_no_match()

    def test_missing_context_falls_back_to_unknown(self):
        for key in ('userIdentity', 'sourceIPAddress', 'eventTime', 'awsRegion', 'eventID'):
            self.record.pop(key)
        self.assertTrue(self.analyze())
        alert = json.loads(self.sns.publish.call_args.kwargs['Message'])
        for key in ('actor', 'source_ip', 'event_time', 'aws_region', 'event_id'):
            self.assertEqual(alert[key], 'unknown')

    def test_compressed_mixed_batch(self):
        negative = copy.deepcopy(self.record)
        negative['errorCode'] = 'AccessDenied'
        response = self.detector.lambda_handler(subscription([self.record, negative]), None)
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(json.loads(response['body']), {'processed_events': 2, 'alerts_published': 1})
        self.sns.publish.assert_called_once()

    def test_empty_batch(self):
        result = self.detector.lambda_handler(subscription(), None)
        self.assertEqual(json.loads(result['body']), {'processed_events': 0, 'alerts_published': 0})
        self.sns.publish.assert_not_called()

    def test_control_message_ignored(self):
        result = self.detector.lambda_handler(subscription([self.record], 'CONTROL_MESSAGE'), None)
        self.assertEqual(result, {'statusCode': 200, 'body': 'Control message ignored'})
        self.sns.publish.assert_not_called()

    def test_legacy_detail_input(self):
        result = self.detector.lambda_handler({'detail': self.record}, None)
        self.assertEqual(result, {'statusCode': 200, 'body': 'Security alert published'})
        self.sns.publish.assert_called_once()

    def test_legacy_negative_input(self):
        self.record['errorCode'] = 'AccessDenied'
        result = self.detector.lambda_handler({'detail': self.record}, None)
        self.assertEqual(result['body'], 'No matching high-risk IAM activity')
        self.sns.publish.assert_not_called()

    def test_unsupported_envelope(self):
        self.assertEqual(self.detector.lambda_handler({}, None)['statusCode'], 400)
        self.sns.publish.assert_not_called()

    def test_malformed_cloudtrail_message_raises(self):
        envelope = subscription([self.record])
        payload = json.loads(gzip.decompress(base64.b64decode(envelope['awslogs']['data'])))
        payload['logEvents'][0]['message'] = '{invalid json'
        envelope['awslogs']['data'] = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
        with self.assertRaises(json.JSONDecodeError):
            self.detector.lambda_handler(envelope, None)
        self.sns.publish.assert_not_called()

    def test_invalid_gzip_raises(self):
        with self.assertRaises(gzip.BadGzipFile):
            self.detector.lambda_handler({'awslogs': {'data': base64.b64encode(b'invalid gzip').decode()}}, None)
        self.sns.publish.assert_not_called()

    def test_sns_failure_propagates(self):
        self.sns.publish.side_effect = RuntimeError('simulated publish failure')
        with self.assertRaisesRegex(RuntimeError, 'simulated publish failure'):
            self.analyze()

    def test_duplicate_records_publish_twice(self):
        result = self.detector.lambda_handler(subscription([self.record, self.record]), None)
        self.assertEqual(json.loads(result['body'])['alerts_published'], 2)
        self.assertEqual(self.sns.publish.call_count, 2)


if __name__ == '__main__':
    unittest.main()
