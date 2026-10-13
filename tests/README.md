# Offline simulated unit tests

These tests import the unchanged Lambda export while substituting a mocked boto3 module and SNS client. They do not load the AWS SDK, read AWS credentials, contact AWS, or deploy resources. Python's standard library is sufficient.

Run from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The fixture is synthetic: account `123456789012`, documentation IP `192.0.2.10`, a simulated identity, and a simulated event ID. Positive and negative variants are generated from that record. Subscription fixtures are JSON envelopes compressed with gzip and encoded with base64 inside the tests.

Coverage includes the three rule predicates, excluded events, failed API calls, missing context, mixed and empty subscription batches, control messages, the legacy `detail` input, unsupported envelopes, malformed JSON/gzip, propagated SNS errors, and duplicate delivery behavior.

The failure and duplicate cases document current limitations; they do not add recovery or deduplication to the deployed code. SNS publishing assertions validate the destination, subject, and structured finding.

Successful offline tests do not prove an AWS deployment or email delivery. Only the AdministratorAccess attachment has separate real AWS end-to-end validation. See the [incident report](../docs/incident-report.md).
