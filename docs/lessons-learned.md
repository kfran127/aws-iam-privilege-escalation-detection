# Engineering decisions and lessons learned

## Regional telemetry constraints

The original design explored EventBridge for IAM event delivery. In this lab, global IAM events were not delivered to the EventBridge rule in the available Ohio region, and the AWS Free plan restricted access to the region needed for that design. This is the operator's observed lab constraint, not a claim about all AWS accounts or every EventBridge configuration.

The pipeline was redesigned to use the multi-region CloudTrail trail's delivery to CloudWatch Logs. A log subscription then invoked the Python Lambda detector. The October 12 real AdministratorAccess attachment produced an SNS email through this revised path.

EventBridge-shaped test payload support remains in the function for compatibility. It is not part of the final architecture. Images documenting the abandoned EventBridge approach were excluded from the evidence set to keep the working architecture clear.

## Separate rule logic from transport verification

A successful Lambda console test demonstrates behavior for the supplied payload. It does not prove that real CloudTrail records arrive through the deployed subscription. Screenshots 06 and 07 document synthetic testing; screenshot 11 documents a real IAM event and delivered notification. These evidence types answer different questions and should remain explicitly labeled.

## Preserve event provenance

Global IAM records can carry `us-east-1` while processing happens in `us-east-2`. Keeping the CloudTrail event region and event ID in the finding helps analysts correlate the original record without conflating resource location and event provenance.

## Document what permission evidence proves

A topic-scoped `sns:Publish` statement is useful evidence of constrained publication permission. The screenshot does not show every policy attached to the role, and its filename alone cannot establish least privilege. A future configuration review should inventory the complete execution-role permissions and Lambda invocation policy.

## Verify response independently

An alert confirms a rule match; a detach event records the response action. Neither alone establishes the user's complete final permission state. Record policy, group, and credential checks separately, retaining their timestamps and outputs in future exercises.

## Proposed next steps

1. Validate group membership and default-policy-version detections with authorized AWS tests.
2. Review role permissions and record the full filter and invocation configuration.
3. Add deduplication, per-record failure isolation, and pipeline health monitoring.
4. Add approval context and effective-permission analysis to improve triage.
5. Retain sanitized raw events and timestamped post-response inventory evidence.

These improvements are not present in the supplied deployment.

[Back to README](../README.md)
