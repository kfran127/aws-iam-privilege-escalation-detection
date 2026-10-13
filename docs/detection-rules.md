# Detection rules

## Evaluation contract

The predicates below are taken from the [actual Lambda export](../src/lambda_function.py). Every rule first requires `eventSource` to equal `iam.amazonaws.com` and a falsy or absent `errorCode`. The detector does not evaluate `errorMessage` independently or query AWS to confirm a change's effect.

| API event | Source predicate | Severity | End-to-end AWS status |
|---|---|---|---|
| `AttachUserPolicy` | `requestParameters.policyArn == "arn:aws:iam::aws:policy/AdministratorAccess"` | CRITICAL | Validated October 12, 2026 |
| `AddUserToGroup` | `requestParameters.groupName == "lab-privileged-admins"` | HIGH | Implemented; not validated |
| `CreatePolicyVersion` | `setAsDefault in (True, "true")` and policy ARN ends with `:policy/lab-privileged-policy` | HIGH | Implemented; not validated |

The AdministratorAccess rule applies to any user, not only `lab-iam-test-user`. It does not cover `AttachRolePolicy`, `AttachGroupPolicy`, inline policies, or other powerful managed policies. The group rule matches the group name; it does not inspect the group's policies. The policy-version rule matches the exact ARN suffix, so a policy under an IAM path will not match that suffix. It does not inspect the new policy document or determine whether permissions increased. Python tuple equality also means numeric `1` compares equal to `True` in this predicate; uppercase string `"True"` does not match.

## Finding schema

| Field | Source / meaning |
|---|---|
| `alert_type` | Constant `IAM Privilege Change` |
| `severity`, `reason` | Selected rule |
| `target` | User name, or policy ARN for policy-version changes |
| `event_name` | CloudTrail `eventName` |
| `actor` | `userIdentity.arn` |
| `source_ip` | `sourceIPAddress` |
| `event_time` | `eventTime` |
| `aws_region` | CloudTrail `awsRegion` |
| `event_id` | CloudTrail `eventID` |
| `classification` | Constant `Potentially risky permission change` |

SNS subject: `[SEVERITY] AWS IAM Privilege Change`. Message: indented JSON finding. Failed API calls are intentionally skipped; visibility into failed attempts requires separate detection coverage.

## Analyst triage

Use the event ID to correlate the alert with CloudTrail. Verify the initiating identity, request parameters, authorization context, and change approval. Check the target's direct policies, group memberships, credentials, and broader effective access. Determine whether subsequent activity used the new permissions. If an unexpected change is confirmed, follow the organization's approved containment procedure and verify the resulting state.

Approved administrator actions can match these rules. Severity represents the risk of the permission change, not proof of malicious intent. The authorized simulation intentionally produced a CRITICAL match.

## Validation boundaries

The real AdministratorAccess test proved ingestion, rule evaluation, SNS publication, and email delivery for one controlled event. [Offline tests](../tests/README.md) exercise synthetic positive and negative cases for all three rules. They cannot prove the HIGH rules' AWS delivery path or resolve coverage gaps.

[Back to README](../README.md)
