# Incident report: authorized IAM privilege-change simulation

## Identification and classification

| Attribute | Value |
|---|---|
| Exercise date | October 12, 2026 |
| Environment | Personal AWS security lab; processing region `us-east-2` |
| Target | `lab-iam-test-user` |
| Activity | Controlled attachment of AWS-managed AdministratorAccess |
| Detection classification | CRITICAL — potentially risky permission change |
| Exercise classification | Authorized simulation; no confirmed compromise |
| Response | Manual policy removal |

## Executive summary

A controlled permission change exercised the completed CloudTrail → CloudWatch Logs → subscription filter → Lambda → SNS email pipeline. The detector generated a CRITICAL finding for AdministratorAccess attached to the test user. The operator manually detached the policy, and CloudTrail recorded the removal. Post-test checks were reported to confirm zero directly attached policies, no group memberships, and no access keys.

No malicious actor, unauthorized access, or use of the elevated permissions is established by this exercise. Detection was automatic; containment was manual.

## Detection evidence and CloudTrail details

| Field | Attachment |
|---|---|
| API name | `AttachUserPolicy` |
| Event source | IAM; `iam.amazonaws.com` |
| Event time | `2026-10-12T23:37:33Z` |
| Event ID | `af73f570-2212-4354-b5c8-8206bfbeeca4` |
| Target user | `lab-iam-test-user` |
| Policy | `arn:aws:iam::aws:policy/AdministratorAccess` |
| Event region | `us-east-1` |
| Initiating identity | Assumed-role ARN for `AccountFullAccessRole`; account portion obscured in evidence |
| Source IP | `45.134.142.210` — operator's VPN |

[Screenshot 13](../screenshots/13-real-iam-privilege-escalation-alert.png) shows the SNS-delivered email, its CRITICAL subject, and the above event context. The raw CloudTrail JSON for this final attachment was not supplied; the attachment fields are supported by the delivered finding and the operator's test record.

[Screenshot 14](../screenshots/14-iam-privilege-remediation.png) shows the removal event for the same user and policy. It displays log timestamp `2026-10-12T19:39:15.471-04:00` and event ID `713773e9-88a1-4d9e-bb5d-ac06837d003f`. The table field is `@timestamp`; without raw JSON, do not treat its milliseconds as an independently verified CloudTrail `eventTime`.

[Screenshot 10](../screenshots/10-real-iam-cloudtrail-events.png) shows earlier real attachment/detachment activity around 01:10 EDT with different event IDs. It is supporting evidence of IAM telemetry, not the final 23:37 UTC attachment.

## Investigation methodology

1. Read the CRITICAL email and identify the user, initiating role, policy, source IP, event region, and event ID.
2. Correlate CloudTrail IAM activity in the lab's CloudWatch log group, distinguishing earlier tests from the final simulation.
3. Establish that the activity was an authorized operator action. The detector itself does not infer intent.
4. Remove the test elevation manually and locate the matching `DetachUserPolicy` event.
5. Verify the test user's policies, groups, and credentials after the exercise.

The following query is supplied for investigation, not as a transcript of an additional executed check:

```text
fields @timestamp, eventTime, eventName, eventSource,
       requestParameters.userName, requestParameters.policyArn, eventID
| filter eventSource = "iam.amazonaws.com"
| filter requestParameters.userName = "lab-iam-test-user"
| filter eventName in ["AttachUserPolicy", "DetachUserPolicy"]
| sort @timestamp asc
| limit 50
```

## Timeline

EDT is UTC−04:00. All entries below are on October 12, 2026.

| Activity | UTC | EDT | Basis |
|---|---|---|---|
| Attach AdministratorAccess | 23:37:33 | 19:37:33 | Finding event time and operator record |
| Automatic CRITICAL email | Exact timestamp not retained | UI shows 19:39, minute precision | Screenshot 13 |
| Manual policy removal | Approximately 23:39:15 | Approximately 19:39:15 | Operator record and screenshot 14 |
| Post-remediation verification | Not recorded | Not recorded | Operator-reported checks |

The approximately 102-second interval from attachment to removal reflects this exercise's manual response. Alert delivery is only visible at minute precision, so exact detection and notification latency cannot be calculated.

## Containment and remediation

The operator manually removed AdministratorAccess from `lab-iam-test-user`. CloudTrail recorded `DetachUserPolicy` with event ID `713773e9-88a1-4d9e-bb5d-ac06837d003f`. Lambda did not perform this action, and removal is not one of the three alerting rules.

Post-test verification confirmed:

- Zero directly attached IAM policies.
- No IAM group memberships.
- No access keys.

These final-state checks are supplied by the operator. Screenshot 14 proves the removal event, but does not independently prove all three inventory checks. Screenshot 03 is a pre-test baseline, not post-remediation evidence. A complete effective-permission assessment was not supplied.

## MITRE ATT&CK

The observed addition of administrative permissions aligns with [T1098.003 — Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/), under [T1098](https://attack.mitre.org/techniques/T1098/). This mapping concerns behavior that could support privilege escalation or persistence in an adversarial setting; this exercise establishes neither malicious persistence nor account compromise.

## Outcome and limitations

The real test validated the AdministratorAccess rule's complete alerting path and demonstrated manual containment with a correlated removal event. The `AddUserToGroup` and `CreatePolicyVersion` rules remain unvalidated end-to-end. No SLA, repeated-trial performance metric, automated remediation, or evidence of attacker activity is claimed.

[Back to README](../README.md)
