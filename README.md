# AWS IAM Security Lab



I investigated an AWS permission failure, verified the fix in CloudTrail,

and built a Python scanner that flags three IAM changes for review.



## Run the offline demo



From the project folder, run:



```cmd

python scan_events.py sample_events.json

```



The sample contains four synthetic events. Three trigger findings:

an access key was created, the AdministratorAccess policy was attached,

and a role trust policy was updated. The fourth event is a routine read.



Verified output: `Events scanned: 4 | Findings: 3`



## Real AWS investigation



CloudTrail showed that `PortfolioLabRole` was denied permission to list

its own inline policies. I added `iam:ListRolePolicies` for that role

and verified the same command succeeded. Listing IAM users remained denied.



I also ran the scanner against 10 real `ListRolePolicies` events. It

reported zero findings, as expected: all 10 were reads, while the three

detection rules look for changes.



[Read the investigation](docs/iam-access-denied-investigation.md)



## Run the tests



```cmd

python -m pip install pytest

python -m pytest -q test_detections.py

```

## Current scope

The lab investigates IAM management events from one AWS account. The Python scanner runs on demand against a saved CloudTrail CLI export or the synthetic sample. Its three rules identify successful access-key creation, attachment of the AWS-managed AdministratorAccess policy, and role trust-policy updates. An analyst reviews the findings. Continuous collection, live notifications and automated remediation are outside the current implementation.

## Real world problems the lab addresses

| Operational problem | How the lab helps |
|---|---|
| A support ticket reports AccessDenied | Identify the calling role, requested action and error in CloudTrail. In the live exercise, adding iam:ListRolePolicies on the specific role restored the intended read. A separate ListUsers test still returned AccessDenied. |
| A new access key appears | Flag a successful CreateAccessKey call so an analyst can check the identity and confirm the owner expected the credential. |
| A user, group or role receives administrator access | Flag attachment of the exact AdministratorAccess policy. Use the event ID to investigate the actor and recipient and compare the change with its approval. |
| A role’s trust policy changes | Identify the affected role. Review the policy change to determine who can now assume it and whether that access was intended. |

The permissions ticket was reproduced in AWS. The three change-detection cases were demonstrated with synthetic events.

## Future improvements

Planned work, in suggested implementation order:

1. **Collect new events on demand.** Build a read-only Boto3 collector with pagination and a saved checkpoint. Deduplicate by event ID and test that replaying the same time window produces no duplicate findings.
2. **Make findings easier to investigate.** Produce a local JSON or Markdown report with event ID, time, actor, target and outcome. Add tests for missing fields, duplicate events and denied changes.
3. **Rebuild and validate the lab automatically.** Describe the disposable IAM role and policy in Terraform. Run offline tests on each pull request and verify creation and cleanup before claiming reproducibility.
4. **Evaluate near-real-time alerts.** Pilot scheduled local collection while the laptop is running. Measure the delay from an event’s timestamp to its alert and check for missed or repeated alerts after a restart. Evaluate hosted delivery separately against the ₹0 budget.
5. **Add optional local AI summaries.** Use Ollama on demand to draft summaries from sanitized findings. Compare each claim with its event ID and retain human review of permission changes.
