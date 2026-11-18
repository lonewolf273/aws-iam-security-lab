\# AWS IAM Security Lab



I investigated an AWS permission failure, verified the fix in CloudTrail,

and built a Python scanner that flags three IAM changes for review.



\## Run the offline demo



From the project folder, run:



```cmd

python scan\_events.py sample\_events.json

```



The sample contains four synthetic events. Three trigger findings:

an access key was created, the AdministratorAccess policy was attached,

and a role trust policy was updated. The fourth event is a routine read.



Verified output: `Events scanned: 4 | Findings: 3`



\## Real AWS investigation



CloudTrail showed that `PortfolioLabRole` was denied permission to list

its own inline policies. I added `iam:ListRolePolicies` for that role

and verified the same command succeeded. Listing IAM users remained denied.



I also ran the scanner against 10 real `ListRolePolicies` events. It

reported zero findings, as expected: all 10 were reads, while the three

detection rules look for changes.



\[Read the investigation](docs/iam-access-denied-investigation.md)



\## Run the tests



```cmd

python -m pip install pytest

python -m pytest -q test\_detections.py

```

