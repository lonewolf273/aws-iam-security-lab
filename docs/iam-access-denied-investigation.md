# AWS IAM Permission Troubleshooting

## Project details

- Date: November 18, 2026
- Region: us-east-1
- Role: PortfolioLabRole

## Before the fix

The ListRolePolicies request failed because the role did not have permission to perform iam:ListRolePolicies.

CloudTrail recorded AccessDenied at 00:14:51 IST.

![Before the fix: AccessDenied](../evidence-private/before-access-denied.png)

## Permission fix

Added iam:ListRolePolicies to the existing policy while keeping the resource restricted to PortfolioLabRole.

## After the fix

ListRolePolicies succeeded and returned the policy name PortfolioReadOwnRole.

CloudTrail recorded the successful request at 00:33:13 IST.

![After the fix: successful request](../evidence-private/after-access-allowed.png)

## Additional verification

ListUsers remained denied because the role did not have iam:ListUsers permission.

## Conclusion

The specific missing permission was corrected. The intended operation succeeded, while the unrelated ListUsers operation remained blocked.