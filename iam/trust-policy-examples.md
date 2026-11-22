# Deploying the audit role

`audit-role.cfn.yaml` creates `AWSHealthAuditRole`: the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies, an inline explicit deny (the same statements as `deny-policy.json`), and a one-hour maximum session. The role cannot change anything.

Account `111122223333` is the audited account in every example; `444455556666` is a management or identity account.

## 1. Trust an IAM user or role in the same account

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name aws-health-audit-role \
  --template-file iam/audit-role.cfn.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustedPrincipalArn=arn:aws:iam::111122223333:user/alice
```

The resulting trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustedPrincipal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:user/alice"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

The user `alice` still needs `sts:AssumeRole` on `arn:aws:iam::111122223333:role/AWSHealthAuditRole` in her own policy.

## 2. Trust an IAM Identity Center (SSO) role

Use the full ARN of the permission set role, including its path, as shown in IAM > Roles:

```
TrustedPrincipalArn=arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_0123456789abcdef
```

If the permission set is reprovisioned, the suffix changes and the stack must be updated.

## 3. Trust a role in the management account

```
TrustedPrincipalArn=arn:aws:iam::444455556666:role/aws-health-auditor
```

To audit many accounts, deploy the template with a CloudFormation StackSet from the management account and run `awshealth collect` once per account profile.

## 4. GitHub Actions through OIDC

The account needs the GitHub OIDC provider (`token.actions.githubusercontent.com`) already created. Deploy with:

```
GitHubRepo=example-org/aws-health-reports GitHubEnvironment=aws-health-audit
```

The trust statement only accepts tokens for that repository running in that GitHub environment:

```json
{
  "Sid": "GitHubOidc",
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:example-org/aws-health-reports:environment:aws-health-audit"
    }
  }
}
```

Protect the environment with required reviewers in GitHub so a pull request from a fork cannot run the audit. A workflow step:

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::111122223333:role/AWSHealthAuditRole
    aws-region: us-east-1
- run: awshealth collect --out "$RUNNER_TEMP/run" && awshealth check --run "$RUNNER_TEMP/run"
```

## 5. CLI profile for awshealth

In `~/.aws/config` (edit it yourself; the plugin never reads it):

```ini
[profile aws-health-audit]
role_arn = arn:aws:iam::111122223333:role/AWSHealthAuditRole
source_profile = default
duration_seconds = 3600
region = us-east-1
```

With IAM Identity Center, use `sso_session` and `sso_role_name` in the source profile instead of `source_profile = default`. Then:

```bash
awshealth collect --profile aws-health-audit
```

## Cost and metric reads

`AllowCostAndMetrics=false` (the default) denies `cloudwatch:GetMetricData` and `cloudwatch:GetMetricStatistics`, so `awshealth collect --metrics` reports those checks as `no_access`. Cost Explorer is not in the deny; with the default the template simply does not grant `ce:Get*`. Set it to `true` to allow `ce:Get*` and `cloudwatch:GetMetricData`. Cost Explorer costs US$0.01 per request and metric reads are billed per metric.

## Using only the deny policy

If you prefer your own role, attach `SecurityAudit` and `ViewOnlyAccess` and add `deny-policy.json` as an inline policy. Inline policies of a role share a 10,240-character aggregate limit (whitespace not counted); if you create it as a customer managed policy instead, each managed policy is limited to 6,144 characters. The deny policy is well under both. Remove the `DenyBilledMetricReads` statement if you want `--metrics`.
