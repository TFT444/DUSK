# Bedrock OIDC Setup for Real-Agent Validation

This document covers everything an operator needs to provision the AWS
infrastructure and run the DUSK real-agent Bedrock validation workflow.

---

## Architecture and Trust Boundary

The real-agent sandbox uses GitHub OIDC to obtain short-lived AWS credentials
with no long-lived keys stored anywhere.

```
GitHub Actions (real-agent environment)
  |
  | OIDC token
  | sub: repo:ShieldTech-Ltd/DUSK:environment:real-agent
  | aud: sts.amazonaws.com
  |
  v
AWS STS AssumeRoleWithWebIdentity
  |
  | session: up to 3600 s
  |
  v
IAM Role: DuskRealAgentBedrockRole
  |
  | bedrock:GetFoundationModel + bedrock:InvokeModel
  | resource: foundation model ARN (no account ID, no wildcard)
  |
  v
Bedrock Runtime Converse API (us-east-1)
  |
  v
DUSK Gate /v1/gate (Docker Compose, local only, no public endpoint)
```

The IAM role cannot be assumed by:
- Pull requests
- Arbitrary branches or forks
- Any environment other than `real-agent`
- Any repository other than `ShieldTech-Ltd/DUSK`

---

## Why OIDC

OIDC eliminates the need to store permanent AWS access keys in GitHub Secrets.
Credentials are issued per workflow run, scoped to the session duration (3600 s
maximum), and expire automatically. A leaked OIDC token from a workflow log is
useless after the session ends.

---

## Exact GitHub OIDC Subject

```
repo:ShieldTech-Ltd/DUSK:environment:real-agent
```

This is enforced in the IAM trust policy's `StringEquals` condition. Any token
with a different subject is rejected by STS before any AWS API call is made.

---

## Least-Privilege IAM Permissions

| Permission | Reason |
|---|---|
| `bedrock:GetFoundationModel` | Required by the workflow model pre-check |
| `bedrock:InvokeModel` | Required by Bedrock Converse API (`client.converse()`) |

No other permissions are granted. `bedrock:InvokeModelWithResponseStream` is
not included because the application does not use streaming.

Resource restriction:
```
arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0
```

The double colon (`::`) is correct. AWS foundation model ARNs do not include
an account ID.

---

## AWS Prerequisites

1. An AWS account with Bedrock access in `us-east-1`.
2. Model access enabled for `anthropic.claude-3-5-sonnet-20241022-v2:0`.
   Enable it in the Bedrock console under Model Access.
3. AWS CLI installed and authenticated (`aws sts get-caller-identity` returns
   successfully).
4. IAM permissions to create/update a CloudFormation stack with
   `CAPABILITY_NAMED_IAM`.
5. GitHub CLI installed and authenticated (`gh auth status` returns successfully)
   with admin access to the `ShieldTech-Ltd/DUSK` repository environment.

---

## Model Access Prerequisite

Before deploying, verify:

```bash
aws bedrock get-foundation-model \
  --model-identifier anthropic.claude-3-5-sonnet-20241022-v2:0 \
  --region us-east-1
```

If this returns `ValidationException` or `AccessDeniedException`, enable model
access in the AWS console (Bedrock > Model access > Manage model access) and
wait up to 5 minutes for propagation.

Do not change the model ID without explicit approval. Report the blocker
separately.

---

## Deployment Command

Run from the repository root after the PR is merged to `main`:

```powershell
scripts/setup-bedrock-oidc.ps1 -Deploy -Confirm
```

This will:
1. Check all prerequisites.
2. Validate Bedrock model availability.
3. Create or update the `dusk-bedrock-real-agent` CloudFormation stack.
4. Set `AWS_ROLE_ARN` as a GitHub environment variable in `real-agent`.

If a GitHub OIDC provider already exists in the account:

```powershell
scripts/setup-bedrock-oidc.ps1 -Deploy -Confirm `
  -ExistingOidcProviderArn arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
```

---

## Read-Only Validation Command

```powershell
scripts/test-bedrock-oidc-config.ps1
```

or equivalently:

```powershell
scripts/setup-bedrock-oidc.ps1
```

Safe to run at any time. Makes no changes.

---

## GitHub Environment Configuration

The `real-agent` environment must have:

| Name | Type | Value |
|---|---|---|
| `AWS_ROLE_ARN` | Variable | Set by the setup script after deployment |
| `AWS_REGION` | Variable | `us-east-1` |
| `BEDROCK_MODEL_ID` | Variable | `anthropic.claude-3-5-sonnet-20241022-v2:0` |
| `DUSK_GATE_API_KEY` | Secret | Set manually, not by this script |

Set variables and secrets in the GitHub UI:
Settings > Environments > real-agent > Environment variables / secrets.

---

## Manual Approval Process

The `real-agent` environment requires approval from `ritiksah141` before every
run. Self-review is prevented. When the workflow is triggered:

1. GitHub sends an approval request to `ritiksah141`.
2. The workflow is queued until approval is granted.
3. After approval, the runner starts, obtains OIDC credentials, and proceeds.

The setup script refuses to continue if `ritiksah141` is not a required reviewer.
Do not weaken this protection.

---

## How to Run the Workflow After the PR Reaches Main

Do not run the workflow from this PR. After the PR is merged to `main`:

1. Run the deployment steps above to configure `AWS_ROLE_ARN`.
2. Navigate to the repository on GitHub.
3. Go to Actions > Real-Agent Sandbox.
4. Click "Run workflow".
5. Select gate mode: `watch` (recommended for first run).
6. Submit. Wait for `ritiksah141` to approve.

The workflow will not proceed without explicit approval.

---

## How to Download and Inspect Evidence

After a successful run:

1. Go to Actions > Real-Agent Sandbox > the completed run.
2. Under "Artifacts", download `real-agent-validation-evidence`.
3. The archive contains:
   - `real-agent-results.xml`: pytest JUnit results
   - `real-agent-gate.log`: DUSK Gate container logs

Verify that `real-agent-results.xml` shows real test cases with pass/fail
results, not an empty file. Inspect `real-agent-gate.log` for actual ALLOW/BLOCK
verdicts.

---

## Rollback and Stack Deletion

To remove all AWS resources created by this stack:

```bash
aws cloudformation delete-stack \
  --stack-name dusk-bedrock-real-agent \
  --region us-east-1
```

After deletion, remove the `AWS_ROLE_ARN` variable from the `real-agent`
environment in the GitHub UI.

The GitHub OIDC provider is only deleted if this stack created it (it is
conditional). If you supplied an existing provider ARN, it will not be deleted.

---

## Expected Costs

The Bedrock Converse API is billed per input and output token. A single test
run with `anthropic.claude-3-5-sonnet-20241022-v2:0` typically costs under
USD 0.10 for a short scenario. The weekly scheduled run (Sunday 02:00 UTC)
still requires `ritiksah141` approval, so it will not run unattended.

Review the Bedrock pricing page for current rates before running large test
suites.

---

## Troubleshooting

**AccessDenied from Bedrock:**
- Verify the IAM role has `bedrock:GetFoundationModel` for the model pre-check.
- Verify model access is enabled in the Bedrock console.
- Verify the IAM role has `bedrock:InvokeModel` on the correct model ARN.
- Verify the region in `AWS_REGION` matches where model access was enabled.
- Run `aws bedrock get-foundation-model --model-identifier <id>` with the role's credentials.

**Invalid model ID:**
- Run `aws bedrock list-foundation-models --region us-east-1` to see available models.
- Do not change the model ID without approval. Report the blocker.

**Missing model access:**
- Enable access in the Bedrock console for the specific model.
- Wait up to 5 minutes for propagation.

**OIDC trust failure (error: not authorized to perform sts:AssumeRoleWithWebIdentity):**
- Verify the workflow is running in the `real-agent` environment.
- Verify the `sub` in the OIDC token matches the trust policy exactly.
- Check the OIDC provider ARN in the IAM role's trust policy.
- Verify the GitHub OIDC provider URL is `token.actions.githubusercontent.com`.

**Missing GitHub variables:**
- Run `scripts/test-bedrock-oidc-config.ps1` and check the output.
- Set missing variables in Settings > Environments > real-agent.

**EntityAlreadyExists (OIDC provider):**
- Supply the existing provider ARN with `-ExistingOidcProviderArn`.
- Run: `aws iam list-open-id-connect-providers` to find the ARN.

---

## Evidence Limitations

Green CI on any PR does not indicate a real Bedrock run.

A skipped or mocked test is not success.

The scheduled trigger still requires `ritiksah141` approval and will not run
unattended.

Only a credentialed, inspectable workflow run that completes with real Bedrock
responses is real validation. Inspect the evidence artifact to confirm.
