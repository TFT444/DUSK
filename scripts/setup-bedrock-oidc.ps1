#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys or validates DUSK Bedrock OIDC infrastructure.
.DESCRIPTION
    Modes:
      (default)        Read-only validation. No AWS or GitHub writes.
      -Deploy -Confirm Creates or updates the CloudFormation stack and sets
                       AWS_ROLE_ARN as a GitHub environment variable.

    This script never dispatches the real-agent workflow.
    This script never prints secret values.
    AWS account ID is printed as deployment context; it is not a secret.

.PARAMETER Deploy
    Enable deployment mode. Requires -Confirm.

.PARAMETER Confirm
    Required when using -Deploy. Acknowledges that AWS IAM resources will be
    created or updated.

.PARAMETER StackName
    CloudFormation stack name. Default: dusk-bedrock-real-agent

.PARAMETER GitHubRepo
    GitHub repository in owner/repo format. Default: ShieldTech-Ltd/DUSK

.PARAMETER GitHubEnvironment
    GitHub Actions environment name. Default: real-agent

.PARAMETER TemplatePath
    Path to the CloudFormation template. Default: resolved relative to script.

.PARAMETER ExistingOidcProviderArn
    ARN of an existing GitHub OIDC provider in this account. Leave blank to
    create a new provider. Supply to avoid EntityAlreadyExists errors.

.EXAMPLE
    scripts/setup-bedrock-oidc.ps1
    Validate prerequisites only.

.EXAMPLE
    scripts/setup-bedrock-oidc.ps1 -Deploy -Confirm
    Deploy the CloudFormation stack and configure GitHub environment variable.
#>
[CmdletBinding()]
param(
    [switch]$Deploy,
    [switch]$Confirm,
    [string]$StackName = "dusk-bedrock-real-agent",
    [string]$GitHubRepo = "ShieldTech-Ltd/DUSK",
    [string]$GitHubEnvironment = "real-agent",
    [string]$TemplatePath = "",
    [string]$ExistingOidcProviderArn = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $TemplatePath) {
    $TemplatePath = Join-Path $ScriptDir "..\infra\aws\bedrock-real-agent\template.yaml"
}
$TemplatePath = Resolve-Path $TemplatePath

function Test-CommandAvailable {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Error "$Name is not installed or not in PATH. Install it and re-run."
        exit 1
    }
    Write-Host "$Name found: $((Get-Command $Name).Source)"
}

function Get-AwsRegion {
    $region = $env:AWS_DEFAULT_REGION
    if (-not $region) { $region = $env:AWS_REGION }
    if (-not $region) {
        $region = aws configure get region 2>$null
    }
    if (-not $region) {
        Write-Error "AWS region not configured. Set AWS_DEFAULT_REGION or run 'aws configure'."
        exit 1
    }
    return $region
}

# Step 1: Prerequisites
Write-Host "=== Checking prerequisites ==="
Test-CommandAvailable "aws"
Test-CommandAvailable "gh"

# Step 2: AWS authentication
Write-Host ""
Write-Host "=== Verifying AWS authentication ==="
$identityJson = aws sts get-caller-identity --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "AWS CLI is not authenticated. Configure credentials and re-run.`n$identityJson"
    exit 1
}
$identity = $identityJson | ConvertFrom-Json
Write-Host "AWS account: $($identity.Account)"
Write-Host "AWS ARN:     $($identity.Arn)"

# Step 3: GitHub CLI authentication
Write-Host ""
Write-Host "=== Verifying GitHub CLI authentication ==="
gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "GitHub CLI is not authenticated. Run 'gh auth login'."
    exit 1
}
Write-Host "GitHub CLI authenticated."

# Step 4: AWS region
$region = Get-AwsRegion
Write-Host "AWS region: $region"

# Step 5: Bedrock model availability
Write-Host ""
Write-Host "=== Validating Bedrock model availability ==="
$modelId = "us.anthropic.claude-sonnet-4-6"
$foundationModelId = "anthropic.claude-sonnet-4-6"
# Claude 4.x models use inference profiles. Check via list-inference-profiles.
$profilesJson = aws bedrock list-inference-profiles `
    --region $region `
    --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error @"
Could not list Bedrock inference profiles in region '$region'.
AWS error: $profilesJson

Action required:
  1. Confirm the AWS region is correct (must be us-east-1 for Claude Sonnet 4.6).
  2. Confirm the IAM user has bedrock:ListInferenceProfiles permission.
  3. Do not silently change the model ID. Report this blocker separately.
"@
    exit 1
}
$profiles = $profilesJson | ConvertFrom-Json
$match = $profiles.inferenceProfileSummaries | Where-Object { $_.inferenceProfileId -eq $modelId }
if (-not $match) {
    Write-Error @"
Inference profile '$modelId' not found in region '$region'.
Available profiles: $($profiles.inferenceProfileSummaries.inferenceProfileId -join ', ')
"@
    exit 1
}
Write-Host "Bedrock inference profile available: $($match.inferenceProfileId)"

# Step 6: GitHub environment protection check
Write-Host ""
Write-Host "=== Verifying GitHub environment protection ==="
$envJson = gh api "repos/$GitHubRepo/environments/$GitHubEnvironment" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not read environment '$GitHubEnvironment' in $GitHubRepo. Check repo access.`n$envJson"
    exit 1
}
$envInfo = $envJson | ConvertFrom-Json
$reviewerLogins = @()
foreach ($rule in $envInfo.protection_rules) {
    if ($rule.type -eq "required_reviewers") {
        foreach ($reviewer in $rule.reviewers) {
            $reviewerLogins += $reviewer.reviewer.login
        }
    }
}
if ("ritiksah141" -notin $reviewerLogins) {
    Write-Error "SECURITY: Environment '$GitHubEnvironment' does not require ritiksah141 approval. Do not weaken environment protection."
    exit 1
}
Write-Host "Environment protection confirmed: ritiksah141 required as reviewer."

# Step 6b: Validate deployment branch policy restricts to main only.
# The real-agent workflow checks github.ref at runtime, but the environment
# deployment_branch_policy is the GitHub-enforced gate that prevents any
# non-main branch from even entering the environment. Both controls must
# be in place. custom_branch_policies:true with no branches configured
# allows any branch; protected_branches:true restricts to protected branches
# (which must include main). Either form is acceptable, but unrestricted
# deployments are not.
Write-Host ""
Write-Host "=== Verifying environment deployment branch policy ==="
$deployPolicy = $envInfo.deployment_branch_policy
if ($null -eq $deployPolicy) {
    Write-Error @"
SECURITY: Environment '$GitHubEnvironment' has no deployment_branch_policy.
Without a branch policy, any branch can deploy to this environment and assume
the real-agent OIDC role. Configure the environment to restrict deployments
to the protected main branch only.
"@
    exit 1
}

$protectedBranches  = $deployPolicy.protected_branches
$customBranchPolicy = $deployPolicy.custom_branch_policies

if ($protectedBranches -eq $true) {
    Write-Host "Deployment branch policy: protected_branches=true (main is protected)"
} elseif ($customBranchPolicy -eq $true) {
    # Verify that custom policies actually list 'main' and nothing else.
    $branchPoliciesJson = gh api "repos/$GitHubRepo/environments/$GitHubEnvironment/deployment-branch-policies" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Could not read custom deployment branch policies for '$GitHubEnvironment'.`n$branchPoliciesJson"
        exit 1
    }
    $branchPolicies   = ($branchPoliciesJson | ConvertFrom-Json).branch_policies
    $allowedPatterns  = @($branchPolicies | ForEach-Object { $_.name })
    $onlyMainAllowed  = ($allowedPatterns.Count -eq 1) -and ($allowedPatterns[0] -eq "main")
    if (-not $onlyMainAllowed) {
        Write-Error @"
SECURITY: Environment '$GitHubEnvironment' uses custom_branch_policies but
the allowed patterns are: $($allowedPatterns -join ', ')
Only 'main' must be allowed. Remove any other patterns and re-run.
"@
        exit 1
    }
    Write-Host "Deployment branch policy: custom_branch_policies, pattern=['main'] only"
} else {
    Write-Error @"
SECURITY: Environment '$GitHubEnvironment' deployment_branch_policy is
unrestricted (protected_branches=false, custom_branch_policies=false).
Any branch can deploy to this environment. Restrict it to main only.
"@
    exit 1
}
Write-Host "Deployment branch restriction confirmed: only main may deploy to '$GitHubEnvironment'."

# Step 7: Confirm existing variables and secrets are configured
Write-Host ""
Write-Host "=== Checking environment variable and secret presence ==="
$varsJson = gh api "repos/$GitHubRepo/environments/$GitHubEnvironment/variables" 2>&1
$secretsJson = gh api "repos/$GitHubRepo/environments/$GitHubEnvironment/secrets" 2>&1
$configuredVars = @()
$configuredSecrets = @()
if ($LASTEXITCODE -eq 0) {
    $configuredVars = ($varsJson | ConvertFrom-Json).variables.name
    $configuredSecrets = ($secretsJson | ConvertFrom-Json).secrets.name
}

foreach ($varName in @("AWS_REGION", "BEDROCK_MODEL_ID")) {
    if ($varName -in $configuredVars) {
        Write-Host "Variable $varName : configured"
    } else {
        Write-Warning "Variable $varName : NOT configured in '$GitHubEnvironment'"
    }
}

$gateKeyName = "DUSK_GATE_API_KEY"
if ($gateKeyName -in $configuredSecrets) {
    Write-Host "Secret $gateKeyName : present (value not shown)"
} else {
    Write-Warning "Secret $gateKeyName : NOT configured in '$GitHubEnvironment'"
}

if ("AWS_ROLE_ARN" -in $configuredVars) {
    Write-Host "Variable AWS_ROLE_ARN: configured"
} else {
    Write-Warning "Variable AWS_ROLE_ARN: NOT configured (will be set after deployment)"
}

# Validate-only path
if (-not $Deploy) {
    Write-Host ""
    Write-Host "Validation complete. No AWS or GitHub changes were made."
    Write-Host "Run with -Deploy -Confirm to create the CloudFormation stack."
    exit 0
}

# Step 8: Require explicit confirmation
if (-not $Confirm) {
    Write-Error "Add -Confirm to acknowledge that AWS IAM resources will be created or updated."
    exit 1
}

# Step 9: Deploy CloudFormation stack
Write-Host ""
Write-Host "=== Deploying CloudFormation stack: $StackName ==="

$overrides = @(
    "GitHubOrg=ShieldTech-Ltd"
    "GitHubRepo=DUSK"
    "GitHubEnvironment=$GitHubEnvironment"
    "BedrockModelId=$modelId"
    "BedrockFoundationModelId=$foundationModelId"
)
if ($ExistingOidcProviderArn) {
    $overrides += "ExistingOidcProviderArn=$ExistingOidcProviderArn"
}

aws cloudformation deploy `
    --stack-name $StackName `
    --template-file $TemplatePath `
    --parameter-overrides @overrides `
    --capabilities CAPABILITY_NAMED_IAM `
    --region $region `
    --no-fail-on-empty-changeset

if ($LASTEXITCODE -ne 0) {
    Write-Error "CloudFormation deployment failed. Check the AWS console for stack events."
    exit 1
}
Write-Host "Stack deployed successfully."

# Step 10: Capture RoleArn output
$outputsJson = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $region `
    --query "Stacks[0].Outputs" `
    --output json
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to read stack outputs."
    exit 1
}
$outputs = $outputsJson | ConvertFrom-Json
$roleArn = ($outputs | Where-Object { $_.OutputKey -eq "RoleArn" }).OutputValue

if (-not $roleArn) {
    Write-Error "RoleArn not found in stack outputs."
    exit 1
}
Write-Host "RoleArn: $roleArn"

# Step 11: Set AWS_ROLE_ARN as GitHub environment variable (not a secret)
Write-Host ""
Write-Host "=== Setting AWS_ROLE_ARN GitHub environment variable ==="
gh variable set AWS_ROLE_ARN `
    --body $roleArn `
    --env $GitHubEnvironment `
    --repo $GitHubRepo

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to set AWS_ROLE_ARN. Check gh auth permissions."
    exit 1
}
Write-Host "AWS_ROLE_ARN configured in environment '$GitHubEnvironment'."

Write-Host ""
Write-Host "=== Setup complete ==="
Write-Host "Verify configuration: scripts/test-bedrock-oidc-config.ps1"
Write-Host ""
Write-Host "Next steps (manual, after PR is merged to main):"
Write-Host "  1. Trigger the workflow via GitHub Actions UI (requires ritiksah141 approval)."
Write-Host "  2. Do not dispatch automatically from this script."
