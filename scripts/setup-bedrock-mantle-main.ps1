#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys or validates DUSK Bedrock Mantle main validation infrastructure.
.DESCRIPTION
    Modes:
      (default)        Read-only validation. No AWS or GitHub writes.
      -Deploy -Confirm Creates or updates the CloudFormation stack and sets
                       AWS_ROLE_ARN as a GitHub environment variable.

    This script never dispatches any workflow.
    This script never prints secret values or bearer tokens.
    AWS account ID is printed as deployment context; it is not a secret.

    This targets the protected main environment (real-agent), validates the
    deployment branch policy is restricted to
    'main' only, and confirms the deployed role holds
    bedrock-mantle:CallWithBearerToken for SHORT_TERM tokens (not InvokeModel).

.PARAMETER Deploy
    Enable deployment mode. Requires -Confirm.

.PARAMETER Confirm
    Required when using -Deploy. Acknowledges that AWS IAM resources will be
    created or updated.

.PARAMETER StackName
    CloudFormation stack name. Default: dusk-bedrock-mantle-main

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
    scripts/setup-bedrock-mantle-main.ps1
    Validate prerequisites only.

.EXAMPLE
    scripts/setup-bedrock-mantle-main.ps1 -Deploy -Confirm
    Deploy the CloudFormation stack and configure the GitHub environment var.
#>
[CmdletBinding()]
param(
    [switch]$Deploy,
    [switch]$Confirm,
    [string]$StackName = "dusk-bedrock-mantle-main",
    [string]$GitHubRepo = "ShieldTech-Ltd/DUSK",
    [string]$GitHubEnvironment = "real-agent",
    [string]$TemplatePath = "",
    [string]$ExistingOidcProviderArn = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $TemplatePath) {
    $TemplatePath = Join-Path $ScriptDir "..\infra\aws\bedrock-mantle-main\template.yaml"
}
$TemplatePath = Resolve-Path $TemplatePath

$RoleName = "DuskRealAgentMainMantleRole"

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

# Step 5: GitHub environment protection check
Write-Host ""
Write-Host "=== Verifying GitHub environment protection ==="
$envJson = gh api "repos/$GitHubRepo/environments/$GitHubEnvironment" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not read environment '$GitHubEnvironment' in $GitHubRepo. Check repo access.`n$envJson"
    exit 1
}
$envInfo = $envJson | ConvertFrom-Json
$reviewerLogins = @()
$requiredReviewerRule = $null
foreach ($rule in $envInfo.protection_rules) {
    if ($rule.type -eq "required_reviewers") {
        $requiredReviewerRule = $rule
        foreach ($reviewer in $rule.reviewers) {
            $reviewerLogins += $reviewer.reviewer.login
        }
    }
}
if ("ritiksah141" -notin $reviewerLogins) {
    Write-Error "SECURITY: Environment '$GitHubEnvironment' does not require ritiksah141 approval. Do not weaken environment protection."
    exit 1
}
if ($null -eq $requiredReviewerRule -or $requiredReviewerRule.prevent_self_review -ne $true) {
    Write-Error "SECURITY: Environment '$GitHubEnvironment' must prevent self-review."
    exit 1
}
Write-Host "Environment protection confirmed: ritiksah141 required as reviewer."
Write-Host "Environment protection confirmed: prevent_self_review is enabled."

# Step 5b: Validate deployment branch policy restricts to 'main' only.
# The main workflow checks github.ref at runtime, but the environment
# deployment_branch_policy is the GitHub-enforced gate that prevents any
# non-main branch from entering the environment. Both controls must be in
# place. This stack must be restricted to 'main'.
Write-Host ""
Write-Host "=== Verifying environment deployment branch policy (main only) ==="
$deployPolicy = $envInfo.deployment_branch_policy
if ($null -eq $deployPolicy) {
    Write-Error @"
SECURITY: Environment '$GitHubEnvironment' has no deployment_branch_policy.
Without a branch policy, any branch can deploy to this environment and assume
the Mantle main OIDC role. Configure the environment to restrict deployments to
the 'main' branch only.
"@
    exit 1
}

$customBranchPolicy = $deployPolicy.custom_branch_policies

if ($customBranchPolicy -eq $true) {
    $branchPoliciesJson = gh api "repos/$GitHubRepo/environments/$GitHubEnvironment/deployment-branch-policies" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Could not read custom deployment branch policies for '$GitHubEnvironment'.`n$branchPoliciesJson"
        exit 1
    }
    $branchPolicies  = ($branchPoliciesJson | ConvertFrom-Json).branch_policies
    $allowedPatterns = @($branchPolicies | ForEach-Object { $_.name })
    $onlyMainAllowed  = ($allowedPatterns.Count -eq 1) -and ($allowedPatterns[0] -eq "main")
    if (-not $onlyMainAllowed) {
        Write-Error @"
SECURITY: Environment '$GitHubEnvironment' uses custom_branch_policies but the
allowed patterns are: $($allowedPatterns -join ', ')
Only 'main' must be allowed. Remove every other pattern and re-run.
"@
        exit 1
    }
    Write-Host "Deployment branch policy: custom_branch_policies, pattern=['main'] only"
} else {
    Write-Error @"
SECURITY: Environment '$GitHubEnvironment' deployment_branch_policy must use
custom_branch_policies restricted to 'main'. protected_branches is not
acceptable because this setup requires one explicit branch pattern. Configure
a custom branch policy that allows only 'main'.
"@
    exit 1
}
Write-Host "Deployment branch restriction confirmed: only 'main' may deploy to '$GitHubEnvironment'."

# Step 6: Confirm existing variables and secrets are configured
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

foreach ($varName in @("AWS_REGION", "BEDROCK_PROVIDER", "BEDROCK_MODEL_ID")) {
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

# Validate OIDC subject in the template restricts to real-agent exactly.
Write-Host ""
Write-Host "=== Verifying template OIDC subject (real-agent only) ==="
$templateText = Get-Content -Raw -Path $TemplatePath
if ($templateText -notmatch "environment:\$\{GitHubEnvironment\}" -and $templateText -notmatch "environment:real-agent") {
    Write-Error "Template OIDC subject does not restrict to the real-agent environment."
    exit 1
}
if ($GitHubEnvironment -ne "real-agent") {
    Write-Error "GitHubEnvironment must be 'real-agent' for the main Mantle stack; got '$GitHubEnvironment'."
    exit 1
}
Write-Host "Template OIDC subject restricts to environment:real-agent."

# GitHub uses an immutable, ID-qualified OIDC subject for this repository.
# Resolve both IDs from the authenticated GitHub API instead of hard-coding
# values that could silently become stale after an ownership change.
$githubOrgId = gh api orgs/ShieldTech-Ltd --jq .id 2>&1
if ($LASTEXITCODE -ne 0 -or $githubOrgId -notmatch '^\d+$') {
    Write-Error "Could not resolve the immutable GitHub organisation ID."
    exit 1
}
$githubRepoId = gh api repos/ShieldTech-Ltd/DUSK --jq .id 2>&1
if ($LASTEXITCODE -ne 0 -or $githubRepoId -notmatch '^\d+$') {
    Write-Error "Could not resolve the immutable GitHub repository ID."
    exit 1
}
$expectedSubject = "repo:ShieldTech-Ltd@${githubOrgId}/DUSK@${githubRepoId}:environment:real-agent"
Write-Host "Resolved immutable GitHub OIDC identity for ShieldTech-Ltd/DUSK."

# Validate-only path
if (-not $Deploy) {
    Write-Host ""
    Write-Host "Validation complete. No AWS or GitHub changes were made."
    Write-Host "Run with -Deploy -Confirm to create the CloudFormation stack."
    exit 0
}

# Step 7: Require explicit confirmation
if (-not $Confirm) {
    Write-Error "Add -Confirm to acknowledge that AWS IAM resources will be created or updated."
    exit 1
}

# Step 8: Deploy CloudFormation stack
Write-Host ""
Write-Host "=== Deploying CloudFormation stack: $StackName ==="

$overrides = @(
    "GitHubOrg=ShieldTech-Ltd"
    "GitHubRepo=DUSK"
    "GitHubOrgId=$githubOrgId"
    "GitHubRepoId=$githubRepoId"
    "GitHubEnvironment=$GitHubEnvironment"
    "RoleName=$RoleName"
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

# Step 9: Capture RoleArn output
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

$partition = ($identity.Arn -split ':')[1]
$expectedRoleArn = "arn:${partition}:iam::$($identity.Account):role/$RoleName"
if ($roleArn -ne $expectedRoleArn) {
    Write-Error "SECURITY: Stack RoleArn '$roleArn' does not match expected role '$expectedRoleArn'."
    exit 1
}

$roleJson = aws iam get-role --role-name $RoleName --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not read deployed role '$RoleName'.`n$roleJson"
    exit 1
}
$deployedRole = ($roleJson | ConvertFrom-Json).Role
$trustStatements = @($deployedRole.AssumeRolePolicyDocument.Statement)
if ($trustStatements.Count -ne 1) {
    Write-Error "SECURITY: Deployed role trust policy must contain exactly one statement."
    exit 1
}
$trust = $trustStatements[0]
$expectedProviderArn = if ($ExistingOidcProviderArn) {
    $ExistingOidcProviderArn
} else {
    "arn:${partition}:iam::$($identity.Account):oidc-provider/token.actions.githubusercontent.com"
}
$trustConditionNames = @($trust.Condition.PSObject.Properties.Name)
$trustStringEqualsNames = @($trust.Condition.StringEquals.PSObject.Properties.Name | Sort-Object)
$expectedTrustKeys = @(
    "token.actions.githubusercontent.com:aud"
    "token.actions.githubusercontent.com:sub"
) | Sort-Object
if ($trust.Effect -ne "Allow" -or
    $trust.Action -ne "sts:AssumeRoleWithWebIdentity" -or
    $trust.Principal.Federated -ne $expectedProviderArn -or
    $trustConditionNames.Count -ne 1 -or $trustConditionNames[0] -ne "StringEquals" -or
    ($trustStringEqualsNames -join ',') -ne ($expectedTrustKeys -join ',') -or
    $trust.Condition.StringEquals.'token.actions.githubusercontent.com:aud' -ne "sts.amazonaws.com" -or
    $trust.Condition.StringEquals.'token.actions.githubusercontent.com:sub' -ne $expectedSubject) {
    Write-Error "SECURITY: Deployed role trust policy does not exactly match the real-agent GitHub OIDC trust."
    exit 1
}
Write-Host "Confirmed: deployed RoleArn and live OIDC trust match the expected main-only role."

# Step 10: Validate the deployed role allows only short-term Mantle tokens.
Write-Host ""
Write-Host "=== Validating short-term Mantle bearer-token permission ==="
$policyNamesJson = aws iam list-role-policies --role-name $RoleName --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not list inline policies for role '$RoleName'.`n$policyNamesJson"
    exit 1
}
$policyNames = ($policyNamesJson | ConvertFrom-Json).PolicyNames
$attachedPoliciesJson = aws iam list-attached-role-policies --role-name $RoleName --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not list attached policies for role '$RoleName'.`n$attachedPoliciesJson"
    exit 1
}
$attachedPolicies = @((($attachedPoliciesJson | ConvertFrom-Json).AttachedPolicies))
if ($attachedPolicies.Count -ne 0) {
    Write-Error "SECURITY: Role '$RoleName' must not have attached managed policies."
    exit 1
}

if ($policyNames.Count -ne 1 -or $policyNames[0] -ne "BedrockMantleMainInference") {
    Write-Error "SECURITY: Role '$RoleName' must have exactly the BedrockMantleMainInference inline policy."
    exit 1
}

$requiredInferenceActions = @(
    "bedrock-mantle:CreateInference"
    "bedrock-mantle:GetProject"
    "bedrock-mantle:ListProjects"
    "bedrock-mantle:ListTagsForResource"
)
$policyJson = aws iam get-role-policy --role-name $RoleName --policy-name $policyNames[0] --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not read the BedrockMantleMainInference policy.`n$policyJson"
    exit 1
}
$policy = $policyJson | ConvertFrom-Json
if ($policy.PolicyDocument.Statement.Count -ne 2) {
    Write-Error "SECURITY: BedrockMantleMainInference must contain exactly two statements."
    exit 1
}

$foundShortTermToken = $false
$foundInference = $false
$expectedProjectResource = "arn:${partition}:bedrock-mantle:${region}:$($identity.Account):project/*"
foreach ($statement in @($policy.PolicyDocument.Statement)) {
    if ($statement.Effect -ne "Allow" -or
        $statement.PSObject.Properties['NotAction'] -or
        $statement.PSObject.Properties['NotResource']) {
        Write-Error "SECURITY: Every Mantle policy statement must be an explicit Allow with Action and Resource."
        exit 1
    }

    $actions = @($statement.Action)
    $sortedActions = @($actions | Sort-Object)
    $sortedRequired = @($requiredInferenceActions | Sort-Object)

    if ($actions.Count -eq 1 -and $actions[0] -eq "bedrock-mantle:CallWithBearerToken") {
        $conditionNames = @($statement.Condition.PSObject.Properties.Name)
        $tokenConditions = @($statement.Condition.StringEquals.PSObject.Properties.Name)
        $tokenType = $statement.Condition.StringEquals.'bedrock-mantle:bearerTokenType'
        if ($statement.Resource -ne "*" -or
            $conditionNames.Count -ne 1 -or $conditionNames[0] -ne "StringEquals" -or
            $tokenConditions.Count -ne 1 -or $tokenConditions[0] -ne "bedrock-mantle:bearerTokenType" -or
            $tokenType -ne "SHORT_TERM") {
            Write-Error "SECURITY: CallWithBearerToken must be restricted exactly to SHORT_TERM tokens on Resource '*'."
            exit 1
        }
        $foundShortTermToken = $true
    } elseif (($sortedActions -join ',') -eq ($sortedRequired -join ',')) {
        if ($statement.Resource -ne $expectedProjectResource -or $statement.Condition) {
            Write-Error "SECURITY: Mantle inference permissions must use the current account and region project scope only."
            exit 1
        }
        $foundInference = $true
    } else {
        Write-Error "SECURITY: Unexpected action in BedrockMantleMainInference: $($actions -join ', ')"
        exit 1
    }
}
if (-not $foundShortTermToken) {
    Write-Error "Role '$RoleName' does not grant bedrock-mantle:CallWithBearerToken for SHORT_TERM tokens."
    exit 1
}
if (-not $foundInference) {
    Write-Error "Role '$RoleName' is missing the exact scoped Mantle inference statement."
    exit 1
}
Write-Host "Confirmed: role allows short-term Mantle authentication and scoped inference, not InvokeModel."

# Step 11: Set AWS_ROLE_ARN as GitHub environment variable (not a secret)
Write-Host ""
Write-Host "=== Setting AWS_ROLE_ARN GitHub environment variable ==="
gh variable set "AWS_ROLE_ARN" `
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
Write-Host "This script does not dispatch the validation workflow."
Write-Host ""
Write-Host "Next steps (manual, after this change is merged to main):"
Write-Host "  1. Ensure BEDROCK_PROVIDER=mantle and BEDROCK_MODEL_ID are set in the environment."
Write-Host "  2. Trigger the workflow via GitHub Actions UI (requires ritiksah141 approval)."
Write-Host "  3. Do not dispatch automatically from this script."
