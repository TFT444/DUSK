#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only validation of DUSK Bedrock OIDC configuration.
    No AWS or GitHub resources are created or modified.
.DESCRIPTION
    Runs setup-bedrock-oidc.ps1 in validate-only mode.
    Safe to run at any time.
#>
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& "$scriptDir\setup-bedrock-oidc.ps1" @args
exit $LASTEXITCODE
