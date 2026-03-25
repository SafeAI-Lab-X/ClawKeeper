#!/usr/bin/env pwsh
# uninstall-skill.ps1 - Windows PowerShell equivalent of skill/uninstall.sh
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-StateDir {
    # Check OPENCLAW_HOME env var first
    if ($env:OPENCLAW_HOME -and (Test-Path $env:OPENCLAW_HOME -PathType Container)) {
        return $env:OPENCLAW_HOME
    }

    # Check candidate directories in order
    $candidates = @(
        "$env:USERPROFILE\.openclaw",
        "$env:USERPROFILE\.moltbot",
        "$env:USERPROFILE\.clawdbot",
        "$env:USERPROFILE\clawd"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate -PathType Container) {
            return $candidate
        }
    }

    # Default fallback
    return "$env:USERPROFILE\.openclaw"
}

$STATE_DIR = Get-StateDir
$TARGET_DIR = Join-Path $STATE_DIR "skills\windows-safety-guide"

# Remove directory and all its contents
if (Test-Path $TARGET_DIR) {
    Remove-Item -Path $TARGET_DIR -Recurse -Force
}

Write-Host "windows-safety-guide skill removed from $TARGET_DIR"
