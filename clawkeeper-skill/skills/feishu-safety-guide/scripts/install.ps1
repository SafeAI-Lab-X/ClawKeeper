#!/usr/bin/env pwsh
# install-skill.ps1 - Windows PowerShell equivalent of skill/install.sh
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Equivalent of: SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
$SOURCE_DIR = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

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
$TARGET_DIR = Join-Path $STATE_DIR "skills\feishu-safety-guide"

# mkdir -p equivalent
New-Item -ItemType Directory -Force -Path $TARGET_DIR | Out-Null

# cp -R equivalent: copy all contents of SOURCE_DIR into TARGET_DIR
Copy-Item -Path "$SOURCE_DIR\*" -Destination $TARGET_DIR -Recurse -Force

Write-Host "feishu-safety-guide skill installed to $TARGET_DIR"