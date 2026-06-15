# ==============================================================================
# Save-Baseline.ps1
#
# Description : Computes the SHA-256 hash of openclaw.json and saves it as a
#               CSV baseline file (.config-baseline.sha256) inside the OpenClaw
#               state directory.  Run this script once to establish a trusted
#               baseline, then use Verify-Baseline.ps1 at any time to detect
#               unexpected changes.
#
# State dir   : Resolved in priority order:
#                 1. Environment variable  OPENCLAW_STATE_DIR  (if set)
#                 2. Default path          %USERPROFILE%\.openclaw
#
# Output file : <state_dir>\.config-baseline.sha256  (UTF-8 CSV)
# ==============================================================================

# --- Resolve state directory --------------------------------------------------
if ($env:OPENCLAW_STATE_DIR) {
    $OC = $env:OPENCLAW_STATE_DIR
} else {
    $OC = Join-Path $env:USERPROFILE ".openclaw"
}

# --- Validate that the target file exists before hashing ---------------------
$targetFile = Join-Path $OC "openclaw.json"
if (-not (Test-Path $targetFile)) {
    Write-Error "Target file not found: $targetFile"
    exit 1
}

# --- Compute SHA-256 and write the baseline CSV ------------------------------
$baseline = Join-Path $OC ".config-baseline.sha256"

Get-FileHash $targetFile -Algorithm SHA256 |
    Select-Object Hash, Path |
    ConvertTo-Csv -NoTypeInformation |
    Out-File $baseline -Encoding UTF8

Write-Host "Baseline saved to: $baseline"