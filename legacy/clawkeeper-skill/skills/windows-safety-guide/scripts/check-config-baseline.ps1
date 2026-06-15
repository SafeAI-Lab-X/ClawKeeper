# ==============================================================================
# Verify-Baseline.ps1
#
# Description : Reads the baseline CSV produced by Save-Baseline.ps1, re-hashes
#               the original file, and compares the two SHA-256 values.
#               Exits with code 0 if the file is intact, or code 1 if tampering
#               (or accidental modification) is detected.
#
# State dir   : Resolved in priority order:
#                 1. Environment variable  OPENCLAW_STATE_DIR  (if set)
#                 2. Default path          %USERPROFILE%\.openclaw
#
# Prerequisites: Save-Baseline.ps1 must have been run at least once so that
#                .config-baseline.sha256 exists in the state directory.
# ==============================================================================

# --- Resolve state directory --------------------------------------------------
if ($env:OPENCLAW_STATE_DIR) {
    $OC = $env:OPENCLAW_STATE_DIR
} else {
    $OC = Join-Path $env:USERPROFILE ".openclaw"
}

# --- Validate that the baseline file exists ----------------------------------
$baseline = Join-Path $OC ".config-baseline.sha256"
if (-not (Test-Path $baseline)) {
    Write-Error "Baseline file not found: $baseline"
    Write-Error "Run Save-Baseline.ps1 first to generate a trusted baseline."
    exit 1
}

# --- Load stored hash and re-hash the original file --------------------------
$stored = Import-Csv $baseline

if (-not (Test-Path $stored.Path)) {
    Write-Error "Original file no longer exists: $($stored.Path)"
    exit 1
}

$current = Get-FileHash $stored.Path -Algorithm SHA256

# --- Compare and report -------------------------------------------------------
if ($current.Hash -ne $stored.Hash) {
    Write-Warning "Hash verification FAILED: $($stored.Path) has been tampered with!"
    Write-Host    "  Stored  : $($stored.Hash)"
    Write-Host    "  Current : $($current.Hash)"
    exit 1
} else {
    Write-Host "Hash verification passed: $($stored.Path) is intact."
    exit 0
}