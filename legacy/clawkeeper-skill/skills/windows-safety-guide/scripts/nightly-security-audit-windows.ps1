
# OpenClaw Security Guide v1.0 - Nightly Comprehensive Security Inspection Script (Windows PowerShell Version)
# Requirements: PowerShell 5.1+
# It is recommended to run with administrator privileges to obtain complete data.
$ErrorActionPreference = "SilentlyContinue"

# ── Init ──────────────────────────────────────────────────────
if ($env:OPENCLAW_STATE_DIR) { $OC = $env:OPENCLAW_STATE_DIR }
else { $OC = Join-Path $env:USERPROFILE ".openclaw" }

$REPORT_DIR  = Join-Path $OC "workspace\security-reports"
$DATE_STR    = Get-Date -Format "yyyy-MM-dd"
$REPORT_FILE = Join-Path $REPORT_DIR "report-$DATE_STR.txt"
New-Item -ItemType Directory -Force -Path $REPORT_DIR | Out-Null
"=== OpenClaw Security Audit ($DATE_STR) ===" | Set-Content -Path $REPORT_FILE -Encoding UTF8
$SUMMARY = @()

function WR { param([string]$T); Add-Content -Path $REPORT_FILE -Value $T -Encoding UTF8 }
function AS { param([string]$M); $script:SUMMARY += $M }

# ── [1/12] OpenClaw Audit ─────────────────────────────────────
WR ""; WR "[1/12] OpenClaw --deep audit"
$ocExe = Get-Command "openclaw" -ErrorAction SilentlyContinue
if ($null -ne $ocExe) {
    WR (& openclaw security audit --deep 2>&1 | Out-String)
    AS "1. Platform Audit: OK"
} else {
    WR "openclaw not found, skipped."
    AS "1. Platform Audit: WARN - openclaw not in PATH"
}

# ── [2/12] Ports & Processes ─────────────────────────────────
WR ""; WR "[2/12] Listening ports & top processes"
$listening = netstat -ano 2>&1 | Where-Object { $_ -match "LISTENING" }
WR ($listening | Out-String)
$top15 = Get-Process | Sort-Object CPU -Descending | Select-Object -First 15
foreach ($p in $top15) {
    $cpu = [math]::Round($p.CPU, 2)
    $mem = [math]::Round($p.WorkingSet64 / 1MB, 1)
    WR ("  {0,-30} PID:{1,-6} CPU:{2} Mem:{3}MB" -f $p.Name, $p.Id, $cpu, $mem)
}
AS "2. Ports & Procs: OK"

# ── [3/12] File Changes ───────────────────────────────────────
WR ""; WR "[3/12] Sensitive dirs changed files (24h)"
$cutoff = (Get-Date).AddHours(-24)
$dirs   = @($OC, (Join-Path $env:USERPROFILE ".ssh"), "C:\Windows\System32\drivers\etc")
$modCount = 0
foreach ($d in $dirs) {
    if (Test-Path $d) {
        $cnt = (Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff } | Measure-Object).Count
        $modCount += $cnt
    }
}
WR "Total modified: $modCount"
AS "3. Dir Changes: OK - $modCount files"

# ── [4/12] Scheduled Tasks ────────────────────────────────────
WR ""; WR "[4/12] Scheduled Tasks"
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
foreach ($t in $tasks) {
    WR ("  [{0}] {1}{2}" -f $t.State, $t.TaskPath, $t.TaskName)
}
AS "4. Scheduled Tasks: OK"

# ── [5/12] OpenClaw Cron ──────────────────────────────────────
WR ""; WR "[5/12] OpenClaw Cron Jobs"
if ($null -ne $ocExe) {
    WR (& openclaw cron list 2>&1 | Out-String)
    AS "5. OpenClaw Cron: OK"
} else {
    WR "openclaw not found."
    AS "5. OpenClaw Cron: WARN - openclaw not installed"
}

# ── [6/12] Login Audit ────────────────────────────────────────
WR ""; WR "[6/12] Logins & failed attempts"
$f4624 = @{ LogName = "Security"; Id = 4624; StartTime = (Get-Date).AddDays(-1) }
$logins = Get-WinEvent -FilterHashtable $f4624 -MaxEvents 5 -ErrorAction SilentlyContinue
if ($null -ne $logins) {
    foreach ($ev in $logins) {
        $u = $ev.Properties[5].Value
        $ip = $ev.Properties[18].Value
        $lt = $ev.Properties[8].Value
        WR ("  {0}  User:{1}  Type:{2}  IP:{3}" -f $ev.TimeCreated, $u, $lt, $ip)
    }
} else {
    WR "  No data (may need admin rights)"
}
$f4625 = @{ LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddHours(-24) }
$fails = Get-WinEvent -FilterHashtable $f4625 -ErrorAction SilentlyContinue
$failCount = ($fails | Measure-Object).Count
WR "Failed logins (24h): $failCount"
AS "6. Login Security: OK - $failCount failed attempts"

# ── [7/12] File Integrity ─────────────────────────────────────
WR ""; WR "[7/12] Config file hashes & baseline"
$baselineFile = Join-Path $OC ".config-baseline.sha256"
$cfgFiles     = @(
    (Join-Path $OC "openclaw.json"),
    (Join-Path $OC "devices\paired.json"),
    "C:\ProgramData\ssh\sshd_config",
    (Join-Path $env:USERPROFILE ".ssh\authorized_keys")
)
$curLines = @()
foreach ($f in $cfgFiles) {
    if (Test-Path $f) {
        $h = (Get-FileHash -Path $f -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $curLines += "$h  $f"
        WR "  OK  $f => $h"
    } else {
        WR "  MISSING  $f"
    }
}
$curContent = $curLines -join "`n"
$bDir = Split-Path $baselineFile
if (-not (Test-Path $bDir)) { New-Item -ItemType Directory -Force -Path $bDir | Out-Null }
if (Test-Path $baselineFile) {
    $stored = (Get-Content $baselineFile -Raw -ErrorAction SilentlyContinue)
    if ($null -eq $stored) { $stored = "" }
    if ($stored.Trim() -eq $curContent.Trim()) {
        WR "Baseline: MATCH"
        AS "7. Config Baseline: OK - hashes match"
    } else {
        WR "Baseline: MISMATCH"
        AS "7. Config Baseline: WARN - hash changed, possible tampering"
    }
} else {
    $curContent | Set-Content -Path $baselineFile -Encoding UTF8
    WR "Baseline: created for first time"
    AS "7. Config Baseline: WARN - created new baseline"
}

# ── [8/12] Privilege Audit ────────────────────────────────────
WR ""; WR "[8/12] Privilege events vs memory"
$f4672 = @{ LogName = "Security"; Id = 4672; StartTime = (Get-Date).AddHours(-24) }
$privEvts  = Get-WinEvent -FilterHashtable $f4672 -ErrorAction SilentlyContinue
$privCount = ($privEvts | Measure-Object).Count
$memCount  = 0
$memFile   = Join-Path $OC "workspace\memory\$DATE_STR.md"
if (Test-Path $memFile) {
    $memCount = (Select-String -Path $memFile -Pattern "sudo|admin|privilege" -CaseSensitive:$false |
                 Measure-Object).Count
}
WR "Privilege events: $privCount  Memory entries: $memCount"
AS "8. Privilege Audit: OK - events=$privCount mem=$memCount"

# ── [9/12] Disk Usage ─────────────────────────────────────────
WR ""; WR "[9/12] Disk usage & large files"
$drv = Get-PSDrive -Name C -ErrorAction SilentlyContinue
if ($null -ne $drv) {
    $used  = [math]::Round($drv.Used / 1GB, 2)
    $free  = [math]::Round($drv.Free / 1GB, 2)
    $total = $used + $free
    if ($total -gt 0) { $pct = [math]::Round($used / $total * 100, 1) } else { $pct = 0 }
    WR "C: ${used}GB / ${total}GB (${pct}%)"
} else {
    $pct = "N/A"
}
$lgCut   = (Get-Date).AddHours(-24)
$lgFiles = (Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 100MB -and $_.LastWriteTime -gt $lgCut } |
            Measure-Object).Count
WR "Large files >100MB (24h): $lgFiles"
AS "9. Disk: OK - C: $pct used, $lgFiles large new files"

# ── [10/12] Gateway Env Vars ──────────────────────────────────
WR ""; WR "[10/12] Gateway process env var scan"
$gwProcs = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match "openclaw" -and $_.CommandLine -match "gateway"
}
if ($gwProcs.Count -gt 0) {
    foreach ($gwProc in $gwProcs) {
        WR "  Target process found: $($gwProc.Name) (PID: $($gwProc.ProcessId))"
        $envKeys = [System.Environment]::GetEnvironmentVariables().Keys
        $hits = @()
        foreach ($k in $envKeys) {
            if ($k -match "SECRET|TOKEN|PASSWORD|KEY|API") {
                $hits += "$k=(Hidden)"
            }
        }
        if ($hits.Count -gt 0) {
            foreach ($h in $hits) { WR "    $h" }
        } else {
            WR "    No sensitive env var names found"
        }
    }
    AS "10. Env Vars: OK"
} else {
    WR "  Error: OpenClaw gateway process (node + openclaw.mjs) not found"
    AS "10. Env Vars: WARN - gateway process not found"
}

# ── [11/12] DLP Scan ──────────────────────────────────────────
WR ""; WR "[11/12] DLP - plaintext key/mnemonic scan"
$scanRoot   = Join-Path $OC "workspace"
$dlpHits    = 0
$skipExt    = @(".png",".jpg",".jpeg",".gif",".webp",".mp4",".zip",".exe",".dll")
$reEth      = '\b0x[a-fA-F0-9]{64}\b'
$reMnem     = '\b([a-z]{3,12}\s+){11}[a-z]{3,12}\b'
if (Test-Path $scanRoot) {
    $scanFiles = Get-ChildItem -Path $scanRoot -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $skipExt -notcontains $_.Extension.ToLower() }
    foreach ($sf in $scanFiles) {
        $txt = Get-Content -Path $sf.FullName -Raw -ErrorAction SilentlyContinue
        if ($null -eq $txt) { continue }
        $dlpHits += ([regex]::Matches($txt, $reEth)).Count
        $dlpHits += ([regex]::Matches($txt, $reMnem)).Count
    }
}
WR "DLP hits: $dlpHits"
if ($dlpHits -gt 0) { AS "11. DLP: WARN - $dlpHits suspicious matches, review manually" }
else { AS "11. DLP: OK - no plaintext keys found" }

# ── [12/12] Skill/MCP Baseline ───────────────────────────────
WR ""; WR "[12/12] Skill/MCP integrity baseline"
$skillDir = Join-Path $OC "workspace\skills"
$mcpDir   = Join-Path $OC "workspace\mcp"
$hashDir  = Join-Path $OC "security-baselines"
New-Item -ItemType Directory -Force -Path $hashDir | Out-Null
$curFile  = Join-Path $hashDir "skill-mcp-current.sha256"
$baseFile = Join-Path $hashDir "skill-mcp-baseline.sha256"
$curHashes = @()
$smDirs = @($skillDir, $mcpDir)
foreach ($sd in $smDirs) {
    if (Test-Path $sd) {
        $sdFiles = Get-ChildItem -Path $sd -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName
        foreach ($sf in $sdFiles) {
            $h = (Get-FileHash -Path $sf.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($null -ne $h) { $curHashes += "$h  $($sf.FullName)" }
        }
    }
}
if ($curHashes.Count -gt 0) {
    $curHashes | Set-Content -Path $curFile -Encoding UTF8
    if (Test-Path $baseFile) {
        $baseHashes = Get-Content $baseFile -ErrorAction SilentlyContinue
        if ($null -eq $baseHashes) { $baseHashes = @() }
        $added   = $curHashes  | Where-Object { $baseHashes -notcontains $_ }
        $removed = $baseHashes | Where-Object { $curHashes  -notcontains $_ }
        if ($added.Count -eq 0 -and $removed.Count -eq 0) {
            WR "Skill/MCP: baseline match"
            AS "12. Skill/MCP: OK - no changes"
        } else {
            WR "Skill/MCP: DIFF detected"
            foreach ($ln in $added)   { WR "+ $ln" }
            foreach ($ln in $removed) { WR "- $ln" }
            AS "12. Skill/MCP: WARN - hash changes detected"
        }
        Copy-Item -Path $curFile -Destination $baseFile -Force
    } else {
        Copy-Item -Path $curFile -Destination $baseFile -Force
        WR "Skill/MCP: first baseline created"
        AS "12. Skill/MCP: OK - first baseline created"
    }
} else {
    AS "12. Skill/MCP: OK - no skill/mcp files found"
}

# ── Summary Output ────────────────────────────────────────────
Write-Host ""
Write-Host "=== OpenClaw Daily Security Audit ($DATE_STR) ===" -ForegroundColor Cyan
Write-Host ""
foreach ($line in $SUMMARY) {
    if ($line -match "WARN") { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line -ForegroundColor Green }
}
Write-Host ""
Write-Host "Full report: $REPORT_FILE" -ForegroundColor Gray
WR ""; WR "=== SUMMARY ==="
foreach ($line in $SUMMARY) { WR $line }
