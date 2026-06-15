#!/usr/bin/env bash

set -euo pipefail

case_name="${1:-all}"

if [[ "${case_name}" == "--help" || "${case_name}" == "-h" ]]; then
  cat <<'EOF'
Usage:
  scripts/readme-cases.sh [audit|harden|scan|judge|bridge|bands|all]

Purpose:
  Print stable, screenshot-friendly terminal cases for the Clawkeeper README.

Examples:
  scripts/readme-cases.sh audit
  scripts/readme-cases.sh harden
  scripts/readme-cases.sh scan
  scripts/readme-cases.sh judge
  scripts/readme-cases.sh bridge
  scripts/readme-cases.sh bands
  scripts/readme-cases.sh all
EOF
  exit 0
fi

bold="$(printf '\033[1m')"
dim="$(printf '\033[2m')"
cyan="$(printf '\033[36m')"
green="$(printf '\033[32m')"
yellow="$(printf '\033[33m')"
red="$(printf '\033[31m')"
reset="$(printf '\033[0m')"

hr() {
  printf '%s\n' "${dim}────────────────────────────────────────────────────────────────────────────${reset}"
}

title() {
  hr
  printf '%s%s%s\n' "${bold}${cyan}" "$1" "${reset}"
  hr
}

audit_case() {
  title "Case 1 · Local Watcher Audit"
  cat <<EOF
${dim}\$${reset} clawkeeper local clawkeeper-watcher audit

${bold}Clawkeeper-Watcher Audit Report${reset}
Score: ${yellow}63/100${reset}
Mode: local

Findings:
  ${red}HIGH${reset}   network.local-gateway
         gateway.bind is currently lan, exposing the gateway to a wider reachable surface.
         fix: Restrict gateway.bind to loopback

  ${red}HIGH${reset}   execution.bounded-filesystem
         agents.defaults.sandbox.mode=off, so filesystem/runtime containment is effectively disabled by default.
         fix: Set agents.defaults.sandbox.mode to "all"

  ${yellow}MEDIUM${reset} execution.human-checkpoint
         tools.exec.security=full, so host exec is not constrained to an allowlist boundary.
         fix: Set tools.exec.security to "allowlist"

  ${yellow}MEDIUM${reset} behavior.runtime-constitution
         AGENTS.md lacks a clear runtime boundary rules section.
         fix: Inject Clawkeeper-Watcher runtime constitution into AGENTS.md

Next:
  1. Run ${bold}clawkeeper local clawkeeper-watcher harden${reset}
  2. Re-run the audit to verify the new score
EOF
}

judge_case() {
  title "Case 2 · Remote Context Judge"
  cat <<EOF
${dim}\$${reset} curl -sS -X POST http://127.0.0.1:19002/plugins/clawkeeper-watcher/context-judge \\
    -H 'Content-Type: application/json' \\
    --data @examples/context-judge-request.json | jq

{
  "version": 1,
  "mode": "remote",
  "localEnhanced": false,
  "decision": "ask_user",
  "stopReason": "waiting_user_confirmation",
  "shouldContinue": false,
  "needsUserDecision": true,
  "userQuestion": "Command execution or another high-risk tool call was detected. Do you want to continue to the next step?",
  "summary": "The context contains high-risk actions, and the policy requires explicit user confirmation.",
  "riskLevel": "high",
  "evidence": [
    "tool=bash",
    "toolCount=2",
    "fingerprint=bash|waiting_user_confirmation"
  ],
  "nextAction": "ask_user",
  "continueHint": "Continue only after explicit user confirmation."
}
EOF
}

harden_case() {
  title "Case 5 · Local Hardening Run"
  cat <<EOF
${dim}\$${reset} clawkeeper local clawkeeper-watcher harden

User OpenClaw hardening applied. Backup:
  ~/.clawkeeper/local/.clawkeeper-watcher/backups/2026-03-25T12-18-44-511Z

Actions:
  - gateway.bind -> loopback
  - agents.defaults.sandbox.mode -> all
  - tools.exec.security -> allowlist
  - AGENTS.md injected with runtime constitution

${dim}Recommended verification:${reset}

${dim}\$${reset} clawkeeper local clawkeeper-watcher audit

${bold}Clawkeeper-Watcher Audit Report${reset}
Score: ${green}100/100${reset}
Mode: local
Findings:
  none
EOF
}

scan_case() {
  title "Case 6 · Skill Security Scan"
  cat <<EOF
${dim}\$${reset} clawkeeper local clawkeeper-watcher scan-skill demo-skill

${bold}Clawkeeper-Watcher Skill Scan${reset}
Skill: demo-skill
Directory: ~/.openclaw/skills/demo-skill
Score: ${yellow}72/100${reset}

Findings:
  ${red}HIGH${reset}   skill.remote-script-execution
         file: install.sh
         evidence: curl -fsSL https://example.invalid/install.sh | bash
         remediation: Replace curl-to-bash with a pinned download + checksum verification

  ${yellow}MEDIUM${reset} skill.unpinned-download
         file: README.md
         evidence: install latest release without version pin
         remediation: Pin the downloaded version and document the expected hash

Next:
  1. Remove remote pipe-to-shell execution
  2. Pin the release or package version
  3. Re-run scan-skill after the fix
EOF
}

bridge_case() {
  title "Case 3 · Startup Audit Forwarded To User Gateway"
  cat <<EOF
${dim}\$${reset} clawkeeper local config set plugins.entries.clawkeeper-watcher.config.notify.userBridge.enabled true
${dim}\$${reset} clawkeeper local config set plugins.entries.clawkeeper-watcher.config.notify.userBridge.url http://127.0.0.1:18889
${dim}\$${reset} clawkeeper local config set plugins.entries.clawkeeper-watcher.config.notify.userBridge.token demo-token
${dim}\$${reset} clawkeeper local gateway run

[Clawkeeper-Watcher] mode=local
[Clawkeeper-Watcher] score=${yellow}63/100${reset}
[Clawkeeper-Watcher] startup audit notification sent to user bridge
[Clawkeeper-Watcher] drift monitor started for user OpenClaw

${dim}User-side gateway receives:${reset}

${bold}User OpenClaw startup audit: score 63/100.${reset}
Top findings:
  - gateway.bind is wider than loopback
  - default sandbox containment is disabled
  - host exec security is too open

Suggested next step:
  Run ${bold}clawkeeper local clawkeeper-watcher harden${reset} on the trusted side.
EOF
}

bands_case() {
  title "Case 4 · Bands Approval Prompt"
  cat <<EOF
${dim}\$${reset} clawkeeper-bands audit --lines 4

16:05:00 | FileSystem.read              | ${green}ALLOWED${reset}    |   0.0s
16:06:00 | FileSystem.write             | ${green}APPROVED${reset}   |   2.4s (human)
16:07:00 | Shell.bash                   | ${red}REJECTED${reset}   |   1.1s (human)
16:08:00 | FileSystem.delete            | ${red}BLOCKED${reset}    |   0.0s - Policy: DENY

${dim}Interactive approval flow:${reset}

┌──────────────────────────────────────────────────────────────┐
│ CLAWKEEPER-BANDS SECURITY ALERT                             │
│ Module: Shell                                               │
│ Method: bash                                                │
│ Risk: high                                                  │
│ Args: ["rm -rf /tmp/demo-cache"]                            │
│                                                             │
│ Approve once: YES                                           │
│ Reject: NO                                                  │
│ Allow for 15 min: ALLOW                                     │
└──────────────────────────────────────────────────────────────┘
EOF
}

run_case() {
  case "$1" in
    audit) audit_case ;;
    harden) harden_case ;;
    scan) scan_case ;;
    judge) judge_case ;;
    bridge) bridge_case ;;
    bands) bands_case ;;
    all)
      audit_case
      printf '\n'
      harden_case
      printf '\n'
      scan_case
      printf '\n'
      judge_case
      printf '\n'
      bridge_case
      printf '\n'
      bands_case
      ;;
    *)
      printf '%sUnknown case:%s %s\n' "${red}" "${reset}" "$1" >&2
      printf 'Run %s for usage.\n' "scripts/readme-cases.sh --help" >&2
      exit 1
      ;;
  esac
}

run_case "${case_name}"
