# TOOLS — Clawkeeper Watcher (Remote Mode)

## Available Tools

### context-judge

- **Route**: `POST /plugins/clawkeeper-watcher/context-judge`
- **Purpose**: Evaluate forwarded context for risk, confirmation boundaries, and execution safety
- **Input**: Context payload with metadata
- **Output**: Structured judgment with `continue`, `ask_user`, or `stop`

### decision-memory

- **Purpose**: Reuse archived remote decisions for recurring risk review
- **Scope**: Remote watcher decision-memory archive
- **Output**: Historical decision summaries, stop reasons, session patterns, and tool summaries

### fingerprint-match

- **Purpose**: Detect recurring cross-session risk fingerprints
- **Scope**: Remote decision-memory-derived fingerprint cache
- **Output**: Fingerprint warnings with risk rank, recurrence count, and recent-hit context

### agent-profile

- **Purpose**: Compare current behavior against per-agent historical baselines
- **Scope**: Remote event-log-derived agent profiles
- **Output**: Novel-tool, tool-distribution, and token-usage anomaly signals

### intent-drift

- **Purpose**: Detect when the current tool chain drifts away from the user's original request
- **Scope**: Current forwarded context only, with configured heuristics
- **Output**: Drift warnings covering persistence, credential access, exfiltration, and other high-risk shifts

## Unavailable Tools (Remote Mode)

The following tools are only available in local mode:

- **startup-audit**: Audit the user's `~/.openclaw` state on gateway start
- **auto-harden**: Apply local safe fixes and create backups
- **drift-monitor**: Watch local config and rules files for risky changes
- **skill-guard**: Scan installed skills under the user's `~/.openclaw/skills`
- **rollback**: Restore backups after local remediation
