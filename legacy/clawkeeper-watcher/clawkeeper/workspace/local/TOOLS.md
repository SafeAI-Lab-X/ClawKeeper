# TOOLS — Clawkeeper Watcher (Local Mode)

## Available Tools

### context-judge

- **Route**: `POST /plugins/clawkeeper-watcher/context-judge`
- **Purpose**: Evaluate forwarded context for risk, confirmation boundaries, and execution safety
- **Input**: Context payload with metadata
- **Output**: Structured judgment with `continue`, `ask_user`, or `stop`, plus local evidence

### local-audit

- **Purpose**: Inspect the user's `~/.openclaw` state for integrity and policy violations
- **Scope**: User OpenClaw config, rules, and runtime state selected by the audit controls
- **Output**: Audit findings, severity counts, score, and remediation hints

### startup-audit-bridge

- **Purpose**: Forward risky startup audit summaries back to the user's OpenClaw when a `clawkeeper-bands` plugin is configured on the receiving side
- **Scope**: Summary-only forwarding of startup audit results
- **Output**: Notification payload with score, counts, top findings, and next action

### hardening-and-rollback

- **Purpose**: Apply safe auto-fixable controls and preserve rollback points
- **Scope**: Explicitly supported hardening targets in the user's `~/.openclaw`
- **Output**: Change list, backup path, and rollback-ready state

### drift-monitor

- **Purpose**: Watch key config and rule files, rerun audits, and emit deduplicated severe alerts
- **Scope**: High-signal local governance files selected by the audit context
- **Output**: Drift findings, risky summaries, and deduplicated alert events

### skill-scan

- **Purpose**: Enumerate and evaluate installed user skills
- **Scope**: `~/.openclaw/skills/`
- **Output**: Skill inventory with score, severity counts, and risky finding summaries

### governance-records

- **Purpose**: Review local governance activity such as audits, drift detections, and hardening outcomes
- **Scope**: Clawkeeper local logs and runtime governance traces
- **Output**: Traceable records for confirmation, debugging, and rollback review

### log-analysis

- **Purpose**: Parse and search runtime logs
- **Scope**: Clawkeeper local mode logs and watcher event traces
- **Output**: Matching log entries, patterns, timeline summaries

### state-inspection

- **Purpose**: Read selected runtime state files for additional context
- **Scope**: Local runtime state plus governed user OpenClaw state where the audit flow requires it
- **Output**: State snapshots, delta comparisons
