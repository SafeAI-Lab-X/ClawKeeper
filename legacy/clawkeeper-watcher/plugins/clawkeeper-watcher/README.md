# Clawkeeper-Watcher for OpenClaw

<p align="left">
  <a href="https://github.com/openclaw/openclaw">
    <img src="https://img.shields.io/badge/OpenClaw-Compatible-blue.svg" alt="OpenClaw">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
</p>

**A watcher-first governance plugin for OpenClaw.**

Clawkeeper-Watcher is the core governance layer in the Clawkeeper stack. It adds context judgment, runtime event logging, local audit and hardening, drift monitoring, rollback, skill scanning, and remote risk intelligence around an OpenClaw gateway. It can run in `remote` mode for read-only judgment or `local` mode for trusted remediation.

[Repository](https://github.com/xunyoyo/clawkeeper) · [Root Overview](../../README.md) · [Bands Plugin](../clawkeeper-bands/README.md)

# 💡 Features

Clawkeeper-Watcher is built around the idea that watcher logic should stay explicit and inspectable instead of being hidden inside ad hoc prompts or one-off middleware.

### 👁️ Context Judgment

Evaluate structured runtime context before execution continues:

- **Shared Judge Endpoint**: Exposes `POST /plugins/clawkeeper-watcher/context-judge`
- **Decision Contract**: Returns `continue`, `ask_user`, or `stop`
- **Evidence-Based Output**: Includes `summary`, `riskLevel`, `stopReason`, and evidence strings
- **Mode Awareness**: Returns `mode` and `localEnhanced` so callers can distinguish the active side

### 🔐 Local Governance

On the trusted side, the watcher can actively inspect and remediate local state:

- **Startup Audit**: Audit the user OpenClaw state on gateway start
- **Safe Hardening**: Apply only explicit safe remediations
- **Drift Monitoring**: Re-audit key config and rule files on change
- **Skill Guard**: Periodically scan user-installed skills under `~/.openclaw/skills`
- **Backup and Rollback**: Preserve rollback points before local changes are applied

### 🧠 Remote Intelligence

On the remote side, the watcher can accumulate higher-level judgment signals:

- **Decision Memory**: Persist elevated-risk and non-continue outcomes
- **Risk Fingerprints**: Match recurring cross-session risk patterns
- **Agent Profiling**: Compare agent behavior against historical baselines
- **Intent Drift Detection**: Flag tool chains that diverge from the user's apparent request

### 📋 Event Visibility

Record the runtime behavior needed for review and retrospective analysis:

- **Tool Logging**: Capture `before_tool_call` activity
- **Message Logging**: Capture received and outgoing message events
- **LLM Logging**: Capture input and output metadata for model activity
- **JSONL Storage**: Write daily event logs under `$OPENCLAW_WORKSPACE/log/YYYY-MM-DD.jsonl`

# 🚀 Quick Start

## Install the plugin

From the plugin directory:

```bash
npx openclaw plugins install -l .
```

From the repo root or another checkout:

```bash
openclaw plugins install --link /path/to/clawkeeper/plugins/clawkeeper-watcher
```

## Choose a mode

Clawkeeper-Watcher supports two operating modes:

- `remote`: read-only context judgment and passive intelligence
- `local`: full local audit, hardening, monitoring, and rollback

The plugin resolves mode from:

1. plugin config `mode`
2. `CLAWKEEPER_MODE`
3. fallback `local`

When using the full Clawkeeper stack, let the `clawkeeper` launcher set the mode for you.

## Validate the watcher

```bash
npx openclaw clawkeeper-watcher status
npx openclaw clawkeeper-watcher logs
npx openclaw clawkeeper-watcher log-path
```

On the local side, also validate:

```bash
npx openclaw clawkeeper-watcher audit
npx openclaw clawkeeper-watcher scan-skill <name-or-path>
```

---

# 🛠️ Command Reference

### Commands available in both modes

```bash
# Show current watcher score and top threats
npx openclaw clawkeeper-watcher status

# Read event logs
npx openclaw clawkeeper-watcher logs
npx openclaw clawkeeper-watcher logs --date 2026-03-14
npx openclaw clawkeeper-watcher logs --type before_tool_call
npx openclaw clawkeeper-watcher logs --tool bash
npx openclaw clawkeeper-watcher logs --scan
npx openclaw clawkeeper-watcher logs --scan --save-report
npx openclaw clawkeeper-watcher logs --all
npx openclaw clawkeeper-watcher log-path

# Scan third-party or user skills
npx openclaw clawkeeper-watcher scan-skill <name-or-path>

# Inspect remote intelligence outputs
npx openclaw clawkeeper-watcher fingerprints
npx openclaw clawkeeper-watcher profiles
```

### Local-only commands

These commands are rejected in `remote` mode:

```bash
npx openclaw clawkeeper-watcher audit
npx openclaw clawkeeper-watcher audit --json
npx openclaw clawkeeper-watcher audit --fix
npx openclaw clawkeeper-watcher harden
npx openclaw clawkeeper-watcher monitor
npx openclaw clawkeeper-watcher rollback [backup]
```

# 🔄 Operating Modes

| Capability                           | `remote` | `local` |
| ------------------------------------ | -------- | ------- |
| Context Judge HTTP endpoint          | yes      | yes     |
| Event logging                        | yes      | yes     |
| Read-only status and log inspection  | yes      | yes     |
| Decision memory persistence          | yes      | no      |
| Risk fingerprints                    | yes      | no      |
| Agent behavior profiling             | yes      | no      |
| Intent drift detection               | yes      | yes     |
| Startup audit against user state     | no       | yes     |
| Audit / hardening / drift monitoring | no       | yes     |
| Startup audit notification bridge    | no       | yes     |
| Skill scanning and local remediation | no       | yes     |
| Backup and rollback for local fixes  | no       | yes     |

# 🌐 Context Judge Contract

Both watcher modes register the same route:

```text
POST /plugins/clawkeeper-watcher/context-judge
```

The handler returns one of:

- `continue`
- `ask_user`
- `stop`

Typical response shape:

```json
{
  "version": 1,
  "mode": "local",
  "localEnhanced": true,
  "decision": "ask_user",
  "stopReason": "waiting_user_confirmation",
  "shouldContinue": false,
  "needsUserDecision": true,
  "userQuestion": "Command execution or another high-risk tool call was detected. Do you want to continue to the next step?",
  "summary": "The context contains high-risk actions, and the policy requires explicit user confirmation.",
  "riskLevel": "high",
  "evidence": ["tool=bash", "toolCount=2"],
  "nextAction": "ask_user",
  "continueHint": "Continue only after explicit user confirmation."
}
```

# 🔗 Bridge Integration

Clawkeeper-Watcher can integrate with `clawkeeper-bands` in two directions:

- **Outbound local notification**: forward risky startup-audit summaries to a user-side Bands receiver
- **Inbound remote judgment**: accept context-judge requests from Clawkeeper-Bands over the watcher route

The default user-side notification target is:

```text
POST /plugins/clawkeeper-bands/clawkeeper-startup-audit
```

For the user-side receiver and approval layer, see [../clawkeeper-bands/README.md](../clawkeeper-bands/README.md).

# 📂 Architecture

Clawkeeper-Watcher is organized around three main surfaces:

1. **Core** (`src/core/`)
   - Audit engine, hardening, rollback, drift monitoring, skill scanning
   - Decision memory, risk fingerprints, profiling, intent drift
   - Startup audit notification and event logging

2. **Plugin Entry** (`src/plugin/`)
   - CLI registration
   - HTTP route registration
   - Mode selection and gateway lifecycle hooks

3. **Reporting** (`src/reporters/`)
   - Console and JSON output formatting for audits and scans

### File Structure

```text
plugins/clawkeeper-watcher/
├── src/
│   ├── core/         # Audit, hardening, drift monitor, skill scan, event logs, intelligence
│   ├── plugin/       # CLI registration, HTTP route, lifecycle hooks
│   ├── reporters/    # Console and JSON report formatting
│   └── index.js
├── skill/            # Skill scan rules and scripts
├── docs/             # Extra watcher docs
├── openclaw.plugin.json
└── package.json
```

# 🧪 Development

Run the watcher test suite:

```bash
npm test
```

Quick smoke for skill scanning:

```bash
npm run smoke:scan
```

Before publishing or relying on changes, verify:

- `npm test` passes
- `npx openclaw clawkeeper-watcher audit` succeeds in local mode
- `npx openclaw clawkeeper-watcher scan-skill <path>` succeeds

# 📕 Reference

- Root overview: [../../README.md](../../README.md)
- Bands plugin: [../clawkeeper-bands/README.md](../clawkeeper-bands/README.md)
- Risk fingerprints: [docs/cross-session-risk-fingerprint.md](docs/cross-session-risk-fingerprint.md)
