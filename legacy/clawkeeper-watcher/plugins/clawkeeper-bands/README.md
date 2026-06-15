# Clawkeeper-Bands for OpenClaw

<p align="left">
  <a href="https://github.com/openclaw/openclaw">
    <img src="https://img.shields.io/badge/OpenClaw-Compatible-blue.svg" alt="OpenClaw">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
</p>

**A user-side approval and bridge plugin for Clawkeeper-connected gateways.**

Clawkeeper-Bands runs on the user-facing OpenClaw gateway. It intercepts risky tool calls, pauses execution until a human decision is available, receives startup-audit notifications from the local watcher side, and can forward finished agent context to a remote `clawkeeper-watcher` for structured judgment.

Install it on the receiving or user-side gateway, not on the trusted local watcher runtime.

[Repository](https://github.com/xunyoyo/clawkeeper) · [Root Overview](../../README.md) · [Watcher Plugin](../clawkeeper-watcher/README.md)

# 💡 Features

Clawkeeper-Bands is the user-facing control layer in the Clawkeeper stack. It keeps human approval state on the gateway that talks to the user instead of burying those decisions inside the remote or local watcher runtime.

### ✋ Human Approval

Pause risky actions until the user decides:

- **`before_tool_call` Interception**: Evaluate tool calls before execution
- **Synchronous Blocking**: Stop execution until policy or user response resolves it
- **Policy Actions**: Support `ALLOW`, `ASK`, and `DENY`
- **Channel-Safe Prompts**: Work in TTY and messaging flows

### 🔗 Remote Judge Bridge

Forward completed agent context to a remote watcher for judgment:

- **Agent-End Forwarding**: Send serialized context on `agent_end`
- **Shared Judge Contract**: Call `POST /plugins/clawkeeper-watcher/context-judge`
- **Pending Decision Storage**: Hold `ask_user` state on the user-side gateway
- **Stop Mirroring**: Surface watcher stop summaries back to the user channel

### 📬 Startup Audit Receiver

Accept local-side watcher notifications:

- **Receiver Route**: Exposes `POST /plugins/clawkeeper-bands/clawkeeper-startup-audit`
- **User-Facing Summaries**: Deliver startup-audit findings back to the current session
- **Separated Trust Boundaries**: Keep full remediation local while sending summaries to the user side

### 📋 Audit Trail

Keep approval history and bridge behavior inspectable:

- **Decision Log**: Store approve, reject, allow, and block outcomes
- **Statistics**: Track aggregate counts and response timing
- **Bridge Events**: Persist bridge request and result metadata
- **Local Policy Store**: Save editable rules under `~/.openclaw/clawkeeper-bands/`

# 🚀 Quick Start

## Install as an OpenClaw plugin

From the plugin directory:

```bash
openclaw plugins install --link .
```

From the repo root or another checkout:

```bash
openclaw plugins install --link /path/to/clawkeeper/plugins/clawkeeper-bands
```

## Optional: install the CLI

If you want the setup wizard and local policy management commands:

```bash
npm install -g clawkeeper-bands
clawkeeper-bands init
```

## Validate the plugin role

Bands is intended for the user-facing gateway. Typical checks:

```bash
clawkeeper-bands audit
clawkeeper-bands policy
clawkeeper-bands stats
```

If using the full Clawkeeper stack, pair it with `clawkeeper-watcher` on the remote or local watcher side.

---

# 🛠️ Command Reference

### CLI commands

```bash
clawkeeper-bands init        # Interactive setup wizard
clawkeeper-bands policy      # Show or edit security policies
clawkeeper-bands stats       # Show decision statistics
clawkeeper-bands audit       # Show decision audit trail
clawkeeper-bands reset       # Reset stats
clawkeeper-bands disable     # Temporarily disable the plugin
clawkeeper-bands enable      # Re-enable the plugin
```

### HTTP routes and tools

Bands exposes or depends on these surfaces:

```text
POST /plugins/clawkeeper-bands/clawkeeper-startup-audit
POST /plugins/clawkeeper-watcher/context-judge
tool clawkeeper_bands_respond
```

# 🔄 How It Works

### TTY approval flow

1. A risky tool call reaches `before_tool_call`.
2. Bands maps the tool to a policy module and method.
3. Policy returns `ALLOW`, `ASK`, or `DENY`.
4. If `ASK`, the runtime pauses and waits for a human decision.
5. The decision is logged to the audit trail.

### Messaging-channel approval flow

When a gateway session is not interactive, Bands keeps approval state in memory and asks the user through the current channel.

The preferred response path is:

```text
clawkeeper_bands_respond({ decision: "yes" | "no" | "allow" })
```

- `yes`: approve once
- `no`: deny
- `allow`: auto-approve the same action for 15 minutes

### Remote judge bridge flow

When `bridge.enabled` is on:

1. Bands collects the finished agent context on `agent_end`.
2. It forwards that context to the remote watcher route:

```text
POST /plugins/clawkeeper-watcher/context-judge
```

3. The remote watcher returns `continue`, `ask_user`, or `stop`.
4. Bands stores pending approvals or mirrors summaries back to the user channel.

# 🔐 Policy Model

Bands uses three policy outcomes:

| Policy  | Behavior                          |
| ------- | --------------------------------- |
| `ALLOW` | Execute immediately               |
| `ASK`   | Pause and require a user decision |
| `DENY`  | Block automatically               |

Default behavior is centered on cautious interactive control:

- file reads are generally allowed
- writes and shell/network actions generally ask
- destructive actions such as deletes can be denied
- unmapped actions fall back to `defaultAction`

Protected tools are mapped into policy modules such as:

- `FileSystem`
- `Shell`
- `Browser`
- `Network`
- `Gateway`

# 🔗 Bridge and Receiver Integration

Clawkeeper-Bands sits between users and watcher runtimes:

- **Incoming notifications from watcher local mode**
  - receiver route: `POST /plugins/clawkeeper-bands/clawkeeper-startup-audit`
- **Outgoing finished-context judgment requests**
  - watcher route: `POST /plugins/clawkeeper-watcher/context-judge`

Bridge configuration lives under the plugin config `bridge.*`, including:

- `enabled`
- `url`
- `token`
- `judgePath`
- `timeoutMs`
- `maxContextChars`
- `policy`

Deprecated bridge fields exist for backward compatibility but are ignored by the current context-judge bridge:

- `model`
- `systemPrompt`
- `userPrompt`

# 📂 Data and Storage

Bands stores local state under:

```text
~/.openclaw/clawkeeper-bands/
├── policy.json            # persisted policy rules
├── decisions.jsonl        # approval and block audit trail
├── stats.json             # aggregate counters
├── bridge-events.jsonl    # bridge request/result events
├── bridge-last-request.json
└── clawkeeper-bands.log
```

# 📂 Architecture

Clawkeeper-Bands is organized around four surfaces:

1. **Core** (`src/core/`)
   - Policy evaluation
   - Human arbitration
   - Approval queue
   - Logging

2. **Plugin Entry** (`src/plugin/`)
   - `before_tool_call` interception
   - `agent_end` bridge
   - startup-audit receiver route
   - `clawkeeper_bands_respond` tool registration

3. **Storage** (`src/storage/`)
   - persisted policy
   - decision log
   - stats tracking

4. **CLI** (`src/cli/`)
   - setup wizard
   - audit, stats, policy, enable, disable

### File Structure

```text
plugins/clawkeeper-bands/
├── src/
│   ├── core/         # Policy evaluation, arbitration, approval queue, logging
│   ├── plugin/       # Hooks, bridge, startup-audit receiver, tool registration
│   ├── storage/      # Policy, decisions, stats
│   ├── cli/          # Wizard and local management commands
│   ├── config.ts
│   └── types.ts
├── dist/
├── openclaw.plugin.json
└── package.json
```

# 🧪 Development

For local development:

```bash
cd plugins/clawkeeper-bands
npm install
npm run build
```

To test the CLI after building:

```bash
node dist/cli/index.js --help
node dist/cli/index.js init
```

To test as a linked CLI package:

```bash
npm link
clawkeeper-bands --help
```

# 📕 Reference

- Root overview: [../../README.md](../../README.md)
- Watcher plugin: [../clawkeeper-watcher/README.md](../clawkeeper-watcher/README.md)
