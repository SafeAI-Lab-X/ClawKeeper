# clawkeeper-shim — OpenClaw plugin for clawkeeper-core

A thin OpenClaw plugin that forwards every tool-call decision to the
running clawkeeper-core Python server. **All decision logic lives in
Python.** This JS file only registers OpenClaw hooks and serializes
their payloads to HTTP.

## Why a shim?

The v0.1 plugin shipped ~13K LOC of safety logic embedded in JS, which
locked ClawKeeper to OpenClaw and made the codebase impossible to share
with non-OpenClaw agents (Hermes, Claude Code, Cursor, …). v0.2 lifted
that logic into a framework-agnostic Python core. This shim is what
keeps existing OpenClaw installs working through the refactor —
behavior is identical, just with the rule evaluation happening over HTTP.

## Install

```bash
# Inside the OpenClaw plugin tree
npm install <path-to>/clawkeeper/adapters_js/openclaw
```

Then enable in `openclaw.json`:

```json
{
  "plugins": {
    "clawkeeper-shim": {
      "serverUrl": "http://127.0.0.1:7474",
      "failurePolicy": "fail-closed",
      "timeoutMs": 2000
    }
  }
}
```

Start the Python core in parallel:

```bash
conda activate clawkeeper
clawkeeper-server
```

## Failure policy

If `clawkeeper-core` is unreachable, the shim synthesizes a Decision
based on `failurePolicy`:

  - **fail-closed (default)** → `decision: "stop"`. Tool call is blocked.
  - **fail-open** → `decision: "continue"`. Tool call is allowed through.

fail-closed is safer; fail-open avoids breaking developer flow when
you're prototyping and the server is down. Pick deliberately.

## Testing

The round-trip test boots an external server and exercises every
branch. Run from this directory:

```bash
# In one terminal:
clawkeeper-server

# In another:
npm test
```

## What's NOT in this shim

  - No regex rules
  - No path-protection logic
  - No log scanner
  - No skill scanner
  - No decision memory

All of those live in `clawkeeper_core/`. If you find yourself wanting
to add detection logic here, add it there instead.
