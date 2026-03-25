---
name: clawkeeper
description: Install, configure, verify, and debug the Clawkeeper watcher stack in this workspace. Use when a user asks to set up `clawkeeper`, initialize `remote` or `local` mode, enable `clawkeeper-watcher`, wire `clawkeeper-bands`, diagnose `context-judge` routing, inspect watcher logs, fix mode/config mismatches, or troubleshoot startup, audit, hardening, rollback, drift monitoring, or bridge notification issues.
metadata: { "openclaw": { "emoji": "🦞" } }
---

# Clawkeeper

Use this skill only for the Clawkeeper workspace. Treat `clawkeeper-watcher` as the product center and `clawkeeper` as the launcher that prepares mode-specific runtime state.

## Core mental model

- `plugins/clawkeeper-watcher/` is the watcher plugin and governance engine.
- `clawkeeper/` is the launcher that prepares isolated `remote` and `local` mode roots, then delegates to OpenClaw.
- `plugins/clawkeeper-bands/` is the user-side bridge for notifications and approvals.
- `remote` is read-only judgment and historical intelligence.
- `local` is trusted audit, hardening, rollback, drift monitoring, and skill guard.
- Both watcher modes expose `POST /plugins/clawkeeper-watcher/context-judge`.

Read these files when needed:

- `README.md`
- `plugins/clawkeeper-watcher/README.md`
- `plugins/clawkeeper-bands/README.md`
- `clawkeeper/src/cli.ts`

## Preferred workflow

Follow this order unless the user explicitly narrows the task:

1. Identify whether the user wants install, config, validation, or debugging.
2. Check whether the issue is about the launcher, the watcher plugin, or the bands bridge.
3. Verify the exact mode in play: `remote`, `local`, or both.
4. Run the smallest direct validation command first.
5. Only after validation fails, inspect config, logs, bridge wiring, and code paths.

Do not jump straight to speculative fixes.

## Install and initialize

For source checkout setup in this repo, use:

```bash
pnpm install
cd clawkeeper
npm install
npm run build
npm link
cd ..
```

Initialize modes with:

```bash
clawkeeper init remote
clawkeeper init local
clawkeeper local config set gateway.mode local
clawkeeper status
```

Important:

- `local` mode expects `gateway.mode=local`.
- The launcher stores mode state under `~/.clawkeeper/` by default unless `--root` overrides it.
- If the problem is only inside the watcher plugin, do not blame launcher setup until `clawkeeper status` or mode launch actually fails.

## Validation commands

Use the most direct command for the claimed problem.

### Launcher validation

```bash
clawkeeper --help
clawkeeper status
clawkeeper init remote
clawkeeper init local
```

### Mode launch validation

```bash
clawkeeper remote gateway run
clawkeeper local gateway run
```

### Watcher validation

```bash
clawkeeper remote clawkeeper-watcher status
clawkeeper remote clawkeeper-watcher logs
clawkeeper remote clawkeeper-watcher fingerprints
clawkeeper remote clawkeeper-watcher profiles

clawkeeper local clawkeeper-watcher status
clawkeeper local clawkeeper-watcher logs
clawkeeper local clawkeeper-watcher audit
clawkeeper local clawkeeper-watcher harden
clawkeeper local clawkeeper-watcher monitor
clawkeeper local clawkeeper-watcher rollback
clawkeeper local clawkeeper-watcher scan-skill <name-or-path>
```

### Context-judge validation

Confirm that the route is the watcher route, not the bands route:

```text
POST /plugins/clawkeeper-watcher/context-judge
```

### Bridge validation

Install the receiving-side bridge plugin with:

```bash
openclaw plugins install --link /path/to/clawkeeper/plugins/clawkeeper-bands
```

Then verify the local watcher bridge config:

```bash
clawkeeper local config set plugins.entries.clawkeeper-watcher.config.notify.userBridge.enabled true
clawkeeper local config set plugins.entries.clawkeeper-watcher.config.notify.userBridge.url http://127.0.0.1:18889
clawkeeper local config set plugins.entries.clawkeeper-watcher.config.notify.userBridge.token <gateway-token>
```

## Debugging order

When debugging, follow this sequence:

1. Confirm the exact failing command.
2. Confirm whether the command is running in `remote` or `local`.
3. Confirm whether the command is launcher-level or watcher-level.
4. Inspect current config relevant to that failure.
5. Read watcher logs or gateway output.
6. Check bridge endpoint path and token if notifications or approvals are involved.
7. Only then inspect code.

Report the first verified failing boundary, not every possible theory.

## Common failure patterns

### Local command run in remote mode

Symptoms:

- `audit`, `harden`, `monitor`, or `rollback` rejected
- output says the command is only available in local mode

Fix:

- rerun on the local instance
- verify `CLAWKEEPER_MODE` or config mode if behavior is unexpected

### `gateway.mode` mismatch

Symptoms:

- local launch behaves like plain or wrong mode
- local-only watcher behavior does not appear

Fix:

- set `clawkeeper local config set gateway.mode local`
- restart the local mode process

### Wrong route when testing context judgment

Symptoms:

- request sent to bands instead of watcher
- remote judgment appears missing

Fix:

- use `POST /plugins/clawkeeper-watcher/context-judge` for watcher judgment
- use `clawkeeper-bands` only for the receiving-side bridge and approval surface

### Bridge configured but notifications do not arrive

Symptoms:

- startup audit or approval summary never reaches user-side gateway

Check:

- bridge `enabled`
- bridge `url`
- bridge `token`
- receiving gateway has `clawkeeper-bands` installed
- user-side receiver path exists and gateway is reachable

### Logs exist but the wrong file is inspected

Symptoms:

- "no events" while watcher is active

Check:

- today vs explicit `--date`
- current mode and workspace
- whether the command is reading watcher event logs or launcher stdout

Use:

```bash
clawkeeper local clawkeeper-watcher log-path
clawkeeper local clawkeeper-watcher logs --all
clawkeeper local clawkeeper-watcher logs --date YYYY-MM-DD
```

### Audit result interpreted as host hardening

Symptoms:

- user expects firewall, SSH, or OS policy changes

Clarify:

- Clawkeeper watcher audits and hardens OpenClaw-side runtime state
- it does not automatically perform generic host OS hardening

## Command accuracy guardrails

Do not invent flags or routes. Prefer commands already documented in:

- `README.md`
- `plugins/clawkeeper-watcher/README.md`
- `clawkeeper/src/cli.ts`

Current launcher surface:

- `clawkeeper init <mode>`
- `clawkeeper status`
- `clawkeeper remote ...`
- `clawkeeper local ...`

Current watcher CLI surface includes:

- `audit`
- `harden`
- `monitor`
- `rollback`
- `status`
- `logs`
- `log-path`
- `scan-skill`
- `fingerprints`
- `profiles`

## Response expectations

When using this skill:

- State whether the issue is launcher, watcher, or bridge related.
- State whether it is `remote`, `local`, or cross-mode.
- Show the exact command you used to validate the issue.
- Separate verified facts from inference.
- Prefer the narrowest fix that matches the failing boundary.
