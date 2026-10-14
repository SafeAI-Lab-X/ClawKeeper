# ClawKeeper

Host-agnostic safety middleware for tool-using agentic systems (can be wired into Hermes Agent, MCP tools, HTTP bridges, OpenClaw-style runtimes, or a custom host).

ClawKeeper sits between an agent and its tools. It can block risky tool calls, redact sensitive tool results, remember recurring attack patterns & self improve guardrail layers, and delegate harder trajectory-level decisions to an external Watcher.


## What it is for

- Guarding shell, Python, browser, filesystem, and network tool calls before execution.
- Catching common agent-security failures: prompt injection, credential reads, credential exfiltration chains, unsafe shell execution, protected-path access, SSRF-like URLs, encoded second-stage payloads, and poisoned tool output.
- Running a host-independent Judge API for non-Python adapters.
- Running an optional Watcher daemon that reasons over intent, recent tool history, deterministic findings, and proposed tool calls.
- Self-improving guard coverage: Watcher catches can synthesize learned patterns, persist them under `~/.clawkeeper/`, and hot-reload them into the live guard layer.


## Install

```bash
git clone git@github.com:SafeAI-Lab-X/ClawKeeper.git
cd ClawKeeper

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Sanity check:

```bash
pytest -q
```

## Use with Hermes Agent

```python
from run_agent import AIAgent

from clawkeeper_core import Judge
from clawkeeper_core.adapters.hermes import install as install_clawkeeper

agent = AIAgent(...)
install_clawkeeper(Judge(), agent)

agent.run("your task")
```

This installs the default pre-tool guard chain and post-tool-result scanners. No Hermes patching is required.

## Run the HTTP core

For hosts that cannot import the Python package directly:

```bash
clawkeeper-server
curl http://127.0.0.1:7474/v1/health
```

Useful endpoints include `/v1/judge`, `/v1/event`, `/v1/audit`, `/v1/scan/logs`, `/v1/scan/skill`, and maintenance harden/rollback routes.

## Run the Watcher

The Watcher is optional. It is useful when single-command rules are not enough and the decision depends on intent, recent tool history, or multi-step drift.

```bash
export CK_WATCHER_API_KEY="$OPENAI_API_KEY"
export CK_WATCHER_BASE_URL="$OPENAI_BASE_URL"   # optional, OpenAI-compatible
export CK_WATCHER_MODEL="gpt-5.5"               # or your configured model

python -m clawkeeper_core.watcher.daemon
curl http://127.0.0.1:9099/watcher/health
```

Wire it into Hermes:

```python
install_clawkeeper(
    Judge(),
    agent,
    watcher_url="http://127.0.0.1:9099",
)
```

## Test Codex CLI hooks (experimental)

`examples/codex_pre_tool_use.py` is a minimal shell-only `PreToolUse` hook.
It runs the existing execution, protected-path, URL, and script-body guards
in-process. A denial uses Codex's hook response format; safe calls leave
Codex's normal permissions and sandbox in place. It does not use the HTTP
server or Watcher, and does not scan tool results or chat messages.

Test the real CLI without changing your active Codex configuration:

```bash
uv run --extra dev python examples/codex_hook_smoke.py
```

The smoke test needs a local Codex CLI with hook support (verified on 0.162.1)
and permission to bind a loopback port. It uses a deterministic local Responses
fixture, temporary files, and invocation-only configuration. It makes no
external model requests and never reads actual credentials. It verifies an
unguarded control, hooks skipped pending trust, and guarded native shell calls.
Only the guarded test invocation uses `--dangerously-bypass-hook-trust` for the
reviewed fixture; no persisted trust or global hook configuration is changed.

Start a separate interactive CLI with the hook enabled for that invocation:

```bash
bash examples/start_codex_guarded.sh
```

The launcher starts Codex with `--no-daemon`, keeps the native workspace-write
sandbox and on-request approvals, and inherits your normal account and model
settings. At startup it locates the project's Python interpreter and hook script
relative to the launcher and passes their paths to Codex using `--config`.
The hook applies only to the session started by the launcher.

Before submitting tasks in the new CLI, open `/hooks`, inspect the `PreToolUse`
entry whose command runs `codex_pre_tool_use.py`, and trust that definition.
If the CLI asks you to restart after trust review, close it and run the same
launcher again. The launcher never bypasses hook trust. To check protection
without reading secrets, ask the new agent to run `printf CLAWKEEPER_OK`, then
`printf '%s\\n' ~/.aws/credentials`. The first should execute; the second
should be denied with a `[ClawKeeper]` reason. Exit this CLI and start ordinary
`codex` to omit the invocation-only hook.

To continue a saved conversation with the hook configured again, use the
launcher for resume too:

```bash
bash examples/start_codex_guarded.sh resume <SESSION_ID>
```

Or use `resume --last` to continue the most recent session. Conversation
history and invocation-only hook configuration are separate; check `/hooks`
after reopening the conversation before relying on protection.

For a persistent installation, merge this entry into your Codex `hooks.json`
using absolute, quoted paths for your checkout and virtual environment:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "\"/absolute/path/ClawKeeper/.venv/bin/python\" \"/absolute/path/ClawKeeper/examples/codex_pre_tool_use.py\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Review and trust the definition with `/hooks` in a separate Codex session.
Project hooks also require a trusted project. Merely writing a hook file does
not activate protection. The prototype denies malformed input and guard
exceptions, but runtime failures outside the script (missing interpreter,
timeout, skipped/untrusted hook) are subject to Codex's own behavior. Hosted
tools and subsequent input to an existing `write_stdin` session are outside
this shell-only hook's coverage. See the [official hook documentation](https://learn.chatgpt.com/docs/hooks).

## Core guards

The default guard set currently covers:

- dangerous shell execution
- protected path access
- unsafe URL / SSRF patterns
- script-body and dynamic-path inspection
- base64/hex encoded payloads
- credential discovery plus network exfiltration chains
- poisoned return content
- credential redaction

The exact policies are intentionally small and inspectable; see `clawkeeper_core/guards/`.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

Red-team fixtures and benchmark scripts live under `tests/redteam/` and `experiments/`.


## License

Apache-2.0.
