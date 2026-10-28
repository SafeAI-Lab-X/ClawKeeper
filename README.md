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

## Command execution gate

The execution gate runs locally and makes no model calls. Built-in command
patterns are scoped to the program called in each shell segment. Text in an
`echo` argument, a comment, a Python string, or a normal file-write payload is
not treated as a shell program invocation. The gate checks each executable
field independently, and log scanning uses the same context-aware detector.

The analyzer uses upstream tree-sitter for Bash syntax and Python's `ast` for
inline Python, Python heredocs and literal here-strings. It follows command substitutions, literal
shell `-c` bodies, common literal `os.system`/`subprocess` calls (including import
aliases and explicit `subprocess` executable overrides), and supported wrappers
such as `sudo`, `env`, and `command`. Redirections survive wrapper unwrapping,
and pipeline analysis preserves redirected and grouped stages. Ordinary dynamic
data arguments after a known wrapper target remain data; dynamic program names
and code operands require review. Process substitutions supplying executable
source also require review. Each
built-in pattern declares its executable scope; a clean segment cannot exempt
another segment. Existing rule IDs and risk policies, including the restriction
on actual `whoami`/`ver` calls, are preserved.

Malformed syntax, unresolved executable text, unsupported inline languages,
and source/node/depth limits produce `block=true`, `outcome=ask`, and
`analysis=indeterminate`. This pauses the call through existing adapters; it is
not a claim that a known dangerous command was found. PowerShell code is not
fully parsed; PowerShell interpreter invocations require review. Simple literal
`cmd /c` calls are inspected, but this is not a complete Cmd parser.

All 49 built-in patterns use executable scopes. Built-in and learned checks
share the same extraction and syntax analysis: explicit execution fields
(`command`, `cmd`, `script`, plus code/input fields on execution tools), including
nested execution envelopes and generic `payload` fields. Descriptions, headers,
environment metadata and known file/content tools are excluded from command
analysis. Custom tools using other fields need a corresponding field mapping.
Independent path and content guards still apply.

Parsing now produces immutable facts: original source documents, UTF-8 byte
ranges, argument values/roles, nested code origins, pipeline stages and effective
stdin. Guards, log scanning, learning and explanations consume this same model.
A guard-chain scope parses each distinct input once; facts expire at the end of
that evaluation. Changed inputs invalidate the scoped cache. No model is called
by this assessment path.

New learned rules select a semantic `subject`: `program.name`, `python.module`,
`script.path`, `python.operation` or `path`. Names use full matching; paths use
search. The `invocation` subject preserves the earlier executable-first matching
projection for rules that need several arguments. Synthesis, validation, reload
and enforcement use the same field selectors. The script heuristic also uses
parsed calls, excluding comments, standalone Python strings and recognized
literal output data while retaining dynamic-path proximity detection.

Source samples carry a subject and schema version. Legacy raw samples are
reparsed; version-3 bare program samples migrate to `program.name` so an anchored
`node$` rule still matches `node script.js`. Incompatible samples stay inactive
with an inspectable reason. Version-4 invocation samples retain their projection.
Protocol **2**, validator **5**, and subject schema **1** prevent silently mixing
matching semantics; upgrade Watcher and adapters together. Immutable snapshots,
atomic replacement, deletions (including legacy IDs) and restart synchronization
from issues #7/#8 remain covered by tests.

Inspect a proposed call without running it or invoking a Judge:

```bash
python -m clawkeeper_core.execution 'echo whoami'
python -m clawkeeper_core.execution 'bash -c whoami'
python -m clawkeeper_core.execution 'bash -c "$SOURCE"'
```

The JSON output contains the real guard-chain decision (`allow`/`deny`/`ask`),
facts, source ranges, diagnostics and pinned rule version. Recognized secrets
are masked while preserving byte offsets. Use `--event-stdin` for a JSON tool
event and `--rules-snapshot exported-rules.json` to replay an exported
`GET /watcher/rules` snapshot; this never reads or migrates the live learned store.
The installed entry point is `clawkeeper-explain`.

This is bounded static detection, not a sandbox or a proof of arbitrary program
safety. It does not follow external scripts, runtime aliases, arbitrary Python
data flow, or executable files on disk. Keep the host's permissions and sandbox
enabled. Some valid Bash redirection forms exceed the upstream grammar or fail
its descriptor-boundary checks; these require review. Regression tests pair
inert data with actual calls and use generated quoting/wrapper transformations;
only fixed benign `printf` probes execute to cross-check shell stdin semantics.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

Red-team fixtures and benchmark scripts live under `tests/redteam/` and `experiments/`.


## License

Apache-2.0.
