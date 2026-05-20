# ClawKeeper Quickstart

A framework-agnostic safety layer for LLM agents. Drop it in front of
Hermes Agent, Claude Code (via MCP), an OpenClaw plugin host, or anything
you build — same policy, no rewriting per framework.

## Install

```bash
# Python 3.11+
pip install -e .                       # local install from the repo
pip install -e ".[mcp]"                # add the MCP gateway adapter
pip install -e ".[adversarial]"        # add the Phase-5 adversarial layer
pip install -e ".[dev]"                # pytest, ruff, mypy
```

## Three integration paths

### 1. Hermes Agent (Python, fastest path)

```python
from run_agent import AIAgent
from clawkeeper_core import Judge
from clawkeeper_core.adapters.hermes import install as install_clawkeeper

judge = Judge()                                  # default policy

agent = AIAgent(
    base_url="https://api.scode.chat/v1",        # or api.openai.com/v1
    api_key="...",
    model="claude-haiku-4-5-20251001",
    enabled_toolsets=["terminal"],               # see notes below
)

install_clawkeeper(judge, agent)                 # one call wires everything

response = agent.chat("Set up a backup script in /tmp/backups.")
```

**What `install` does** (no Hermes patches required):

- Registers `path_guard` + `exec_gate` as a **pre-check** in front of
  Hermes' own `check_all_command_guards`. ClawKeeper sees every terminal
  command before Hermes' built-in detector decides. First-to-block wins.
- Wires `set_approval_callback` on `tools.terminal_tool` and
  `tools.computer_use.tool` so when Hermes does ask for approval,
  ClawKeeper's `Judge` answers.
- Wraps `tool_start_callback` / `tool_complete_callback` so every tool
  call is observable, regardless of who decided about it. The data
  feeds `clawkeeper_core.profile.AgentProfiler` if `judge.profiler`
  is set.

**Provider notes (Anthropic-via-third-party endpoints):**

- The `openai` Python SDK sends `User-Agent: OpenAI/Python ...`, which
  many Claude-relaying proxies (api.scode.chat, …) reject as 403. The
  demo runner monkey-patches the SDK to send a generic browser UA. If
  you hit 403s, do the same. See `examples/hermes_demo.py` for the
  16-line patch.
- Hermes loads ~40 toolsets by default; some have JSON schemas that
  fail strict Anthropic-side validation (Anthropic enforces JSON Schema
  draft 2020-12). Use `enabled_toolsets=["terminal"]` to narrow to the
  ones we want to govern, or use a GPT-class model where Anthropic
  validation doesn't apply.

### 2. Claude Code / Cursor / Cline (via MCP gateway)

```python
from clawkeeper_core import Judge
from clawkeeper_core.adapters.mcp import GatewayServer

server = GatewayServer(name="clawkeeper-gw", judge=Judge())

@server.guarded_tool(description="Run a shell command")
async def bash(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True, text=True)

server.run()      # stdio transport, ready for Claude Code's MCP config
```

Then in your Claude Code (or Cursor / Cline / Goose / Hermes' own MCP
client) configuration, point at this server. Every `tools/call` goes
through `Judge` first; if it returns `stop` or `ask_user`, the client
sees a `McpError` and never executes the tool.

### 3. OpenClaw (legacy, via HTTP shim)

Run the Python core as an HTTP server:

```bash
clawkeeper-server                                # listens on 127.0.0.1:7474
```

Then enable the slim JS shim in your OpenClaw config:

```json
{
  "plugins": {
    "clawkeeper-shim": {
      "serverUrl": "http://127.0.0.1:7474",
      "failurePolicy": "fail-closed"
    }
  }
}
```

The shim has zero decision logic — it just forwards `before_tool_call`
events as `POST /v1/judge`. All rules live in Python.

## What policy is

`Judge()` with no arguments uses a sensible default:

- Max 3 tool calls without a user turn before asking
- `exec`, `bash`, `shell`, `network`, `write` always require user confirmation
- Risk threshold: stop at `critical`
- `treatCommandExecutionAsHighRisk: true`

Customize:

```python
judge = Judge(policy={
    "maxToolStepsWithoutUserTurn": 5,
    "autoContinueAllowed": False,
    "requireUserConfirmationFor": ["exec", "bash", "shell", "network", "write"],
})
```

For richer detection (regex patterns, protected paths, sensitive verbs),
the rules live in:

- `clawkeeper_core.security_rules` — 60 prompt-injection patterns, 49
  dangerous-command patterns, 96 high-risk tool names
- `clawkeeper_core.drift.SENSITIVE_TOPIC_PATTERNS` — SSH keys,
  cloud creds, persistence locations, etc.
- `clawkeeper_core.guards.path_guard` — protected-path glob list

You can add to these directly, or wait for the Phase-5 adversarial loop
to surface new patterns from real attack data.

## What's in the box

```
clawkeeper_core/
├── judge.py           — central decision engine (context-judge.js port)
├── risk.py            — cross-session risk fingerprinting
├── drift.py           — intent vs. tool-chain drift
├── profile.py         — agent behavioral baseline + anomaly
├── memory.py          — append-only decision log (JSONL)
├── controls.py        — 5 built-in hardening checks
├── audit.py           — audit driver + scoring
├── maintenance.py     — harden + rollback (snapshots state files)
├── scanner.py         — log + skill scanners
├── security_rules.py  — pattern catalogue
├── permission.py      — HMAC-signed allow/deny store
├── guards/
│   ├── exec_gate.py      — dangerous-command pre-block
│   ├── path_guard.py     — protected paths (~/.ssh, /etc/shadow, ~/.aws, …)
│   ├── input_validator.py — JSON-schema-subset validator
│   └── budget.py         — token-budget tracker
├── server.py          — FastAPI HTTP surface (POST /v1/judge, etc.)
└── adapters/
    ├── hermes.py      — Hermes Agent
    ├── mcp.py         — MCP gateway (Claude Code, Cursor, …)
    └── openclaw_http  — see adapters_js/openclaw/
```

## Running the demo

```bash
# Set up the env (one-time)
conda create -n clawkeeper-demo python=3.11 -y
conda activate clawkeeper-demo
pip install -e .[dev]
pip install hermes-agent psutil                  # if testing Hermes path

# Provide an API key for whatever LLM you want to use
export OPENAI_API_KEY="..."
export OPENAI_BASE_URL="https://api.scode.chat/v1"   # if using a third-party endpoint
export HERMES_INTERACTIVE=1                          # so Hermes invokes the approval callback

# Run the scenario suite
python examples/hermes_demo.py --model claude-haiku-4-5-20251001

# Output:
#   examples/runs/<timestamp>/raw.json   — full structured trace
#   examples/runs/<timestamp>/report.md  — human-readable summary
```

Each scenario captures: prompt, tool calls attempted, ClawKeeper
decisions, elapsed time, memory delta, final assistant response, and a
verdict tag classifying whether the model refused at LLM level, Hermes'
pipeline blocked, ClawKeeper's pre-check blocked, or everyone agreed
the call was fine.

## Where ClawKeeper actually adds value

Based on the included scenario suite running against Claude haiku +
Hermes Agent:

| Defense layer | Catches |
|---|---|
| Claude (LLM-level refusal) | Direct exfiltration prompts (`cat ~/.ssh/id_rsa`), explicit jailbreaks, embedded prompt injection in retrieved files |
| Hermes' built-in `check_all_command_guards` | Direct `rm -rf /`, `~/.bashrc` modifications, recognized SSH-key-write patterns |
| **ClawKeeper's `path_guard` pre-check** | **Slow-drift toward `~/.aws/credentials` when wrapped in `\|\| echo` (Hermes' regex misses this); SSH key directory setup before write happens; any path-based exfiltration Hermes doesn't recognize** |
| **ClawKeeper's `exec_gate` pre-check** | Dangerous commands Hermes considers benign + things in the long tail Hermes' patterns don't cover |

The story isn't "ClawKeeper alone protects you from a dangerous LLM."
The story is "ClawKeeper is the framework-agnostic policy layer that
runs in front of whatever the host agent already does, adds coverage
where the host has gaps, and applies the same rules across Hermes,
Claude Code, OpenClaw, and anything else that comes next."

## Tests

```bash
pytest -q                          # 171 Python tests
pytest tests/test_hermes_adapter.py -q  # 9 Hermes tests (needs hermes-agent installed)
cd adapters_js/openclaw && node test/round_trip.test.mjs  # 6 JS shim tests
```
