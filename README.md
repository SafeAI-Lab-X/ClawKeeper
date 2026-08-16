# ClawKeeper

Host-agnostic safety middleware for tool-using LLM agents.

ClawKeeper sits between an agent and its tools. It can block risky tool calls, redact sensitive tool results, remember recurring attack patterns, and delegate harder trajectory-level decisions to an external Watcher.

It is not OpenClaw-specific anymore. The core is Python, the integration surface is adapter-based, and the same policy/guard layer can be wired into Hermes Agent, MCP tools, HTTP bridges, OpenClaw-style runtimes, or a custom host.

## What it is for

- Guarding shell, Python, browser, filesystem, and network tool calls before execution.
- Catching common agent-security failures: prompt injection, credential reads, credential exfiltration chains, unsafe shell execution, protected-path access, SSRF-like URLs, encoded second-stage payloads, and poisoned tool output.
- Running a host-independent Judge API for non-Python adapters.
- Running an optional Watcher daemon that reasons over intent, recent tool history, deterministic findings, and proposed tool calls.
- Self-improving guard coverage: Watcher catches can synthesize learned patterns, persist them under `~/.clawkeeper/`, and hot-reload them into the live guard layer.

## Shape

```text
agent host  ->  adapter  ->  ClawKeeper core  ->  tool / tool result
                 |              |
                 |              deterministic guards + Judge
                 |
                 optional Watcher daemon for trajectory-level policy
```

Current adapters include:

- `clawkeeper_core.adapters.hermes` for Hermes Agent.
- `clawkeeper_core.adapters.mcp` for MCP-style tool gateways.
- `clawkeeper-server` for HTTP/JSON bridges used by non-Python hosts.
- Legacy OpenClaw integration code under `legacy/` and `adapters_js/`.

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

## Status

ClawKeeper v0.2 is an alpha research prototype. The strongest current surface is deterministic guard-layer enforcement plus host adapters. Watcher policy and self-evolving patterns are active research components and should be evaluated before production use.

## License

Apache-2.0.
