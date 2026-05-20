# ClawKeeper v0.2 — Quickstart for Hermes Agent

This guide gets ClawKeeper running in front of a Hermes Agent install from scratch.

If you already have a working Hermes setup, skip to step 3.

---

## Prerequisites

| | Required | Notes |
|---|---|---|
| Python | 3.11+ | Hermes itself requires 3.11; ClawKeeper inherits |
| A Hermes Agent checkout | Yes | We integrate as an in-process plugin, so Hermes needs to be importable. Clone from `git@github.com:NousResearch/hermes-agent.git` |
| An OpenAI-compatible LLM endpoint | Yes | OpenAI / Anthropic / OpenRouter / scode.chat / any local server that exposes `/v1/chat/completions` |
| Network access from the box running Hermes | To your LLM endpoint | If your box is firewalled off from your provider, set up a proxy first (clash / WireGuard / corp HTTP proxy) — ClawKeeper does not add network requirements of its own beyond what Hermes already needs |

ClawKeeper does NOT need:
- Docker, Kubernetes, or any orchestrator (it's a Python library + an optional FastAPI daemon)
- A separate database — session state is in-memory by default
- A separate LLM API key beyond what Hermes already uses (the optional Watcher can reuse Hermes's key or take its own)

---

## Step 1 — Install Hermes Agent

If you don't already have it:

```bash
git clone git@github.com:NousResearch/hermes-agent.git
cd hermes-agent
./setup-hermes.sh         # creates a .venv, installs deps, links the `hermes` CLI
```

Or with a venv you manage yourself:

```bash
git clone git@github.com:NousResearch/hermes-agent.git
cd hermes-agent
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verify:

```bash
python -c "from run_agent import AIAgent; print('Hermes OK')"
```

## Step 2 — Configure Hermes

Two files matter:

### `~/.hermes/config.yaml` — model + terminal backend

Minimum viable example for an OpenAI-compatible provider:

```yaml
model:
  default: "gpt-5.4-openai-compact"     # any model id your provider exposes
  provider: "custom"                     # for OpenAI-compatible endpoints
  base_url: "https://api.openai.com/v1"  # change to your endpoint

terminal:
  backend: "local"                       # or "docker" for containerised execution
  cwd: "/path/to/your/workdir"           # the directory Hermes runs tools in
  timeout: 180

session_reset:
  mode: idle
  idle_minutes: 1440

group_sessions_per_user: true
```

### `~/.hermes/.env` — secrets (mode 0600)

```bash
OPENAI_API_KEY="sk-…"
OPENAI_BASE_URL="https://api.openai.com/v1"

# If you'll run the Hermes messaging gateway against Discord/Telegram/etc.:
# DISCORD_BOT_TOKEN="..."
# DISCORD_ALLOWED_USERS="numeric_user_id_1,numeric_user_id_2"
```

`chmod 600 ~/.hermes/.env` after creating it.

Smoke test Hermes alone (no ClawKeeper yet):

```bash
hermes chat -m gpt-5.4-openai-compact
# type "list the files here" — should work
```

## Step 3 — Install ClawKeeper

In the same Python environment Hermes is installed in:

```bash
git clone git@github.com:SafeAI-Lab-X/ClawKeeper.git
cd ClawKeeper
git checkout v0.2-refactor               # currently the active branch
pip install -e .                         # core
pip install -e ".[mcp]"                  # optional: MCP gateway adapter
pip install -e ".[dev]"                  # optional: pytest, ruff, mypy
```

Verify the install:

```bash
python -c "
from clawkeeper_core import Judge
from clawkeeper_core.adapters.hermes import install
print('ClawKeeper OK')
"
pytest -q --ignore=tests/redteam tests/   # should report 250+ passing
```

## Step 4 — Wire ClawKeeper into Hermes (deterministic mode)

This is the minimum integration. No daemon, no extra LLM calls. Catches a strong set of attacks via deterministic guards (path access, dangerous-command regex, SSRF, homoglyph URLs, script-body sensitive-path detection, credential redaction).

```python
# my_agent.py — your own entrypoint or wrap-script
from run_agent import AIAgent
from clawkeeper_core import Judge
from clawkeeper_core.adapters.hermes import install as install_clawkeeper

agent = AIAgent(
    model="gpt-5.4-openai-compact",
    base_url="https://api.openai.com/v1",
    enabled_toolsets=["terminal"],       # see note below
    max_iterations=30,
)

install_clawkeeper(Judge(), agent)       # one call wires every documented hook

response = agent.chat("List the files in this directory.")
print(response)
```

What `install_clawkeeper(...)` actually does:

1. Registers a `pre_tool_call` plugin hook with Hermes — Hermes's **documented** blocking API. The hook runs ClawKeeper's deterministic guard chain on every tool call; if any guard blocks, Hermes returns a block message to the LLM and the tool never executes.
2. Wires `set_approval_callback` on `tools.terminal_tool` and `tools.computer_use.tool` — when Hermes's own regex flags a command and asks for approval, ClawKeeper's `Judge` answers.
3. Attaches `tool_start_callback` / `tool_complete_callback` for telemetry (drift detection, profiling).

The Hermes CLI (`hermes chat`, `hermes gateway`) doesn't expose a plugin-mount point directly — wrap it the way `examples/hermes_demo.py` does (UA patch + `install_clawkeeper(...)` + delegate to `hermes_cli.main.main()`). See `examples/hermes_discord_bot.py` for a complete gateway-mode launcher.

## Step 5 (optional) — Enable the LLM-driven Watcher

The Watcher is the third architectural layer: an external LLM-driven supervisor that reasons about whole trajectories rather than individual commands. Pay 1 extra LLM call (~2–5 s) per tool call; gain trajectory-level drift detection.

Start the daemon in a separate shell (or under systemd / a process supervisor):

```bash
# Environment knobs (all optional — defaults shown)
export CK_WATCHER_HOST="127.0.0.1"        # bind address (do NOT bind 0.0.0.0)
export CK_WATCHER_PORT="9099"
export CK_WATCHER_MODEL="gpt-5.4-openai-compact"  # what the Watcher reasons with
export CK_WATCHER_BASE_URL="$OPENAI_BASE_URL"     # falls back to OPENAI_BASE_URL
export CK_WATCHER_API_KEY="$OPENAI_API_KEY"       # falls back to OPENAI_API_KEY

python -m clawkeeper_core.watcher.daemon
```

Health check:

```bash
curl http://127.0.0.1:9099/watcher/health
# {"status":"ok","model_id":"gpt-5.4-openai-compact","known_sessions":0}
```

Wire it into the adapter:

```python
install_clawkeeper(
    Judge(),
    agent,
    watcher_url="http://127.0.0.1:9099",
)
```

The Watcher is consulted only when the deterministic guards didn't already block. If the Watcher is unreachable, the client falls back to `ask` (defer to operator) — never silently allows.

## Step 6 — Verify end-to-end

`examples/hermes_demo.py` is a self-contained runner that exercises a few benign + adversarial scenarios against a live agent. Run it from the ClawKeeper repo root:

```bash
source /path/to/hermes/.env             # provides OPENAI_API_KEY / OPENAI_BASE_URL
cd ClawKeeper
python examples/hermes_demo.py
```

The script writes a JSON trace + a markdown summary into `examples/runs/<timestamp>/`. ClawKeeper decisions show up under `_clawkeeper_decisions` on each tool call.

For a more aggressive validation, use the red-team suite:

```bash
# Need a workspace for the agent to operate in:
mkdir -p tests/redteam/workspaces
git clone --depth 1 git@github.com:miguelgrinberg/microblog.git \
  tests/redteam/workspaces/flask-todo

# Run a scenario
export REDTEAM_USE_WATCHER=1                            # optional
export REDTEAM_WATCHER_URL="http://127.0.0.1:9099"      # only if using Watcher
python -m tests.redteam.runner --only 07.a
```

Reports go to `tests/redteam/results/<timestamp>/`.

---

## Configuration reference

### Hermes `~/.hermes/config.yaml`

| Key | What it does | Recommended for ClawKeeper |
|---|---|---|
| `model.default` | Which LLM the agent uses | Any. The agent's own LLM is one defense layer; smaller models = ClawKeeper does more work. |
| `model.provider` | `"custom"` for OpenAI-compatible | `"custom"` for scode.chat / OpenRouter / local servers |
| `terminal.backend` | `local` / `docker` / `ssh` / `modal` | Choose based on isolation needs. ClawKeeper's policy applies regardless of backend. |
| `approvals.mode` | `manual` / `smart` / `off` | **Use `manual`.** `smart` delegates safety to an aux LLM (jailbreakable); `off` disables Hermes's regex layer entirely. |
| `command_allowlist` | Hermes's permanent-allow list | Keep small. ClawKeeper still applies its own guards independently. |

### Hermes `~/.hermes/.env`

```
# LLM endpoint
OPENAI_API_KEY=...
OPENAI_BASE_URL=...

# Gateway (only if running the messaging gateway)
DISCORD_BOT_TOKEN=...
DISCORD_ALLOWED_USERS=numeric_id_1,numeric_id_2     # NUMERIC IDs not handles
DISCORD_REQUIRE_MENTION=false                       # DMs only
# TELEGRAM_BOT_TOKEN, SLACK_BOT_TOKEN, etc. follow the same pattern
```

### ClawKeeper environment variables

| Var | Default | Purpose |
|---|---|---|
| `CK_WATCHER_HOST` | `127.0.0.1` | Bind address — **do not expose externally** |
| `CK_WATCHER_PORT` | `9099` | |
| `CK_WATCHER_MODEL` | `gpt-5.4-openai-compact` | LLM the Watcher uses (can differ from the agent's) |
| `CK_WATCHER_BASE_URL` | `$OPENAI_BASE_URL` | |
| `CK_WATCHER_API_KEY` | `$OPENAI_API_KEY` | |
| `CK_WATCHER_URL` | `http://127.0.0.1:9099` | Read by `WatcherClient` if you don't pass `watcher_url` explicitly |

---

## Common deployments

| Use case | Setup |
|---|---|
| CLI agent ("talk to Hermes locally with safety on") | Step 4 only. Run your wrapper that calls `install_clawkeeper(...)`. |
| CLI + trajectory reasoning | Step 4 + Step 5. Start daemon, pass `watcher_url`. |
| Discord / Telegram / Slack bot | See `examples/hermes_discord_bot.py`. The launcher applies the User-Agent patch (needed for some proxies like scode.chat), installs ClawKeeper, and delegates to `hermes_cli.main`. |
| Protecting an MCP client (Claude Desktop, Cursor, Continue, Zed) | Use the MCP gateway adapter at `clawkeeper_core.adapters.mcp.GatewayServer` (independent path, doesn't need Hermes). See `docs/integration-surfaces.md` §3.7. |

---

## Provider compatibility notes

**User-Agent rejection (api.scode.chat and some other Anthropic relays).** The `openai` Python SDK sends `User-Agent: OpenAI/Python X.Y.Z`, which some proxies 403-reject. Patch it at startup:

```python
import openai as _openai
_orig = _openai.OpenAI.__init__
def _patched(self, *a, **kw):
    h = dict(kw.get("default_headers") or {})
    h.setdefault("User-Agent", "Mozilla/5.0")
    kw["default_headers"] = h
    return _orig(self, *a, **kw)
_openai.OpenAI.__init__ = _patched
```

Apply before constructing any `AIAgent` or `Watcher`. The Watcher daemon does this itself at import time.

**JSON-schema validation on Anthropic endpoints.** Hermes ships ~40 toolsets; some tool schemas don't fully satisfy JSON Schema draft 2020-12, which Anthropic enforces strictly. If you see 400 errors mentioning schema validation, restrict to a subset:

```python
agent = AIAgent(
    enabled_toolsets=["terminal"],
    # ...
)
```

GPT-class models don't enforce this, so the issue is provider-specific.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `install_clawkeeper` runs cleanly but blocked-looking commands still execute | You wired into `tool_start_callback` only. Hermes silently swallows callback exceptions. | Use the latest `clawkeeper_core/adapters/hermes.py` from `v0.2-refactor` — it registers the documented `pre_tool_call` plugin hook (the real blocking API). |
| `pre_tool_call hooks: 0` when you `_ensure_plugins_discovered()._hooks` | You called `install_clawkeeper` BEFORE constructing the AIAgent. | Construct the agent first, then install. |
| `HTTP 403` from your provider | Default OpenAI-SDK User-Agent rejected. | Apply the UA patch above. |
| `HTTP 400 JSON schema validation` from Anthropic-side endpoint | Hermes toolsets have schemas Anthropic rejects. | Use `enabled_toolsets=["terminal"]`. |
| Watcher daemon returns `decision: "ask"` for everything | LLM output unparseable (model returning prose instead of JSON). | Check daemon logs; try a stronger Watcher model via `CK_WATCHER_MODEL`. |
| Watcher latency ~5–10 s per tool call | This is expected for a single LLM round trip. | Use a faster Watcher model (`gpt-5.4-openai-compact` or Haiku); or skip the Watcher for high-throughput cases (Step 4 alone). |
| `127.0.0.1:9099 connection refused` when adapter consults Watcher | Daemon isn't running. | `python -m clawkeeper_core.watcher.daemon`. Or omit `watcher_url=` to fall back to deterministic-only mode. |

---

## What ClawKeeper does and doesn't change about Hermes

| | |
|---|---|
| Hermes's hardline blocklist (`rm -rf /`, fork bombs) | **Unchanged.** Runs first, always. |
| Hermes's dangerous-command regex | **Unchanged.** Still gates the approval prompt. ClawKeeper's `Judge` answers when Hermes asks. |
| Hermes's context-file scan (AGENTS.md, .cursorrules, SOUL.md) | **Unchanged.** ClawKeeper adds `return_content_scan` for anything else entering context. |
| Hermes's Tirith pre-exec scan | **Unchanged.** ClawKeeper's `url_safety` adds homoglyph + SSRF coverage. |
| Hermes's MCP env filter | **Unchanged.** |
| Hermes's gateway authorization (allowlists, DM pairing) | **Unchanged.** |
| Hermes's container backend hardening | **Unchanged.** Out of scope for ClawKeeper (deployment concern). |

ClawKeeper runs **in addition to** Hermes's built-in safety, not instead of it. Both pipelines fire; strictest wins.

---

## Where to go next

| | |
|---|---|
| Understand which threats ClawKeeper handles | `tests/redteam/THREAT_MODEL.md` |
| Wire CK into something other than Hermes (Claude Code, MCP client, LangGraph, …) | `docs/integration-surfaces.md` |
| Read every guard's source | `clawkeeper_core/guards/` |
| Read the Watcher's prompt + decision shape | `clawkeeper_core/watcher/prompts.py` |
| File a bug or request a new guard | `github.com/SafeAI-Lab-X/ClawKeeper/issues` |
