# Integrating ClawKeeper with Hermes Agent

This is the v0.2.0 reference integration. Hermes is the first universal target
because (a) it's open source, (b) it's mostly Python, and (c) its callback API
maps cleanly onto ClawKeeper's `Decision` shape.

## Interception points Hermes exposes

| Hermes hook | Path | What it gives us | Used for |
| --- | --- | --- | --- |
| `set_approval_callback(cb)` | `hermes_agent/tools/terminal_tool.py:255` | Pre-execution gating for shell commands. Callback returns `"once" / "session" / "always" / "deny"`. **Blocks execution if it returns "deny".** | The judge's enforcement path |
| `set_approval_callback(cb)` | `hermes_agent/tools/computer_use/tool.py:60` | Same, for GUI/computer-use actions | The judge's enforcement path |
| `tool_start_callback` | `AIAgent.__init__` arg | Fires when a tool call begins | Profiler, drift, decision memory |
| `tool_complete_callback` | `AIAgent.__init__` arg | Fires after a tool call returns | Profiler, post-hoc risk scoring |
| `step_callback`, `thinking_callback`, `reasoning_callback` | `AIAgent.__init__` args | Trace of model reasoning | Intent extraction for drift detection |
| `stream_delta_callback` | `AIAgent.__init__` arg | Streaming tokens | Could feed early-warning input guards |

## Wiring (minimal example)

```python
from clawkeeper_core import Judge
from clawkeeper_core.adapters.hermes import install as install_clawkeeper
# Hermes Agent installs flat top-level modules (no `hermes_agent.` prefix):
from run_agent import AIAgent

judge = Judge()    # default policy; Judge(policy={...}) to customize

agent = AIAgent(
    model="anthropic/claude-opus-4-7",
    enabled_toolsets=["terminal", "files"],
    # … usual Hermes config (provider, API key env vars, etc.) …
)

install_clawkeeper(judge, agent)

# Off you go.
agent.run(user_prompt="Refactor the auth module.")
```

## Install footprint

Hermes' `pyproject.toml` exact-pins its core deps (including
`pydantic==2.12.5`), which conflicts with clawkeeper-core's looser
`pydantic>=2.6`. Two ways to handle this:

  - **Separate conda env (recommended)**: install hermes-agent into a
    dedicated env, then `pip install -e .` clawkeeper-core into the
    same env. Tested working with Python 3.11.
  - **Single env**: accept whichever pydantic version Hermes installs.
    clawkeeper-core works with 2.12.x and 2.13.x.

## What `install(judge, agent)` does

Three wires get connected on the agent:

  - `tools.terminal_tool.set_approval_callback(approval_cb)` —
    every dangerous bash/exec invocation goes through `approval_cb`,
    which builds a `JudgeContext`, calls `judge.evaluate`, and
    returns `"once" | "session" | "always" | "deny"`.
  - `tools.computer_use.tool.set_approval_callback(approval_cb)` —
    same callback wired into GUI/computer-use actions.
  - `agent.tool_start_callback` / `agent.tool_complete_callback` —
    observation hooks. The adapter wraps the existing callbacks
    (chains to them after emitting a `tool_start` / `tool_complete`
    `AgentEvent`). If `judge.profiler` is set, the events feed the
    profiler; otherwise they're discarded.

## Mapping from JS-style judgement to Hermes return strings

```
judge.evaluate -> dict["decision"]    Hermes return string
─────────────────────────────────────────────────────────
"continue"                            "once"   (allow)
"stop"                                "deny"
"ask_user"                            "deny"   (cannot ask from inside an approval callback)
```

That's the entire user-facing API for the Hermes path. No fork. No
monkey-patching of Hermes internals.

## What happens at runtime

1. Hermes decides it wants to run `rm -rf /tmp/build`. Terminal tool sees this
   is a "dangerous" command and invokes our `approval_cb`.
2. The adapter builds a `JudgeContext`, calls `judge.evaluate(ctx)`, and gets
   back a `Decision(outcome=Outcome.DENY, scope=ONCE, risk=HIGH, reason=…)`.
3. The adapter translates that to `"deny"` per the mapping in
   `clawkeeper_core/adapters/hermes.py`. Hermes refuses to execute.
4. For *all* tool starts/completes (dangerous or not), Hermes also fires
   `tool_start_callback` / `tool_complete_callback`. Those go through to
   `AgentProfiler.update(...)` and the decision-memory append-only log.

## Limits to keep in mind

- `set_approval_callback` only fires for commands Hermes has *already* flagged
  as dangerous. Anything Hermes considers "safe by default" is invisible to the
  approval path. The observation callbacks see everything though, so risky
  patterns the rule engine knows about but Hermes doesn't will still trigger
  the drift / fingerprint / profile detectors — they just can't *block*.
- If you need to gate a tool Hermes deems safe (e.g. a `Read` of a sensitive
  path), the right move is to wrap that tool in the MCP gateway adapter when
  that lands in v0.2.1.

## Comparison with the v0.1 OpenClaw plugin

| Concern | v0.1 (OpenClaw plugin) | v0.2 (Hermes adapter) |
| --- | --- | --- |
| How attached | Plugin manifest + `api.on("before_tool_call", …)` | Two Python calls (`install(...)` after `AIAgent(...)`) |
| Decision logic location | Same JS module as the hook | Out-of-process or in-process Python core |
| Switching agents | Requires OpenClaw | Works for any agent with a callback hook |
| Add a new framework | Rewrite the plugin in that framework's SDK | New ~200 LOC adapter file under `clawkeeper_core/adapters/` |
