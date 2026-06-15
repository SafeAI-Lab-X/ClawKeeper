# ClawKeeper Watcher

The Watcher is the third architectural layer from the original ClawKeeper paper: an *external* LLM-driven supervisor that reasons about trajectories rather than individual commands.

## Run the daemon

```bash
# Foreground
python -m clawkeeper_core.watcher.daemon

# Or via the bundled console script (if installed)
clawkeeper-watcher

# Background
nohup python -m clawkeeper_core.watcher.daemon > watcher.log 2>&1 &
```

The daemon binds to `127.0.0.1:9099` by default. All env knobs:

| Var | Default | Purpose |
|---|---|---|
| `CK_WATCHER_HOST` | `127.0.0.1` | Bind address — DO NOT bind to `0.0.0.0` unless you intend a network-exposed Watcher (and even then, fronted by a real auth proxy) |
| `CK_WATCHER_PORT` | `9099` | |
| `CK_WATCHER_MODEL` | `gpt-5.5` | LLM the Watcher reasons with |
| `CK_WATCHER_BASE_URL` | `$OPENAI_BASE_URL` or `https://api.scode.chat/v1` | OpenAI-compatible endpoint |
| `CK_WATCHER_API_KEY` | `$OPENAI_API_KEY` | |

Health check:

```bash
curl http://127.0.0.1:9099/watcher/health
```

## Wire it into a host (Hermes)

```python
from clawkeeper_core.adapters.hermes import install
from clawkeeper_core.judge import Judge

agent = AIAgent(...)
install(Judge(), agent, watcher_url="http://127.0.0.1:9099")
```

Without `watcher_url`, the adapter falls back to the deterministic-only guard chain (still useful, just no LLM reasoning).

## What the Watcher does on each pre-tool-call event

1. Runs the deterministic guards (`exec_gate`, `path_guard`, `script_body_scan`, `url_safety`) synchronously
2. Gathers stated user intent + recent tool-call history for the session
3. Sends ONE structured prompt to the LLM containing all of the above + the proposed call
4. Parses a JSON decision: `{decision, reason, severity, signals, confidence}`
5. Applies a deterministic post-filter — hardline/critical deterministic blocks always win over the LLM's `allow`
6. Returns the final decision to the calling adapter

Single LLM call per evaluation. Single round-trip from adapter → Watcher → response. Typical latency: 1–3 s depending on model.

## Design notes

- **The LLM proposes, the post-filter disposes.** See `policy.py`. The Watcher's LLM cannot accidentally weaken the hardline floor — if any deterministic guard says critical-block, the LLM's verdict is overridden.
- **Fail-safe default is `ask`.** When the daemon is unreachable, or the LLM output is unparseable, the client returns `ask` (defer to operator) rather than silently allowing.
- **Per-session memory only.** Cross-session learning ("the self-evolving piece") is deliberately not in v1. Future revision will load N similar past cases from `risk.py`'s fingerprint store into the prompt.
- **No multi-step tool-loop.** v1 gathers data eagerly and makes one LLM call. v2 may upgrade to smolagents' `ToolCallingAgent` so the LLM can interactively pull more context.
