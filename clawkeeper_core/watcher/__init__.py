"""ClawKeeper Watcher — LLM-driven supervisor agent.

The Watcher is the third architectural layer from the original ClawKeeper
paper: an *external* supervisor that reasons about full trajectories
rather than individual commands. Lives in its own process, runs its own
LLM, communicates with protected agents over HTTP.

Per-file responsibilities:
  - `agent.py`   — Watcher class (LLM reasoning + decision emission)
  - `tools.py`   — data-gathering helpers (deterministic guard findings, recent-call history)
  - `policy.py`  — deterministic post-filter that overrides Watcher's LLM proposal
                   if it tries to greenlight a hardline-blocked pattern
  - `prompts.py` — system prompt + decision-shape schema
  - `daemon.py`  — FastAPI server exposing POST /watcher/evaluate
  - `client.py`  — HTTP client used by per-host adapters (hermes, mcp, claude_code)

Boundary with deterministic guards in `clawkeeper_core/guards/`:
  Deterministic guards return verdicts SYNCHRONOUSLY before the Watcher is
  consulted. The Watcher receives their findings as inputs to its reasoning
  and emits a proposal. The deterministic post-filter then overrides if the
  proposal contradicts a hardline rule. Two-layer system: LLM proposes,
  deterministic disposes.
"""

from clawkeeper_core.watcher.agent import Watcher, WatcherDecision  # noqa: F401
from clawkeeper_core.watcher.policy import apply_post_filter  # noqa: F401
