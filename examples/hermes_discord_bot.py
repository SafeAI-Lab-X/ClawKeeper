#!/usr/bin/env python
"""Run Hermes Agent's Discord gateway with ClawKeeper as the approval gate.

Three things this launcher does before handing control to `hermes gateway`:
  1) Inject a browser User-Agent into the openai SDK (api.scode.chat rejects
     the default `OpenAI/Python ...` UA with HTTP 403).
  2) Wrap `run_agent.AIAgent.__init__` so every AIAgent the gateway spawns
     gets ClawKeeper's `install(judge, agent)` applied — that registers the
     module-level approval callback on `tools.terminal_tool` AND
     `tools.computer_use.tool`, plus per-agent observers. This is the natural
     Hermes integration surface; no monkey-patching of Hermes' own safety
     pipeline.
  3) Delegate to `hermes_cli.main.main()` with argv set to `["hermes",
     "gateway"]` — equivalent to running the gateway from the CLI.
"""
from __future__ import annotations

import os
import sys

# ── 1) User-Agent patch for api.scode.chat ──────────────────────────────────
import openai as _openai_pkg

_BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
_orig_oai_init = _openai_pkg.OpenAI.__init__


def _patched_oai_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
    headers = dict(kwargs.get("default_headers") or {})
    headers.setdefault("User-Agent", _BROWSER_UA)
    kwargs["default_headers"] = headers
    return _orig_oai_init(self, *args, **kwargs)


_openai_pkg.OpenAI.__init__ = _patched_oai_init

if hasattr(_openai_pkg, "AsyncOpenAI"):
    _orig_async_init = _openai_pkg.AsyncOpenAI.__init__

    def _patched_async_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        headers = dict(kwargs.get("default_headers") or {})
        headers.setdefault("User-Agent", _BROWSER_UA)
        kwargs["default_headers"] = headers
        return _orig_async_init(self, *args, **kwargs)

    _openai_pkg.AsyncOpenAI.__init__ = _patched_async_init


# ── 2) Wrap AIAgent.__init__ to install ClawKeeper on every new agent ──────
import run_agent  # noqa: E402

from clawkeeper_core.adapters.hermes import install as install_clawkeeper  # noqa: E402
from clawkeeper_core.judge import Judge  # noqa: E402

_judge = Judge()
_orig_agent_init = run_agent.AIAgent.__init__


def _agent_init_with_clawkeeper(self, *args, **kwargs):  # type: ignore[no-untyped-def]
    _orig_agent_init(self, *args, **kwargs)
    try:
        install_clawkeeper(_judge, self)
    except Exception as exc:  # noqa: BLE001
        # Never let a ClawKeeper wiring problem prevent the agent from running
        # — log loudly and continue.
        print(f"[clawkeeper] install failed: {exc!r}", file=sys.stderr)


run_agent.AIAgent.__init__ = _agent_init_with_clawkeeper


# ── 3) Hand off to Hermes' CLI gateway subcommand ──────────────────────────
from hermes_cli.main import main as _hermes_main  # noqa: E402

if __name__ == "__main__":
    sys.argv = ["hermes", "gateway"] + sys.argv[1:]
    _hermes_main()
