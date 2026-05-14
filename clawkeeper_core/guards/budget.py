"""Token-budget tracker. Ported from
legacy/clawkeeper-plugin/src/core/budget-guard.js.

Tracks LLM input/output tokens in a rolling window. State persists to
$OPENCLAW_WORKSPACE/clawkeeper/budget.json (override with the explicit
file_path argument). `check_budget` is pure; `record_usage` mutates +
persists.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "unlimited": False,
    "windowDays": 1,
    "limits": {"input": 1_000_000, "output": 200_000, "total": 1_200_000},
    "warnRatio": 0.8,
    "stateFile": None,
}


_cached_config: dict[str, Any] | None = None


def load_config(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    global _cached_config
    if _cached_config is not None and overrides is None:
        return _cached_config
    cfg = {**_DEFAULT_CONFIG, **(overrides or {})}
    if cfg.get("unlimited") and os.environ.get("CLAWKEEPER_BUDGET_FORCE") == "1":
        cfg["unlimited"] = False
    _cached_config = cfg
    return _cached_config


def reset_budget_cache() -> None:
    global _cached_config
    _cached_config = None


def resolve_budget_file(cfg: dict[str, Any] | None = None) -> Path:
    cfg = cfg or load_config()
    if cfg.get("stateFile"):
        state_file = str(cfg["stateFile"])
        if state_file.startswith("~"):
            state_file = str(Path.home() / state_file.lstrip("~/"))
        return Path(state_file)
    workspace = os.environ.get("OPENCLAW_WORKSPACE") or str(Path.home() / ".openclaw" / "workspace")
    return Path(workspace) / "clawkeeper" / "budget.json"


def _fresh_budget(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "windowStart": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "windowDays": cfg["windowDays"],
        "limits": dict(cfg["limits"]),
        "thresholds": {"warn": cfg["warnRatio"]},
        "usage": {"input": 0, "output": 0, "total": 0, "calls": 0},
        "lastDecision": "ok",
    }


def load_budget(file_path: Path | str | None = None) -> dict[str, Any]:
    cfg = load_config()
    f = Path(file_path) if file_path else resolve_budget_file(cfg)
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return _fresh_budget(cfg)
    if not isinstance(raw, dict):
        return _fresh_budget(cfg)
    raw.setdefault("limits", dict(cfg["limits"]))
    raw.setdefault("usage", {"input": 0, "output": 0, "total": 0, "calls": 0})
    raw.setdefault("thresholds", {"warn": cfg["warnRatio"]})
    return raw


def save_budget(budget: dict[str, Any], file_path: Path | str | None = None) -> bool:
    cfg = load_config()
    f = Path(file_path) if file_path else resolve_budget_file(cfg)
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(f.suffix + ".tmp")
        tmp.write_text(json.dumps(budget, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, f)
        return True
    except OSError as err:
        print(f"[clawkeeper] budget-guard save failed: {err}", file=sys.stderr)
        return False


def _roll_window_if_needed(budget: dict[str, Any]) -> dict[str, Any]:
    try:
        start = datetime.fromisoformat(budget["windowStart"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError):
        return budget
    days = budget.get("windowDays", 1)
    if not isinstance(days, (int, float)):
        days = 1
    expires_at = start.timestamp() + days * 86400
    if time.time() >= expires_at:
        budget["windowStart"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        budget["usage"] = {"input": 0, "output": 0, "total": 0, "calls": 0}
        budget["lastDecision"] = "ok"
    return budget


def _classify(budget: dict[str, Any]) -> dict[str, Any]:
    usage = budget["usage"]
    limits = budget["limits"]
    warn = (budget.get("thresholds") or {}).get("warn", 0.8)
    ratios = {
        "input": usage["input"] / limits["input"] if limits.get("input") else 0,
        "output": usage["output"] / limits["output"] if limits.get("output") else 0,
        "total": usage["total"] / limits["total"] if limits.get("total") else 0,
    }
    if any(r >= 1 for r in ratios.values()):
        return {"status": "over", "ratios": ratios}
    if any(r >= warn for r in ratios.values()):
        return {"status": "warn", "ratios": ratios}
    return {"status": "ok", "ratios": ratios}


def check_budget(file_path: Path | str | None = None) -> dict[str, Any]:
    """Pure check, no mutation. Returns block=True if over limits."""
    cfg = load_config()
    if not cfg["enabled"]:
        return {"block": False, "status": "disabled"}
    if cfg["unlimited"]:
        return {"block": False, "status": "unlimited"}
    budget = _roll_window_if_needed(load_budget(file_path))
    c = _classify(budget)
    return {
        "block": c["status"] == "over",
        "status": c["status"],
        "ratios": c["ratios"],
        "usage": budget["usage"],
        "limits": budget["limits"],
    }


def record_usage(usage: dict[str, Any] | None = None, file_path: Path | str | None = None) -> dict[str, Any]:
    cfg = load_config()
    if not cfg["enabled"]:
        return {"status": "disabled"}
    u = usage or {}
    budget = _roll_window_if_needed(load_budget(file_path))
    in_tok = int(u.get("input") or 0)
    out_tok = int(u.get("output") or 0)
    budget["usage"]["input"] += in_tok
    budget["usage"]["output"] += out_tok
    budget["usage"]["total"] += in_tok + out_tok
    budget["usage"]["calls"] += 1
    c = _classify(budget)
    budget["lastDecision"] = c["status"]
    save_budget(budget, file_path)
    return {
        "status": c["status"],
        "ratios": c["ratios"],
        "usage": budget["usage"],
        "limits": budget["limits"],
        "delta": {"input": in_tok, "output": out_tok},
    }


def format_budget_summary(state: dict[str, Any]) -> str:
    u = state.get("usage") or {}
    l = state.get("limits") or {}
    return (
        f"input={u.get('input', 0)}/{l.get('input', 0)} "
        f"output={u.get('output', 0)}/{l.get('output', 0)} "
        f"total={u.get('total', 0)}/{l.get('total', 0)} "
        f"calls={u.get('calls', 0)}"
    )
