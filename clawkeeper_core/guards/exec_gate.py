"""Pre-execution dangerous-command gate. Ported from
legacy/clawkeeper-plugin/src/core/exec-gate.js.

Synchronous regex-based detector — runs after path_guard inside the
before_tool_call hook so the interceptor can hard-block clearly
destructive shell invocations before the agent executes them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from clawkeeper_core.security_rules import DANGEROUS_COMMAND_PATTERNS

_DEFAULT_FAILURE_POLICY = "fail-closed"
_BASH_LIKE_HINT_RE = re.compile(r"bash|shell|exec|command|terminal", re.IGNORECASE)

_DEFAULT_GATE = {
    "rules": [
        {"id": f"dangerous-cmd-{i}", "regex": p, "severity": "HIGH",
         "reason": "Matches a known destructive command pattern"}
        for i, p in enumerate(DANGEROUS_COMMAND_PATTERNS)
    ],
    "config": {"enabled": True, "failurePolicy": _DEFAULT_FAILURE_POLICY, "bashLikeTools": []},
}

_cached: dict[str, Any] | None = None


def load_exec_gate(rules_path: str | Path | None = None) -> dict[str, Any]:
    global _cached
    if rules_path is None:
        _cached = _DEFAULT_GATE
        return _cached
    if _cached and _cached.get("_source") == str(rules_path):
        return _cached
    raw = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    cfg = raw.get("executionGate") or {}
    rules = [
        {**r, "regex": re.compile(r["pattern"], re.IGNORECASE)}
        for r in (cfg.get("dangerousCommands") or [])
    ]
    _cached = {
        "rules": rules,
        "config": {
            "enabled": cfg.get("enabled") is not False,
            "failurePolicy": cfg.get("failurePolicy") or _DEFAULT_FAILURE_POLICY,
            "bashLikeTools": cfg.get("bashLikeTools") or [],
        },
        "_source": str(rules_path),
    }
    return _cached


def reset_exec_gate_cache() -> None:
    global _cached
    _cached = None


def _collect_string_values(obj: Any, out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    if obj is None:
        return out
    if isinstance(obj, str):
        out.append(obj)
        return out
    if isinstance(obj, list):
        for v in obj:
            _collect_string_values(v, out)
        return out
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_string_values(v, out)
        return out
    return out


def extract_command_text(tool_name: Any, params: Any, bash_like_tools: list[str] | None = None) -> str:
    t = str(tool_name or "").lower()
    bash_like = {s.lower() for s in (bash_like_tools or [])}
    looks_like_bash = t in bash_like or bool(_BASH_LIKE_HINT_RE.search(t))
    p = params if isinstance(params, dict) else {}
    if looks_like_bash:
        named = "\n".join(
            v for v in (p.get(k) for k in ("command", "cmd", "script", "input", "code", "bash", "shell"))
            if isinstance(v, str)
        )
        if named:
            return named
    return "\n".join(_collect_string_values(params))


def guard_execution(event: dict[str, Any]) -> dict[str, Any]:
    try:
        loaded = load_exec_gate()
    except (OSError, json.JSONDecodeError) as err:
        policy = (_cached or {}).get("config", {}).get("failurePolicy", _DEFAULT_FAILURE_POLICY)
        if policy == "fail-closed":
            return {"block": True, "error": str(err), "reason": "exec-gate rule load failed (fail-closed policy)"}
        return {"block": False, "error": str(err)}
    rules = loaded["rules"]
    cfg = loaded["config"]
    if not cfg["enabled"]:
        return {"block": False}
    command = extract_command_text(event.get("toolName"), event.get("params"), cfg["bashLikeTools"])
    if not command:
        return {"block": False}
    for rule in rules:
        if rule["regex"].search(command):
            return {
                "block": True,
                "matched": rule["id"],
                "severity": rule.get("severity"),
                "reason": rule.get("reason"),
                "command": command[:500] + "…" if len(command) > 500 else command,
            }
    return {"block": False}
