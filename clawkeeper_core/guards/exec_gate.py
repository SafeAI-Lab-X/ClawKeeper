"""Pre-execution dangerous-command gate. Ported from
legacy/clawkeeper-plugin/src/core/exec-gate.js.

Local context-aware detector. Rules apply to visible program calls, not to
arbitrary strings in tool parameters. Incomplete analysis stops execution for
review without claiming a known destructive command was found.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from clawkeeper_core.security_rules import COMMAND_EXECUTABLES, DANGEROUS_COMMAND_PATTERNS

_DEFAULT_FAILURE_POLICY = "fail-closed"
_BASH_LIKE_HINT_RE = re.compile(r"bash|shell|exec|command|terminal", re.IGNORECASE)
_CONTENT_TOOLS = {
    "write",
    "write_file",
    "file_write",
    "fs_write",
    "read",
    "read_file",
    "file_read",
    "fs_read",
    "edit",
    "edit_file",
    "apply_patch",
    "patch",
    "replace",
    "search",
    "grep",
}
_COMMAND_FIELDS = ("command", "cmd", "script", "input", "code", "bash", "shell")
_PYTHON_TOOLS = {"python", "python_exec", "run_python"}


def _build_default_gate() -> dict[str, Any]:
    return {
        "rules": [
            {
                "id": f"dangerous-cmd-{i}",
                "regex": p,
                "executables": COMMAND_EXECUTABLES.get(p.pattern),
                "severity": "HIGH",
                "reason": "Matches a known destructive command pattern",
            }
            for i, p in enumerate(DANGEROUS_COMMAND_PATTERNS)
        ],
        "config": {"enabled": True, "failurePolicy": _DEFAULT_FAILURE_POLICY, "bashLikeTools": []},
        "_source": None,
    }


_cached: dict[str, Any] | None = None


def load_exec_gate(rules_path: str | Path | None = None) -> dict[str, Any]:
    global _cached  # noqa: PLW0603 -- process-local parsed configuration cache
    if rules_path is None:
        if _cached is None or _cached.get("_source") is not None:
            _cached = _build_default_gate()
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
    global _cached  # noqa: PLW0603
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


def extract_command_text(
    tool_name: Any, params: Any, bash_like_tools: list[str] | None = None
) -> str:
    """Legacy text extraction API; guard matching uses execution_contexts.

    Retained for callers expecting a display string. Neither built-in nor
    learned command detection treats this concatenated text as executable code.
    """
    t = str(tool_name or "").lower()
    if t in _CONTENT_TOOLS:
        return ""
    bash_like = {s.lower() for s in (bash_like_tools or [])}
    looks_like_bash = t in bash_like or bool(_BASH_LIKE_HINT_RE.search(t))
    p = params if isinstance(params, dict) else {}
    if looks_like_bash:
        named = "\n".join(v for v in (p.get(k) for k in _COMMAND_FIELDS) if isinstance(v, str))
        if named:
            return named
    return "\n".join(_collect_string_values(params))


def extract_execution_requests(
    tool_name: Any, params: Any, bash_like_tools: list[str] | None = None
) -> list[tuple[str, str]]:
    return [(language, source) for language, source, _ in _execution_requests(tool_name, params, bash_like_tools)]


def _execution_requests(tool_name, params, bash_like_tools=None):
    """Do not concatenate independent executable fields or scan metadata."""
    t = str(tool_name or "").lower()
    if t in _CONTENT_TOOLS:
        return []
    p = params if isinstance(params, dict) else {}
    shell_tool = t in {"sh", "zsh", "ksh", "spawn"} or bool(_BASH_LIKE_HINT_RE.search(t))
    shell_tool |= t in {s.lower() for s in (bash_like_tools or [])}
    fields = _COMMAND_FIELDS if shell_tool or t in _PYTHON_TOOLS else ("command", "cmd", "script")
    language = "python" if t in _PYTHON_TOOLS else "shell"
    # Preserve the generic/nested execution envelopes used by #7/#8 without
    # interpreting arbitrary description, header or environment strings as code.
    remaining = 10_000
    max_envelope_depth = 64

    def nested(value, path=()):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or len(path) > max_envelope_depth:
            raise ValueError("execution envelope budget exhausted")
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"env", "environment", "headers", "metadata", "description", "body"}:
                    continue
                if key in {*fields, "payload"} and isinstance(child, str) and child.strip():
                    yield language, child, (*path, key)
                elif isinstance(child, (dict, list)):
                    yield from nested(child, (*path, str(key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from nested(child, (*path, str(index)))

    return list(nested(p))


def execution_contexts(event: dict[str, Any]):
    """Shared parsed sources for built-in checks, learning and enforcement."""
    from clawkeeper_core.execution import analyze_event  # noqa: PLC0415

    return (analyze_event(event),)


def _incomplete(reasons: list[str]) -> dict[str, Any]:
    return {
        "block": True,
        "outcome": "ask",
        "source": "exec_gate:analysis",
        "severity": "high",
        "error": "exec_analysis_incomplete",
        "analysis": "indeterminate",
        "evidence": {"reasons": reasons},
        "reason": "Command analysis was incomplete; review required: " + "; ".join(reasons[:3]),
    }


def guard_execution(event: dict[str, Any]) -> dict[str, Any]:
    try:
        loaded = load_exec_gate()
    except (OSError, json.JSONDecodeError) as err:
        policy = (_cached or {}).get("config", {}).get("failurePolicy", _DEFAULT_FAILURE_POLICY)
        if policy == "fail-closed":
            return {
                "block": True,
                "error": str(err),
                "reason": "exec-gate rule load failed (fail-closed policy)",
            }
        return {"block": False, "error": str(err)}
    from clawkeeper_core.execution import evaluate_execution  # noqa: PLC0415

    return evaluate_execution(event, loaded)
