"""Protected-path guard. Ported from
legacy/clawkeeper-plugin/src/core/path-guard.js.

Hard-blocks any tool that would read/write/exec against a path on the
protected list (e.g. ~/.ssh, /etc/shadow, ~/.aws/credentials).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_DEFAULT_FAILURE_POLICY = "fail-closed"
_BASH_LIKE_HINT_RE = re.compile(r"bash|shell|exec|command|terminal", re.IGNORECASE)

_DEFAULT_RULES = [
    {"pattern": "~/.ssh/**", "severity": "CRITICAL", "reason": "SSH key material"},
    {"pattern": "~/.aws/**", "severity": "CRITICAL", "reason": "AWS credentials"},
    {"pattern": "~/.gnupg/**", "severity": "CRITICAL", "reason": "GPG key material"},
    {"pattern": "~/.env", "severity": "HIGH", "reason": "Local secrets"},
    {"pattern": "/etc/passwd", "severity": "HIGH", "reason": "System users"},
    {"pattern": "/etc/shadow", "severity": "CRITICAL", "reason": "System password hashes"},
    {"pattern": "/etc/sudoers", "severity": "CRITICAL", "reason": "Sudoer rules"},
]

_PATH_TOKEN_RE = re.compile(
    r"""(?:^|[\s'"`=:;(){}\[\],])(~/[^\s'"`;|&()<>]+|/[A-Za-z0-9._/\-]+|\.{1,2}/[^\s'"`;|&()<>]+)"""
)

_cached: dict[str, Any] | None = None


def expand_home(p: str | None) -> str | None:
    if not p:
        return p
    if p == "~":
        return str(Path.home())
    if p.startswith("~/") or p.startswith("~\\"):
        return str(Path.home() / p[2:])
    return p


def glob_to_regex(glob: str) -> re.Pattern[str]:
    """Convert simple glob to anchored regex. ** -> .* ; * -> [^/]* ; ? -> [^/]"""
    out = ["^"]
    i = 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c in ".+^${}()|[]\\":
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    out.append("$")
    return re.compile("".join(out))


def load_protected_paths(rules_path: str | Path | None = None) -> dict[str, Any]:
    global _cached
    if rules_path is None:
        rules = [{**r, "regex": glob_to_regex(expand_home(r["pattern"])),
                  "expanded": expand_home(r["pattern"])}
                 for r in _DEFAULT_RULES]
        _cached = {"rules": rules,
                   "config": {"enabled": True, "failurePolicy": _DEFAULT_FAILURE_POLICY, "bashLikeTools": []},
                   "_source": None}
        return _cached
    if _cached and _cached.get("_source") == str(rules_path):
        return _cached
    raw = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    rules = [
        {**r, "regex": glob_to_regex(expand_home(r["pattern"])),
         "expanded": expand_home(r["pattern"])}
        for r in (raw.get("protectedPaths") or [])
    ]
    cfg = raw.get("pathGuard") or {"enabled": True, "failurePolicy": "fail-closed", "bashLikeTools": []}
    _cached = {"rules": rules, "config": cfg, "_source": str(rules_path)}
    return _cached


def reset_path_guard_cache() -> None:
    global _cached
    _cached = None


def normalize_path(input_path: Any, cwd: str | Path | None = None) -> str | None:
    if not isinstance(input_path, str) or not input_path:
        return None
    p = expand_home(input_path.strip()) or ""
    # Strip surrounding quotes
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    if not os.path.isabs(p):
        p = os.path.abspath(os.path.join(str(cwd or os.getcwd()), p))
    try:
        return os.path.realpath(p)
    except OSError:
        return os.path.abspath(p)


def match_protected(abs_path: str | None, rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not abs_path:
        return None
    for rule in rules:
        if rule["regex"].match(abs_path):
            return rule
        if rule["pattern"].endswith("/**"):
            prefix = rule["expanded"][:-3]
            if abs_path == prefix or abs_path.startswith(prefix + os.sep) or abs_path.startswith(prefix + "/"):
                return rule
    return None


def extract_paths_from_command(command: str | None) -> list[str]:
    if not isinstance(command, str) or not command:
        return []
    out: set[str] = set()
    for m in _PATH_TOKEN_RE.finditer(command):
        token = m.group(1)
        if len(token) >= 2:
            out.add(token)
    return list(out)


def _collect_string_values(obj: Any, out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    if obj is None:
        return out
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, list):
        for v in obj:
            _collect_string_values(v, out)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_string_values(v, out)
    return out


_BASENAME_RE = re.compile(r"^(id_rsa|id_ed25519|\.env|credentials|shadow|sudoers)$", re.IGNORECASE)


def extract_paths_from_params(tool_name: Any, params: Any, *, bash_like_tools: list[str] | None = None) -> list[str]:
    bash_like = {s.lower() for s in (bash_like_tools or [])}
    t = str(tool_name or "").lower()
    looks_like_bash = t in bash_like or bool(_BASH_LIKE_HINT_RE.search(t))
    candidates: set[str] = set()
    p = params if isinstance(params, dict) else {}

    if looks_like_bash:
        cmd_parts = [v for v in (p.get(k) for k in ("command", "cmd", "script", "input", "code", "bash", "shell"))
                     if isinstance(v, str)]
        text = "\n".join(cmd_parts) if cmd_parts else "\n".join(_collect_string_values(params))
        for t2 in extract_paths_from_command(text):
            candidates.add(t2)

    for v in _collect_string_values(params):
        s = v.strip()
        if not s:
            continue
        if s.startswith("~/") or s.startswith("~\\") or os.path.isabs(s):
            candidates.add(s)
        elif s.startswith("./") or s.startswith("../"):
            candidates.add(s)
        elif _BASENAME_RE.match(s):
            candidates.add(s)
    return list(candidates)


def guard_before_tool_call(event: dict[str, Any]) -> dict[str, Any]:
    try:
        loaded = load_protected_paths()
    except (OSError, json.JSONDecodeError) as err:
        policy = (_cached or {}).get("config", {}).get("failurePolicy", _DEFAULT_FAILURE_POLICY)
        if policy == "fail-closed":
            return {"block": True, "error": str(err), "reason": "path-guard rule load failed (fail-closed policy)"}
        return {"block": False, "error": str(err)}
    rules, cfg = loaded["rules"], loaded["config"]
    if not cfg["enabled"]:
        return {"block": False}

    candidates = extract_paths_from_params(
        event.get("toolName"), event.get("params"),
        bash_like_tools=cfg.get("bashLikeTools") or [],
    )
    for candidate in candidates:
        resolved = normalize_path(candidate)
        hit = match_protected(resolved, rules) or match_protected(expand_home(candidate), rules)
        if hit:
            return {
                "block": True,
                "matched": hit["pattern"],
                "candidate": candidate,
                "resolved": resolved,
                "severity": hit.get("severity"),
                "reason": hit.get("reason"),
            }
    return {"block": False}
