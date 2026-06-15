"""Persistent allow/deny store for tool calls — HMAC-signed JSON on disk.

Ported from legacy/clawkeeper-plugin/src/core/permission-store.js.

Two files under $WORKSPACE/clawkeeper/:
  - permissions-session.json — wiped on startup
  - permissions-forever.json — persists across runs

Decisions are keyed by (toolName, fingerprint) where fingerprint is a
sha256 hash of normalized command/path material. Lookup precedence:
forever > session, and deny beats allow within the same scope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BASH_LIKE_TOOLS = {
    "bash", "shell", "exec", "command", "run_command", "execute_command", "terminal",
}
_PATH_LIKE_TOOLS = {
    "read_file", "read", "fs_read", "file_read",
    "write_file", "write", "fs_write", "file_write",
}


def _workspace_dir() -> Path:
    override = os.environ.get("OPENCLAW_WORKSPACE")
    if override:
        return Path(override)
    return Path.home() / ".openclaw" / "workspace"


def _hmac_key_file() -> Path:
    return _workspace_dir() / "clawkeeper" / ".hmac-key"


def _get_hmac_key() -> bytes:
    env_key = os.environ.get("CLAWKEEPER_HMAC_KEY")
    if env_key:
        return env_key.encode("utf-8")
    key_file = _hmac_key_file()
    try:
        return key_file.read_text(encoding="utf-8").strip().encode("utf-8")
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        # First run: generate and persist.
        key = secrets.token_hex(32)
        try:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_text(key, encoding="utf-8")
            os.chmod(key_file, 0o600)
        except OSError as err:
            print(f"[clawkeeper] permission: failed to persist HMAC key: {err}", file=sys.stderr)
        return key.encode("utf-8")


def _compute_hmac(entries: list[dict[str, Any]]) -> str:
    payload = json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hmac.new(_get_hmac_key(), payload, hashlib.sha256).hexdigest()


def _verify_hmac(store: dict[str, Any]) -> bool:
    stored = store.get("_hmac")
    if not isinstance(stored, str):
        return False
    return hmac.compare_digest(stored, _compute_hmac(store.get("entries") or []))


def resolve_session_file() -> Path:
    return _workspace_dir() / "clawkeeper" / "permissions-session.json"


def resolve_forever_file() -> Path:
    return _workspace_dir() / "clawkeeper" / "permissions-forever.json"


def _fresh_store() -> dict[str, Any]:
    return {"entries": []}


def _read_store(file_path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, NotADirectoryError, PermissionError, json.JSONDecodeError):
        return _fresh_store()
    if not isinstance(raw, dict) or not isinstance(raw.get("entries"), list):
        return _fresh_store()
    # Empty entries skip HMAC check to support first-write.
    if raw["entries"] and not _verify_hmac(raw):
        print(
            f"[clawkeeper] permission: HMAC verification failed for {file_path} — "
            f"treating as empty (possible tampering)",
            file=sys.stderr,
        )
        return _fresh_store()
    return raw


def _write_store(file_path: Path, store: dict[str, Any]) -> bool:
    try:
        store["_hmac"] = _compute_hmac(store.get("entries") or [])
        file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = file_path.with_suffix(file_path.suffix + ".tmp")
        tmp.write_text(json.dumps(store, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, file_path)
        return True
    except OSError as err:
        print(f"[clawkeeper] permission: save failed: {err}", file=sys.stderr)
        return False


def fingerprint_for(tool_name: Any, params: Any = None) -> str:
    """Stable 32-char hex digest of the (tool, params) pair.

    Bash-like tools key on command/cmd/script; path-like tools key on
    path/file/filename; anything else falls back to a JSON dump of params.
    """
    p = params if isinstance(params, dict) else {}
    t = str(tool_name or "").lower()
    if t in _BASH_LIKE_TOOLS:
        cmd = p.get("command") or p.get("cmd") or p.get("script") or ""
        material = f"cmd:{str(cmd).strip()}"
    elif t in _PATH_LIKE_TOOLS:
        path_val = p.get("path") or p.get("file") or p.get("filename") or ""
        material = f"path:{str(path_val).strip()}"
    else:
        try:
            material = "json:" + json.dumps(p, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            material = "json:unserializable"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def check_permission(tool_name: Any, params: Any = None) -> dict[str, Any]:
    """Look up a (tool, fingerprint) pair across both stores.

    Forever > session; deny > allow within same scope. Returns:
      {"decision": "allow" | "deny", "scope": ..., "entry": ..., "fingerprint": ...}
    or {"decision": "none", "fingerprint": ...}.
    """
    fp = fingerprint_for(tool_name, params)
    tool = str(tool_name or "").lower()

    for file in (resolve_forever_file(), resolve_session_file()):
        store = _read_store(file)
        matches = [e for e in store["entries"] if e.get("tool") == tool and e.get("fingerprint") == fp]
        if not matches:
            continue
        scope = "forever" if file == resolve_forever_file() else "session"
        denied = next((e for e in matches if e.get("decision") == "deny"), None)
        if denied:
            return {"decision": "deny", "scope": scope, "entry": denied, "fingerprint": fp}
        allowed = next((e for e in matches if e.get("decision") == "allow"), None)
        if allowed:
            return {"decision": "allow", "scope": scope, "entry": allowed, "fingerprint": fp}
    return {"decision": "none", "fingerprint": fp}


def _sample_of(tool_name: Any, params: Any = None) -> str:
    p = params if isinstance(params, dict) else {}
    t = str(tool_name or "").lower()
    if t in _BASH_LIKE_TOOLS:
        return str(p.get("command") or p.get("cmd") or "")[:200]
    if t in _PATH_LIKE_TOOLS:
        return str(p.get("path") or p.get("file") or "")[:200]
    try:
        return json.dumps(p, ensure_ascii=False)[:200]
    except (TypeError, ValueError):
        return ""


def grant_permission(*, tool: Any, params: Any = None, decision: str, scope: str, reason: Any = None) -> dict[str, Any]:
    """Insert or replace the (tool, fingerprint) entry at the given scope."""
    if decision not in ("allow", "deny"):
        raise ValueError(f"invalid decision: {decision}")
    if scope not in ("session", "forever"):
        raise ValueError(f"invalid scope: {scope}")

    file = resolve_forever_file() if scope == "forever" else resolve_session_file()
    store = _read_store(file)
    fp = fingerprint_for(tool, params)
    t = str(tool or "").lower()
    store["entries"] = [e for e in store["entries"] if not (e.get("tool") == t and e.get("fingerprint") == fp)]
    store["entries"].append({
        "tool": t,
        "fingerprint": fp,
        "decision": decision,
        "scope": scope,
        "reason": reason if reason else None,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sample": _sample_of(tool, params),
    })
    _write_store(file, store)
    return {"fingerprint": fp, "scope": scope}


def revoke_permission(*, tool: Any, fingerprint: str, scope: str) -> dict[str, int]:
    file = resolve_forever_file() if scope == "forever" else resolve_session_file()
    store = _read_store(file)
    t = str(tool or "").lower()
    before = len(store["entries"])
    store["entries"] = [e for e in store["entries"] if not (e.get("tool") == t and e.get("fingerprint") == fingerprint)]
    _write_store(file, store)
    return {"removed": before - len(store["entries"])}


def list_permissions(scope: str | None = None) -> list[dict[str, Any]]:
    targets = [scope] if scope in ("forever", "session") else ["forever", "session"]
    out: list[dict[str, Any]] = []
    for s in targets:
        file = resolve_forever_file() if s == "forever" else resolve_session_file()
        store = _read_store(file)
        for e in store["entries"]:
            out.append({**e, "scope": s})
    return out


def reset_session_permissions() -> bool:
    try:
        return _write_store(resolve_session_file(), _fresh_store())
    except OSError:
        return False


def reset_forever_permissions() -> bool:
    try:
        return _write_store(resolve_forever_file(), _fresh_store())
    except OSError:
        return False
