"""Workspace state management — SOUL/AGENTS file, openclaw.json config.

Ported from legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/state.js.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from clawkeeper_core.metadata import DEFAULT_RULES, RULE_BLOCK_END, RULE_BLOCK_START


def _state_dir_candidates() -> list[Path]:
    home = Path.home()
    raw = [
        os.environ.get("OPENCLAW_STATE_DIR"),
        os.environ.get("OPENCLAW_HOME"),
        home / ".openclaw",
        home / ".moltbot",
        home / ".clawdbot",
        home / "clawd",
    ]
    return [Path(p) for p in raw if p]


async def resolve_state_dir() -> Path:
    """First existing candidate, else fall back to the first candidate path."""
    candidates = _state_dir_candidates()
    for c in candidates:
        if await asyncio.to_thread(c.exists):
            return c
    return candidates[0] if candidates else Path.home() / ".openclaw"


async def resolve_user_openclaw_state_dir() -> Path:
    state_dir = Path.home() / ".openclaw"
    await asyncio.to_thread(state_dir.mkdir, parents=True, exist_ok=True)
    return state_dir


def get_config_path(state_dir: Path) -> Path:
    """Return the first config file that exists; otherwise the default `openclaw.json`."""
    for name in ("openclaw.json", "moltbot.json", "clawdbot.json"):
        candidate = state_dir / name
        if candidate.exists():
            return candidate
    return state_dir / "openclaw.json"


async def read_json_if_exists(file_path: Path) -> dict[str, Any]:
    try:
        raw = await asyncio.to_thread(file_path.read_text, encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return {}
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


async def file_exists(file_path: Path) -> bool:
    return await asyncio.to_thread(file_path.exists)


async def write_json(file_path: Path, value: Any) -> None:
    await asyncio.to_thread(file_path.parent.mkdir, parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    await asyncio.to_thread(file_path.write_text, payload, encoding="utf-8")


def get_soul_path(state_dir: Path) -> Path:
    return state_dir / "AGENTS.md"


async def read_soul(state_dir: Path) -> str:
    try:
        return await asyncio.to_thread(get_soul_path(state_dir).read_text, encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return ""


def build_rule_block() -> str:
    """Build the canonical SOUL.md rule block (between RULE_BLOCK_START / RULE_BLOCK_END)."""
    lines = [
        RULE_BLOCK_START,
        "## ClawKeeper Operational Constitution",
        "This is not a set of static prohibitions, but an execution constraint chain: first "
        "confirm the boundary, then obtain information, and then implement the action.",
        *[f"{i + 1}. {rule}" for i, rule in enumerate(DEFAULT_RULES)],
        RULE_BLOCK_END,
    ]
    return "\n".join(lines) + "\n"


def has_rule_block(content: str) -> bool:
    return RULE_BLOCK_START in content and RULE_BLOCK_END in content


async def ensure_rule_block(state_dir: Path) -> dict[str, Any]:
    """Inject the rule block into AGENTS.md if absent."""
    soul_path = get_soul_path(state_dir)
    content = await read_soul(state_dir)
    if has_rule_block(content):
        return {"changed": False, "path": str(soul_path)}

    if content.strip():
        next_content = content.rstrip() + "\n\n" + build_rule_block()
    else:
        next_content = "# AGENTS\n\n" + build_rule_block()

    await asyncio.to_thread(soul_path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(soul_path.write_text, next_content, encoding="utf-8")
    return {"changed": True, "path": str(soul_path)}
