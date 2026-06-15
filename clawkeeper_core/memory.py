"""Decision memory — append-only JSONL log of significant decisions.

Ported from legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/decision-memory.js.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from clawkeeper_core.state import resolve_state_dir

_PERSIST_RISK_LEVELS = {"medium", "high", "critical"}
_BEIJING = timezone(timedelta(hours=8))


def _truncate(value: Any, max_length: int = 240) -> str:
    if not isinstance(value, str):
        return ""
    return value[:max_length] + "..." if len(value) > max_length else value


def get_beijing_date_stamp(ref: datetime | None = None) -> str:
    """YYYY-MM-DD in Beijing time (UTC+8)."""
    if ref is None:
        ref = datetime.now(timezone.utc)
    return ref.astimezone(_BEIJING).strftime("%Y-%m-%d")


def _should_persist_decision(decision: Any) -> bool:
    if not isinstance(decision, dict):
        return False
    d = decision.get("decision")
    if d and d != "continue":
        return True
    risk_level = str(decision.get("riskLevel") or "").lower()
    return risk_level in _PERSIST_RISK_LEVELS


def _summarize_forwarded_context(body: Any = None) -> dict[str, Any]:
    body_d = body if isinstance(body, dict) else {}
    forwarded = body_d.get("forwardedContext") if isinstance(body_d.get("forwardedContext"), dict) else {}
    metadata = forwarded.get("metadata") if isinstance(forwarded.get("metadata"), dict) else {}
    messages = forwarded.get("messages") if isinstance(forwarded.get("messages"), list) else []

    normalized = [m for m in messages if isinstance(m, dict)]
    last_user_content = ""
    tool_names: list[str] = []
    seen_tools: set[str] = set()

    for message in normalized:
        role = message.get("role") if isinstance(message.get("role"), str) else ""
        if role == "user" and isinstance(message.get("content"), str):
            last_user_content = message["content"]

        tool_name = message.get("toolName") if isinstance(message.get("toolName"), str) else (
            message.get("name") if isinstance(message.get("name"), str) else ""
        )
        if tool_name:
            tool_names.append(tool_name)

    # Dedup preserving order, cap at 8.
    unique_tools: list[str] = []
    for n in tool_names:
        if n not in seen_tools:
            seen_tools.add(n)
            unique_tools.append(n)

    return {
        "requestId": body_d.get("requestId") if isinstance(body_d.get("requestId"), str) else None,
        "sessionKey": metadata.get("sessionKey") if isinstance(metadata.get("sessionKey"), str) else None,
        "messageCount": len(normalized),
        "toolCount": len(tool_names),
        "toolNames": unique_tools[:8],
        "lastUserMessage": _truncate(last_user_content),
    }


def _build_decision_memory_record(*, mode: str, body: Any, decision: dict[str, Any]) -> dict[str, Any]:
    summary = _summarize_forwarded_context(body)
    # Match JS: ISO timestamp shifted to Beijing time
    beijing_now = datetime.now(_BEIJING).replace(tzinfo=None)
    timestamp = beijing_now.isoformat(timespec="milliseconds") + "Z"

    return {
        "timestamp": timestamp,
        "mode": mode,
        "requestId": summary["requestId"],
        "sessionKey": summary["sessionKey"],
        "decision": decision.get("decision"),
        "stopReason": decision.get("stopReason"),
        "riskLevel": decision.get("riskLevel"),
        "nextAction": decision.get("nextAction"),
        "needsUserDecision": bool(decision.get("needsUserDecision")),
        "shouldContinue": bool(decision.get("shouldContinue")),
        "localEnhanced": bool(decision.get("localEnhanced")),
        "summary": decision.get("summary") if isinstance(decision.get("summary"), str) else "",
        "evidence": (decision.get("evidence") or [])[:8] if isinstance(decision.get("evidence"), list) else [],
        "messageCount": summary["messageCount"],
        "toolCount": summary["toolCount"],
        "toolNames": summary["toolNames"],
        "lastUserMessage": summary["lastUserMessage"],
    }


async def resolve_decision_memory_dir() -> Path:
    """Directory where per-day JSONL files live. Created on first call."""
    override = os.environ.get("CLAWKEEPER_DECISION_MEMORY_DIR")
    if override:
        memory_dir = Path(override)
    else:
        state_dir = await resolve_state_dir()
        memory_dir = state_dir / ".clawkeeper-watcher" / "decision-memory"
    await asyncio.to_thread(memory_dir.mkdir, parents=True, exist_ok=True)
    return memory_dir


async def _resolve_today_file() -> Path:
    memory_dir = await resolve_decision_memory_dir()
    return memory_dir / f"{get_beijing_date_stamp()}.jsonl"


async def append_decision_memory(
    *,
    mode: str,
    body: Any,
    decision: dict[str, Any],
    logger: Any = None,
) -> dict[str, Any]:
    """Append one decision to today's JSONL file, if it qualifies.

    Only persists remote-mode, non-continue or medium+/risk decisions.
    """
    if mode != "remote" or not _should_persist_decision(decision):
        return {"saved": False, "reason": "skipped"}

    record = _build_decision_memory_record(mode=mode, body=body, decision=decision)
    target = await _resolve_today_file()
    line = json.dumps(record, ensure_ascii=False) + "\n"
    await asyncio.to_thread(_atomic_append, target, line)

    if logger is not None and hasattr(logger, "debug"):
        logger.debug(
            f"[clawkeeper] decision memory saved decision={record['decision']} "
            f"risk={record['riskLevel']}"
        )

    return {"saved": True, "path": str(target), "record": record}


def _atomic_append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line)


# ── OO façade matching DESIGN.md ────────────────────────────────────────────


class DecisionMemory:
    """Append-only decision log. DESIGN.md surface for adapters."""

    async def append(self, *, mode: str, body: Any, decision: dict[str, Any]) -> dict[str, Any]:
        return await append_decision_memory(mode=mode, body=body, decision=decision)

    async def resolve_dir(self) -> Path:
        return await resolve_decision_memory_dir()
