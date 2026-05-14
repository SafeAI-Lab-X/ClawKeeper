"""Cross-session risk fingerprinting.

Ported from legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/risk-fingerprint.js.

A "fingerprint" is a normalized key derived from the (sorted) tool combination
and stop reason of a non-`continue` decision. When the same fingerprint appears
repeatedly across sessions in the lookback window, it becomes a known risk
pattern and `match_fingerprint` flags subsequent matches.

Storage: reads the JSONL files written by `clawkeeper_core.memory.DecisionMemory`.
Date-stamp and directory helpers live there too — this module just imports them.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from clawkeeper_core.memory import (
    get_beijing_date_stamp as _get_beijing_date_stamp,
    resolve_decision_memory_dir as _resolve_decision_memory_dir,
)

# ── Constants ───────────────────────────────────────────────────────────────


RISK_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_LEVEL: list[str] = ["low", "low", "medium", "high", "critical"]

_DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000  # 5 minutes


def _get_lookback_date_stamps(lookback_days: int, reference_date: datetime | None = None) -> list[str]:
    """Generate YYYY-MM-DD stamps for the lookback window, most-recent first."""
    if reference_date is None:
        reference_date = datetime.now(timezone.utc)
    return [
        _get_beijing_date_stamp(reference_date - timedelta(days=i))
        for i in range(lookback_days)
    ]


# ── Fingerprint key ────────────────────────────────────────────────────────


def _build_fingerprint_key(record: dict[str, Any]) -> str:
    """Build the stable fingerprint key from a record-like dict.

    Format: "<sorted,tool,names>|<stopReason>"
    Examples: "bash,exec|tool_loop_limit", "|user_requested_stop"
    """
    tool_names = record.get("toolNames") if isinstance(record, dict) else None
    if isinstance(tool_names, list):
        tools = ",".join(sorted({t for t in tool_names if isinstance(t, str)}))
    else:
        tools = ""

    stop_reason = record.get("stopReason") if isinstance(record, dict) else None
    reason = stop_reason if isinstance(stop_reason, str) else "unknown"
    return f"{tools}|{reason}"


# ── History loader ─────────────────────────────────────────────────────────


async def load_decision_history(lookback_days: int = 7) -> list[dict[str, Any]]:
    """Read JSONL decision records within the lookback window.

    Silently skips missing files and unparseable lines.
    """
    memory_dir = await _resolve_decision_memory_dir()
    records: list[dict[str, Any]] = []
    for stamp in _get_lookback_date_stamps(lookback_days):
        file_path = memory_dir / f"{stamp}.jsonl"
        try:
            raw = await asyncio.to_thread(file_path.read_text, encoding="utf-8")
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        for line in raw.split("\n"):
            trimmed = line.strip()
            if not trimmed:
                continue
            try:
                records.append(json.loads(trimmed))
            except json.JSONDecodeError:
                pass
    return records


# ── Fingerprint extraction ─────────────────────────────────────────────────


def extract_fingerprints(records: list[Any]) -> dict[str, dict[str, Any]]:
    """Aggregate non-`continue` decisions into a fingerprint map.

    Each entry: {key, count, maxRiskLevel, stopReason, toolNames, lastSeen, sessions}.
    """
    fingerprint_map: dict[str, dict[str, Any]] = {}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        decision = record.get("decision")
        if not decision or decision == "continue":
            continue

        key = _build_fingerprint_key(record)
        existing = fingerprint_map.get(key)
        if existing is not None:
            existing["count"] += 1

            incoming_rank = RISK_RANK.get(record.get("riskLevel"), 0)
            existing_rank = RISK_RANK.get(existing["maxRiskLevel"], 0)
            if incoming_rank > existing_rank:
                existing["maxRiskLevel"] = (
                    _RANK_TO_LEVEL[incoming_rank]
                    if 0 <= incoming_rank < len(_RANK_TO_LEVEL)
                    else record.get("riskLevel") or "medium"
                )

            ts = record.get("timestamp")
            if ts and isinstance(ts, str) and ts > existing["lastSeen"]:
                existing["lastSeen"] = ts

            session_key = record.get("sessionKey")
            if session_key:
                existing["sessions"].add(session_key)
        else:
            tool_names = record.get("toolNames")
            sorted_tools = (
                sorted({t for t in tool_names if isinstance(t, str)})
                if isinstance(tool_names, list)
                else []
            )
            sessions: set[str] = set()
            session_key = record.get("sessionKey")
            if session_key:
                sessions.add(session_key)
            fingerprint_map[key] = {
                "key": key,
                "count": 1,
                "maxRiskLevel": record.get("riskLevel") or "medium",
                "stopReason": record.get("stopReason") or "unknown",
                "toolNames": sorted_tools,
                "lastSeen": record.get("timestamp") or "",
                "sessions": sessions,
            }
    return fingerprint_map


# ── Fingerprint matching ───────────────────────────────────────────────────


def match_fingerprint(
    current_context: dict[str, Any],
    fingerprint_map: dict[str, dict[str, Any]] | None,
    threshold: int = 2,
) -> dict[str, Any] | None:
    """Match current context against the fingerprint map.

    Returns a match descriptor if `count >= threshold`, else None.
    """
    if not fingerprint_map:
        return None

    current_key = _build_fingerprint_key(current_context if isinstance(current_context, dict) else {})
    match = fingerprint_map.get(current_key)
    if match is None or match["count"] < threshold:
        return None

    return {
        "matched": True,
        "key": match["key"],
        "occurrences": match["count"],
        "maxRiskLevel": match["maxRiskLevel"],
        "sessionCount": len(match["sessions"]),
        "lastSeen": match["lastSeen"],
        "toolNames": list(match["toolNames"]),
        "stopReason": match["stopReason"],
        "warning": (
            f"This tool+reason combination has triggered {match['count']} "
            f"non-continue decisions across {len(match['sessions'])} "
            f"session(s) in the lookback window."
        ),
    }


# ── In-memory cache ────────────────────────────────────────────────────────


_cache: dict[str, Any] = {
    "entries": {},  # lookback_days -> {"fingerprintMap": ..., "loadedAt": ms}
    "ttlMs": _DEFAULT_CACHE_TTL_MS,
}


async def get_cached_fingerprint_map(lookback_days: int = 7) -> dict[str, dict[str, Any]]:
    """Load fingerprint map, using a 5-minute TTL cache keyed on lookback window."""
    now_ms = int(time.time() * 1000)
    entries = _cache["entries"]
    cached = entries.get(lookback_days)
    if cached and now_ms - cached["loadedAt"] < _cache["ttlMs"]:
        return cached["fingerprintMap"]

    records = await load_decision_history(lookback_days)
    fingerprint_map = extract_fingerprints(records)
    entries[lookback_days] = {"fingerprintMap": fingerprint_map, "loadedAt": now_ms}
    return fingerprint_map


def invalidate_fingerprint_cache() -> None:
    """Force a reload on the next `get_cached_fingerprint_map` call."""
    _cache["entries"].clear()


# ── Context summary helper ─────────────────────────────────────────────────


def _summarize_forwarded_context_for_fingerprint(body: Any = None) -> dict[str, list[str]]:
    body_d = body if isinstance(body, dict) else {}
    fc = body_d.get("forwardedContext")
    if not isinstance(fc, dict) or not isinstance(fc.get("messages"), list):
        return {"toolNames": []}

    tool_names: list[str] = []
    seen: set[str] = set()
    for msg in fc["messages"]:
        if not isinstance(msg, dict):
            continue
        name = msg.get("toolName") if isinstance(msg.get("toolName"), str) else msg.get("name")
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            tool_names.append(name)
    return {"toolNames": tool_names[:8]}


# ── Top-level entry point ──────────────────────────────────────────────────


async def resolve_fingerprint(
    *,
    body: Any = None,
    decision: Any = None,
    config: Any = None,
) -> dict[str, Any] | None:
    """HTTP-handler entry. Returns a match descriptor or None."""
    cfg = config if isinstance(config, dict) else {}
    fp_config = cfg.get("fingerprint") or {}
    if not isinstance(fp_config, dict) or not fp_config.get("enabled"):
        return None

    lookback_days = max(1, int(fp_config.get("lookbackDays") or 7))
    min_occurrences = max(1, int(fp_config.get("minOccurrences") or 2))

    context_summary = _summarize_forwarded_context_for_fingerprint(body)
    decision_d = decision if isinstance(decision, dict) else {}
    current_context = {
        "toolNames": context_summary["toolNames"],
        "stopReason": decision_d.get("stopReason"),
    }
    fingerprint_map = await get_cached_fingerprint_map(lookback_days)
    return match_fingerprint(current_context, fingerprint_map, min_occurrences)


# ── Human-readable report ──────────────────────────────────────────────────


def build_fingerprint_report(
    fingerprint_map: dict[str, dict[str, Any]],
    threshold: int = 2,
) -> str:
    qualified = sorted(
        (fp for fp in fingerprint_map.values() if fp["count"] >= threshold),
        key=lambda fp: -fp["count"],
    )
    if not qualified:
        return "No recurring risk fingerprints found in the lookback window."

    lines = [
        f"\nRisk Fingerprints ({len(qualified)} known patterns)\n",
        "------------------------------------------------------------------------",
    ]
    for fp in qualified:
        tools = ", ".join(fp["toolNames"]) if fp["toolNames"] else "(none)"
        lines.append(f"  Key:       {fp['key']}")
        lines.append(f"  Tools:     {tools}")
        lines.append(f"  Reason:    {fp['stopReason']}")
        lines.append(
            f"  Count:     {fp['count']} occurrences across {len(fp['sessions'])} session(s)"
        )
        lines.append(f"  Max Risk:  {fp['maxRiskLevel']}")
        lines.append(f"  Last Seen: {fp['lastSeen']}")
        lines.append("------------------------------------------------------------------------")
    return "\n".join(lines)


# ── OO façade matching DESIGN.md surface ────────────────────────────────────


class RiskEngine:
    """Convenience wrapper over the module-level functions."""

    def __init__(self, lookback_days: int = 7, threshold: int = 2) -> None:
        self.lookback_days = lookback_days
        self.threshold = threshold

    def extract(self, records: list[Any]) -> dict[str, dict[str, Any]]:
        return extract_fingerprints(records)

    def match(
        self,
        current_context: dict[str, Any],
        fingerprint_map: dict[str, dict[str, Any]] | None,
        threshold: int | None = None,
    ) -> dict[str, Any] | None:
        return match_fingerprint(
            current_context,
            fingerprint_map,
            threshold if threshold is not None else self.threshold,
        )

    async def load(self) -> dict[str, dict[str, Any]]:
        return await get_cached_fingerprint_map(self.lookback_days)

    def report(self, fingerprint_map: dict[str, dict[str, Any]], threshold: int | None = None) -> str:
        return build_fingerprint_report(
            fingerprint_map,
            threshold if threshold is not None else self.threshold,
        )

    def invalidate_cache(self) -> None:
        invalidate_fingerprint_cache()
