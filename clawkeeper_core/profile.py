"""Agent behavioral profiling — baseline + deviation + anomaly detection.

Ported from legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/agent-profiler.js.

The profiler aggregates per-agent statistics over a rolling lookback window
(tool distribution, token usage, session counts, judge-decision ratios) and
flags significant deviations as anomalies. Uses Jensen–Shannon divergence
for distribution shift and multiplicative thresholds for token/frequency
spikes.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from clawkeeper_core.memory import get_beijing_date_stamp, resolve_decision_memory_dir

# ── Constants ───────────────────────────────────────────────────────────────


_DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000
_DEFAULT_TOOL_DEVIATION_THRESHOLD = 3.0
_DEFAULT_TOKEN_DEVIATION_THRESHOLD = 2.5
_DEFAULT_NOVEL_TOOL_SEVERITY = "medium"
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_AGENT_SESSION_RE = re.compile(r"^agent:([^:]+):", re.IGNORECASE)


# ── Generic helpers ────────────────────────────────────────────────────────


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _positive_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
        return float(value)
    return None


def _threshold_number(value: Any, fallback: float) -> float:
    try:
        parsed = float(str(value))
    except (TypeError, ValueError):
        return fallback
    return parsed if math.isfinite(parsed) and parsed >= 0 else fallback


def _normalize_tool_name(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return ""


def _normalize_agent_id(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return ""


def _parse_agent_id_from_session_key(session_key: Any) -> str:
    if not isinstance(session_key, str):
        return ""
    m = _AGENT_SESSION_RE.match(session_key.strip())
    return _normalize_agent_id(m.group(1)) if m else ""


def _resolve_agent_id_from_record(record: Any) -> str:
    if not _is_record(record):
        return ""
    return _normalize_agent_id(record.get("agentId")) or _parse_agent_id_from_session_key(record.get("sessionKey"))


def _resolve_session_identifier(record: Any) -> str:
    if not _is_record(record):
        return ""
    sk = record.get("sessionKey")
    if isinstance(sk, str) and sk.strip():
        return sk.strip()
    sid = record.get("sessionId")
    if isinstance(sid, str) and sid.strip():
        return f"session:{sid.strip()}"
    return ""


def _get_lookback_date_stamps(lookback_days: Any, reference_date: datetime | None = None) -> list[str]:
    try:
        safe_days = max(1, int(str(lookback_days)) or 7)
    except (TypeError, ValueError):
        safe_days = 7
    if reference_date is None:
        reference_date = datetime.now(timezone.utc)
    return [
        get_beijing_date_stamp(reference_date - timedelta(days=i))
        for i in range(safe_days)
    ]


def _build_distribution(counts: dict[str, int], total: int) -> dict[str, float]:
    if not counts or total <= 0:
        return {}
    return {tool: counts[tool] / total for tool in sorted(counts.keys())}


# ── Profile structures ─────────────────────────────────────────────────────


def _create_empty_profile(agent_id: str) -> dict[str, Any]:
    return {
        "agentId": agent_id,
        "toolDistribution": {},
        "toolCallCount": 0,
        "avgInputTokensPerCall": 0,
        "avgOutputTokensPerCall": 0,
        "avgTotalTokensPerCall": 0,
        "totalTokens": 0,
        "sessionCount": 0,
        "avgToolCallsPerSession": 0,
        "riskDecisionCount": 0,
        "riskRatio": 0,
        "judgeDecisionCount": 0,
        "knownTools": set(),
        "firstSeen": "",
        "lastSeen": "",
        "dataPointCount": 0,
        # Accumulators (popped at end of buildAgentProfiles)
        "_toolCounts": {},
        "_sessionKeys": set(),
        "_inputTokenSum": 0,
        "_inputTokenSamples": 0,
        "_outputTokenSum": 0,
        "_outputTokenSamples": 0,
        "_totalTokenSum": 0,
        "_totalTokenSamples": 0,
    }


def _ensure_profile(profile_map: dict[str, dict[str, Any]], agent_id: str) -> dict[str, Any]:
    if agent_id not in profile_map:
        profile_map[agent_id] = _create_empty_profile(agent_id)
    return profile_map[agent_id]


def _update_timestamp_range(profile: dict[str, Any], timestamp: Any) -> None:
    if not isinstance(timestamp, str) or not timestamp:
        return
    if not profile["firstSeen"] or timestamp < profile["firstSeen"]:
        profile["firstSeen"] = timestamp
    if not profile["lastSeen"] or timestamp > profile["lastSeen"]:
        profile["lastSeen"] = timestamp


def _record_token_sample(profile: dict[str, Any], record: dict[str, Any]) -> None:
    if record.get("type") != "llm_output":
        return

    inp = _positive_number(record.get("inputTokens"))
    if inp is not None:
        profile["_inputTokenSum"] += inp
        profile["_inputTokenSamples"] += 1

    out = _positive_number(record.get("outputTokens"))
    if out is not None:
        profile["_outputTokenSum"] += out
        profile["_outputTokenSamples"] += 1

    total = _positive_number(record.get("totalTokens"))
    if total is None:
        parts = [
            _positive_number(record.get("inputTokens")) or 0,
            _positive_number(record.get("outputTokens")) or 0,
            _positive_number(record.get("cacheReadTokens")) or 0,
            _positive_number(record.get("cacheWriteTokens")) or 0,
        ]
        total = sum(parts)

    if total > 0:
        profile["_totalTokenSum"] += total
        profile["_totalTokenSamples"] += 1
        profile["totalTokens"] += total


def _normalize_known_tools(value: Any, distribution: dict[str, float] | None = None) -> set[str]:
    if isinstance(value, (set, list, tuple)):
        return {t for t in (_normalize_tool_name(v) for v in value) if t}
    if distribution:
        return {t for t in (_normalize_tool_name(k) for k in distribution.keys()) if t}
    return set()


def _normalize_behavior_summary(summary: Any) -> dict[str, Any]:
    s = summary if _is_record(summary) else {}
    tool_distribution = s.get("toolDistribution") if _is_record(s.get("toolDistribution")) else {}
    known_tools = _normalize_known_tools(s.get("knownTools"), tool_distribution)

    tool_call_count = _positive_number(s.get("toolCallCount"))
    if tool_call_count is None:
        tool_call_count = len(tool_distribution)

    avg_input = _positive_number(s.get("avgInputTokensPerCall"))
    avg_output = _positive_number(s.get("avgOutputTokensPerCall"))
    avg_total = _positive_number(s.get("avgTotalTokensPerCall"))
    if avg_total is None:
        inp = avg_input or 0
        out = avg_output or 0
        avg_total = (inp + out) if (inp > 0 or out > 0) else None

    return {
        "agentId": _normalize_agent_id(s.get("agentId")),
        "toolDistribution": tool_distribution,
        "toolCallCount": tool_call_count,
        "avgInputTokensPerCall": avg_input,
        "avgOutputTokensPerCall": avg_output,
        "avgTotalTokensPerCall": avg_total,
        "sessionCount": _positive_number(s.get("sessionCount")) or 0,
        "riskDecisionCount": _positive_number(s.get("riskDecisionCount")) or 0,
        "judgeDecisionCount": _positive_number(s.get("judgeDecisionCount")) or 0,
        "knownTools": known_tools,
    }


def _safe_log2(value: float) -> float:
    return math.log2(value) if value > 0 else 0


def _jensen_shannon_divergence(left: dict[str, float], right: dict[str, float]) -> float:
    tools = set((left or {}).keys()) | set((right or {}).keys())
    if not tools:
        return 0
    divergence = 0.0
    for tool in tools:
        lv = _positive_number((left or {}).get(tool)) or 0
        rv = _positive_number((right or {}).get(tool)) or 0
        midpoint = (lv + rv) / 2
        if lv > 0:
            divergence += 0.5 * lv * (_safe_log2(lv) - _safe_log2(midpoint))
        if rv > 0:
            divergence += 0.5 * rv * (_safe_log2(rv) - _safe_log2(midpoint))
    return divergence


# ── Per-request context summary ────────────────────────────────────────────


def summarize_forwarded_context_for_profiling(body: Any = None, decision: Any = None) -> dict[str, Any]:
    body_d = body if _is_record(body) else {}
    decision_d = decision if _is_record(decision) else {}
    forwarded = body_d.get("forwardedContext") if _is_record(body_d.get("forwardedContext")) else {}
    metadata = forwarded.get("metadata") if _is_record(forwarded.get("metadata")) else {}
    messages = [m for m in (forwarded.get("messages") or []) if _is_record(m)]

    last_user_idx = -1
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "user":
            last_user_idx = i
            break
    active = messages[last_user_idx:] if last_user_idx >= 0 else messages

    tool_counts: dict[str, int] = {}
    for message in active:
        name = _normalize_tool_name(message.get("toolName") or message.get("name"))
        if not name or name in ("clawbands_respond", "clawkeeper_bands_respond"):
            continue
        tool_counts[name] = tool_counts.get(name, 0) + 1

    tool_call_count = sum(tool_counts.values())
    usage = (
        metadata.get("usage") if _is_record(metadata.get("usage"))
        else body_d.get("usage") if _is_record(body_d.get("usage"))
        else {}
    )

    def _first_positive(*candidates):
        for c in candidates:
            v = _positive_number(c)
            if v is not None:
                return v
        return None

    input_tokens = _first_positive(
        usage.get("input"), usage.get("inputTokens"),
        metadata.get("inputTokens"), body_d.get("inputTokens"),
    )
    output_tokens = _first_positive(
        usage.get("output"), usage.get("outputTokens"),
        metadata.get("outputTokens"), body_d.get("outputTokens"),
    )
    total_tokens = _first_positive(
        usage.get("total"), usage.get("totalTokens"),
        metadata.get("totalTokens"), body_d.get("totalTokens"),
    )
    if total_tokens is None and (input_tokens is not None or output_tokens is not None):
        total_tokens = (input_tokens or 0) + (output_tokens or 0)

    session_key = (
        metadata.get("sessionKey") if isinstance(metadata.get("sessionKey"), str) else
        body_d.get("sessionKey") if isinstance(body_d.get("sessionKey"), str) else ""
    )
    agent_id = (
        _normalize_agent_id(metadata.get("agentId"))
        or _normalize_agent_id(body_d.get("agentId"))
        or _parse_agent_id_from_session_key(session_key)
    )
    risk_count = 1 if (decision_d.get("decision") and decision_d.get("decision") != "continue") else 0

    return {
        "agentId": agent_id,
        "toolDistribution": _build_distribution(tool_counts, tool_call_count),
        "toolCallCount": tool_call_count,
        "avgInputTokensPerCall": input_tokens,
        "avgOutputTokensPerCall": output_tokens,
        "avgTotalTokensPerCall": total_tokens,
        "totalTokens": total_tokens or 0,
        "sessionCount": 1 if (session_key or len(active) > 0) else 0,
        "avgToolCallsPerSession": tool_call_count,
        "riskDecisionCount": risk_count,
        "riskRatio": risk_count,
        "judgeDecisionCount": 1 if decision_d.get("decision") else 0,
        "knownTools": set(tool_counts.keys()),
    }


# ── Disk loaders ───────────────────────────────────────────────────────────


async def _load_decision_records(lookback_days: int = 7) -> list[dict[str, Any]]:
    memory_dir = await resolve_decision_memory_dir()
    records: list[dict[str, Any]] = []
    for stamp in _get_lookback_date_stamps(lookback_days):
        file_path = memory_dir / f"{stamp}.jsonl"
        try:
            content = await asyncio.to_thread(file_path.read_text, encoding="utf-8")
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        for line in content.split("\n"):
            trimmed = line.strip()
            if not trimmed:
                continue
            try:
                parsed = json.loads(trimmed)
                if _is_record(parsed):
                    records.append(parsed)
            except json.JSONDecodeError:
                pass
    return records


async def load_event_logs(lookback_days: int = 7) -> list[dict[str, Any]]:
    """Load interceptor event-log records for the lookback window.

    The legacy JS imports `getLogFiles` / `readLogFile` from interceptor.js;
    those routes will move to clawkeeper_core.scanner when ported. For now
    this resolves the same JSONL path layout under the decision-memory
    sibling `event-log/` directory. Tests don't exercise this path.
    """
    stamps = {f"{s}.jsonl" for s in _get_lookback_date_stamps(lookback_days)}
    memory_dir = await resolve_decision_memory_dir()
    log_dir = memory_dir.parent / "event-log"
    if not await asyncio.to_thread(log_dir.exists):
        return []
    records: list[dict[str, Any]] = []
    for filename in stamps:
        path = log_dir / filename
        try:
            content = await asyncio.to_thread(path.read_text, encoding="utf-8")
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        for line in content.split("\n"):
            trimmed = line.strip()
            if not trimmed:
                continue
            try:
                parsed = json.loads(trimmed)
                if _is_record(parsed):
                    records.append(parsed)
            except json.JSONDecodeError:
                pass
    return records


# ── Core API ───────────────────────────────────────────────────────────────


def build_agent_profiles(
    records: Iterable[dict[str, Any]] | None,
    *,
    decision_records: Iterable[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    profile_map: dict[str, dict[str, Any]] = {}

    for record in records or []:
        agent_id = _resolve_agent_id_from_record(record)
        if not agent_id:
            continue
        profile = _ensure_profile(profile_map, agent_id)
        profile["dataPointCount"] += 1
        _update_timestamp_range(profile, record.get("timestamp"))

        sess = _resolve_session_identifier(record)
        if sess:
            profile["_sessionKeys"].add(sess)

        if record.get("type") == "before_tool_call":
            tool_name = _normalize_tool_name(record.get("toolName"))
            if tool_name:
                profile["toolCallCount"] += 1
                profile["knownTools"].add(tool_name)
                profile["_toolCounts"][tool_name] = profile["_toolCounts"].get(tool_name, 0) + 1

        _record_token_sample(profile, record)

    for record in (decision_records or []):
        agent_id = _resolve_agent_id_from_record(record)
        if not agent_id:
            continue
        profile = _ensure_profile(profile_map, agent_id)
        _update_timestamp_range(profile, record.get("timestamp"))

        sess = _resolve_session_identifier(record)
        if sess:
            profile["_sessionKeys"].add(sess)

        profile["judgeDecisionCount"] += 1
        if record.get("decision") and record["decision"] != "continue":
            profile["riskDecisionCount"] += 1

    for profile in profile_map.values():
        profile["sessionCount"] = len(profile["_sessionKeys"])
        profile["avgToolCallsPerSession"] = (
            profile["toolCallCount"] / profile["sessionCount"]
            if profile["sessionCount"] > 0 else 0
        )
        profile["toolDistribution"] = _build_distribution(profile["_toolCounts"], profile["toolCallCount"])
        profile["avgInputTokensPerCall"] = (
            profile["_inputTokenSum"] / profile["_inputTokenSamples"]
            if profile["_inputTokenSamples"] > 0 else 0
        )
        profile["avgOutputTokensPerCall"] = (
            profile["_outputTokenSum"] / profile["_outputTokenSamples"]
            if profile["_outputTokenSamples"] > 0 else 0
        )
        profile["avgTotalTokensPerCall"] = (
            profile["_totalTokenSum"] / profile["_totalTokenSamples"]
            if profile["_totalTokenSamples"] > 0 else 0
        )
        profile["riskRatio"] = (
            profile["riskDecisionCount"] / profile["judgeDecisionCount"]
            if profile["judgeDecisionCount"] > 0 else 0
        )
        for k in ("_toolCounts", "_sessionKeys", "_inputTokenSum", "_inputTokenSamples",
                  "_outputTokenSum", "_outputTokenSamples", "_totalTokenSum", "_totalTokenSamples"):
            profile.pop(k, None)

    return profile_map


def compute_deviation(current_behavior: Any = None, baseline: Any = None) -> dict[str, Any]:
    current = _normalize_behavior_summary(current_behavior or {})
    base = _normalize_behavior_summary(baseline) if baseline else None

    if not base:
        return {
            "agentId": current["agentId"],
            "hasBaseline": False,
            "toolDistributionDivergence": 0,
            "novelTools": [],
            "toolFrequencyChanges": [],
            "tokenDeviation": {},
            "baseline": None,
            "current": current,
        }

    novel_tools = sorted(t for t in current["knownTools"] if t not in base["knownTools"])
    tool_frequency_changes: list[dict[str, Any]] = []
    for tool in current["knownTools"]:
        cur_freq = _positive_number(current["toolDistribution"].get(tool)) or 0
        base_freq = _positive_number(base["toolDistribution"].get(tool)) or 0
        if cur_freq <= 0 or base_freq <= 0:
            continue
        tool_frequency_changes.append({
            "tool": tool,
            "baseline": base_freq,
            "current": cur_freq,
            "multiplier": cur_freq / base_freq,
            "delta": cur_freq - base_freq,
        })

    token_deviation: dict[str, dict[str, float]] = {}
    for metric, cur_v, base_v in [
        ("input", current["avgInputTokensPerCall"], base["avgInputTokensPerCall"]),
        ("output", current["avgOutputTokensPerCall"], base["avgOutputTokensPerCall"]),
        ("total", current["avgTotalTokensPerCall"], base["avgTotalTokensPerCall"]),
    ]:
        if cur_v is None or base_v is None or base_v <= 0 or cur_v <= 0:
            continue
        token_deviation[metric] = {
            "current": cur_v,
            "baseline": base_v,
            "multiplier": cur_v / base_v,
        }

    return {
        "agentId": current["agentId"] or base["agentId"],
        "hasBaseline": True,
        "toolDistributionDivergence": _jensen_shannon_divergence(
            base["toolDistribution"], current["toolDistribution"]
        ),
        "novelTools": novel_tools,
        "toolFrequencyChanges": sorted(tool_frequency_changes, key=lambda x: -x["multiplier"]),
        "tokenDeviation": token_deviation,
        "baseline": base,
        "current": current,
    }


def _pick_higher_severity(left: str, right: str) -> str:
    return right if _SEVERITY_RANK.get(right, 0) > _SEVERITY_RANK.get(left, 0) else left


def _build_warning(agent_id: str, findings: list[dict[str, Any]], lookback_days: int) -> str:
    fragments: list[str] = []
    for f in findings[:2]:
        if f["type"] == "novel_tool":
            fragments.append(f"using novel tool '{f['tool']}'")
        elif f["type"] == "tool_frequency_spike":
            fragments.append(f"{f['multiplier']:.1f}x spike in '{f['tool']}' usage")
        elif f["type"] == "token_spike":
            fragments.append(f"{f['multiplier']:.1f}x spike in {f['metric']} tokens")
        else:
            fragments.append(f.get("message", ""))
    return (
        f"Agent {agent_id} is exhibiting behavior significantly different from its "
        f"{lookback_days}-day baseline: {' and '.join(fragments)}"
    )


def detect_anomalies(deviations: Any = None, thresholds: Any = None) -> dict[str, Any]:
    t = thresholds if _is_record(thresholds) else {}
    try:
        lookback_days = max(1, int(str(t.get("lookbackDays", 7))) or 7)
    except (TypeError, ValueError):
        lookback_days = 7
    tool_thr = _threshold_number(t.get("toolDeviationThreshold", _DEFAULT_TOOL_DEVIATION_THRESHOLD), _DEFAULT_TOOL_DEVIATION_THRESHOLD)
    token_thr = _threshold_number(t.get("tokenDeviationThreshold", _DEFAULT_TOKEN_DEVIATION_THRESHOLD), _DEFAULT_TOKEN_DEVIATION_THRESHOLD)
    novel_sev = str(t.get("novelToolSeverity", _DEFAULT_NOVEL_TOOL_SEVERITY))
    novel_sev = novel_sev if novel_sev in ("low", "medium", "high") else _DEFAULT_NOVEL_TOOL_SEVERITY

    d = deviations if _is_record(deviations) else {}
    if not d.get("hasBaseline") or not d.get("baseline"):
        return {
            "detected": False,
            "agentId": d.get("agentId", ""),
            "severity": "low",
            "deviations": [],
            "baselineSummary": None,
            "warning": None,
        }

    findings: list[dict[str, Any]] = []
    severity = "low"

    for tool in d.get("novelTools", []):
        severity = _pick_higher_severity(severity, novel_sev)
        findings.append({
            "type": "novel_tool",
            "tool": tool,
            "severity": novel_sev,
            "message": (
                f"Agent has never used '{tool}' in {lookback_days}-day baseline "
                f"({d['baseline']['toolCallCount']} historical calls)"
            ),
        })

    for change in d.get("toolFrequencyChanges", []):
        if change["multiplier"] < tool_thr:
            continue
        change_sev = "high" if (change["multiplier"] >= tool_thr * 2 or change["current"] >= 0.5) else "medium"
        severity = _pick_higher_severity(severity, change_sev)
        findings.append({
            "type": "tool_frequency_spike",
            "tool": change["tool"],
            "baseline": change["baseline"],
            "current": change["current"],
            "multiplier": change["multiplier"],
            "severity": change_sev,
            "message": (
                f"{change['tool']} usage {change['multiplier']:.1f}x above baseline "
                f"({round(change['baseline'] * 100)}% -> {round(change['current'] * 100)}%)"
            ),
        })

    for metric, change in d.get("tokenDeviation", {}).items():
        if change["multiplier"] < token_thr:
            continue
        change_sev = "high" if change["multiplier"] >= token_thr * 1.75 else "medium"
        severity = _pick_higher_severity(severity, change_sev)
        findings.append({
            "type": "token_spike",
            "metric": metric,
            "baseline": change["baseline"],
            "current": change["current"],
            "multiplier": change["multiplier"],
            "severity": change_sev,
            "message": (
                f"{metric} tokens {change['multiplier']:.1f}x above baseline "
                f"({round(change['baseline'])} -> {round(change['current'])})"
            ),
        })

    baseline_summary = {
        "sessionCount": d["baseline"]["sessionCount"],
        "toolCallCount": d["baseline"]["toolCallCount"],
        "knownTools": sorted(d["baseline"]["knownTools"]),
        "lookbackDays": lookback_days,
    }

    if not findings:
        return {
            "detected": False,
            "agentId": d.get("agentId", ""),
            "severity": "low",
            "deviations": [],
            "baselineSummary": baseline_summary,
            "warning": None,
        }

    return {
        "detected": True,
        "agentId": d.get("agentId", ""),
        "severity": severity,
        "deviations": findings,
        "baselineSummary": baseline_summary,
        "warning": _build_warning(d.get("agentId", ""), findings, lookback_days),
    }


# ── Cache ──────────────────────────────────────────────────────────────────


_cache: dict[str, Any] = {"entries": {}, "ttlMs": _DEFAULT_CACHE_TTL_MS}


async def get_cached_profiles(lookback_days: int = 7) -> dict[str, dict[str, Any]]:
    try:
        safe = max(1, int(str(lookback_days)) or 7)
    except (TypeError, ValueError):
        safe = 7
    now_ms = int(time.time() * 1000)
    cached = _cache["entries"].get(safe)
    if cached and now_ms - cached["loadedAt"] < _cache["ttlMs"]:
        return cached["profileMap"]
    records = await load_event_logs(safe)
    decisions = await _load_decision_records(safe)
    profile_map = build_agent_profiles(records, decision_records=decisions)
    _cache["entries"][safe] = {"profileMap": profile_map, "loadedAt": now_ms}
    return profile_map


def invalidate_profile_cache() -> None:
    _cache["entries"].clear()


async def resolve_agent_anomaly(*, body: Any = None, decision: Any = None, config: Any = None) -> dict[str, Any] | None:
    cfg = config if _is_record(config) else {}
    profile_cfg = cfg.get("agentProfiling") if _is_record(cfg.get("agentProfiling")) else {}
    if not profile_cfg.get("enabled"):
        return None
    try:
        lookback_days = max(1, int(str(profile_cfg.get("lookbackDays", 7))) or 7)
    except (TypeError, ValueError):
        lookback_days = 7

    current = summarize_forwarded_context_for_profiling(body, decision)
    if not current["agentId"]:
        return None
    profiles = await get_cached_profiles(lookback_days)
    baseline = profiles.get(current["agentId"])
    if not baseline:
        return None

    deviations = compute_deviation(current, baseline)
    anomaly = detect_anomalies(deviations, {**profile_cfg, "lookbackDays": lookback_days})
    return anomaly if anomaly["detected"] else None


# ── OO façade ──────────────────────────────────────────────────────────────


class AgentProfiler:
    def update(self, event: Any) -> None:
        raise NotImplementedError(
            "AgentProfiler.update is event-stream API; use build_agent_profiles "
            "for batch construction from event logs."
        )

    def baseline(self, agent_id: str) -> dict[str, Any] | None:
        return None

    def deviation(self, agent_id: str, recent: Any) -> dict[str, Any]:
        return compute_deviation(recent, None)
