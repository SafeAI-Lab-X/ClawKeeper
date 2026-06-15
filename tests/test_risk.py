"""Behavior-parity tests ported from
legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/risk-fingerprint.test.js.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from clawkeeper_core.risk import (
    build_fingerprint_report,
    extract_fingerprints,
    invalidate_fingerprint_cache,
    match_fingerprint,
    resolve_fingerprint,
)
from clawkeeper_core.risk import (
    _build_fingerprint_key,
    _cache,
    _get_lookback_date_stamps,
    _summarize_forwarded_context_for_fingerprint,
)


def make_record(**overrides: Any) -> dict[str, Any]:
    base = {
        "timestamp": "2026-03-24T10:00:00.000Z",
        "mode": "remote",
        "requestId": "req-1",
        "sessionKey": "session-a",
        "decision": "stop",
        "stopReason": "tool_loop_limit",
        "riskLevel": "high",
        "nextAction": "stop_run",
        "needsUserDecision": False,
        "shouldContinue": False,
        "localEnhanced": False,
        "summary": "Tool loop detected.",
        "evidence": ["toolCount=5"],
        "messageCount": 6,
        "toolCount": 2,
        "toolNames": ["bash", "exec"],
        "lastUserMessage": "run the script",
    }
    base.update(overrides)
    return base


# ── buildFingerprintKey ───────────────────────────────────────────────────


class TestBuildFingerprintKey:
    def test_builds_key_from_sorted_tools_and_reason(self):
        assert _build_fingerprint_key(
            {"toolNames": ["exec", "bash"], "stopReason": "tool_loop_limit"}
        ) == "bash,exec|tool_loop_limit"

    def test_sorts_tool_names_alphabetically(self):
        assert _build_fingerprint_key(
            {"toolNames": ["write", "bash", "exec"], "stopReason": "high_risk_action"}
        ) == "bash,exec,write|high_risk_action"

    def test_deduplicates_tool_names(self):
        assert _build_fingerprint_key(
            {"toolNames": ["bash", "bash", "exec"], "stopReason": "tool_loop_limit"}
        ) == "bash,exec|tool_loop_limit"

    def test_handles_empty_tool_names(self):
        assert _build_fingerprint_key(
            {"toolNames": [], "stopReason": "user_requested_stop"}
        ) == "|user_requested_stop"

    def test_handles_missing_tool_names(self):
        assert _build_fingerprint_key({"stopReason": "upstream_error"}) == "|upstream_error"

    def test_handles_missing_stop_reason(self):
        assert _build_fingerprint_key({"toolNames": ["bash"]}) == "bash|unknown"

    def test_handles_non_string_stop_reason(self):
        assert _build_fingerprint_key({"toolNames": ["bash"], "stopReason": 42}) == "bash|unknown"


# ── getLookbackDateStamps ────────────────────────────────────────────────


class TestGetLookbackDateStamps:
    def test_returns_correct_number_of_stamps(self):
        stamps = _get_lookback_date_stamps(3)
        assert len(stamps) == 3

    def test_returns_today_first(self):
        from datetime import datetime, timezone
        ref = datetime(2026, 3, 24, 4, 0, 0, tzinfo=timezone.utc)  # Beijing 12:00
        stamps = _get_lookback_date_stamps(3, ref)
        assert stamps[0] == "2026-03-24"
        assert stamps[1] == "2026-03-23"
        assert stamps[2] == "2026-03-22"

    def test_handles_lookback_days_one(self):
        from datetime import datetime, timezone
        ref = datetime(2026, 3, 24, 4, 0, 0, tzinfo=timezone.utc)
        stamps = _get_lookback_date_stamps(1, ref)
        assert stamps == ["2026-03-24"]


# ── summarizeForwardedContextForFingerprint ──────────────────────────────


class TestSummarizeForwardedContext:
    def test_extracts_unique_tool_names(self):
        result = _summarize_forwarded_context_for_fingerprint({
            "forwardedContext": {
                "messages": [
                    {"role": "tool", "toolName": "bash"},
                    {"role": "tool", "toolName": "exec"},
                    {"role": "tool", "toolName": "bash"},
                ],
            },
        })
        assert sorted(result["toolNames"]) == ["bash", "exec"]

    def test_handles_missing_forwarded_context(self):
        assert _summarize_forwarded_context_for_fingerprint({})["toolNames"] == []

    def test_handles_empty_messages(self):
        result = _summarize_forwarded_context_for_fingerprint({"forwardedContext": {"messages": []}})
        assert result["toolNames"] == []

    def test_limits_to_eight_tool_names(self):
        messages = [{"role": "tool", "toolName": f"tool-{i}"} for i in range(12)]
        result = _summarize_forwarded_context_for_fingerprint({"forwardedContext": {"messages": messages}})
        assert len(result["toolNames"]) == 8

    def test_supports_name_field_fallback(self):
        result = _summarize_forwarded_context_for_fingerprint({
            "forwardedContext": {"messages": [{"role": "tool", "name": "write"}]},
        })
        assert result["toolNames"] == ["write"]


# ── extractFingerprints ──────────────────────────────────────────────────


class TestExtractFingerprints:
    def test_extracts_from_stop_and_ask_user(self):
        records = [
            make_record(decision="stop", stopReason="tool_loop_limit"),
            make_record(decision="ask_user", stopReason="waiting_user_confirmation"),
        ]
        assert len(extract_fingerprints(records)) == 2

    def test_ignores_continue_decisions(self):
        records = [
            make_record(decision="continue", riskLevel="medium"),
            make_record(decision="stop"),
        ]
        assert len(extract_fingerprints(records)) == 1

    def test_counts_occurrences(self):
        records = [
            make_record(decision="stop", sessionKey="s1"),
            make_record(decision="stop", sessionKey="s2"),
            make_record(decision="stop", sessionKey="s3"),
        ]
        m = extract_fingerprints(records)
        entry = next(iter(m.values()))
        assert entry["count"] == 3

    def test_tracks_max_risk_level(self):
        records = [
            make_record(decision="stop", riskLevel="medium"),
            make_record(decision="stop", riskLevel="critical"),
            make_record(decision="stop", riskLevel="high"),
        ]
        entry = next(iter(extract_fingerprints(records).values()))
        assert entry["maxRiskLevel"] == "critical"

    def test_tracks_unique_sessions(self):
        records = [
            make_record(decision="stop", sessionKey="s1"),
            make_record(decision="stop", sessionKey="s1"),
            make_record(decision="stop", sessionKey="s2"),
        ]
        entry = next(iter(extract_fingerprints(records).values()))
        assert len(entry["sessions"]) == 2

    def test_handles_empty_and_corrupt_records(self):
        records = [None, None, {}, make_record(decision="stop")]
        assert len(extract_fingerprints(records)) == 1

    def test_tracks_last_seen_as_latest_timestamp(self):
        records = [
            make_record(decision="stop", timestamp="2026-03-20T10:00:00.000Z"),
            make_record(decision="stop", timestamp="2026-03-24T10:00:00.000Z"),
            make_record(decision="stop", timestamp="2026-03-22T10:00:00.000Z"),
        ]
        entry = next(iter(extract_fingerprints(records).values()))
        assert entry["lastSeen"] == "2026-03-24T10:00:00.000Z"


# ── matchFingerprint ─────────────────────────────────────────────────────


class TestMatchFingerprint:
    @pytest.fixture
    def fingerprint_map(self) -> dict[str, dict[str, Any]]:
        records = [
            make_record(decision="stop", sessionKey="s1"),
            make_record(decision="stop", sessionKey="s2"),
            make_record(decision="stop", sessionKey="s3"),
        ]
        return extract_fingerprints(records)

    def test_returns_match_when_count_ge_threshold(self, fingerprint_map):
        m = match_fingerprint(
            {"toolNames": ["bash", "exec"], "stopReason": "tool_loop_limit"},
            fingerprint_map, 2,
        )
        assert m is not None
        assert m["matched"] is True
        assert m["occurrences"] == 3

    def test_returns_none_when_count_below_threshold(self, fingerprint_map):
        assert match_fingerprint(
            {"toolNames": ["bash", "exec"], "stopReason": "tool_loop_limit"},
            fingerprint_map, 10,
        ) is None

    def test_returns_none_when_key_missing(self, fingerprint_map):
        assert match_fingerprint(
            {"toolNames": ["unknown_tool"], "stopReason": "never_seen"},
            fingerprint_map, 1,
        ) is None

    def test_returns_none_for_empty_map(self):
        assert match_fingerprint(
            {"toolNames": ["bash"], "stopReason": "tool_loop_limit"},
            {}, 1,
        ) is None

    def test_returns_none_for_none_map(self):
        assert match_fingerprint(
            {"toolNames": ["bash"], "stopReason": "tool_loop_limit"},
            None, 1,
        ) is None

    def test_populates_all_fields(self, fingerprint_map):
        m = match_fingerprint(
            {"toolNames": ["bash", "exec"], "stopReason": "tool_loop_limit"},
            fingerprint_map, 1,
        )
        assert m is not None
        assert m["matched"] is True
        assert isinstance(m["key"], str)
        assert isinstance(m["occurrences"], int)
        assert isinstance(m["maxRiskLevel"], str)
        assert isinstance(m["sessionCount"], int)
        assert isinstance(m["lastSeen"], str)
        assert isinstance(m["toolNames"], list)
        assert isinstance(m["stopReason"], str)
        assert isinstance(m["warning"], str)


# ── buildFingerprintReport ───────────────────────────────────────────────


class TestBuildFingerprintReport:
    def test_produces_readable_report(self):
        records = [
            make_record(decision="stop", sessionKey="s1"),
            make_record(decision="stop", sessionKey="s2"),
        ]
        report = build_fingerprint_report(extract_fingerprints(records), 2)
        assert "Risk Fingerprints" in report
        assert "bash, exec" in report
        assert "tool_loop_limit" in report

    def test_empty_state_message(self):
        m = extract_fingerprints([make_record(decision="stop")])
        assert "No recurring risk fingerprints" in build_fingerprint_report(m, 5)

    def test_sorts_by_count_descending(self):
        records = [
            make_record(decision="stop", toolNames=["bash"], stopReason="r1", sessionKey="s1"),
            make_record(decision="stop", toolNames=["bash"], stopReason="r1", sessionKey="s2"),
            make_record(decision="stop", toolNames=["bash"], stopReason="r1", sessionKey="s3"),
            make_record(decision="stop", toolNames=["exec"], stopReason="r2", sessionKey="s1"),
            make_record(decision="stop", toolNames=["exec"], stopReason="r2", sessionKey="s2"),
        ]
        report = build_fingerprint_report(extract_fingerprints(records), 2)
        assert report.index("bash|r1") < report.index("exec|r2")


# ── resolveFingerprint ───────────────────────────────────────────────────


class TestResolveFingerprint:
    @pytest.mark.asyncio
    async def test_none_when_no_config(self):
        result = await resolve_fingerprint(
            body={}, decision={"stopReason": "tool_loop_limit"}, config={},
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_none_when_disabled(self):
        result = await resolve_fingerprint(
            body={}, decision={"stopReason": "tool_loop_limit"},
            config={"fingerprint": {"enabled": False}},
        )
        assert result is None


# ── invalidateFingerprintCache ───────────────────────────────────────────


class TestInvalidateFingerprintCache:
    def setup_method(self):
        invalidate_fingerprint_cache()

    def test_clears_all_entries(self):
        _cache["entries"][7] = {"fingerprintMap": {}, "loadedAt": int(time.time() * 1000)}
        assert len(_cache["entries"]) == 1
        invalidate_fingerprint_cache()
        assert len(_cache["entries"]) == 0
