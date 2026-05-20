"""Unit tests for clawkeeper_core.watcher.policy — the deterministic post-filter.

The Watcher's LLM is advisory. These tests verify that the post-filter
correctly overrides the LLM's proposal when a deterministic guard says
otherwise.
"""

from __future__ import annotations

from clawkeeper_core.watcher.policy import apply_post_filter


def _watcher_says(decision: str, severity: str = "low", confidence: float = 0.9) -> dict:
    return {
        "decision": decision,
        "reason": f"watcher: {decision}",
        "severity": severity,
        "signals": ["watcher_signal"],
        "confidence": confidence,
    }


def _det_block(severity: str, source: str = "path_guard", reason: str = "blocked path") -> dict:
    return {
        "block": True,
        "outcome": "deny",
        "source": source,
        "severity": severity,
        "reason": reason,
    }


def _det_allow(source: str = "exec_gate") -> dict:
    return {
        "block": False,
        "outcome": "allow",
        "source": source,
        "severity": "low",
        "reason": "ok",
    }


# ── Rule 1: hardline / critical blocks override any watcher decision ───────


def test_critical_block_overrides_watcher_allow():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("allow"),
        deterministic_findings=[_det_block("critical")],
    )
    assert final["decision"] == "deny"
    assert final["post_filter_overrode"] is True
    assert "path_guard" in final["post_filter_reason"]


def test_hardline_block_overrides_watcher_allow():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("allow"),
        deterministic_findings=[_det_block("hardline", source="exec_gate")],
    )
    assert final["decision"] == "deny"
    assert final["post_filter_overrode"]


def test_critical_block_overrides_watcher_ask():
    # Even if Watcher said "ask", a hardline still forces deny.
    final = apply_post_filter(
        watcher_proposal=_watcher_says("ask"),
        deterministic_findings=[_det_block("critical")],
    )
    assert final["decision"] == "deny"


def test_critical_block_passes_through_watcher_deny():
    # Watcher said deny; det also blocks critical — still deny, override flag set
    final = apply_post_filter(
        watcher_proposal=_watcher_says("deny"),
        deterministic_findings=[_det_block("critical")],
    )
    assert final["decision"] == "deny"
    # Override is True because we replaced the Watcher's reason w/ the det reason.
    assert final["post_filter_overrode"]


# ── Rule 2: non-hardline block + watcher allow → ask (escalate to operator) ──


def test_high_block_plus_watcher_allow_escalates_to_ask():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("allow", confidence=0.95),
        deterministic_findings=[_det_block("high", source="script_body_scan")],
    )
    assert final["decision"] == "ask"
    assert final["post_filter_overrode"]
    assert "script_body_scan" in final["post_filter_reason"]


def test_medium_block_plus_watcher_allow_escalates_to_ask():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("allow"),
        deterministic_findings=[_det_block("medium", source="url_safety")],
    )
    assert final["decision"] == "ask"


# ── Rule 3: pass-through when no deterministic block ───────────────────────


def test_clean_passes_through_watcher_allow():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("allow"),
        deterministic_findings=[_det_allow()],
    )
    assert final["decision"] == "allow"
    assert final["post_filter_overrode"] is False


def test_clean_passes_through_watcher_deny():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("deny", severity="high"),
        deterministic_findings=[_det_allow()],
    )
    assert final["decision"] == "deny"
    assert final["post_filter_overrode"] is False


def test_clean_passes_through_watcher_ask():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("ask"),
        deterministic_findings=[],
    )
    assert final["decision"] == "ask"
    assert final["post_filter_overrode"] is False


# ── Watcher proposes deny on its own (no det block) — still respected ──────


def test_watcher_can_deny_alone():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("deny", severity="critical"),
        deterministic_findings=[],
    )
    assert final["decision"] == "deny"
    assert final["post_filter_overrode"] is False
    assert "watcher:" in final["reason"]


# ── Multiple deterministic findings: highest severity wins ─────────────────


def test_multiple_findings_highest_severity_wins():
    final = apply_post_filter(
        watcher_proposal=_watcher_says("allow"),
        deterministic_findings=[
            _det_block("low",     source="g1"),
            _det_block("critical", source="g2"),
            _det_block("medium",   source="g3"),
        ],
    )
    assert final["decision"] == "deny"
    assert "g2" in final["post_filter_reason"]
