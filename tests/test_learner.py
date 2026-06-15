"""Tests for the self-improvement loop (learner + reload)."""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from clawkeeper_core.watcher.learner import (
    LearnedPatternStore,
    PatternCandidate,
    synthesize_pattern,
)


def _make_store(tmp_path: Path) -> LearnedPatternStore:
    return LearnedPatternStore(tmp_path / "learned.json")


def _candidate(**kw) -> PatternCandidate:
    defaults = dict(
        pattern=r"Path\.home\(\).*\.aws",
        source_command="Path.home()/'.aws'/'credentials'",
        guard_target="script_body_scan",
        confidence=0.91,
        created_at="2026-05-21T00:00:00+00:00",
    )
    defaults.update(kw)
    return PatternCandidate(**defaults)


# ── Store ──────────────────────────────────────────────────────────────────


def test_store_add_and_retrieve(tmp_path):
    store = _make_store(tmp_path)
    c = _candidate()
    assert store.add(c) is True
    loaded = store.all()
    assert len(loaded) == 1
    assert loaded[0].pattern == c.pattern


def test_store_rejects_duplicate(tmp_path):
    store = _make_store(tmp_path)
    c = _candidate()
    store.add(c)
    assert store.add(c) is False  # same pattern → duplicate


def test_store_rejects_overbroad_pattern(tmp_path):
    store = _make_store(tmp_path)
    # ".*" matches every benign command
    c = _candidate(pattern=".*")
    assert store.add(c) is False


def test_store_rejects_invalid_regex(tmp_path):
    store = _make_store(tmp_path)
    c = _candidate(pattern="[invalid(")
    assert store.add(c) is False


def test_store_remove(tmp_path):
    import hashlib
    store = _make_store(tmp_path)
    c = _candidate()
    store.add(c)
    h = hashlib.sha256(c.pattern.encode()).hexdigest()
    assert store.remove(h) is True
    assert store.all() == []


# ── synthesize_pattern ─────────────────────────────────────────────────────


def test_synthesize_pattern_returns_candidate():
    mock_model = MagicMock()
    mock_model.return_value = MagicMock(
        content=json.dumps({
            "pattern": r"Path\.home\(\).*credentials",
            "guard_target": "script_body_scan",
            "confidence": 0.88,
        })
    )
    result = synthesize_pattern(
        "Path.home()/'.aws'/'credentials'",
        "credential access via dynamic path",
        mock_model,
    )
    assert result is not None
    assert result.guard_target == "script_body_scan"
    assert result.confidence == pytest.approx(0.88)


def test_synthesize_pattern_returns_none_on_null():
    mock_model = MagicMock()
    mock_model.return_value = MagicMock(content="null")
    result = synthesize_pattern("ls -la", "benign", mock_model)
    assert result is None


def test_synthesize_pattern_returns_none_on_low_confidence():
    mock_model = MagicMock()
    mock_model.return_value = MagicMock(
        content=json.dumps({"pattern": r"ls", "guard_target": "exec_gate", "confidence": 0.3})
    )
    result = synthesize_pattern("ls -la", "low conf", mock_model)
    assert result is None


def test_synthesize_pattern_returns_none_on_llm_error():
    mock_model = MagicMock(side_effect=RuntimeError("network error"))
    result = synthesize_pattern("some command", "reason", mock_model)
    assert result is None


# ── reload ─────────────────────────────────────────────────────────────────


def test_apply_learned_patterns_adds_to_exec_gate(tmp_path):
    import clawkeeper_core.security_rules as rules
    from clawkeeper_core.watcher import reload as rl

    store = _make_store(tmp_path)
    c = _candidate(pattern=r"__ck_test_unique_xyz__", guard_target="exec_gate")
    store.add(c)

    before = len(rules.DANGEROUS_COMMAND_PATTERNS)
    with patch("clawkeeper_core.watcher.reload.STORE", store):
        rl._loaded_hashes.clear()
        added = rl.apply_learned_patterns()

    assert added == 1
    assert len(rules.DANGEROUS_COMMAND_PATTERNS) == before + 1
    # Idempotent second call
    with patch("clawkeeper_core.watcher.reload.STORE", store):
        added2 = rl.apply_learned_patterns()
    assert added2 == 0


# ── daemon endpoints ───────────────────────────────────────────────────────


def test_daemon_learned_endpoint(tmp_path):
    from fastapi.testclient import TestClient
    from clawkeeper_core.watcher.daemon import build_app
    from clawkeeper_core.watcher import learner as lm

    store = _make_store(tmp_path)
    c = _candidate()
    store.add(c)

    mock_watcher = MagicMock()
    with patch.object(lm, "STORE", store), \
         patch("clawkeeper_core.watcher.daemon.STORE", store), \
         patch("clawkeeper_core.watcher.daemon.apply_learned_patterns"):
        app = build_app(watcher=mock_watcher)
        client = TestClient(app)
        resp = client.get("/watcher/learned")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["pattern"] == c.pattern


# ── integration: no learn when det guard fired ─────────────────────────────


def test_no_learn_when_det_guard_fired():
    """_maybe_learn must not be called when deterministic guards already fired."""
    from clawkeeper_core.watcher import agent as ag

    called = []

    def fake_learn(*a, **kw):
        called.append(1)

    with patch.object(ag, "_maybe_learn", fake_learn):
        watcher = ag.Watcher(model=MagicMock(), fail_safe="ask")
        # Patch gather_deterministic_findings to return a blocking finding
        with patch("clawkeeper_core.watcher.agent.gather_deterministic_findings") as mock_det, \
             patch("clawkeeper_core.watcher.agent.apply_post_filter") as mock_pf:
            mock_det.return_value = [{"block": True, "severity": "high", "reason": "test", "source": "test"}]
            mock_pf.return_value = {"decision": "deny", "reason": "blocked", "severity": "high",
                                    "signals": [], "confidence": 0.99, "post_filter_overrode": False}
            watcher.evaluate(session_id="s1", tool_name="bash", args={"command": "rm -rf /"})

    assert called == [], "_maybe_learn should not fire when det guard already blocked"
