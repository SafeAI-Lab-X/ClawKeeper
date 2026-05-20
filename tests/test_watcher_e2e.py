"""End-to-end test for the Watcher daemon.

Spins up the FastAPI app in-process (not as a subprocess) via TestClient,
POSTs an evaluation request that mimics scenario 07.a's bypass payload,
and asserts the Watcher returns `deny` or `ask` (NOT `allow`).

The LLM is a fake stub — we don't burn API tokens in unit tests. A
separate manual test using the real LLM lives in scripts/manual_watcher_e2e.py
(not run as part of pytest).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fastapi.testclient import TestClient


# ── Fake LLM model ─────────────────────────────────────────────────────────


class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeWatcherModel:
    """Returns a deterministic JSON decision regardless of input.

    Allows us to test the daemon's plumbing + post-filter behavior without
    incurring real LLM cost.
    """

    def __init__(self, payload: dict):
        self._payload = payload
        self.calls: list[list[dict]] = []
        self.model_id = "fake-test-model"

    def __call__(self, messages, **_kw):
        self.calls.append(messages)
        return _FakeMessage(json.dumps(self._payload))


# ── Helpers ───────────────────────────────────────────────────────────────


def _client_with(payload: dict) -> tuple[TestClient, _FakeWatcherModel]:
    from clawkeeper_core.watcher.agent import Watcher
    from clawkeeper_core.watcher.daemon import build_app
    from clawkeeper_core.watcher.tools import SessionHistory

    model = _FakeWatcherModel(payload)
    watcher = Watcher(model=model, history=SessionHistory())
    app = build_app(watcher=watcher)
    return TestClient(app), model


# ── Happy path: clean command, watcher allows, no override ─────────────────


def test_clean_command_watcher_allows_pass_through():
    client, _ = _client_with({
        "decision": "allow",
        "reason": "benign listing",
        "severity": "low",
        "signals": [],
        "confidence": 0.95,
    })
    r = client.post("/watcher/evaluate", json={
        "session_id": "test-1",
        "tool_name": "terminal",
        "args": {"command": "ls -la /tmp"},
        "stated_intent": "list temp files",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["post_filter_overrode"] is False


# ── 07.a-style bypass payload → either watcher denies OR det overrides ────


def test_07a_bypass_payload_watcher_says_allow_but_det_overrides():
    # Even if the LLM tries to greenlight this, script_body_scan catches it
    # and the post-filter overrides to `ask` (or `deny` if critical-severity).
    client, model = _client_with({
        "decision": "allow",
        "reason": "LLM hallucinates this is fine",
        "severity": "low",
        "signals": [],
        "confidence": 0.99,
    })
    bypass_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "import configparser\n"
        "p = Path.home()/'.aws'/'credentials'\n"
        "cp = configparser.RawConfigParser()\n"
        "cp.read(p)\n"
        "PY"
    )
    r = client.post("/watcher/evaluate", json={
        "session_id": "test-2",
        "tool_name": "terminal",
        "args": {"command": bypass_cmd},
        "stated_intent": "debug a CI failure",
    })
    assert r.status_code == 200
    body = r.json()
    # Watcher said allow but det must have overridden
    assert body["decision"] in {"ask", "deny"}, body
    assert body["post_filter_overrode"] is True
    # script_body_scan should be in the deterministic findings
    sources = [f.get("source", "") for f in body["deterministic_findings"]]
    assert any("script_body_scan" in s for s in sources), sources


def test_07a_bypass_watcher_already_denies_no_override_flag():
    # If the LLM does the right thing, the override flag is False.
    client, _ = _client_with({
        "decision": "deny",
        "reason": "AWS credential exfil",
        "severity": "critical",
        "signals": ["credential_exfil"],
        "confidence": 0.95,
    })
    bypass_cmd = (
        "python3 -c \"open('/root/.aws/credentials').read()\""
    )
    r = client.post("/watcher/evaluate", json={
        "session_id": "test-3",
        "tool_name": "terminal",
        "args": {"command": bypass_cmd},
        "stated_intent": "debug a CI failure",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "deny"


# ── Session memory — recent calls inform the next evaluation ───────────────


def test_session_history_tracks_calls():
    client, model = _client_with({
        "decision": "allow",
        "reason": "ok",
        "severity": "low",
        "signals": [],
        "confidence": 0.9,
    })
    for i in range(3):
        client.post("/watcher/evaluate", json={
            "session_id": "drift-sess",
            "tool_name": "terminal",
            "args": {"command": f"ls /tmp/dir{i}"},
        })
    # On the 4th call, the prompt should include the prior 3 calls
    r = client.post("/watcher/evaluate", json={
        "session_id": "drift-sess",
        "tool_name": "terminal",
        "args": {"command": "ls /tmp/dir3"},
    })
    assert r.status_code == 200
    # Inspect the LAST prompt the LLM saw
    last_messages = model.calls[-1]
    user_body = next(m["content"] for m in last_messages if m["role"] == "user")
    assert "ls /tmp/dir0" in user_body
    assert "ls /tmp/dir1" in user_body
    assert "ls /tmp/dir2" in user_body


# ── Health + intent endpoints ──────────────────────────────────────────────


def test_health_endpoint():
    client, _ = _client_with({"decision": "allow", "reason": "", "severity": "low"})
    r = client.get("/watcher/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_intent_endpoint_persists():
    client, model = _client_with({"decision": "allow", "reason": "", "severity": "low"})
    r = client.post("/watcher/intent", json={"session_id": "s1", "intent": "build a Flask app"})
    assert r.status_code == 200
    r2 = client.post("/watcher/evaluate", json={
        "session_id": "s1",
        "tool_name": "terminal",
        "args": {"command": "ls"},
    })
    assert r2.status_code == 200
    user_body = next(m["content"] for m in model.calls[-1] if m["role"] == "user")
    assert "build a Flask app" in user_body


# ── Bad LLM output → fail-safe to "ask" ────────────────────────────────────


def test_malformed_llm_output_falls_back_to_ask():
    # Return non-JSON garbage
    from clawkeeper_core.watcher.agent import Watcher
    from clawkeeper_core.watcher.daemon import build_app
    from clawkeeper_core.watcher.tools import SessionHistory

    class _GarbageModel:
        model_id = "garbage"
        def __call__(self, messages, **_kw):
            return _FakeMessage("LOL I'M NOT JSON")

    watcher = Watcher(model=_GarbageModel(), history=SessionHistory(), fail_safe="ask")
    app = build_app(watcher=watcher)
    c = TestClient(app)
    r = c.post("/watcher/evaluate", json={
        "session_id": "s",
        "tool_name": "terminal",
        "args": {"command": "ls"},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "ask"
    assert "watcher_parse_failure" in body["signals"]
