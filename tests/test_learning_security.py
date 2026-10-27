"""Regression tests for learned-policy failures and source privacy."""

# Scenario-local imports and numeric resource/assertion limits are intentional.
# ruff: noqa: PLR2004

import json
import subprocess
import sys
import time
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from clawkeeper_core import bounded_regex
from clawkeeper_core import learned_rules as rules
from clawkeeper_core.adapters.base import make_event
from clawkeeper_core.adapters.hermes import _with_rule_sync
from clawkeeper_core.guards.exec_gate import guard_execution
from clawkeeper_core.guards.path_guard import guard_before_tool_call
from clawkeeper_core.watcher import agent, daemon, learner, reload
from clawkeeper_core.watcher.client import RuleSyncError, WatcherClient
from tests.test_learned_rules import candidate

pytestmark = pytest.mark.usefixtures("isolated_learning")


def fake_watcher():
    return SimpleNamespace(
        model=SimpleNamespace(model_id="fake"), history=SimpleNamespace(_calls={})
    )


def test_redos_is_bounded_and_child_is_reaped(monkeypatch):
    rule = rules.validate_rule(
        r"CK_REVIEW_(a+)+$",
        "exec_gate",
        source_event={"toolName": "terminal", "params": {"command": "echo CK_REVIEW_aaa"}},
    )
    rules.install_snapshot(rules.make_snapshot([rule]))
    bounded_regex._close_workers()
    children = []
    real_popen = subprocess.Popen

    def track(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", track)
    started = time.monotonic()
    result = guard_execution(
        make_event(tool_name="terminal", command="echo CK_REVIEW_" + "a" * 32 + "!")
    )
    assert time.monotonic() - started < 2
    assert result["block"] and result["outcome"] == "ask" and result["error"]
    assert children and all(child.poll() is not None for child in children)
    # A timed-out call must not permanently disable the rule or leak a slot.
    assert (
        guard_execution(make_event(tool_name="terminal", command="echo CK_REVIEW_aaa"))["matched"]
        == rule.id
    )


@pytest.mark.parametrize(
    "pattern",
    [
        "(" * 700 + "CK_REVIEW" + ")" * 700,
        "CK_REVIEW_a{999999999999999999999}",
        "[",
        "a" * 2049,
    ],
)
def test_regex_compile_failures_are_bounded_validation_errors(pattern):
    with pytest.raises(bounded_regex.RegexValidationError):
        rules.validate_rule(pattern, "exec_gate")


def test_validation_match_itself_has_timeout():
    with pytest.raises(ValueError):
        rules.validate_rule(
            r"CK_REVIEW_(a+)+$",
            "exec_gate",
            source_event={
                "toolName": "terminal",
                "params": {"command": "CK_REVIEW_" + "a" * 32 + "!"},
            },
        )


def test_resource_failure_and_oversized_input_never_allow(monkeypatch):
    rules.install_snapshot(
        rules.make_snapshot([rules.validate_rule(r"CK_CANARY_\d+", "exec_gate")])
    )
    event = make_event(tool_name="terminal", command="x" * (bounded_regex.MAX_TEXT_CHARS + 1))
    assert guard_execution(event)["block"]
    monkeypatch.setattr(bounded_regex, "_execute", Mock(side_effect=OSError("worker unavailable")))
    result = guard_execution(make_event(tool_name="terminal", command="ls -la"))
    assert result["block"] and result["error"]


def test_busy_workers_do_not_spawn_unbounded_processes(monkeypatch):
    busy = Mock()
    busy.acquire.return_value = False
    monkeypatch.setattr(bounded_regex, "_slots", busy)
    spawn = Mock()
    monkeypatch.setattr(subprocess, "Popen", spawn)
    with pytest.raises(ValueError):
        bounded_regex.search_groups(["CK_REVIEW"], [["CK_REVIEW"]])
    spawn.assert_not_called()


@pytest.mark.parametrize("failure", ["busy", "spawn", "timeout", "worker_error"])
def test_transient_reload_failure_keeps_whole_snapshot_and_recovers(
    isolated_learning, monkeypatch, failure
):
    assert isolated_learning.add(candidate())
    with TestClient(daemon.build_app(watcher=fake_watcher())) as client:
        previous = rules.current_snapshot()
        assert isolated_learning.add(candidate(pattern="CK_OTHER", command="echo CK_OTHER"))
        saved = isolated_learning._path.read_bytes()
        real_execute = bounded_regex._execute

        def fail_second(payload, deadline, pattern_count, group_count):
            # Validate the first record successfully, then fail: no partial
            # replacement may escape even after some records have passed.
            if "CK_OTHER" not in payload:
                return real_execute(payload, deadline, pattern_count, group_count)
            if failure == "timeout":
                raise TimeoutError("worker timed out")
            raise bounded_regex.RegexResourceError("matching worker unavailable")

        with monkeypatch.context() as patch:
            if failure == "busy":
                busy = Mock()
                busy.acquire.return_value = False
                patch.setattr(bounded_regex, "_slots", busy)
            elif failure == "spawn":
                bounded_regex._close_workers()
                patch.setattr(subprocess, "Popen", Mock(side_effect=OSError("worker unavailable")))
            else:
                patch.setattr(bounded_regex, "_execute", fail_second)
            assert client.post("/watcher/rules/reload").status_code == 503
            assert rules.current_snapshot() is previous
            assert rules.policy_error() == "learned_validation_unavailable"
            assert client.get("/watcher/health").json()["status"] == "degraded"
            assert client.get(
                "/watcher/rules", headers={"If-None-Match": f'"{previous.version}"'}
            ).status_code == 503
            result = guard_execution(make_event(tool_name="terminal", command="ls -la"))
            assert result["block"] and result["outcome"] == "ask"
            assert isolated_learning._path.read_bytes() == saved
        assert client.post("/watcher/rules/reload").status_code == 200
        assert client.get("/watcher/health").json()["status"] == "ok"
        assert len(rules.current_snapshot().rules) == 2
        for command in ("echo CK_CANARY_8421", "echo CK_OTHER"):
            assert guard_execution(make_event(tool_name="terminal", command=command))["matched"]
        assert not guard_execution(make_event(tool_name="terminal", command="ls -la"))["block"]


def test_malformed_stored_regex_is_rejected_without_degrading_valid_policy(isolated_learning):
    records = [asdict(candidate()), asdict(candidate(pattern="["))]
    isolated_learning._path.write_text(json.dumps(records))
    assert reload.apply_learned_patterns() == 1
    assert rules.policy_error() is None
    assert len(rules.current_snapshot().rules) == 1
    assert len(isolated_learning.all()) == 2
    assert guard_execution(make_event(tool_name="terminal", command="echo CK_CANARY_8421"))["matched"]


def test_windows_one_shot_fallback_still_matches_and_reports_timeout(monkeypatch):
    # Exercise the fallback dispatch on Linux too, without changing sys.platform
    # for subprocess/httpx or the rest of the host.
    monkeypatch.setattr(bounded_regex, "sys", SimpleNamespace(platform="win32", executable=sys.executable))
    assert bounded_regex.search_groups(["CK_WINDOWS"], [["CK_WINDOWS"], ["other"]]) == [0, None]
    assert not bounded_regex._workers
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired("worker", 0.5)))
    with pytest.raises(bounded_regex.RegexResourceError):
        bounded_regex.search_groups(["CK_WINDOWS"], [["CK_WINDOWS"]])


@pytest.mark.parametrize(
    "target,tool,params,guard",
    [
        ("exec_gate", "custom_tool", {"payload": "echo CK_CANARY_8421"}, guard_execution),
        ("exec_gate", "custom_tool", {"request": [{"payload": "echo CK_CANARY_8421"}]}, guard_execution),
        ("path_guard", "read_file", {"location": "/tmp/CK_CANARY_8421"}, guard_before_tool_call),
        ("path_guard", "read_file", {"request": [{"location": "/tmp/CK_CANARY_8421"}]}, guard_before_tool_call),
    ],
)
@pytest.mark.parametrize("legacy", [False, True])
def test_generic_and_nested_samples_survive_learning_and_migration(
    *, isolated_learning, target, tool, params, guard, legacy
):
    params = {**params, "metadata": {"api_key": "FAKE_NESTED_SECRET_7319"},
              "headers": {"Authorization": "FAKE_HEADER_SECRET_4928"}}
    event = {"toolName": tool, "params": params}
    rule = rules.validate_rule(r"CK_CANARY_\d+", target, source_event=event)
    c = candidate(target=target, command="", source_tool_name=tool, source_args=params)
    if legacy:
        isolated_learning._path.write_text(json.dumps([asdict(c)]))
    else:
        assert isolated_learning.add(c)
    assert reload.apply_learned_patterns() == 1
    assert guard(event)["matched"] == rule.id
    record = isolated_learning.all()[0]
    assert record.source_args is None and record.source_command == ""
    assert any("CK_CANARY_8421" in text for text in record.source_texts)
    saved = isolated_learning._path.read_text()
    assert "FAKE_NESTED_SECRET_7319" not in saved and "FAKE_HEADER_SECRET_4928" not in saved
    assert reload.apply_learned_patterns() == 0
    assert guard(event)["matched"] == rule.id


def test_generic_nested_arguments_reach_synthesis_without_credentials(isolated_learning):
    responses = iter([
        {"decision": "deny", "reason": "synthetic", "severity": "high",
         "signals": [], "confidence": 0.99},
        {"pattern": r"CK_CANARY_\d+", "guard_target": "exec_gate", "confidence": 0.99},
    ])
    prompts = []

    def model(messages):
        prompts.append(messages)
        return SimpleNamespace(content=json.dumps(next(responses)))

    params = {"request": [{"payload": "echo CK_CANARY_8421",
                           "password": "FAKE_SYNTHESIS_SECRET_6123",
                           "client_secret": "FAKE_CLIENT_SECRET_3128",
                           "OPENAI_API_KEY": "FAKE_PROVIDER_KEY_7639",
                           "auth_token": "FAKE_AUTH_TOKEN_8914"}]}
    result = agent.Watcher(model=model).evaluate(
        session_id="generic", tool_name="custom_tool", args=params
    )
    assert result.decision == "deny" and len(prompts) == 2
    assert "echo CK_CANARY_8421" in json.dumps(prompts[1])
    for secret in ("FAKE_SYNTHESIS_SECRET_6123", "FAKE_CLIENT_SECRET_3128",
                   "FAKE_PROVIDER_KEY_7639", "FAKE_AUTH_TOKEN_8914"):
        assert secret not in json.dumps(prompts[1])
        assert secret not in isolated_learning._path.read_text()
    assert len(isolated_learning.all()) == 1
    assert guard_execution({"toolName": "custom_tool", "params": params})["matched"]


def test_credentials_not_in_model_synthesis_store_or_list(isolated_learning):
    secrets = ["FAKE_ENV_SECRET_7341", "FAKE_HEADER_SECRET_6391", "FAKE_BODY_SECRET_9241"]
    replies = iter(
        [
            {
                "decision": "deny",
                "reason": "synthetic",
                "severity": "high",
                "signals": [],
                "confidence": 0.99,
            },
            {"pattern": r"CK_CANARY_\d+", "guard_target": "exec_gate", "confidence": 0.99},
        ]
    )
    prompts = []

    def model(messages):
        prompts.append(messages)
        return SimpleNamespace(content=json.dumps(next(replies)))

    watcher = agent.Watcher(model=model)
    watcher.evaluate(
        session_id="privacy",
        tool_name="terminal",
        args={
            "command": "echo CK_CANARY_8421",
            "env": {"API_KEY": secrets[0]},
            "headers": {"Authorization": secrets[1]},
            "body": {"password": secrets[2]},
        },
    )
    assert len(isolated_learning.all()) == 1
    with TestClient(daemon.build_app(watcher=watcher)) as client:
        public = client.get("/watcher/learned").text
        wire = client.get("/watcher/rules").text
    assert all(
        secret not in text
        for secret in secrets
        for text in (isolated_learning._path.read_text(), public, wire, json.dumps(prompts[1]))
    )
    data = json.loads(public)[0]
    assert data["source_args"] is None and data["source_command"] == ""
    assert "source_texts" not in data
    saved = isolated_learning.all()[0]
    assert saved.source_texts == ["echo CK_CANARY_8421"]
    assert not isolated_learning._path.stat().st_mode & 0o077


@pytest.mark.parametrize(
    "source,secret",
    [
        ("echo CK_CANARY_8421; API_KEY='short'", "short"),
        ('echo CK_CANARY_8421; print({"password": "short"})', "short"),
        ("echo CK_CANARY_8421\nAuthorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("echo CK_CANARY_8421 https://user:pass@example.com/", "user:pass"),
    ],
)
def test_inline_and_legacy_credentials_are_scrubbed(isolated_learning, source, secret):
    record = asdict(
        candidate(
            command=source,
            source_args={"command": source, "env": {"API_KEY": "FAKE_LEGACY_SECRET"}},
        )
    )
    isolated_learning._path.write_text(json.dumps([record]))
    assert reload.apply_learned_patterns() == 1
    saved = isolated_learning._path.read_text()
    assert secret not in saved and "FAKE_LEGACY_SECRET" not in saved
    assert reload.apply_learned_patterns() == 0
    assert guard_execution(make_event(tool_name="terminal", command="echo CK_CANARY_8421"))["block"]


def test_rule_cannot_depend_on_redacted_secret(isolated_learning):
    c = candidate(
        pattern="FAKE_PRIVATE_SECRET",
        command="echo CK_CANARY_8421",
        source_args={"command": "echo CK_CANARY_8421", "env": {"API_KEY": "FAKE_PRIVATE_SECRET"}},
    )
    assert not isolated_learning.add(c)
    assert not isolated_learning._path.exists()


@pytest.mark.parametrize("raw", [b'[{"pattern":', b"{}", b"\xff", b"[" * 2000])
def test_corrupt_store_boots_degraded_retains_policy_and_recovers(isolated_learning, raw):
    assert isolated_learning.add(candidate())
    reload.apply_learned_patterns()
    previous = rules.current_snapshot()
    isolated_learning._path.write_bytes(raw)
    with TestClient(daemon.build_app(watcher=fake_watcher())) as client:
        assert rules.current_snapshot() is previous
        assert isolated_learning._path.read_bytes() == raw
        assert client.get("/watcher/health").json()["status"] == "degraded"
        assert (
            client.get(
                "/watcher/rules", headers={"If-None-Match": f'"{previous.version}"'}
            ).status_code
            == 503
        )
        assert client.get("/watcher/learned").status_code == 503
        assert client.post("/watcher/rules/reload").status_code == 503
        assert guard_execution(make_event(tool_name="terminal", command="ls -la"))["block"]
        # Failed writes/deletes must not overwrite the damaged evidence.
        with pytest.raises(learner.StoreUnavailableError):
            isolated_learning.add(candidate(pattern="CK_OTHER", command="echo CK_OTHER"))
        assert isolated_learning._path.read_bytes() == raw
        isolated_learning._path.write_text("[]")
        assert client.post("/watcher/rules/reload").status_code == 200
        assert client.get("/watcher/health").json()["status"] == "ok"
        assert not rules.current_snapshot().rules
        assert not guard_execution(make_event(tool_name="terminal", command="ls -la"))["block"]


def test_oversized_store_is_not_read_as_clean(isolated_learning, monkeypatch):
    monkeypatch.setattr(learner, "_MAX_STORE_BYTES", 32)
    isolated_learning._path.write_text(" " * 33)
    reload.apply_learned_patterns()
    assert rules.policy_error()
    assert isolated_learning._path.stat().st_size == 33


@pytest.mark.parametrize(
    "bad",
    [
        "(" * 700 + "CK_REVIEW" + ")" * 700,
        "CK_REVIEW_a{999999999999999999999}",
    ],
)
def test_malformed_snapshot_returns_block_and_keeps_last_policy(bad):
    good = rules.make_snapshot([rules.validate_rule(r"CK_CANARY_\d+", "exec_gate")]).as_dict()
    failed = {**good, "rules": [{"id": "invalid", "guard_target": "exec_gate", "pattern": bad}]}
    bodies = iter([good, failed, failed])
    with WatcherClient("http://review-watcher") as client:
        client._client.close()
        client._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200, json=(body := next(bodies)), headers={"ETag": f'"{body["version"]}"'}
                )
            )
        )
        previous = client.sync_rules()
        with pytest.raises(RuleSyncError):
            client.sync_rules()
        callback = Mock(return_value=None)
        wrapped = _with_rule_sync(callback, client, SimpleNamespace(), {"action": "block"})
        assert wrapped() == {"action": "block"}
        callback.assert_not_called()
        assert rules.current_snapshot() is previous and client._rules is previous


def test_unexpected_sync_exception_and_mutated_block_result_are_safe():
    client = Mock()
    client.sync_rules.side_effect = RuntimeError("sensitive diagnostic")
    callback = Mock()
    wrapped = _with_rule_sync(callback, client, SimpleNamespace(), {"action": "block"})
    first = wrapped()
    first["action"] = "allow"
    assert wrapped() == {"action": "block"}
    callback.assert_not_called()


def test_oversized_snapshot_stream_is_closed_without_installing():
    class Stream(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b"x" * (1024 * 1024 + 1)
            raise AssertionError("should stop consuming the oversized response")

        def close(self):
            self.closed = True

    stream = Stream()
    previous = rules.current_snapshot()
    with WatcherClient("http://review-watcher") as client:
        client._client.close()
        client._client = httpx.Client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, stream=stream))
        )
        with pytest.raises(RuleSyncError):
            client.sync_rules()
    assert stream.closed and rules.current_snapshot() is previous


def test_sync_logs_never_expose_url_credentials(caplog):
    caplog.set_level("INFO")
    rules.audit(
        "sync_failed", authority="https://user:FAKE_URL_PASSWORD@example.com/?token=FAKE_URL_TOKEN"
    )
    assert "FAKE_URL_PASSWORD" not in caplog.text and "FAKE_URL_TOKEN" not in caplog.text


def test_store_capacity_rejection_retains_readable_previous_policy(isolated_learning, monkeypatch):
    assert isolated_learning.add(candidate())
    reload.apply_learned_patterns()
    previous = rules.current_snapshot()
    saved = isolated_learning._path.read_bytes()
    monkeypatch.setattr(learner, "_MAX_STORE_BYTES", len(saved) + 10)
    assert not isolated_learning.add(candidate(pattern="CK_OTHER", command="echo CK_OTHER"))
    assert isolated_learning._path.read_bytes() == saved
    assert reload.apply_learned_patterns() == 0
    assert rules.current_snapshot().version == previous.version and rules.policy_error() is None


def test_aggregate_pattern_limit_checked_before_activation():
    # Individual regex lengths may be valid while the whole set exceeds the
    # runtime worker's input budget. Such sets must never become active.
    patterns = [rules.LearnedRule(str(i), "exec_gate", "x" * 2048) for i in range(17)]
    with pytest.raises(ValueError):
        rules.make_snapshot(patterns)


def test_invalid_legacy_record_does_not_retain_raw_arguments(isolated_learning):
    record = {
        **asdict(candidate()),
        "unknown_field": True,
        "source_args": {"env": {"API_KEY": "FAKE_MALFORMED_RECORD_SECRET"}},
    }
    isolated_learning._path.write_text(json.dumps([record]))
    assert isolated_learning.all() == []
    assert "FAKE_MALFORMED_RECORD_SECRET" not in isolated_learning._path.read_text()


def test_compressed_snapshot_is_rejected_before_decompression():
    class CompressedStream(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("must not consume or inflate compressed policy")
            yield b""  # pragma: no cover -- make this a generator

    with WatcherClient("http://review-watcher") as client:
        client._client.close()
        client._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200, headers={"Content-Encoding": "gzip"}, stream=CompressedStream()
                )
            )
        )
        with pytest.raises(RuleSyncError):
            client.sync_rules()


def test_sanitized_source_migration_is_idempotent(isolated_learning, monkeypatch):
    isolated_learning._path.write_text(json.dumps([asdict(candidate())]))
    first = isolated_learning.all()
    save = Mock(side_effect=AssertionError("second read must not rewrite unchanged policy"))
    monkeypatch.setattr(isolated_learning, "_save", save)
    assert isolated_learning.all() == first
    save.assert_not_called()
