"""Protocol rejection, Hermes interception, and real process separation."""

# Numeric assertions and fixture-local imports keep scenario setup explicit.
# ruff: noqa: PLR2004, PLC0415

import json
import select
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from clawkeeper_core import learned_rules as rules
from clawkeeper_core.watcher.client import RuleSyncError, WatcherClient
from tests.watcher_process import fake_hermes_modules


def payload():
    return rules.make_snapshot([rules.validate_rule(r"CK_CANARY_\d+", "exec_gate")]).as_dict()


def response(data):
    return httpx.Response(200, json=data, headers={"ETag": f'"{data["version"]}"'})


def test_client_conditional_sync_and_single_authority():
    body = payload()
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return response(body)
        return httpx.Response(
            304,
            headers={"ETag": f'"{body["version"]}"', "X-ClawKeeper-Instance": "restarted-server"},
        )

    with WatcherClient("http://watcher") as client:
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        snapshot = client.sync_rules()
        assert client.sync_rules() is snapshot
        assert requests[1].headers["if-none-match"] == f'"{snapshot.version}"'
        assert client._server_instance == "restarted-server"
    with WatcherClient("http://different-watcher") as client:
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(lambda _: response(body)))
        with pytest.raises(RuleSyncError):
            client.sync_rules()
    assert rules.current_snapshot() is snapshot


@pytest.mark.parametrize(
    "failure",
    ["version", "target", "regex", "broad", "duplicate", "validator", "disconnect", "bad304"],
)
def test_invalid_sync_preserves_previous_snapshot(failure):
    body = payload()
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(body)
        bad = json.loads(json.dumps(body))
        if failure == "disconnect":
            raise httpx.ConnectError("offline", request=request)
        if failure == "bad304":
            return httpx.Response(304, headers={"ETag": '"wrong"'})
        if failure == "version":
            bad["version"] = "wrong"
        elif failure == "target":
            bad["rules"][0]["guard_target"] = "unknown"
        elif failure in {"regex", "broad"}:
            bad["rules"][0]["pattern"] = "[" if failure == "regex" else ".*"
        elif failure == "duplicate":
            bad["rules"].append(bad["rules"][0])
        else:
            bad["validation_version"] = 999
        return response(bad)

    with WatcherClient("http://watcher") as client:
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        previous = client.sync_rules()
        with pytest.raises(RuleSyncError):
            client.sync_rules()
        assert client._rules is previous and rules.current_snapshot() is previous


@pytest.mark.parametrize(
    "target,command",
    [
        ("exec_gate", "echo CK_CANARY_8421"),
        ("path_guard", "cat /tmp/CK_CANARY_8421"),
        ("script_body_scan", "print('CK_CANARY_8421')"),
    ],
)
def test_shared_client_for_both_hermes_interceptors(monkeypatch, target, command):
    from clawkeeper_core.adapters.hermes import install

    terminal, computer, manager = fake_hermes_modules(
        lambda k, v: monkeypatch.setitem(sys.modules, k, v)
    )
    client = Mock()
    snapshot = rules.make_snapshot([rules.validate_rule(r"CK_CANARY_\d+", target)])
    client.sync_rules.return_value = snapshot
    factory = Mock(return_value=client)
    monkeypatch.setattr("clawkeeper_core.watcher.client.WatcherClient", factory)
    agent = SimpleNamespace(
        session_id="s",
        conversation_history=[],
        tool_start_callback=None,
        tool_complete_callback=None,
    )
    install(Mock(), agent, watcher_url="http://watcher")
    hook = manager._hooks["pre_tool_call"][0]
    assert f"learned:{target}" in hook(tool_name="terminal", args={"command": command})["message"]
    assert terminal.callback(command) == "deny"
    assert terminal.callback is computer.callback
    factory.assert_called_once()
    assert client.sync_rules.call_count == 2
    client.sync_rules.side_effect = RuleSyncError("offline")
    assert hook(tool_name="terminal", args={"command": "ls -la"})["action"] == "block"
    assert terminal.callback("ls -la") == "deny"
    assert agent._clawkeeper_decisions[-1]["source"] == "watcher:rule_sync"


def test_rules_endpoint_and_legacy_delete(isolated_learning):
    import hashlib

    from fastapi.testclient import TestClient

    from clawkeeper_core.watcher.daemon import build_app
    from tests.test_learned_rules import candidate

    assert isolated_learning.add(candidate())
    watcher = SimpleNamespace(
        model=SimpleNamespace(model_id="fake"), history=SimpleNamespace(_calls={})
    )
    with TestClient(build_app(watcher=watcher)) as client:
        first = client.get("/watcher/rules")
        data = first.json()
        assert len(data["rules"]) == 1 and "source_command" not in str(data)
        assert (
            client.get(
                "/watcher/rules", headers={"If-None-Match": first.headers["etag"]}
            ).status_code
            == 304
        )
        assert client.get("/watcher/health").json()["version"] == data["version"]
        legacy_hash = hashlib.sha256(candidate().pattern.encode()).hexdigest()
        assert client.delete(f"/watcher/learned/{legacy_hash}").json()["removed"]
        after = client.get("/watcher/rules")
        assert not after.json()["rules"] and after.headers["etag"] != first.headers["etag"]


def start_server(store_path, port=0):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen()
    port = listener.getsockname()[1]
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "tests.watcher_process",
            "server",
            str(store_path),
            str(listener.fileno()),
        ],
        pass_fds=(listener.fileno(),),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    listener.close()
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(proc.stderr.read())
        try:
            if httpx.get(url + "/watcher/health", timeout=0.3).status_code == 200:
                return proc, url, port
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    proc.kill()
    proc.wait(timeout=5)
    raise AssertionError("Watcher did not become ready")


def stop(proc):
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()


def ask_adapter(proc, action, command="echo CK_CANARY_8421"):
    proc.stdin.write(json.dumps({"action": action, "command": command}) + "\n")
    proc.stdin.flush()
    ready, _, _ = select.select([proc.stdout], [], [], 15)
    assert ready, "Adapter did not respond"
    line = proc.stdout.readline()
    assert line, proc.stderr.read()
    return json.loads(line)


def test_separate_process_learning_sync_restart_delete_and_disconnect(tmp_path):
    server = adapter = None
    try:
        server, url, port = start_server(tmp_path / "learned.json")
        adapter = subprocess.Popen(
            [sys.executable, "-m", "tests.watcher_process", "adapter", url],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with httpx.Client(base_url=url, timeout=3) as client:
            assert ask_adapter(adapter, "pre", "ls -la")["result"] is None
            empty_version = client.get("/watcher/rules").json()["version"]
            result = client.post(
                "/watcher/evaluate",
                json={
                    "session_id": "learn",
                    "tool_name": "terminal",
                    "args": {"command": "echo CK_CANARY_8421"},
                },
            )
            assert result.status_code == 200 and result.json()["decision"] == "deny"
            assert result.json()["deterministic_findings"] == []
            snapshot = client.get("/watcher/rules").json()
            assert snapshot["pid"] == server.pid and snapshot["pid"] != adapter.pid
            assert snapshot["version"] != empty_version and len(snapshot["rules"]) == 1
            synced = ask_adapter(adapter, "pre")
            assert "learned:exec_gate" in synced["result"]["message"]
            assert synced["version"] == snapshot["version"]
            assert ask_adapter(adapter, "approval")["result"] == "deny"
            old_instance = snapshot["instance_id"]
        stop(server)
        server, url, _ = start_server(tmp_path / "learned.json", port)
        with httpx.Client(base_url=url, timeout=3) as client:
            restored = client.get("/watcher/rules").json()
            assert restored["version"] == snapshot["version"]
            assert restored["instance_id"] != old_instance
            assert "learned:exec_gate" in ask_adapter(adapter, "pre")["result"]["message"]
            assert client.delete("/watcher/learned/" + snapshot["rules"][0]["id"]).json()["removed"]
            refreshed = ask_adapter(adapter, "pre", "ls -la")
            assert refreshed["version"] == empty_version and refreshed["result"] is None
            assert not ask_adapter(adapter, "inspect")["result"]["block"]
            # Restore a last-known rule, then disconnect. Failed synchronization
            # must retain that rule and stop an otherwise benign tool call.
            client.post(
                "/watcher/evaluate",
                json={
                    "session_id": "learn-again",
                    "tool_name": "terminal",
                    "args": {"command": "echo CK_CANARY_8421"},
                },
            ).raise_for_status()
            assert "learned:exec_gate" in ask_adapter(adapter, "pre")["result"]["message"]
        stop(server)
        server = None
        assert ask_adapter(adapter, "pre", "ls -la")["result"]["action"] == "block"
        assert ask_adapter(adapter, "approval", "ls -la")["result"] == "deny"
        assert ask_adapter(adapter, "inspect")["result"]["block"]
    finally:
        stop(adapter)
        stop(server)
