"""Learning eligibility, target semantics, persistence and snapshot integrity."""

# Numeric assertions and fixture-local imports keep scenario setup explicit.
# ruff: noqa: PLR2004, PLC0415

import json
import logging
from dataclasses import asdict, replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from clawkeeper_core import learned_rules as rules
from clawkeeper_core.adapters.base import make_event, run_guard_chain
from clawkeeper_core.guards.exec_gate import guard_execution
from clawkeeper_core.guards.path_guard import guard_before_tool_call
from clawkeeper_core.guards.script_body_scan import script_body_scan_guard
from clawkeeper_core.watcher import agent, reload, tools
from clawkeeper_core.watcher.learner import PatternCandidate, synthesize_pattern

pytestmark = pytest.mark.usefixtures("isolated_learning")


def candidate(target="exec_gate", pattern=r"CK_CANARY_\d+", command="CK_CANARY_8421", **kw):
    return PatternCandidate(pattern, command, target, 0.99, "2026-10-27T00:00:00Z", **kw)


def model_with(decision="deny", confidence=0.99):
    return Mock(
        return_value=SimpleNamespace(
            content=json.dumps(
                {
                    "decision": decision,
                    "confidence": confidence,
                    "reason": "synthetic",
                    "severity": "high",
                    "signals": [],
                }
            )
        )
    )


@pytest.mark.parametrize(
    "decision,confidence,expected",
    [
        ("deny", 0.99, True),
        ("ask", 0.99, True),
        ("deny", 0.75, True),
        ("ask", 0.7499, False),
        ("allow", 0.99, False),
        ("deny", 0, False),
        ("deny", float("nan"), False),
        ("deny", 2, False),
    ],
)
def test_real_collector_learning_threshold(monkeypatch, caplog, decision, confidence, expected):
    caplog.set_level(logging.INFO)
    learn = Mock()
    monkeypatch.setattr(agent, "_maybe_learn", learn)
    assert (
        tools.gather_deterministic_findings(tool_name="terminal", args={"command": "ls -la"}) == []
    )
    watcher = agent.Watcher(model=model_with(decision, confidence), history=tools.SessionHistory())
    watcher.evaluate(session_id="threshold", tool_name="terminal", args={"command": "ls -la"})
    assert learn.called is expected
    record = next(r for r in caplog.records if getattr(r, "stage", "") in {"attempted", "skipped"})
    assert record.session_id == "threshold"
    assert record.pid > 0 and record.instance_id and record.rules_version


@pytest.mark.parametrize(
    "guard_result,kind",
    [
        ({"block": False, "reason": "risk hint"}, "finding"),
        ({"block": False, "outcome": "ask"}, "finding"),
        ({"block": True, "severity": "critical"}, "block"),
        ({"block": False, "error": "failed"}, "error"),
        ([], "error"),
        ({}, "error"),
        ({"block": False, "reason": []}, "error"),
    ],
)
def test_guard_findings_suppress_learning(monkeypatch, guard_result, kind, caplog):
    caplog.set_level(logging.INFO)
    guard = Mock(return_value=guard_result, __name__="test_guard")
    monkeypatch.setattr(tools, "_PRE_TOOL_GUARDS", (guard,))
    learn = Mock()
    monkeypatch.setattr(agent, "_maybe_learn", learn)
    result = agent.Watcher(model=model_with()).evaluate(
        session_id="guard", tool_name="terminal", args={"command": "ls -la"}
    )
    assert result.deterministic_findings[0]["finding_kind"] == kind
    learn.assert_not_called()
    assert any(
        getattr(r, "skip_reason", "")
        == ("guard_error" if kind == "error" else "deterministic_finding")
        for r in caplog.records
    )


def test_guard_exception_and_parse_failure_do_not_learn(monkeypatch):
    learn = Mock()
    monkeypatch.setattr(agent, "_maybe_learn", learn)
    monkeypatch.setattr(tools, "_PRE_TOOL_GUARDS", (Mock(side_effect=RuntimeError("test")),))
    watcher = agent.Watcher(model=model_with())
    result = watcher.evaluate(session_id="s", tool_name="terminal", args={"command": "ls"})
    assert "error" in result.deterministic_findings[0]
    monkeypatch.setattr(tools, "_PRE_TOOL_GUARDS", ())
    watcher.model = Mock(return_value=SimpleNamespace(content="garbage"))
    assert (
        watcher.evaluate(session_id="s", tool_name="terminal", args={"command": "ls"}).decision
        == "ask"
    )
    learn.assert_not_called()


def test_learning_exception_preserves_verdict(monkeypatch, caplog):
    monkeypatch.setattr(agent, "_maybe_learn", Mock(side_effect=OSError("store failure")))
    result = agent.Watcher(model=model_with()).evaluate(
        session_id="s", tool_name="terminal", args={"command": "ls -la"}
    )
    assert result.decision == "deny" and result.confidence == 0.99
    assert any(getattr(r, "stage", "") == "failed" for r in caplog.records)


@pytest.mark.parametrize(
    "target,guard,event",
    [
        (
            "exec_gate",
            guard_execution,
            make_event(tool_name="terminal", command="CK_CANARY_8421"),
        ),
        (
            "path_guard",
            guard_before_tool_call,
            make_event(tool_name="read_file", params={"path": "/tmp/CK_CANARY_8421"}),
        ),
        (
            "script_body_scan",
            script_body_scan_guard,
            make_event(tool_name="terminal", command="CK_CANARY_8421"),
        ),
    ],
)
def test_targets_match_and_revoke(isolated_learning, target, guard, event):
    c = candidate(
        target,
        command=str(event["params"]),
        source_tool_name=event["toolName"],
        source_args=event["params"],
    )
    assert not (guard(event) or {}).get("block")
    assert isolated_learning.add(c)
    assert reload.apply_learned_patterns() == 1
    result = guard(event)
    assert result["source"] == f"learned:{target}" and result["block"]
    assert reload.apply_learned_patterns() == 0
    snapshot = rules.current_snapshot()
    rules.install_snapshot(rules.make_snapshot([]))  # simulate fresh process runtime
    assert reload.apply_learned_patterns() == 1
    assert rules.current_snapshot().version == snapshot.version
    assert isolated_learning.remove(rules.rule_id(target, c.pattern))
    reload.apply_learned_patterns()
    assert not (guard(event) or {}).get("block")


def test_target_routes_do_not_leak():
    rule = rules.validate_rule(r"CK_CANARY_\d+", "path_guard")
    rules.install_snapshot(rules.make_snapshot([rule]))
    assert not guard_execution(make_event(tool_name="terminal", command="CK_CANARY_8421"))[
        "block"
    ]
    assert (
        script_body_scan_guard(make_event(tool_name="terminal", command="CK_CANARY_8421"))
        is None
    )
    assert guard_before_tool_call(
        make_event(tool_name="read_file", params={"path": "/tmp/CK_CANARY_8421"})
    )["block"]


def test_path_matches_normalized_path_not_shell_text(isolated_learning):
    event = make_event(tool_name="read_file", params={"path": "/tmp/project/../CK_CANARY_8421"})
    c = candidate(
        "path_guard",
        r"^/tmp/CK_CANARY_\d+$",
        command="/tmp/project/../CK_CANARY_8421",
        source_tool_name="read_file",
        source_args=event["params"],
    )
    assert isolated_learning.add(c)
    reload.apply_learned_patterns()
    assert guard_before_tool_call(event)["block"]
    assert not isolated_learning.add(replace(c, pattern=r"read_file"))


def test_snapshot_pinned_across_guard_chain():
    snapshot = rules.make_snapshot([rules.validate_rule(r"CK_CANARY_\d+", "exec_gate")])
    rules.install_snapshot(snapshot)

    def reload_between_guards(event):
        rules.install_snapshot(rules.make_snapshot([]))

    blocked, _ = run_guard_chain(
        [reload_between_guards, guard_execution],
        make_event(tool_name="terminal", command="CK_CANARY_8421"),
    )
    assert blocked["evidence"]["rules_version"] == snapshot.version
    assert not rules.current_snapshot().rules


@pytest.mark.parametrize(
    "pattern,target",
    [
        (r"git", "exec_gate"),
        (r"print", "script_body_scan"),
        (r"README", "path_guard"),
        (r"\.env\.example", "path_guard"),
        (r"\.aws", "script_body_scan"),
        (r"pip.*install", "exec_gate"),
        (r"CK_CANARY", "unknown"),
        ("[", "exec_gate"),
    ],
)
def test_rejects_invalid_or_benign_matching_rules(pattern, target):
    with pytest.raises(ValueError):
        if target == "script_body_scan":
            rules.validate_rule(pattern, target, source_event=make_event(
                tool_name="terminal", command="python -c 'print(\".aws\")'"))
        else:
            rules.validate_rule(pattern, target)


def test_candidate_must_match_source_and_dedup_includes_target(isolated_learning):
    assert not isolated_learning.add(candidate(pattern="UNRELATED"))
    assert isolated_learning.add(candidate())
    assert isolated_learning.add(candidate("script_body_scan"))
    assert not isolated_learning.add(candidate())
    assert len(isolated_learning.all()) == 2


def test_invalid_history_preserved_but_not_active(isolated_learning, caplog):
    record = asdict(candidate())
    record.pop("source_args")
    record.pop("source_tool_name")  # legacy format
    records = [record, {**record, "pattern": ".*"}, {**record, "guard_target": "unknown"}, {}]
    isolated_learning._path.write_text(json.dumps(records))
    assert reload.apply_learned_patterns() == 1
    migrated = json.loads(isolated_learning._path.read_text())
    assert len(migrated) == len(records) and migrated[-1] == {}
    assert [r["pattern"] for r in migrated[:-1]] == [r["pattern"] for r in records[:-1]]
    assert all(r["source_args"] is None and not r["source_command"] for r in migrated[:-1])
    assert any(getattr(r, "stage", "") == "rejected" for r in caplog.records)


def test_wire_version_validated_and_private_sample_excluded():
    rule = rules.validate_rule(r"CK_CANARY_\d+", "exec_gate")
    payload = rules.make_snapshot([rule]).as_dict()
    assert rules.snapshot_from_wire(payload).rules == (rule,)
    assert set(payload["rules"][0]) == {"id", "guard_target", "pattern", "subject", "subject_version"}
    payload["rules"][0]["pattern"] = "different"
    with pytest.raises(ValueError):
        rules.snapshot_from_wire(payload)


def test_synthesis_unknown_target_rejected():
    model = Mock(
        return_value=SimpleNamespace(
            content=json.dumps(
                {"pattern": "CK_CANARY", "guard_target": "unknown", "confidence": 0.99}
            )
        )
    )
    assert synthesize_pattern("CK_CANARY", "test", model) is None


@pytest.mark.parametrize("command,variant,pattern", [
    ("CK_CANARY_8421", "CK_CANARY_9988", r"CK_CANARY_\d+"),
    ("python -m CK_CANARY_8421", "python -m CK_CANARY_9988", r"python\s+-m\s+CK_CANARY_\d+"),
    ("node /tmp/CK_CANARY_8421.js", "node /tmp/CK_CANARY_9988.js", r"node\s+/tmp/CK_CANARY_\d+\.js"),
])
def test_full_learning_loop(isolated_learning, caplog, command, variant, pattern):
    caplog.set_level(logging.INFO)
    model = model_with()
    model.side_effect = [
        model.return_value,
        SimpleNamespace(
            content=json.dumps(
                {"pattern": pattern, "guard_target": "exec_gate", "confidence": 0.99}
            )
        ),
    ]
    result = agent.Watcher(model=model).evaluate(
        session_id="loop", tool_name="terminal", args={"command": command}
    )
    assert result.decision == "deny" and not result.deterministic_findings
    assert len(isolated_learning.all()) == 1 and model.call_count == 2
    assert guard_execution(make_event(tool_name="terminal", command=variant))["source"] == "learned:exec_gate"
    assert guard_execution(make_event(tool_name="terminal", command="echo " + variant)) == {"block": False}
    stages = [getattr(r, "stage", "") for r in caplog.records]
    assert stages.index("validated") < stages.index("stored") < stages.index("applied")


def test_default_exec_cache_rebuilds_from_current_catalog(monkeypatch):
    import re

    from clawkeeper_core import security_rules
    from clawkeeper_core.guards import exec_gate

    before = len(exec_gate.load_exec_gate()["rules"])
    monkeypatch.setattr(
        exec_gate,
        "DANGEROUS_COMMAND_PATTERNS",
        [*security_rules.DANGEROUS_COMMAND_PATTERNS, re.compile(r"CK_CACHE_\d+")],
    )
    exec_gate.reset_exec_gate_cache()
    try:
        assert len(exec_gate.load_exec_gate()["rules"]) == before + 1
        assert guard_execution(make_event(tool_name="terminal", command="echo CK_CACHE_8421"))[
            "block"
        ]
    finally:
        exec_gate.reset_exec_gate_cache()
