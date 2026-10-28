"""Stable field semantics survive learning, migration, wire sync and deletion."""
# ruff: noqa: PLC0415, PLR2004, PLR0917

import json
from dataclasses import asdict
from types import SimpleNamespace

import httpx
import pytest

from clawkeeper_core import learned_rules as rules
from clawkeeper_core.bounded_regex import search_groups
from clawkeeper_core.guards import command_context
from clawkeeper_core.watcher import reload
from clawkeeper_core.watcher.client import RuleSyncError, WatcherClient
from clawkeeper_core.watcher.learner import PatternCandidate, synthesize_pattern


def event(command, tool="terminal"):
    return {"toolName": tool, "params": {"command": command}}


def candidate(**kw):
    defaults = dict(pattern=r"CK_FIELD_\d+", guard_target="exec_gate", subject="program.name",
                    source_command="CK_FIELD_8421 --arg", confidence=0.99, created_at="2026-10-28T00:00:00Z")
    defaults.update(kw)
    return PatternCandidate(**defaults)


@pytest.mark.parametrize("subject,target,source,tool,data,executions", [
    ("program.name", "exec_gate", "CK_FIELD_8421", "terminal", "echo CK_FIELD_8421",
     ["CK_FIELD_8421 --different", "/tmp/CK_FIELD_8421"]),
    ("python.module", "exec_gate", "python -m CK_FIELD_8421", "terminal", "python -m good CK_FIELD_8421",
     ["python -u -m CK_FIELD_8421 --arg", "python -mCK_FIELD_8421"]),
    ("script.path", "exec_gate", "node /tmp/CK_FIELD_8421.js", "terminal", "node /tmp/good.js CK_FIELD_8421",
     ["node /tmp/CK_FIELD_8421.js --arg", "env MODE=x node /tmp/CK_FIELD_8421.js"]),
    ("python.operation", "script_body_scan", "CK_FIELD_8421()", "python", "print('CK_FIELD_8421()')",
     ["CK_FIELD_8421('different')", "print(CK_FIELD_8421())"]),
    ("path", "path_guard", "cat /tmp/CK_FIELD_8421", "terminal", "echo harmless",
     ["cat /tmp/CK_FIELD_8421", "head /tmp/CK_FIELD_8421"]),
])
def test_synthesis_to_typed_persistence_reload_and_runtime(isolated_learning, monkeypatch, subject, target, source, tool, data, executions):
    parses = []
    original = command_context.analyze_requests

    def record(requests):
        parses.extend(r[1] for r in requests)
        return original(requests)

    monkeypatch.setattr(command_context, "analyze_requests", record)
    prompts = []

    def model(messages):
        prompts.extend(messages)
        return SimpleNamespace(content=json.dumps({"pattern": r"CK_FIELD_\d+", "guard_target": target,
                                                   "subject": subject, "confidence": 0.99}))

    sample = synthesize_pattern(source, "synthetic detection", model, tool_name=tool)
    assert sample is not None and sample.subject == subject
    assert parses.count(source) == 1
    assert len(prompts) == 1 and "stable fact fields" in prompts[0]["content"]
    assert isolated_learning.add(sample)
    assert reload.apply_learned_patterns() == 1
    stored = isolated_learning.all()[0]
    assert stored.source_command == "" and stored.source_args is None
    assert stored.source_view_version == rules.VALIDATION_VERSION
    assert all(f["subject"] == subject and f["subject_version"] == 1 for f in stored.source_facts)
    saved = isolated_learning._path.read_bytes()
    assert reload.apply_learned_patterns() == 0 and saved == isolated_learning._path.read_bytes()
    for execution in executions:
        result = rules.match_learned(target, event(execution, tool))
        assert result["outcome"] == "deny" and result["evidence"]["subject"] == subject
    assert rules.match_learned(target, event(data, tool)) is None
    body = rules.current_snapshot().as_dict()
    assert rules.snapshot_from_wire(body) == rules.current_snapshot()
    assert "source_facts" not in json.dumps(body)
    assert isolated_learning.remove(body["rules"][0]["id"])
    reload.apply_learned_patterns()
    assert not rules.current_snapshot().rules


def test_same_pattern_in_different_subjects_has_independent_identity(isolated_learning):
    assert isolated_learning.add(candidate())
    module = candidate(subject="python.module", source_command="python -m CK_FIELD_8421")
    assert isolated_learning.add(module)
    assert not isolated_learning.add(module)
    assert reload.apply_learned_patterns() == 2
    first = rules.current_snapshot()
    assert len({r.id for r in first.rules}) == 2
    assert isolated_learning.remove(rules.rule_id("exec_gate", module.pattern, "program.name"))
    reload.apply_learned_patterns()
    assert rules.match_learned("exec_gate", event("CK_FIELD_8421")) is None
    assert rules.match_learned("exec_gate", event("python -m CK_FIELD_8421"))["outcome"] == "deny"


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
def test_v3_bare_interpreter_migrates_to_name_and_keeps_old_delete_id(isolated_learning, target):
    old = candidate(pattern="node$", guard_target=target, subject=None, source_command="",
                    source_texts=["node"], source_view_version=3)
    isolated_learning._path.write_text(json.dumps([asdict(old)]))
    assert reload.apply_learned_patterns() == 1
    stored = isolated_learning.all()[0]
    assert stored.subject == "program.name"
    assert rules.match_learned(target, event("node /tmp/example.js --arg"))["outcome"] == "deny"
    assert rules.match_learned(target, event("echo node")) is None
    assert isolated_learning.remove(rules.rule_id(target, "node$"))
    reload.apply_learned_patterns()
    assert not rules.current_snapshot().rules


def test_ambiguous_v3_and_incompatible_fact_schema_are_inactive_with_reason(isolated_learning):
    ambiguous = candidate(subject=None, source_command="", source_texts=["node", "echo ok"], source_view_version=3)
    incompatible = candidate(pattern="CK_OTHER", source_command="", source_view_version=5,
                             source_facts=[{"subject": "program.name", "subject_version": 999, "value": "CK_OTHER"}])
    isolated_learning._path.write_text(json.dumps([asdict(ambiguous), asdict(incompatible)]))
    assert reload.apply_learned_patterns() == 0
    stored = isolated_learning.all()
    assert "roles cannot be reconstructed" in stored[0].inactive_reason
    assert "incompatible source fact" in stored[1].inactive_reason
    assert all(not c.source_command and not c.source_facts for c in stored)
    saved = isolated_learning._path.read_bytes()
    assert reload.apply_learned_patterns() == 0 and saved == isolated_learning._path.read_bytes()


def test_v4_compatibility_projection_does_not_change_semantics(isolated_learning):
    old = candidate(pattern=r"node\s+/tmp/CK_FIELD_\d+\.js", subject=None, source_command="",
                    source_texts=["node /tmp/CK_FIELD_8421.js"], source_view_version=4)
    isolated_learning._path.write_text(json.dumps([asdict(old)]))
    assert reload.apply_learned_patterns() == 1
    assert rules.match_learned("exec_gate", event("node /tmp/CK_FIELD_8421.js extra"))
    assert not rules.match_learned("exec_gate", event("node /tmp/good.js /tmp/CK_FIELD_8421.js"))


def test_v4_attached_module_spelling_and_stable_module_subject_agree(isolated_learning):
    old = candidate(pattern=r"python\s+-mCK_FIELD_\d+", subject=None, source_command="",
                    source_texts=["python -mCK_FIELD_8421"], source_view_version=4)
    isolated_learning._path.write_text(json.dumps([asdict(old)]))
    assert reload.apply_learned_patterns() == 1
    sample = event("python -mCK_FIELD_8421 --arg")
    assert rules.match_learned("exec_gate", sample)
    assert rules.target_texts("exec_gate", sample, "python.module") == ["CK_FIELD_8421"]


@pytest.mark.parametrize("mutation", ["subject", "subject_version", "bool_version", "old_protocol", "missing", "identity"])
def test_wire_schema_rejection_keeps_previous_snapshot(mutation):
    previous = rules.make_snapshot([rules.validate_rule(r"CK_FIELD_\d+", "exec_gate", subject="program.name")])
    payload = previous.as_dict()
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        body = json.loads(json.dumps(payload))
        if calls > 1:
            if mutation == "subject":
                body["rules"][0]["subject"] = "unknown.field"
            elif mutation == "subject_version":
                body["rules"][0]["subject_version"] = 999
            elif mutation == "bool_version":
                body["rules"][0]["subject_version"] = True
            elif mutation == "old_protocol":
                body["protocol_version"] = 1
            elif mutation == "missing":
                del body["rules"][0]["subject"]
            else:
                body["rules"][0]["subject"] = "python.module"
        return httpx.Response(200, json=body, headers={"ETag": f'"{body["version"]}"'})

    with WatcherClient("http://watcher") as client:
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        installed = client.sync_rules()
        assert installed == previous
        with pytest.raises(RuleSyncError):
            client.sync_rules()
        assert rules.current_snapshot() is installed


def test_mixed_matching_modes_have_field_isolation_and_no_reused_request_state():
    patterns = ["CK_FIELD", "CK_FIELD", "node CK_FIELD"]
    groups = [["CK_FIELD extra"], ["/tmp/CK_FIELD"], ["node CK_FIELD arg"]]
    assert search_groups(patterns, groups, modes=["full", "search", "invocation"], pattern_groups=[0, 1, 2]) == [None, 1, 2]
    assert search_groups(["CK_FIELD"], [["CK_FIELD extra"]]) == [0]
    assert search_groups(["CK_FIELD"], [["CK_FIELD extra"]], modes=["full"]) == [None]


def test_new_field_snapshot_is_pinned_for_whole_chain(isolated_learning):
    from clawkeeper_core.adapters.base import run_guard_chain
    from clawkeeper_core.guards.exec_gate import guard_execution

    assert isolated_learning.add(candidate())
    reload.apply_learned_patterns()
    previous = rules.current_snapshot()

    def replace_policy(sample):
        rules.install_snapshot(rules.make_snapshot([]))

    block, _ = run_guard_chain([replace_policy, guard_execution], event("CK_FIELD_8421 arg"))
    assert block["evidence"]["rules_version"] == previous.version
    assert not guard_execution(event("CK_FIELD_8421 arg"))["block"]
