"""Learn, persist and enforce the same inert data/execution pairs."""

import json
from dataclasses import asdict, replace

import pytest

from clawkeeper_core import learned_rules as rules
from clawkeeper_core.bounded_regex import RegexResourceError
from clawkeeper_core.guards import exec_gate
from clawkeeper_core.guards.exec_gate import guard_execution
from clawkeeper_core.guards.script_body_scan import script_body_scan_guard
from clawkeeper_core.watcher import learner, reload
from clawkeeper_core.watcher.learner import LearnedPatternStore, PatternCandidate


def event(command, tool="terminal"):
    return {"toolName": tool, "params": {"command": command}}


def candidate(target="exec_gate", **kw):
    fields = dict(pattern=r"CK_CONTEXT_\d+", source_command="CK_CONTEXT_8421",
                  guard_target=target, confidence=0.99, created_at="2026-10-28T00:00:00Z")
    fields.update(kw)
    return PatternCandidate(**fields)


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
@pytest.mark.parametrize("data,execution", [
    ("echo CK_CONTEXT_8421", "CK_CONTEXT_8421"),
    ("printf '%s' CK_CONTEXT_8421", "/usr/bin/CK_CONTEXT_8421"),
    ("# CK_CONTEXT_8421\necho ok", "echo ok; CK_CONTEXT_8421"),
    ("echo '$(CK_CONTEXT_8421)'", 'echo "$(CK_CONTEXT_8421)"'),
    ("echo 'bash -c CK_CONTEXT_8421'", "bash -c 'CK_CONTEXT_8421'"),
    ("cat <<'EOF'\nCK_CONTEXT_8421\nEOF", "sh <<'EOF'\nCK_CONTEXT_8421\nEOF"),
    ("python -c 'CK_CONTEXT_8421 = 1'",
     "python -c 'import os; os.system(\"CK_CONTEXT_8421\")'"),
    ("python -c 'print(\"CK_CONTEXT_8421\")'",
     "python -c 'import subprocess; subprocess.run([\"CK_CONTEXT_8421\"])'"),
    ("git commit -m 'CK_CONTEXT_8421'", "git status && CK_CONTEXT_8421"),
    ("cat <<< 'CK_CONTEXT_8421'", "sh <<< 'CK_CONTEXT_8421'"),
    ('python -c \'import subprocess; subprocess.run(["CK_CONTEXT_8421"], executable="/bin/echo")\'',
     'python -c \'import subprocess; subprocess.run(["echo"], executable="/tmp/CK_CONTEXT_8421")\''),
])
def test_learning_and_runtime_share_execution_pairs(isolated_learning, target, data, execution):
    guard = guard_execution if target == "exec_gate" else script_body_scan_guard
    assert isolated_learning.add(candidate(target))
    assert reload.apply_learned_patterns() == 1
    with pytest.raises(ValueError, match="does not match the source"):
        rules.validate_rule(r"CK_CONTEXT_\d+", target, source_event=event(data))
    rules.validate_rule(r"CK_CONTEXT_\d+", target, source_event=event(execution))
    assert not (guard(event(data)) or {}).get("block")
    result = guard(event(execution))
    assert result["block"] and result["source"] == "learned:" + target


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
def test_learning_ignores_content_metadata_and_separate_sources(isolated_learning, target):
    assert isolated_learning.add(candidate(target))
    assert reload.apply_learned_patterns() == 1
    samples = [
        {"toolName": "write_file", "params": {"content": "CK_CONTEXT_8421"}},
        {"toolName": "terminal", "params": {
            "command": "echo ok", "description": "CK_CONTEXT_8421",
            "env": {"EXAMPLE": "CK_CONTEXT_8421"}}},
        {"toolName": "terminal", "params": {"command": "echo CK_CONTEXT_", "script": "8421"}},
    ]
    for sample in samples:
        assert rules.match_learned(target, sample) is None
    nested = {"toolName": "custom_tool", "params": {"request": [{"payload": "CK_CONTEXT_8421"}]}}
    assert rules.match_learned(target, nested)["source"] == "learned:" + target
    nested["params"]["command"] = "echo ok"
    assert rules.match_learned(target, nested)["source"] == "learned:" + target


def test_custom_execution_tool_mapping_is_shared(monkeypatch, isolated_learning):
    gate = exec_gate._build_default_gate()
    gate["config"]["bashLikeTools"] = ["custom_runner"]
    monkeypatch.setattr(exec_gate, "_cached", gate)
    source = {"toolName": "custom_runner", "params": {"input": "CK_CONTEXT_8421"}}
    rules.validate_rule(r"CK_CONTEXT_\d+", "exec_gate", source_event=source)
    assert isolated_learning.add(candidate(source_tool_name="custom_runner", source_args=source["params"]))
    assert reload.apply_learned_patterns() == 1
    assert guard_execution(source)["source"] == "learned:exec_gate"
    source["params"]["input"] = "echo CK_CONTEXT_8421"
    assert guard_execution(source) == {"block": False}


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
def test_program_specific_learning_masks_metadata_arguments(isolated_learning, target):
    pattern = r"git\s+.*CK_CONTEXT_\d+"
    execution = "git -c core.sshCommand=CK_CONTEXT_8421 fetch"
    assert isolated_learning.add(candidate(target, pattern=pattern, source_command=execution))
    assert reload.apply_learned_patterns() == 1
    assert rules.match_learned(target, event(execution))["source"] == "learned:" + target
    for data in ["git commit -m 'CK_CONTEXT_8421'", "git commit --message=CK_CONTEXT_8421",
                 "git log --grep CK_CONTEXT_8421"]:
        assert rules.match_learned(target, event(data)) is None
        with pytest.raises(ValueError, match="does not match the source"):
            rules.validate_rule(pattern, target, source_event=event(data))


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
def test_parameter_only_rule_and_data_only_source_cannot_be_learned(isolated_learning, target):
    assert not isolated_learning.add(candidate(target, source_command="echo CK_CONTEXT_8421"))
    assert not isolated_learning.add(candidate(target, source_command="some_program CK_CONTEXT_8421"))
    assert isolated_learning.all() == []


def test_script_operations_have_call_context_and_persisted_views(isolated_learning):
    sample = candidate("script_body_scan", pattern=r"python:open.*CK_CONTEXT_SECRET",
                       source_command="open('/tmp/CK_CONTEXT_SECRET').read()",
                       source_tool_name="python")
    assert isolated_learning.add(sample)
    first = isolated_learning._path.read_bytes()
    stored = isolated_learning.all()[0]
    assert stored.source_view_version == rules.VALIDATION_VERSION
    assert stored.source_command == "" and stored.source_args is None
    assert stored.source_texts == ["python:open '/tmp/CK_CONTEXT_SECRET'"]
    assert reload.apply_learned_patterns() == 1
    assert isolated_learning._path.read_bytes() == first
    assert script_body_scan_guard(event(sample.source_command, "python"))["source"] == "learned:script_body_scan"
    for data in [
        "print(\"open('/tmp/CK_CONTEXT_SECRET')\")",
        "example = \"open('/tmp/CK_CONTEXT_SECRET')\"",
        "# open('/tmp/CK_CONTEXT_SECRET')\nprint('ok')",
        "open('/tmp/example', 'w').write(\"open('/tmp/CK_CONTEXT_SECRET')\")",
    ]:
        assert script_body_scan_guard(event(data, "python")) is None


@pytest.mark.parametrize("legacy_version", [0, 2])
def test_legacy_raw_samples_reparse_without_relearning_data(isolated_learning, legacy_version):
    good = candidate(source_command="", source_texts=["CK_CONTEXT_8421"],
                     source_view_version=legacy_version)
    data = replace(good, pattern=r"CK_DOCUMENT_\d+", source_texts=["echo CK_DOCUMENT_8421"])
    records = [asdict(good), asdict(data)]
    if legacy_version == 0:
        for record in records:
            record.pop("source_view_version")
    isolated_learning._path.write_text(json.dumps(records))
    assert reload.apply_learned_patterns() == 1
    assert [r.pattern for r in rules.current_snapshot().rules] == [good.pattern]
    assert guard_execution(event("CK_CONTEXT_8421"))["source"] == "learned:exec_gate"
    assert guard_execution(event("echo CK_CONTEXT_8421")) == {"block": False}
    assert guard_execution(event("echo CK_DOCUMENT_8421")) == {"block": False}
    migrated = isolated_learning._path.read_bytes()
    assert reload.apply_learned_patterns() == 0
    assert isolated_learning._path.read_bytes() == migrated
    assert isolated_learning.remove(rules.rule_id(good.guard_target, good.pattern))
    reload.apply_learned_patterns()
    assert not rules.current_snapshot().rules


def test_incomplete_context_never_becomes_a_learned_allow(isolated_learning):
    assert isolated_learning.add(candidate())
    reload.apply_learned_patterns()
    sample = event('bash -c "$SOURCE"')
    assert rules.match_learned("exec_gate", sample)["outcome"] == "ask"
    with pytest.raises(ValueError, match="analysis incomplete"):
        rules.validate_rule(r"CK_CONTEXT_\d+", "exec_gate", source_event=sample)


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
@pytest.mark.parametrize("data,execution,pattern", [
    ("python -c 'print(\"CK_BAD_MODULE\")'", "python -m CK_BAD_MODULE", r"python\s+-m\s+CK_BAD_MODULE"),
    ("python -m CK_GOOD_MODULE CK_BAD_MODULE", "python -m CK_BAD_MODULE", r"python\s+-m\s+CK_BAD_MODULE"),
    ("python -m CK_GOOD_MODULE -c CK_BAD_MODULE", "python -m CK_BAD_MODULE", r"python\s+-m\s+CK_BAD_MODULE"),
    ("echo node /tmp/CK_BAD_SCRIPT.js", "node /tmp/CK_BAD_SCRIPT.js", r"node\s+/tmp/CK_BAD_SCRIPT\.js"),
    ("node /tmp/CK_GOOD_SCRIPT.js /tmp/CK_BAD_SCRIPT.js", "node /tmp/CK_BAD_SCRIPT.js", r"node\s+/tmp/CK_BAD_SCRIPT\.js"),
])
def test_module_and_script_rules_learn_and_survive_reload(isolated_learning, target, data, execution, pattern):
    assert isolated_learning.add(candidate(target, pattern=pattern, source_command=execution))
    assert reload.apply_learned_patterns() == 1
    snapshot = rules.current_snapshot()
    assert rules.match_learned(target, event(execution))["source"] == "learned:" + target
    assert rules.match_learned(target, event(data)) is None
    rules.install_snapshot(rules.make_snapshot([]))
    assert reload.apply_learned_patterns() == 1
    assert rules.current_snapshot().version == snapshot.version
    assert rules.match_learned(target, event(execution))["source"] == "learned:" + target


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
@pytest.mark.parametrize("legacy_version", [0, 2])
def test_valid_legacy_module_rules_survive_migration(isolated_learning, target, legacy_version):
    source = "python -m CK_BAD_MODULE"
    sample = candidate(target, pattern=r"python\s+-m\s+CK_BAD_MODULE", source_command="",
                       source_texts=[source], source_view_version=legacy_version)
    isolated_learning._path.write_text(json.dumps([asdict(sample)]))
    assert reload.apply_learned_patterns() == 1
    assert rules.match_learned(target, event(source))["source"] == "learned:" + target
    assert rules.match_learned(target, event("python -m CK_GOOD_MODULE CK_BAD_MODULE")) is None


@pytest.mark.parametrize("legacy_version", [3, rules.VALIDATION_VERSION])
def test_normalized_python_operations_are_not_reparsed_as_shell(isolated_learning, legacy_version):
    sample = candidate("script_body_scan", pattern=r"python:open.*CK_CONTEXT_SECRET", source_command="",
                       source_texts=["python:open '/tmp/CK_CONTEXT_SECRET'"], source_view_version=legacy_version)
    isolated_learning._path.write_text(json.dumps([asdict(sample)]))
    assert reload.apply_learned_patterns() == 1
    assert rules.match_learned("script_body_scan", event("open('/tmp/CK_CONTEXT_SECRET')", "python"))
    assert not rules.match_learned("script_body_scan", event("print(\"open('/tmp/CK_CONTEXT_SECRET')\")", "python"))
    saved = isolated_learning._path.read_bytes()
    assert reload.apply_learned_patterns() == 0
    assert isolated_learning._path.read_bytes() == saved


@pytest.mark.parametrize("target", ["exec_gate", "script_body_scan"])
def test_inactive_legacy_rule_can_be_relearned_without_losing_other_targets(isolated_learning, target):
    old = candidate(target, source_command="", source_texts=["echo CK_CONTEXT_8421"])
    isolated_learning._path.write_text(json.dumps([asdict(old)]))
    assert reload.apply_learned_patterns() == 0
    other = "script_body_scan" if target == "exec_gate" else "exec_gate"
    assert isolated_learning.add(candidate(other))
    assert isolated_learning.add(candidate(target))  # replaces only the inactive identity
    assert reload.apply_learned_patterns() == 2  # noqa: PLR2004
    for name in (target, other):
        assert rules.match_learned(name, event("CK_CONTEXT_8421"))
        assert not rules.match_learned(name, event("echo CK_CONTEXT_8421"))
    saved = isolated_learning._path.read_bytes()
    assert not isolated_learning.add(candidate(target))  # active duplicate remains rejected
    assert isolated_learning._path.read_bytes() == saved
    assert len(LearnedPatternStore(isolated_learning._path).all()) == 2  # noqa: PLR2004
    assert isolated_learning.remove(rules.rule_id(target, old.pattern))
    reload.apply_learned_patterns()
    assert not rules.match_learned(target, event("CK_CONTEXT_8421"))
    assert rules.match_learned(other, event("CK_CONTEXT_8421"))


def test_inactive_replacement_checks_capacity_after_removing_old_identity(isolated_learning, monkeypatch):
    old = candidate(source_command="", source_texts=["echo CK_CONTEXT_8421"])
    isolated_learning._path.write_text(json.dumps([asdict(old)]))
    reload.apply_learned_patterns()
    monkeypatch.setattr(learner, "MAX_PATTERNS", 1)
    assert isolated_learning.add(candidate())
    saved = isolated_learning._path.read_bytes()
    assert not isolated_learning.add(candidate(pattern="CK_OTHER", source_command="CK_OTHER"))
    assert isolated_learning._path.read_bytes() == saved


def test_relearning_retains_store_on_existing_rule_validation_resource_failure(isolated_learning, monkeypatch):
    old = candidate(source_command="", source_texts=["echo CK_CONTEXT_8421"])
    isolated_learning._path.write_text(json.dumps([asdict(old)]))
    reload.apply_learned_patterns()
    saved = isolated_learning._path.read_bytes()
    snapshot = rules.current_snapshot()
    validate = learner.validate_candidate

    def failed_existing(sample):
        if sample.source_texts == ["echo"]:
            raise RegexResourceError("validation worker unavailable")
        return validate(sample)

    with monkeypatch.context() as scoped:
        scoped.setattr(learner, "validate_candidate", failed_existing)
        assert not isolated_learning.add(candidate())
    assert isolated_learning._path.read_bytes() == saved
    assert rules.current_snapshot() is snapshot
    assert isolated_learning.add(candidate())
    assert reload.apply_learned_patterns() == 1
