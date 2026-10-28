"""Structural contracts, shared assessment and an executable-free explain API."""
# Fixture-local imports and concrete source offsets are deliberate.
# ruff: noqa: PLR2004

import json
import shlex
import subprocess
import sys
from dataclasses import FrozenInstanceError

import pytest

from clawkeeper_core import learned_rules as rules
from clawkeeper_core.adapters.base import run_guard_chain
from clawkeeper_core.execution import analysis_scope, analyze_event, explain
from clawkeeper_core.guards import command_context as context
from clawkeeper_core.guards.exec_gate import guard_execution
from clawkeeper_core.guards.script_body_scan import script_body_scan_guard


def event(command, tool="terminal"):
    return {"toolName": tool, "params": {"command": command}}


def slice_origin(facts, origin):
    return facts.sources[origin.source].text.encode()[origin.start:origin.end].decode()


def test_facts_retain_raw_words_dynamic_roles_utf8_and_source_links():
    code = "print('中文'); import os; os.system('whoami')"
    sample = event("echo '中文'; env MODE=x python -c " + shlex.quote(code) + ' "$ARG"')
    facts = analyze_event(sample)
    assert facts.complete
    python = next(c for c in facts.calls if c.executable == "python")
    assert [w.role for w in python.arguments] == ["option", "code", "data"]
    assert python.arguments[-1].value is None
    assert python.arguments[-1].raw == '"$ARG"'
    assert slice_origin(facts, python.arguments[1].origin) == shlex.quote(code)
    nested = facts.sources[1]
    assert (nested.language, nested.kind, nested.text) == ("python", "inline", code)
    assert nested.parent == python.arguments[1].origin
    assert facts.sources[0].field == ("command",)
    nested_shell = facts.sources[2]
    assert nested_shell.text == "whoami" and nested_shell.parent.source == 1
    assert "os.system" in slice_origin(facts, nested_shell.parent)
    assert slice_origin(facts, facts.calls[-1].origin) == "whoami"
    with pytest.raises(FrozenInstanceError):
        python.kind = "other"
    with pytest.raises(FrozenInstanceError):
        facts.sources[0].text = "other"


@pytest.mark.parametrize("source,expected,kind", [
    ("bash <<< whoami </dev/null", "/dev/null", "file"),
    ("{ bash <<< whoami; } </dev/null", "whoami", "herestring"),
    ("env MODE=x bash <<< whoami </dev/null", "/dev/null", "file"),
])
def test_effective_stdin_and_provenance_follow_shell_descriptor_order(source, expected, kind):
    facts = context.analyze_command(source)
    assert facts.complete
    call = next(c for c in facts.calls if c.executable == "bash")
    assert (call.stdin.target.value, call.stdin.kind) == (expected, kind)
    assert ("whoami" in facts.values("program.name")) == (kind == "herestring")
    if kind == "herestring":
        nested = next(s for s in facts.sources if s.kind == "stdin")
        assert nested.parent == call.stdin.target.origin


@pytest.mark.parametrize("source", ["bash </dev/null <<< whoami", "bash 3<<< whoami 0<&3", "{ bash </dev/null; } <<< whoami"])
def test_valid_shell_forms_outside_upstream_grammar_require_review(source):
    facts = context.analyze_command(source)
    assert not facts.complete
    assert guard_execution(event(source))["outcome"] == "ask"


def test_distinct_input_fields_share_budgets_and_keep_field_origins(monkeypatch):
    sample = {"toolName": "terminal", "params": {"request": [{"command": "echo ok"}], "script": "whoami"}}
    facts = analyze_event(sample)
    assert {s.field for s in facts.sources} == {("request", "0", "command"), ("script",)}
    monkeypatch.setattr(context, "MAX_SOURCE_BYTES", 1)  # builder defaults are frozen; patch its instance budget
    original = context.CommandAnalysis
    monkeypatch.setattr(context, "CommandAnalysis", lambda: original(_bytes=10))
    facts = analyze_event(sample)
    assert not facts.complete
    assert guard_execution(sample)["outcome"] == "ask"


def test_chain_parses_once_and_cache_expires_or_invalidates_on_input_change(monkeypatch):
    snapshot = rules.make_snapshot([
        rules.validate_rule("CK_FACT_8421", "exec_gate", subject="program.name"),
        rules.validate_rule("CK_FACT_8421", "exec_gate", subject="python.module"),
        rules.validate_rule("CK_FACT_8421", "script_body_scan", subject="python.operation"),
    ])
    rules.install_snapshot(snapshot)
    calls = []
    original = context.analyze_requests

    def record(requests):
        calls.append(requests)
        return original(requests)

    monkeypatch.setattr(context, "analyze_requests", record)
    sample = event("echo ok")
    run_guard_chain([guard_execution, script_body_scan_guard], sample, stop_on_block=False)
    assert len(calls) == 1
    explain(sample)
    assert len(calls) == 2  # a fresh evaluation never retains plaintext facts
    with analysis_scope():
        first = analyze_event(sample)
        assert analyze_event(sample) is first
        sample["params"]["command"] = "whoami"
        second = analyze_event(sample)
        assert first is not second
        assert "whoami" in second.values("program.name")
    assert len(calls) == 4


def test_explain_replays_policy_without_model_store_or_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("explain attempted execution or model/store access")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = explain(event("bash -c whoami"))
    assert result["decision"] == "deny" and result["complete"]
    assert result["rules_version"] == rules.current_snapshot().version
    assert result["findings"][0]["evidence"]["origin"]["source"] == 1
    assert explain(event('bash -c "$SOURCE"'))["decision"] == "ask"
    assert explain(event("echo whoami"))["decision"] == "allow"


def test_explain_masks_sensitive_evidence_without_changing_byte_origins():
    source = "echo token=short-secret 中文; whoami"
    result = explain(event(source))
    text = json.dumps(result)
    assert "short-secret" not in text
    redacted = result["analysis"]["sources"][0]["text"]
    assert len(redacted.encode()) == len(source.encode())
    origin = result["findings"][0]["evidence"]["origin"]
    assert redacted.encode()[origin["start"]:origin["end"]] == b"whoami"


def test_python_operation_arguments_preserve_literals_and_dynamic_expressions():
    facts = context.analyze_python("open('/tmp/中文'); open(filename)")
    first, second = facts.script_operations
    assert first.arguments[0].literal and first.arguments[0].value == "/tmp/中文"
    assert slice_origin(facts, first.arguments[0].origin) == "'/tmp/中文'"
    assert not second.arguments[0].literal and second.arguments[0].raw == "filename"


@pytest.mark.parametrize("source", ["echo whoami", "bash -c whoami", 'bash -c "$SOURCE"'])
def test_explain_cli_matches_in_process_decision(source):
    proc = subprocess.run([sys.executable, "-m", "clawkeeper_core.execution", "--event-stdin"],
                          input=json.dumps(event(source)), text=True, capture_output=True, timeout=10, check=True)
    assert json.loads(proc.stdout)["decision"] == explain(event(source))["decision"]


def test_explain_cli_replays_exported_fields_without_mutating_snapshot_file(tmp_path):
    snapshot = rules.make_snapshot([rules.validate_rule(r"CK_FACT_\d+", "exec_gate", subject="python.module")])
    export = tmp_path / "rules.json"
    saved = json.dumps(snapshot.as_dict()).encode()
    export.write_bytes(saved)
    for source, decision in (("python -m CK_FACT_8421", "deny"), ("python -m good CK_FACT_8421", "allow")):
        proc = subprocess.run([sys.executable, "-m", "clawkeeper_core.execution", "--rules-snapshot", str(export), source],
                              text=True, capture_output=True, timeout=10, check=True)
        result = json.loads(proc.stdout)
        assert (result["decision"], result["rules_version"]) == (decision, snapshot.version)
    assert export.read_bytes() == saved


@pytest.mark.parametrize("data,call", [
    ("print(\"open('~/.aws/credentials')\")", "open('~/.aws/credentials').read()"),
    ("# ~/.aws/credentials\nopen('/tmp/normal').read()", "p = '~/.aws/credentials'; open(p).read()"),
    ('"""~/.aws/credentials"""\nopen("/tmp/normal").read()', "from pathlib import Path; (Path.home()/'.aws'/'credentials').read_text()"),
    ("open('/tmp/guide', 'w').write('~/.aws/credentials')", "open('~/.aws/credentials').read()"),
    ("some_function(\"open('~/.aws/credentials')\")", "open('~/.aws/credentials').read()"),
])
def test_script_heuristic_requires_operations_and_excludes_proven_data(data, call):
    assert script_body_scan_guard(event(data, "python")) is None
    assert script_body_scan_guard(event(call, "python"))["outcome"] == "deny"


def test_diagnostics_include_origin_and_internal_failure_never_allows(monkeypatch):
    def broken(requests):
        raise RuntimeError("private source must not be logged")

    monkeypatch.setattr(context, "analyze_requests", broken)
    result = explain(event("echo ok"))
    assert result["decision"] == "ask" and not result["complete"]
    assert "private source" not in json.dumps(result)
