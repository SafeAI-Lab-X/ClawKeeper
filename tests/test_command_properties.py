"""Metamorphic invariants plus small benign probes of actual Bash semantics.

Dangerous commands are never executed. Runtime probes are fixed printf scripts
with /dev/null redirects; they validate the descriptor model independently.
"""

import itertools
import random
import shlex
import subprocess

import pytest

from clawkeeper_core.guards import command_context as context
from clawkeeper_core.guards.exec_gate import guard_execution


def decide(source):
    return guard_execution({"toolName": "terminal", "params": {"command": source}})


@pytest.mark.parametrize("program", ["whoami", "'whoami'", '"whoami"', "/usr/bin/whoami"])
@pytest.mark.parametrize("wrapper", ["{}", "env MODE=x {}", "command -- {}", "sudo -u root {}", "timeout 5 {}"])
def test_transparent_launchers_and_quoting_preserve_blocking(program, wrapper):
    source = wrapper.format(program)
    for transformed in (source, "{ " + source + "; }", "bash -c " + shlex.quote(source)):
        assert decide(transformed)["outcome"] == "deny"
    for data in ("echo " + shlex.quote(source), "printf '%s' " + shlex.quote(source), "# " + source + "\necho ok"):
        assert not decide(data).get("block")


@pytest.mark.parametrize("language,code", [("bash", "whoami"), ("python", 'import os; os.system("whoami")')])
@pytest.mark.parametrize("options", ["$OPTIONS", '"$OPTIONS"', "$(printf %s -u)"])
def test_unresolved_options_cannot_hide_inline_code(language, code, options):
    assert decide(f"{language} {options} -c {shlex.quote(code)}")["outcome"] == "ask"
    assert decide(f"{language} -c {shlex.quote(code)}")["outcome"] == "deny"
    assert not decide(f"{language} /tmp/example {options}").get("block")


@pytest.mark.parametrize("source", [
    "bash <<< 'printf CK_PROBE' </dev/null",
    "bash </dev/null <<< 'printf CK_PROBE'",
    "bash 3<<< 'printf CK_PROBE' 0<&3",
    "{ bash <<< 'printf CK_PROBE'; } </dev/null",
    "{ bash </dev/null; } <<< 'printf CK_PROBE'",
])
def test_descriptor_model_matches_benign_shell_probe(source):
    probe = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", source],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3, check=True,
                           env={"PATH": "/usr/bin:/bin"})
    facts = context.analyze_command(source)
    if facts.complete:
        assert (probe.stdout == "CK_PROBE") == ("printf" in facts.values("program.name"))
    else:
        # tree-sitter-bash rejects some valid combinations of here-strings and
        # file descriptors. Syntax uncertainty must remain visible to callers.
        assert decide(source)["outcome"] == "ask"


def test_each_budget_boundary_and_dynamic_source_defers_instead_of_allowing(monkeypatch):
    for field, amount in (("_bytes", 1), ("_remaining", 1)):
        original = context.CommandAnalysis
        with monkeypatch.context() as patch:
            patch.setattr(context, "CommandAnalysis", lambda original=original, field=field, amount=amount: original(**{field: amount}))
            assert decide("echo a benign payload")["outcome"] == "ask"
    source = "echo ok"
    for _ in range(context.MAX_DEPTH + 2):
        source = "bash -c " + shlex.quote(source)
    assert decide(source)["outcome"] == "ask"
    for source in ("$PROGRAM ok", 'bash -c "$CODE"', "python -m $MODULE", "bash 0<&3 3<<< whoami",
                   "bash <<< whoami 0<&0", "bash <<< whoami 0<&3", "bash <<< whoami 0<&-"):
        assert decide(source)["outcome"] == "ask"


def test_generated_literal_data_never_becomes_an_executable_and_offsets_are_valid():
    rng = random.Random(8421)
    tokens = ["whoami", "systeminfo", "ver", "rm -rf /", "$(whoami)", "中文", "|", ";", "'"]
    for _ in range(100):
        value = " ".join(rng.choices(tokens, k=5))
        source = "printf '%s' " + shlex.quote(value)
        assert not decide(source).get("block")
        facts = context.analyze_command(source)
        assert facts.complete
        for call in facts.calls:
            for origin in (call.origin, call.program.origin, *(w.origin for w in call.arguments)):
                assert 0 <= origin.start <= origin.end <= len(facts.sources[origin.source].text.encode())


def test_heredoc_and_herestring_override_pairs():
    for data, code in itertools.product(("whoami", "systeminfo"), ("bash", "sh")):
        assert not decide(f"{code} <<< {data} </dev/null").get("block")
        assert decide(f"{code} </dev/null <<< {data}")["outcome"] in {"deny", "ask"}
        assert not decide(f"cat <<'EOF' | {code} </dev/null\n{data}\nEOF").get("block")
        assert decide(f"cat <<'EOF' | {code}\n{data}\nEOF")["outcome"] == "deny"
