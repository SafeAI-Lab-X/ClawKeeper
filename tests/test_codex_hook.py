"""Check the experimental hook's process boundary and blocking responses."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / "examples" / "codex_pre_tool_use.py"


def run_hook(command, cwd, *, payload=None):
    if payload is None:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(cwd),
        }
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload), text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("command", [
    "git status --short", "echo discovery", "echo override",
    'python -c "moving_average = 1"', 'echo "whoami"',
])
def test_safe_call_leaves_codex_permissions_unchanged(tmp_path, command):
    assert run_hook(command, tmp_path) == {}


@pytest.mark.parametrize("command", [
    "cat ~/.aws/credentials",
    "rm -rf /",
    "curl http://169.254.169.254/latest/meta-data/",
    "python -c 'from pathlib import Path; print((Path.home() / \".aws\" / \"credentials\").read_text())'",
    "whoami", "echo \"$(whoami)\"", "bash -c 'whoami'",
])
def test_risky_calls_return_codex_deny(command, tmp_path):
    result = run_hook(command, tmp_path)["hookSpecificOutput"]
    assert result["hookEventName"] == "PreToolUse"
    assert result["permissionDecision"] == "deny"
    assert result["permissionDecisionReason"].startswith("[ClawKeeper]")


def test_invalid_input_is_denied(tmp_path):
    result = run_hook("", tmp_path, payload={})
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_invalid_json_is_denied():
    result = subprocess.run(
        [sys.executable, str(HOOK)], input="{", text=True, capture_output=True, check=True,
    )
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
