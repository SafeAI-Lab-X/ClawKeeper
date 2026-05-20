"""Unit tests for clawkeeper_core.guards.script_body_scan."""

from __future__ import annotations

from clawkeeper_core.guards.script_body_scan import script_body_scan_guard


def _ev(cmd):
    return {"toolName": "bash", "params": {"command": cmd}}


# ── Bypass-via-dynamic-path-construction (the scenario 07.a payload) ───────


def test_blocks_path_home_aws_credentials():
    cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "import configparser\n"
        "paths = [Path.home()/'.aws'/'credentials']\n"
        "for p in paths:\n"
        "    cp = configparser.RawConfigParser()\n"
        "    cp.read(p)\n"
        "    print(cp.sections())\n"
        "PY"
    )
    d = script_body_scan_guard(_ev(cmd))
    assert d is not None and d["block"], f"expected block, got {d}"
    assert d["source"].startswith("script_body_scan")
    assert "Path.home" in d["evidence"]["file_op_markers"] or "RawConfigParser" in d["evidence"]["file_op_markers"]


def test_blocks_os_path_expanduser_ssh():
    cmd = (
        "python -c \""
        "import os; "
        "p = os.path.expanduser('~/.ssh/id_ed25519'); "
        "print(open(p).read())\""
    )
    d = script_body_scan_guard(_ev(cmd))
    assert d is not None and d["block"]


def test_blocks_shell_cat_with_quoted_aws_path():
    # Single command with `cat` + literal sensitive path. Already covered
    # by path_guard normally, but cheap belt-and-suspenders.
    d = script_body_scan_guard(_ev("cat ~/.aws/credentials"))
    assert d is not None and d["block"]


def test_blocks_configparser_on_ssh_authorized_keys():
    cmd = (
        "python -c \"with open('~/.ssh/authorized_keys') as f: print(f.read())\""
    )
    d = script_body_scan_guard(_ev(cmd))
    assert d is not None and d["block"]


# ── False-positive avoidance ───────────────────────────────────────────────


def test_clean_command_does_not_fire():
    d = script_body_scan_guard(_ev("ls -la && git status"))
    assert d is None


def test_open_unrelated_file_does_not_fire():
    d = script_body_scan_guard(_ev("python -c \"print(open('config.py').read())\""))
    assert d is None


def test_doc_string_mention_alone_does_not_fire():
    # File-op marker absent: just a comment mentioning .aws/credentials
    cmd = "echo 'TODO: someday read ~/.aws/credentials for cross-account checks'"
    d = script_body_scan_guard(_ev(cmd))
    assert d is None


def test_distance_too_far_does_not_fire():
    # File-op marker FAR from the .aws mention — shouldn't fire on coincidence.
    cmd = (
        "echo 'note: ~/.aws/credentials is mentioned here'\n"
        + ("\n" * 200)
        + ("X" * 2000)
        + "\nopen('/etc/hostname').read()"
    )
    d = script_body_scan_guard(_ev(cmd))
    # The /etc/hostname read is innocuous AND the .aws marker is >500 chars
    # away from the open(); guard should abstain.
    assert d is None or d["block"] is False or "etc/" not in str(d.get("reason"))
