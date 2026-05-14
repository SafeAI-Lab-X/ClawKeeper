"""Tests for clawkeeper_core.permission. The JS module had no test file,
so these cover each public path: fingerprinting, grant/check/revoke,
HMAC integrity, scope precedence, and reset.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import clawkeeper_core.permission as perm


@pytest.fixture
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENCLAW_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("CLAWKEEPER_HMAC_KEY", "test-key-do-not-use-in-prod")
    yield tmp_path


class TestFingerprintFor:
    def test_bash_tool_keys_on_command(self):
        fp1 = perm.fingerprint_for("bash", {"command": "ls"})
        fp2 = perm.fingerprint_for("bash", {"command": "ls"})
        assert fp1 == fp2
        assert len(fp1) == 32

    def test_different_commands_different_fingerprints(self):
        fp1 = perm.fingerprint_for("bash", {"command": "ls"})
        fp2 = perm.fingerprint_for("bash", {"command": "rm -rf /"})
        assert fp1 != fp2

    def test_path_tool_keys_on_path(self):
        fp1 = perm.fingerprint_for("read_file", {"path": "/etc/passwd"})
        fp2 = perm.fingerprint_for("read_file", {"path": "/etc/passwd"})
        assert fp1 == fp2

    def test_unknown_tool_falls_back_to_json(self):
        fp1 = perm.fingerprint_for("custom_tool", {"arg": 1})
        fp2 = perm.fingerprint_for("custom_tool", {"arg": 1})
        assert fp1 == fp2
        fp3 = perm.fingerprint_for("custom_tool", {"arg": 2})
        assert fp1 != fp3


class TestGrantAndCheck:
    def test_grant_then_check_returns_allow(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "ls"}, decision="allow", scope="session")
        result = perm.check_permission("bash", {"command": "ls"})
        assert result["decision"] == "allow"
        assert result["scope"] == "session"

    def test_unknown_tool_returns_none(self, isolated_workspace):
        result = perm.check_permission("bash", {"command": "never-granted"})
        assert result["decision"] == "none"

    def test_deny_wins_over_allow_same_scope(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "rm"}, decision="allow", scope="session")
        perm.grant_permission(tool="bash", params={"command": "rm"}, decision="deny", scope="session")
        assert perm.check_permission("bash", {"command": "rm"})["decision"] == "deny"

    def test_forever_wins_over_session(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "echo"}, decision="deny", scope="session")
        perm.grant_permission(tool="bash", params={"command": "echo"}, decision="allow", scope="forever")
        assert perm.check_permission("bash", {"command": "echo"})["decision"] == "allow"


class TestInvalidArgs:
    def test_invalid_decision_raises(self, isolated_workspace):
        with pytest.raises(ValueError):
            perm.grant_permission(tool="bash", params={"command": "ls"}, decision="maybe", scope="session")

    def test_invalid_scope_raises(self, isolated_workspace):
        with pytest.raises(ValueError):
            perm.grant_permission(tool="bash", params={"command": "ls"}, decision="allow", scope="lifetime")


class TestRevokeAndReset:
    def test_revoke_removes_entry(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "ls"}, decision="allow", scope="session")
        result = perm.check_permission("bash", {"command": "ls"})
        fp = result["fingerprint"]
        revoked = perm.revoke_permission(tool="bash", fingerprint=fp, scope="session")
        assert revoked["removed"] == 1
        assert perm.check_permission("bash", {"command": "ls"})["decision"] == "none"

    def test_reset_session_wipes_all_session_entries(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "a"}, decision="allow", scope="session")
        perm.grant_permission(tool="bash", params={"command": "b"}, decision="allow", scope="session")
        perm.grant_permission(tool="bash", params={"command": "c"}, decision="allow", scope="forever")
        perm.reset_session_permissions()
        assert perm.check_permission("bash", {"command": "a"})["decision"] == "none"
        assert perm.check_permission("bash", {"command": "c"})["decision"] == "allow"


class TestListPermissions:
    def test_lists_both_scopes_by_default(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "s"}, decision="allow", scope="session")
        perm.grant_permission(tool="bash", params={"command": "f"}, decision="deny", scope="forever")
        all_perms = perm.list_permissions()
        scopes = {p["scope"] for p in all_perms}
        assert scopes == {"session", "forever"}

    def test_filters_by_scope(self, isolated_workspace):
        perm.grant_permission(tool="bash", params={"command": "s"}, decision="allow", scope="session")
        perm.grant_permission(tool="bash", params={"command": "f"}, decision="deny", scope="forever")
        only_forever = perm.list_permissions(scope="forever")
        assert all(p["scope"] == "forever" for p in only_forever)
        assert len(only_forever) == 1


class TestHmacIntegrity:
    def test_tampered_file_treated_as_empty(self, isolated_workspace, capsys):
        perm.grant_permission(tool="bash", params={"command": "ls"}, decision="allow", scope="session")
        # Tamper with the file directly to simulate attacker editing the JSON
        session_file = perm.resolve_session_file()
        store = json.loads(session_file.read_text())
        store["entries"][0]["decision"] = "allow"  # touch it
        store["entries"][0]["tool"] = "bash"
        store["entries"][0]["fingerprint"] = "X" * 32  # forge a different fingerprint
        session_file.write_text(json.dumps(store))
        # Now lookup should miss (because HMAC won't validate)
        result = perm.check_permission("bash", {"command": "ls"})
        assert result["decision"] == "none"
        captured = capsys.readouterr()
        assert "HMAC verification failed" in captured.err
