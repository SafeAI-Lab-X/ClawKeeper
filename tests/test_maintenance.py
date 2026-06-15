"""Integration tests for audit + harden + rollback. Ported from
legacy/clawkeeper-watcher/.../hardening.test.js.
"""

from __future__ import annotations

import json

import pytest

from clawkeeper_core.audit import create_audit_context, run_audit
from clawkeeper_core.maintenance import harden, rollback


@pytest.mark.asyncio
async def test_audit_harden_rollback_round_trip(tmp_path):
    state_dir = tmp_path
    config_path = state_dir / "openclaw.json"
    config_path.write_text(json.dumps({
        "gateway": {"bind": "lan", "auth": {"mode": "token", "token": "test-token"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        "tools": {"exec": {"security": "full"}},
    }, indent=2) + "\n", encoding="utf-8")

    # ── audit ────────────────────────────────────────────────────────────
    report = await run_audit(await create_audit_context(state_dir))
    finding_ids = sorted(f["id"] for f in report["findings"])
    assert finding_ids == [
        "behavior.runtime-constitution",
        "execution.bounded-filesystem",
        "execution.human-checkpoint",
        "network.local-gateway",
    ]
    assert report["score"] < 100
    assert report["summary"]["high"] >= 1

    # ── harden ───────────────────────────────────────────────────────────
    harden_result = await harden(state_dir)
    assert harden_result["actions"] == [
        "gateway.bind -> loopback",
        "agents.defaults.sandbox.mode -> all",
        "tools.exec.security -> allowlist",
        "AGENTS.md injected with runtime constitution",
    ]

    hardened = json.loads(config_path.read_text())
    assert hardened["gateway"]["bind"] == "loopback"
    assert hardened["agents"]["defaults"]["sandbox"]["mode"] == "all"
    assert hardened["tools"]["exec"]["security"] == "allowlist"

    agents_path = state_dir / "AGENTS.md"
    agents_content = agents_path.read_text()
    assert "clawkeeper:rules:start" in agents_content

    # ── rollback ─────────────────────────────────────────────────────────
    from pathlib import Path
    backup_name = Path(harden_result["backupDir"]).name
    rollback_result = await rollback(state_dir, backup_name)
    assert rollback_result["restoredFiles"] == ["openclaw.json", "AGENTS.md"]

    rolled_back = json.loads(config_path.read_text())
    assert rolled_back["gateway"]["bind"] == "lan"
    assert rolled_back["agents"]["defaults"]["sandbox"]["mode"] == "off"
    assert rolled_back["tools"]["exec"]["security"] == "full"
    assert not agents_path.exists()


@pytest.mark.asyncio
async def test_rollback_raises_when_no_backups(tmp_path):
    with pytest.raises(FileNotFoundError, match="No ClawKeeper backups"):
        await rollback(tmp_path)


@pytest.mark.asyncio
async def test_audit_score_full_when_config_clean(tmp_path):
    state_dir = tmp_path
    # Clean config: bind loopback, sandbox all, exec allowlist, gateway auth set, AGENTS.md has rules
    (state_dir / "openclaw.json").write_text(json.dumps({
        "gateway": {"bind": "loopback", "auth": {"token": "x"}},
        "agents": {"defaults": {"sandbox": {"mode": "all"}}},
        "tools": {"exec": {"security": "allowlist"}},
    }), encoding="utf-8")
    (state_dir / "AGENTS.md").write_text(
        "# AGENTS\n<!-- clawkeeper:rules:start -->\nrules\n<!-- clawkeeper:rules:end -->\n",
        encoding="utf-8",
    )
    report = await run_audit(await create_audit_context(state_dir))
    assert report["findings"] == []
    assert report["score"] == 100
