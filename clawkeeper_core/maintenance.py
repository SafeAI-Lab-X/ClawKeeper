"""Hardening (backup + apply auto-fixable remediations) and rollback.

Ported from legacy/clawkeeper-watcher/.../hardening.js + rollback.js.

`harden(state_dir)` snapshots openclaw.json + AGENTS.md into a timestamped
backup directory, then runs each control's auto-fix. `rollback(state_dir,
backup_name)` restores files from one of those snapshots.

Backups live under `<state_dir>/.clawkeeper-watcher/backups/<ISO-timestamp>/`
with a `manifest.json` describing what was saved.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clawkeeper_core.audit import create_audit_context
from clawkeeper_core.controls import get_controls
from clawkeeper_core.state import get_config_path


def _backup_root(state_dir: Path) -> Path:
    return state_dir / ".clawkeeper-watcher" / "backups"


async def _create_backup_dir(state_dir: Path) -> Path:
    # ISO timestamp with : and . replaced by - to be filesystem-safe.
    raw = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    timestamp = raw.replace(":", "-").replace(".", "-")
    backup_dir = _backup_root(state_dir) / timestamp
    await asyncio.to_thread(backup_dir.mkdir, parents=True, exist_ok=True)
    return backup_dir


async def _backup_file(source: Path, destination: Path, files: list[dict[str, Any]], relative_path: str) -> None:
    if not await asyncio.to_thread(source.exists):
        files.append({"relativePath": relative_path, "backupName": None, "existed": False})
        return
    try:
        await asyncio.to_thread(destination.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(shutil.copy2, source, destination)
        files.append({
            "relativePath": relative_path,
            "backupName": destination.name,
            "existed": True,
        })
    except OSError:
        # best effort — leave files list unchanged
        pass


async def harden(state_dir: Path, plugin_config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Snapshot state, then apply every auto-fixable control."""
    backup_dir = await _create_backup_dir(state_dir)
    config_path = get_config_path(state_dir)
    context = await create_audit_context(state_dir, plugin_config)
    actions: list[str] = []
    files: list[dict[str, Any]] = []

    await _backup_file(config_path, backup_dir / config_path.name, files, config_path.name)
    await _backup_file(state_dir / "AGENTS.md", backup_dir / "AGENTS.md", files, "AGENTS.md")

    for control in get_controls():
        remediate = control.get("remediate")
        if remediate is None:
            continue
        outcome = await control["describe"](context)
        if not outcome or not outcome.get("autoFixable"):
            continue
        action = await remediate(context)
        if action:
            actions.append(action)

    manifest = {
        "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actions": actions,
        "files": files,
    }
    payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    await asyncio.to_thread((backup_dir / "manifest.json").write_text, payload, encoding="utf-8")

    return {"backupDir": str(backup_dir), "actions": actions}


async def list_backups(state_dir: Path) -> list[str]:
    root = _backup_root(state_dir)
    try:
        entries = await asyncio.to_thread(lambda: sorted(p.name for p in root.iterdir() if p.is_dir()))
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []
    return list(reversed(entries))


async def rollback(state_dir: Path, backup_name: str | None = None) -> dict[str, Any]:
    backups = await list_backups(state_dir)
    selected = backup_name or (backups[0] if backups else None)
    if not selected:
        raise FileNotFoundError("No ClawKeeper backups found")

    backup_dir = _backup_root(state_dir) / selected
    manifest_path = backup_dir / "manifest.json"
    raw = await asyncio.to_thread(manifest_path.read_text, encoding="utf-8")
    manifest = json.loads(raw)

    for file in manifest["files"]:
        target = state_dir / file["relativePath"]
        if file.get("backupName"):
            source = backup_dir / file["backupName"]
            await asyncio.to_thread(target.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, source, target)
        else:
            try:
                await asyncio.to_thread(target.unlink)
            except FileNotFoundError:
                pass

    return {
        "backupDir": str(backup_dir),
        "restoredFiles": [f["relativePath"] for f in manifest["files"]],
    }
