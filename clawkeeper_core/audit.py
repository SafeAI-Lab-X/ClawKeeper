"""Audit engine — runs the control catalogue and scores findings.

Ported from legacy/clawkeeper-watcher/.../audit-engine.js.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clawkeeper_core.controls import get_controls
from clawkeeper_core.metadata import PLUGIN_NAME, VERSION
from clawkeeper_core.state import get_config_path, get_soul_path, read_json_if_exists

_SCORE_BY_SEVERITY = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}


async def create_audit_context(state_dir: Path, plugin_config: dict[str, Any] | None = None) -> dict[str, Any]:
    pc = plugin_config or {}
    config_path = get_config_path(state_dir)
    config = await read_json_if_exists(config_path)
    return {
        "stateDir": state_dir,
        "configPath": config_path,
        "soulPath": get_soul_path(state_dir),
        "config": config,
        "strictMode": bool(pc.get("strictMode")),
    }


async def run_audit(context: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for control in get_controls():
        outcome = await control["describe"](context)
        if not outcome:
            continue
        auto_fixable = outcome.get("autoFixable")
        if auto_fixable is None:
            auto_fixable = bool(control.get("remediate"))
        severity = outcome.get("severity") or control["severity"]
        findings.append({
            "id": control["id"],
            "category": control["category"],
            "threat": control["threat"],
            "intent": control["intent"],
            "severity": severity,
            "title": control["title"],
            "description": outcome.get("description"),
            "evidence": outcome.get("evidence") or {},
            "remediation": outcome.get("remediation"),
            "autoFixable": auto_fixable,
            "canAutoFix": auto_fixable,
            "nextStep": _build_next_step(
                auto_fixable=auto_fixable,
                severity=severity,
                remediation=outcome.get("remediation"),
                id=control["id"],
            ),
        })

    return {
        "tool": PLUGIN_NAME,
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "stateDir": str(context["stateDir"]),
        "configPath": str(context["configPath"]),
        "score": _calculate_score(findings),
        "summary": _summarize(findings),
        "threatSummary": _summarize_threats(findings),
        "nextSteps": _build_next_steps(findings),
        "findings": findings,
    }


def _calculate_score(findings: list[dict[str, Any]]) -> int:
    deducted = sum(_SCORE_BY_SEVERITY.get(f["severity"], 0) for f in findings)
    return max(0, 100 - deducted)


def _summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "autoFixable": 0}
    for item in findings:
        bucket = item["severity"].lower()
        if bucket in summary:
            summary[bucket] += 1
        if item["autoFixable"]:
            summary["autoFixable"] += 1
    return summary


def _summarize_threats(findings: list[dict[str, Any]]) -> dict[str, int]:
    threats: dict[str, int] = {}
    for item in findings:
        threats[item["threat"]] = threats.get(item["threat"], 0) + 1
    return threats


def _build_next_step(*, auto_fixable: bool, severity: str, remediation: str | None, id: str) -> str:
    if auto_fixable:
        return (
            f"Can be auto-fixed. First run `clawkeeper-server harden`, then re-run audit "
            f"to verify {id}."
        )
    if severity in ("CRITICAL", "HIGH"):
        return (
            f'Manual action required. Fix according to "{remediation}", then re-run audit.'
        )
    return (
        f'After adjusting per "{remediation}", re-run audit to confirm the results.'
    )


def _build_next_steps(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["No issues found. Continue maintaining security posture and regularly run audits."]

    critical_or_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    auto_fixable = [f for f in findings if f["autoFixable"]]
    manual = [f for f in findings if not f["autoFixable"]]
    steps: list[str] = []

    if critical_or_high:
        steps.append(f"Address high-severity items first: {', '.join(f['id'] for f in critical_or_high)}.")
    if auto_fixable:
        steps.append("Run `clawkeeper-server harden` for items that can be auto-fixed.")
    if manual:
        steps.append(f"Items requiring manual fixes: {', '.join(f['id'] for f in manual)}.")
    steps.append("After fixes are complete, re-run audit to verify.")
    return steps
