"""Log + skill scanners.

Ported from
  - legacy/clawkeeper-watcher/.../security-scanner.js  (log analysis)
  - legacy/clawkeeper-watcher/.../skill-scanner.js     (skill-package linting)

Both produce structured findings consumable by the audit pipeline.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clawkeeper_core.security_rules import (
    ANOMALOUS_ACTIVITY_CONFIG,
    CREDENTIAL_LEAK_PATTERNS,
    DANGEROUS_COMMAND_PATTERNS,
    DETECTION_DESCRIPTIONS,
    HIGH_RISK_TOOLS,
    PROMPT_INJECTION_PATTERNS,
)
from clawkeeper_core.state import resolve_state_dir, resolve_user_openclaw_state_dir

_COMMAND_TOOL_RE = re.compile(r"^(exec|shell|spawn|bash|sh|command)$", re.IGNORECASE)


# ── Log scanner ────────────────────────────────────────────────────────────


def _extract_date_from_record(record: dict[str, Any]) -> str | None:
    ts = record.get("timestamp")
    if not isinstance(ts, str):
        return None
    try:
        # Normalize trailing 'Z' for fromisoformat in older Python; 3.11+ handles it.
        normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") and "+" not in ts else ts
        dt = datetime.fromisoformat(normalized)
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def _detect_prompt_injection(records: list[dict[str, Any]]) -> list[int]:
    affected: list[int] = []
    for i, record in enumerate(records):
        rtype = record.get("type")
        if rtype == "llm_input":
            content = (record.get("systemPrompt") or "") + " " + (record.get("prompt") or "")
        elif rtype in ("message_received", "message_sending"):
            content = record.get("content") or ""
        else:
            continue
        if not isinstance(content, str) or not content:
            continue
        if any(p.search(content) for p in PROMPT_INJECTION_PATTERNS):
            affected.append(i)
    return affected


def _detect_credential_leaks(records: list[dict[str, Any]]) -> list[int]:
    affected: list[int] = []
    for i, record in enumerate(records):
        rtype = record.get("type")
        if rtype == "llm_output":
            assistant_texts = record.get("assistantTexts") or []
            content = assistant_texts[0] if assistant_texts and isinstance(assistant_texts[0], str) else ""
        elif rtype == "message_sending":
            content = record.get("content") or ""
        else:
            continue
        if not isinstance(content, str) or not content:
            continue
        if any(p.search(content) for p in CREDENTIAL_LEAK_PATTERNS):
            affected.append(i)
    return affected


def _detect_dangerous_commands(records: list[dict[str, Any]]) -> list[int]:
    affected: list[int] = []
    for i, record in enumerate(records):
        if record.get("type") != "before_tool_call":
            continue
        tool_name = record.get("toolName") or ""
        if not _COMMAND_TOOL_RE.match(tool_name):
            continue
        params = record.get("params")
        if not params:
            continue
        params_str = json.dumps(params, ensure_ascii=False)
        if any(p.search(params_str) for p in DANGEROUS_COMMAND_PATTERNS):
            affected.append(i)
    return affected


def _detect_suspicious_tool_calls(records: list[dict[str, Any]]) -> list[int]:
    affected: list[int] = []
    for i, record in enumerate(records):
        if record.get("type") != "before_tool_call":
            continue
        tool_name = (record.get("toolName") or "").lower()
        if tool_name in HIGH_RISK_TOOLS:
            affected.append(i)
    return affected


def _detect_anomalous_activity(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[int]]:
    tool_counts: dict[str, int] = {}
    for record in records:
        if record.get("type") == "before_tool_call":
            name = record.get("toolName") or "unknown"
            tool_counts[name] = tool_counts.get(name, 0) + 1
    threshold = ANOMALOUS_ACTIVITY_CONFIG["toolCallThreshold"]  # type: ignore[index]
    anomalous = [{"toolName": n, "count": c} for n, c in tool_counts.items() if c > threshold]
    if not anomalous:
        return [], []
    flagged = {a["toolName"] for a in anomalous}
    affected = [
        i for i, r in enumerate(records)
        if r.get("type") == "before_tool_call" and r.get("toolName") in flagged
    ]
    return anomalous, affected


async def scan_logs_for_security_risks(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Run every detector over a list of log records. Returns a structured report."""
    records = records or []
    result: dict[str, Any] = {
        "date": _extract_date_from_record(records[0]) if records else None,
        "totalEvents": len(records),
        "risks": [],
        "statistics": {"byType": {}},
        "summary": {"riskCount": 0},
    }
    if not records:
        return result

    for record in records:
        rtype = record.get("type") or "unknown"
        result["statistics"]["byType"][rtype] = result["statistics"]["byType"].get(rtype, 0) + 1

    risks: list[dict[str, Any]] = []

    pi = _detect_prompt_injection(records)
    if pi:
        desc = DETECTION_DESCRIPTIONS["promptInjection"]
        risks.append({
            "title": desc["title"],
            "description": desc["describe"](len(pi)),  # type: ignore[operator]
            "affectedRecords": pi,
        })

    cl = _detect_credential_leaks(records)
    if cl:
        desc = DETECTION_DESCRIPTIONS["credentialLeak"]
        risks.append({
            "title": desc["title"],
            "description": desc["describe"](len(cl)),  # type: ignore[operator]
            "affectedRecords": cl,
        })

    dc = _detect_dangerous_commands(records)
    if dc:
        desc = DETECTION_DESCRIPTIONS["dangerousCommand"]
        risks.append({
            "title": desc["title"],
            "description": desc["describe"](len(dc)),  # type: ignore[operator]
            "affectedRecords": dc,
        })

    st = _detect_suspicious_tool_calls(records)
    if st:
        desc = DETECTION_DESCRIPTIONS["suspiciousToolCall"]
        risks.append({
            "title": desc["title"],
            "description": desc["describe"](len(st)),  # type: ignore[operator]
            "affectedRecords": st,
        })

    anomalous, affected = _detect_anomalous_activity(records)
    if anomalous:
        desc = DETECTION_DESCRIPTIONS["anomalousActivity"]
        risks.append({
            "title": desc["title"],
            "description": desc["describe"](anomalous),  # type: ignore[operator]
            "affectedRecords": affected,
        })

    result["risks"] = risks
    result["summary"]["riskCount"] = len(risks)
    return result


def format_scan_results(scan_result: dict[str, Any], records: list[dict[str, Any]] | None = None) -> str:
    if not scan_result or scan_result.get("totalEvents", 0) == 0:
        return "Scan Result: No log events available for analysis"

    records = records or []
    lines: list[str] = []
    lines.append(f"\nSecurity Scan Report - {scan_result.get('date') or 'Unknown Date'}\n")
    lines.append(
        f"Total Events Scanned: {scan_result['totalEvents']} | "
        f"Risks Detected: {scan_result['summary']['riskCount']}"
    )

    lines.append("\nEvent Type Statistics:")
    for rtype, count in (scan_result["statistics"].get("byType") or {}).items():
        lines.append(f"  - {rtype}: {count}")

    if scan_result["summary"]["riskCount"] > 0:
        lines.append("\nDetected Security Risks:")
        for risk in scan_result["risks"]:
            lines.append(f"  - {risk['title']}")
            if risk.get("description"):
                lines.append(f"    {risk['description']}")
            affected = risk.get("affectedRecords") or []
            if affected:
                lines.append(f"    Affected events: {len(affected)}")
    else:
        lines.append("\nNo security risks detected.")

    return "\n".join(lines)


async def save_security_scan_report(
    scan_result: dict[str, Any],
    records: list[dict[str, Any]] | None,
    state_dir: Path,
    filename: str,
) -> Path:
    report_dir = state_dir / "workspace" / "security-reports"
    await asyncio.to_thread(report_dir.mkdir, parents=True, exist_ok=True)
    report_date = scan_result.get("date") or filename.replace(".jsonl", "")
    report_path = report_dir / f"{report_date}-security-report.txt"
    content = format_scan_results(scan_result, records)
    await asyncio.to_thread(report_path.write_text, content, encoding="utf-8")
    return report_path


# ── Skill scanner ─────────────────────────────────────────────────────────


_DEFAULT_SKILL_RULES: dict[str, Any] = {
    "skillRiskPatterns": [
        {
            "id": "script.curl-pipe-bash",
            "target": "script",
            "mode": "regex",
            "pattern": r"curl\s+[^|]+\|\s*(?:bash|sh)",
            "severity": "HIGH",
            "title": "Pipe curl output directly into shell",
            "remediation": "Download the script, inspect it, then execute it explicitly.",
        },
        {
            "id": "script.disable-sip",
            "target": "script",
            "mode": "substring",
            "pattern": "csrutil disable",
            "severity": "CRITICAL",
            "title": "Disables macOS System Integrity Protection",
            "remediation": "Remove SIP-disabling commands; require recovery-mode confirmation instead.",
        },
        {
            "id": "skill.exec-tool-unbounded",
            "target": "skill",
            "mode": "regex",
            "pattern": r"unrestricted\s+execution|execute\s+arbitrary",
            "severity": "MEDIUM",
            "title": "Skill claims unbounded execution",
            "remediation": "Constrain skill operations to a documented allowlist.",
        },
    ],
    "suspiciousSkillNames": ["updater", "wallet", "installer", "miner", "telemetry"],
    "dangerousPrerequisitePatterns": [
        "disable system integrity",
        "turn off SIP",
        "disable secure boot",
        "run as administrator",
    ],
}


async def _resolve_skill_roots(options: dict[str, Any]) -> list[Path]:
    state = options.get("stateDir") if isinstance(options.get("stateDir"), str) else None
    if state:
        return [Path(state).resolve()]
    state_dir, user_state = await asyncio.gather(
        resolve_state_dir(), resolve_user_openclaw_state_dir()
    )
    return list(dict.fromkeys([user_state, state_dir]))  # dedup, preserve order


async def _resolve_skill_dir(input_path: str, skill_roots: list[Path]) -> Path:
    if not input_path:
        raise ValueError("Skill path or name is required")
    p = Path(input_path)
    if p.is_absolute() or "/" in input_path or input_path.startswith("."):
        return p.resolve()
    for root in skill_roots:
        candidate = root / "skills" / input_path
        if candidate.exists():
            return candidate
    return skill_roots[0] / "skills" / input_path


async def _load_skill_rules(rules_path: str | None) -> dict[str, Any]:
    if rules_path:
        raw = await asyncio.to_thread(Path(rules_path).read_text, encoding="utf-8")
        return json.loads(raw)
    return _DEFAULT_SKILL_RULES


def _collect_files(directory: Path) -> list[Path]:
    return [p for p in directory.rglob("*") if p.is_file()]


def _classify_target(rel_path: str) -> str:
    lower = rel_path.lower()
    if lower.endswith(".sh") or lower.endswith(".bash"):
        return "script"
    if rel_path == "SKILL.md" or lower.endswith(".md"):
        return "skill"
    return "other"


def _matches(content: str, pattern: dict[str, Any]) -> bool:
    if pattern.get("mode") == "substring":
        return str(pattern["pattern"]).lower() in content.lower()
    return bool(re.search(str(pattern["pattern"]), content, re.IGNORECASE))


def _extract_evidence(content: str, pattern: dict[str, Any]) -> dict[str, Any]:
    if pattern.get("mode") == "substring":
        return {"pattern": pattern["pattern"]}
    m = re.search(str(pattern["pattern"]), content, re.IGNORECASE)
    return {"pattern": pattern["pattern"], "match": m.group(0) if m else None}


def _evaluate_skill_name(skill_name: str, rules: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = skill_name.lower()
    findings: list[dict[str, Any]] = []
    parts = {p for p in re.split(r"[^a-z0-9]+", normalized) if p}

    if re.search(r"(clawh|skilkeeper|openclaww|officia1)", normalized, re.IGNORECASE):
        findings.append({
            "id": "name.typosquat-signal",
            "severity": "HIGH",
            "title": "Skill name shows typosquatting signal",
            "file": "(name)",
            "evidence": {"skillName": skill_name},
            "remediation": "Verify publisher, repository source, and installation source.",
            "canAutoFix": False,
            "nextStep": f"Confirm that {skill_name} is the expected skill.",
        })

    matched_theme = next(
        (t for t in (rules.get("suspiciousSkillNames") or []) if t in parts),
        None,
    )
    if matched_theme:
        findings.append({
            "id": "name.high-lure-theme",
            "severity": "LOW",
            "title": "Skill name uses high-lure theme keywords",
            "file": "(name)",
            "evidence": {"skillName": skill_name, "matchedTheme": matched_theme},
            "remediation": "Verify source for skills using keywords like updater, wallet, installer.",
            "canAutoFix": False,
            "nextStep": f"Document the source and purpose of {skill_name}.",
        })

    return findings


def _scan_prerequisites(content: str, rel_path: str, rules: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lower = content.lower()
    for phrase in (rules.get("dangerousPrerequisitePatterns") or []):
        if str(phrase).lower() not in lower:
            continue
        findings.append({
            "id": "docs.dangerous-prerequisite",
            "severity": "MEDIUM",
            "title": "README requires dangerous prerequisite operation",
            "file": rel_path,
            "evidence": {"phrase": phrase},
            "remediation": "Replace with a minimal-privilege installation flow.",
            "canAutoFix": False,
            "nextStep": f'Remove "{phrase}" from {rel_path} and re-scan.',
        })
    return findings


def _check_required_files(skill_dir: Path) -> list[dict[str, Any]]:
    required = [
        ("SKILL.md", "MEDIUM", "Missing skill main rules file",
         "Add SKILL.md with clear execution boundaries."),
        ("skill.json", "LOW", "Missing skill metadata file",
         "Add skill.json with name, version, and entry point."),
    ]
    findings: list[dict[str, Any]] = []
    for file, severity, title, remediation in required:
        if not (skill_dir / file).exists():
            slug = re.sub(r"[^a-z0-9]+", "-", file.lower())
            findings.append({
                "id": f"structure.missing-{slug}",
                "severity": severity,
                "title": title,
                "file": file,
                "evidence": {"exists": False},
                "remediation": remediation,
                "canAutoFix": False,
                "nextStep": f"Add {file}, then re-scan.",
            })
    return findings


def _calculate_skill_score(findings: list[dict[str, Any]]) -> int:
    weights = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 6, "LOW": 2}
    deducted = sum(weights.get(f["severity"], 0) for f in findings)
    return max(0, 100 - deducted)


def _summarize_skill_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        bucket = f["severity"].lower()
        if bucket in summary:
            summary[bucket] += 1
    return summary


def _build_skill_next_steps(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["No known dangerous patterns detected. Proceed with manual review of side-effect scripts."]
    high_risk = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    steps: list[str] = []
    if high_risk:
        steps.append(
            "Address high-risk items first: "
            + ", ".join(f"{f['id']}@{f['file']}" for f in high_risk)
            + "."
        )
    steps.append("Re-run skill scan after fixes.")
    return steps


async def scan_skill(input_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Scan a skill directory for dangerous patterns + missing required files."""
    opts = options or {}
    skill_roots = await _resolve_skill_roots(opts)
    skill_dir = await _resolve_skill_dir(input_path, skill_roots)
    rules = await _load_skill_rules(opts.get("rulesPath"))
    files = await asyncio.to_thread(_collect_files, skill_dir)

    skill_name = skill_dir.name
    findings: list[dict[str, Any]] = []
    findings.extend(_evaluate_skill_name(skill_name, rules))

    for file in files:
        rel = str(file.relative_to(skill_dir))
        try:
            content = await asyncio.to_thread(file.read_text, encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        target = _classify_target(rel)
        for pattern in (rules.get("skillRiskPatterns") or []):
            if pattern.get("target") != target:
                continue
            if not _matches(content, pattern):
                continue
            findings.append({
                "id": pattern["id"],
                "severity": pattern["severity"],
                "title": pattern["title"],
                "file": rel,
                "evidence": _extract_evidence(content, pattern),
                "remediation": pattern["remediation"],
                "canAutoFix": False,
                "nextStep": (
                    f"Check implementation related to {pattern['id']} in {rel}, "
                    f'then re-scan after applying "{pattern["remediation"]}".'
                ),
            })
        if rel.lower() == "readme.md":
            findings.extend(_scan_prerequisites(content, rel, rules))

    findings.extend(_check_required_files(skill_dir))

    return {
        "skillDir": str(skill_dir),
        "skillName": skill_name,
        "score": _calculate_skill_score(findings),
        "summary": _summarize_skill_findings(findings),
        "findings": findings,
        "nextSteps": _build_skill_next_steps(findings),
    }
