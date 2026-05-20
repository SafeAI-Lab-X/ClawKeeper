"""Deterministic post-filter — the LLM proposes, this disposes.

The Watcher's LLM may emit `allow` for an action a deterministic guard
flagged as `block`. By design the LLM is advisory; the post-filter is
the boundary. This module implements that override logic.

Override rules (strictest wins):

  1. If ANY deterministic finding has `severity == "hardline"` or
     `severity == "critical"` AND `block == True`, the final decision is
     `deny`, regardless of what the Watcher proposed.
  2. If ANY deterministic finding has `block == True` (any severity)
     AND the Watcher proposed `allow`, override to `ask` (defer to
     human) — not `deny`, because the LLM might be right that the guard
     is a false positive in this context.
  3. Otherwise pass the Watcher's decision through unchanged.

The override always carries the reason of the highest-severity finding
that triggered it, so the audit trail explains *why* the LLM proposal
was vetoed.
"""

from __future__ import annotations

from typing import Any

_SEV_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
    "hardline": 4,
}


def _max_severity_block(findings: list[dict]) -> tuple[dict | None, str]:
    """Return the highest-severity blocking finding (or None)."""
    best: dict | None = None
    best_rank = -1
    for f in findings or []:
        if not f.get("block"):
            continue
        rank = _SEV_RANK.get(str(f.get("severity", "")).lower(), 0)
        if rank > best_rank:
            best = f
            best_rank = rank
    label = ""
    if best is not None:
        label = str(best.get("severity", "")).lower()
    return best, label


def apply_post_filter(
    *,
    watcher_proposal: dict,
    deterministic_findings: list[dict],
) -> dict:
    """Return a final decision dict after applying override rules.

    `watcher_proposal` shape:
        {decision: "allow"|"ask"|"deny", reason: str, severity: str, signals: [...], confidence: float?}

    Returned shape adds:
        post_filter_overrode: bool
        post_filter_reason: str  (only set when override happens)
    """
    proposal = dict(watcher_proposal)
    blocker, blocker_sev = _max_severity_block(deterministic_findings)

    # Rule 1: hardline/critical block → deny no matter what
    if blocker is not None and blocker_sev in ("hardline", "critical"):
        return {
            "decision": "deny",
            "reason": blocker.get("reason") or "hardline rule",
            "severity": blocker_sev,
            "signals": (proposal.get("signals") or []) + [f"hardline:{blocker.get('source','?')}"],
            "confidence": 1.0,
            "post_filter_overrode": True,
            "post_filter_reason": f"deterministic {blocker_sev} block ({blocker.get('source','?')})",
            "_blocker": blocker,
            "_watcher_proposal": watcher_proposal,
        }

    # Rule 2: non-hardline block but Watcher said allow → escalate to ask
    if blocker is not None and proposal.get("decision") == "allow":
        return {
            "decision": "ask",
            "reason": (
                f"Watcher proposed allow but deterministic guard flagged: "
                f"{blocker.get('reason') or '(no reason)'}"
            ),
            "severity": blocker_sev or "medium",
            "signals": (proposal.get("signals") or []) + [f"deterministic:{blocker.get('source','?')}"],
            "confidence": proposal.get("confidence", 0.5),
            "post_filter_overrode": True,
            "post_filter_reason": (
                f"watcher said allow, but {blocker.get('source','?')} flagged as "
                f"{blocker_sev or 'medium'}"
            ),
            "_blocker": blocker,
            "_watcher_proposal": watcher_proposal,
        }

    # Rule 3: pass through
    proposal["post_filter_overrode"] = False
    return proposal
