"""DecisionMemory — append-only log of past decisions. Phase 0 stub.

Ported (TBD) from clawkeeper-watcher/.../decision-memory.js
"""

from __future__ import annotations

from datetime import datetime

from clawkeeper_core.schemas import Decision, DecisionRecord, JudgeContext


class DecisionMemory:
    def __init__(self) -> None:
        self._records: list[DecisionRecord] = []

    def append(self, ctx: JudgeContext, decision: Decision) -> None:
        from datetime import timezone
        self._records.append(
            DecisionRecord(
                ts=datetime.now(timezone.utc),
                context=ctx,
                decision=decision,
                fingerprint="todo",
            )
        )

    def lookup(self, fingerprint: str) -> Decision | None:
        for r in reversed(self._records):
            if r.fingerprint == fingerprint:
                return r.decision
        return None
