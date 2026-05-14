"""Judge — the decision engine. Ported from clawkeeper-watcher/.../context-judge.js.

The public surface is `Judge.evaluate(JudgeContext) -> Decision`. Detector signals
come from sibling modules (risk, drift, profile, guards) and are combined here.

NOTE (Phase 0 stub): the Phase 1 port will move the actual rule logic out of the
legacy JS file. For now this returns a placeholder Decision so adapter scaffolding
can be exercised end-to-end.
"""

from __future__ import annotations

from clawkeeper_core.schemas import Decision, JudgeContext, Outcome, Risk, Scope


class Judge:
    def __init__(self, policy=None, memory=None, risk=None, drift=None, profiler=None):
        self.policy = policy
        self.memory = memory
        self.risk = risk
        self.drift = drift
        self.profiler = profiler

    def evaluate(self, ctx: JudgeContext) -> Decision:
        """Synchronous decision path. To be filled in during Phase 1."""
        # Placeholder — always ASK while the port is in progress.
        return Decision(
            outcome=Outcome.ASK,
            scope=Scope.ONCE,
            risk=Risk.MEDIUM,
            reason="clawkeeper-core v0.2 scaffold — Judge.evaluate not yet implemented",
        )

    async def evaluate_async(self, ctx: JudgeContext) -> Decision:
        return self.evaluate(ctx)
