"""RiskEngine — pattern-based risk fingerprinting. Phase 0 stub.

Ported (TBD in Phase 1) from:
  - clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/risk-fingerprint.js
  - clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/security-rules.js
"""

from __future__ import annotations

from clawkeeper_core.schemas import JudgeContext, Risk


class RiskEngine:
    def __init__(self) -> None:
        self._patterns: list = []

    def fingerprint(self, ctx: JudgeContext) -> Risk:
        # Phase 1 will port the regex + behavioral pattern catalogue here.
        return Risk.LOW

    def add_pattern(self, pattern) -> None:
        self._patterns.append(pattern)
