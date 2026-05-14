"""IntentDrift — intent extraction + tool-chain drift detection. Phase 0 stub.

Ported (TBD) from clawkeeper-watcher/.../intent-drift.js
"""

from __future__ import annotations

from clawkeeper_core.schemas import Message, ToolCall


class IntentDrift:
    def extract_intent(self, messages: list[Message]) -> dict:
        return {}

    def detect(self, intent: dict, tool_chain: list[ToolCall]) -> dict:
        return {"drift_score": 0.0, "severity": "low"}
