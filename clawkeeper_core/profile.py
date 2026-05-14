"""AgentProfiler — behavioral baseline + deviation. Phase 0 stub.

Ported (TBD) from clawkeeper-watcher/.../agent-profiler.js
"""

from __future__ import annotations

from clawkeeper_core.schemas import AgentEvent


class AgentProfiler:
    def __init__(self) -> None:
        self._events: list[AgentEvent] = []

    def update(self, event: AgentEvent) -> None:
        self._events.append(event)

    def baseline(self, agent_id: str) -> dict:
        return {}

    def deviation(self, agent_id: str, recent) -> dict:
        return {}
