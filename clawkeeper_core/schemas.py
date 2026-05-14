"""Pydantic models — the type boundary between adapters and the core."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ── Primitives ──────────────────────────────────────────────────────────────


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Outcome(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class Scope(str, Enum):
    ONCE = "once"
    SESSION = "session"
    ALWAYS = "always"


# ── Conversation primitives ────────────────────────────────────────────────


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_name: str | None = None
    tool_call_id: str | None = None
    raw: dict[str, Any] | None = None


class ToolCall(BaseModel):
    id: str | None = None
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    result: str | None = None
    error: str | None = None


# ── Judge I/O ──────────────────────────────────────────────────────────────


class JudgeContext(BaseModel):
    """Everything a judge needs to decide about ONE tool call.

    Adapters build this from their framework's payload.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    messages: list[Message] = Field(default_factory=list)
    agent_id: str | None = None
    session_id: str | None = None
    workspace: Path | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Signal(BaseModel):
    """One sub-detector's contribution to a decision."""

    source: str  # e.g. "risk.fingerprint", "drift.intent", "guards.path"
    risk: Risk
    note: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Outcome
    scope: Scope = Scope.ONCE
    risk: Risk
    reason: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    signals: list[Signal] = Field(default_factory=list)
    schema_version: int = 1


# ── Policy ─────────────────────────────────────────────────────────────────


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_risk_before_stop: Risk = Risk.CRITICAL
    require_user_confirmation_for: list[str] = Field(
        default_factory=lambda: ["exec", "bash", "shell", "network", "write"]
    )
    auto_continue_allowed: bool = False
    max_tool_steps_without_user_turn: int = 3
    treat_command_execution_as_high_risk: bool = True
    schema_version: int = 1


# ── Persisted records ──────────────────────────────────────────────────────


class DecisionRecord(BaseModel):
    """Append-only entry in DecisionMemory."""

    ts: datetime
    context: JudgeContext
    decision: Decision
    fingerprint: str  # stable id for ALWAYS_ALLOW/DENY lookups
    schema_version: int = 1


class AgentEvent(BaseModel):
    """Anything observable about agent behavior, fed to the profiler."""

    ts: datetime
    agent_id: str
    session_id: str | None = None
    kind: Literal["tool_start", "tool_complete", "llm_input", "llm_output", "message", "decision"]
    payload: dict[str, Any] = Field(default_factory=dict)
