"""Smoke tests — exercise the v0.2 scaffold end-to-end before any real porting."""

from clawkeeper_core import Decision, Judge, JudgeContext
from clawkeeper_core.schemas import Outcome


def test_imports_resolve():
    judge = Judge()
    ctx = JudgeContext(tool_name="bash", tool_args={"command": "ls /"})
    decision = judge.evaluate(ctx)
    assert isinstance(decision, Decision)
    assert decision.outcome in {Outcome.ALLOW, Outcome.ASK, Outcome.DENY}


def test_decision_serializes_roundtrip():
    judge = Judge()
    ctx = JudgeContext(tool_name="bash", tool_args={"command": "ls"})
    d = judge.evaluate(ctx)
    blob = d.model_dump_json()
    d2 = Decision.model_validate_json(blob)
    assert d == d2


def test_judge_context_rejects_unknown_field():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        JudgeContext.model_validate({"tool_name": "x", "not_a_field": 1})
