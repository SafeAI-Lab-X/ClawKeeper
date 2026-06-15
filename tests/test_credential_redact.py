"""Unit tests for clawkeeper_core.guards.credential_redact."""

from __future__ import annotations

import pytest

from clawkeeper_core.guards.credential_redact import (
    PLACEHOLDER,
    credential_redact_guard,
    redact,
)


# ── Pattern coverage ───────────────────────────────────────────────────────


@pytest.mark.parametrize("token", [
    "ghp_1234567890abcdef1234567890abcdef12",
    "ghs_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ",
    "gho_XXXXYYYYZZZZ11112222333344445555",
])
def test_redacts_github_tokens(token):
    out, reds = redact(f"set GITHUB_TOKEN={token}")
    assert token not in out
    assert PLACEHOLDER in out
    assert any(r.pattern_id == "github_pat" for r in reds)


def test_redacts_openai_key():
    text = 'export OPENAI_API_KEY="sk-fNTCcAw3WhKcKddW36K7f1zziS2gMXL7VXrn2nIPtM6ehMYu"'
    out, reds = redact(text)
    assert "sk-fNT" not in out
    assert any(r.pattern_id in {"openai_key", "generic_secret_kv"} for r in reds)


def test_redacts_anthropic_key():
    out, reds = redact("ANTHROPIC_API_KEY=sk-ant-abc123def456ghi789jklmnop")
    assert "sk-ant-" not in out
    assert reds


def test_redacts_aws_access_key_id():
    out, _ = redact("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_redacts_aws_secret_access_key():
    out, _ = redact(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    assert "wJalrXUtnFEMI" not in out


def test_redacts_authorization_bearer_header():
    text = "Authorization: Bearer abc.def.ghi-jkl_mno"
    out, _ = redact(text)
    assert "abc.def.ghi" not in out


def test_redacts_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.X8X8X8X8X8X8X8X8X8X8X8X8X"
    out, _ = redact(f"token={jwt}")
    assert jwt not in out


def test_redacts_ssh_private_key_block():
    block = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAA\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    out, _ = redact(f"key data:\n{block}\ntail")
    assert "b3BlbnNzaC1r" not in out
    assert PLACEHOLDER in out


def test_clean_text_no_redaction():
    out, reds = redact("This is just a normal sentence about tokens but no secret.")
    assert reds == []
    assert out == "This is just a normal sentence about tokens but no secret."


# ── Guard interface ────────────────────────────────────────────────────────


def test_guard_mutates_event_content_field():
    event = {
        "toolName": "terminal",
        "content": "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789xx",
    }
    d = credential_redact_guard(event)
    assert d is not None
    assert d["block"] is False  # never blocks — scrubs
    assert PLACEHOLDER in event["content"]
    assert "ghp_abc" not in event["content"]
    assert d["evidence"]["redactions"]


def test_guard_mutates_params_result_field():
    event = {
        "toolName": "terminal",
        "params": {"result": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
    }
    d = credential_redact_guard(event)
    assert d is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in event["params"]["result"]


def test_guard_returns_none_on_clean_content():
    event = {"toolName": "terminal", "content": "normal program output here"}
    assert credential_redact_guard(event) is None
