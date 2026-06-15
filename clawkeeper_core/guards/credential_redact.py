"""Credential redaction — scrub secrets before they leave the host
boundary or reach the LLM.

Distilled from Hermes Sec doc §"Credential Redaction" — but generalised
beyond MCP error returns: reusable on terminal stdout, web_extract bodies,
log lines, agent messages, anything textual.

The classic patterns:
  - GitHub tokens (ghp_..., gho_..., ghs_..., ghu_..., ghr_...)
  - OpenAI / Anthropic keys (sk-..., sk-ant-...)
  - AWS access key id (AKIA..., ASIA...) + secret-key-shaped Base64
  - Bearer tokens in Authorization headers
  - Generic API key parameters (token=, key=, api_key=, password=, secret=)
  - JWT-shaped (xxx.yyy.zzz of base64url)
  - SSH private key blocks

Returns the scrubbed string + the list of redactions made (for audit).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

PLACEHOLDER = "[REDACTED]"


@dataclass(frozen=True)
class Redaction:
    pattern_id: str
    start: int
    end: int
    length: int


# Each entry: (id, regex). Order matters slightly — more-specific first.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # GitHub
    ("github_pat", re.compile(r"\bgh[psouar]_[A-Za-z0-9]{30,255}\b")),
    # OpenAI / Anthropic
    ("openai_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{16,128}\b")),
    # AWS
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    # Stripe
    ("stripe_key", re.compile(r"\b(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{24,99}\b")),
    # Bearer tokens in Authorization headers
    ("bearer_header", re.compile(
        r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._\-+/=]+"
    )),
    # JWT (3-segment base64url)
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
    )),
    # SSH private key block (multi-line; DOTALL)
    ("ssh_private_key", re.compile(
        r"-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519|PGP) PRIVATE KEY-----"
        r".*?-----END (?:OPENSSH|RSA|DSA|EC|ED25519|PGP) PRIVATE KEY-----",
        re.DOTALL,
    )),
    # Generic key=value forms (URL-encoded or shell-like)
    # Includes: token=..., api_key=..., apikey=..., password=..., secret=..., key=...
    # Allow ~120 chars of value; stop at whitespace, quote, ampersand, &, etc.
    ("generic_secret_kv", re.compile(
        r"(?i)\b(?:token|api[_\-]?key|apikey|password|passwd|secret|access[_\-]?key|client[_\-]?secret)"
        r"\s*[:=]\s*['\"]?"
        r"([A-Za-z0-9_\-\.+/=]{12,128})"
    )),
    # AWS secret access key (Base64-shaped, 40 chars)
    ("aws_secret_key", re.compile(
        r"(?i)(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40})\b"
    )),
]


def redact(text: str) -> tuple[str, list[Redaction]]:
    """Return (scrubbed_text, redactions). Idempotent."""
    if not text:
        return text, []
    redactions: list[Redaction] = []
    out = text
    for pattern_id, regex in _PATTERNS:
        # Replace each match in `out`, recording position relative to ORIGINAL.
        # For simplicity we record positions relative to the current `out` —
        # not perfect for downstream offset use but fine for audit counts.
        def _sub(m):
            redactions.append(
                Redaction(
                    pattern_id=pattern_id,
                    start=m.start(),
                    end=m.end(),
                    length=m.end() - m.start(),
                )
            )
            return PLACEHOLDER
        out = regex.sub(_sub, out)
    return out, redactions


def redact_lines(lines: Iterable[str]) -> tuple[list[str], list[Redaction]]:
    all_red: list[Redaction] = []
    out_lines: list[str] = []
    for line in lines:
        scrubbed, reds = redact(line)
        out_lines.append(scrubbed)
        all_red.extend(reds)
    return out_lines, all_red


def credential_redact_guard(event: dict) -> dict | None:
    """Guard usable as a post-tool-call / return-content scrubber.

    If the event's `content` or `params.result` contains credential
    patterns, the guard returns a `block=False` decision with
    `evidence.redacted_count` AND mutates `event["content"]` (and
    `event["params"]["result"]` if present) to the redacted form.

    The guard intentionally does NOT block — the goal is to scrub
    sensitive content before the LLM sees it, not to prevent the call.
    For hard-blocking on credential exposure, layer this with
    `return_content_scan` or `path_guard`.
    """
    fields_to_check = [
        ("content", event.get("content", "")),
        ("params.result", (event.get("params") or {}).get("result", "")),
        ("params.output", (event.get("params") or {}).get("output", "")),
    ]
    any_hit = False
    total_redactions: list[dict] = []
    for path, value in fields_to_check:
        if not value or not isinstance(value, str):
            continue
        scrubbed, reds = redact(value)
        if reds:
            any_hit = True
            # Write the scrubbed value back into the event
            if path == "content":
                event["content"] = scrubbed
            elif path == "params.result":
                event.setdefault("params", {})["result"] = scrubbed
            elif path == "params.output":
                event.setdefault("params", {})["output"] = scrubbed
            total_redactions.extend({"field": path, "pattern": r.pattern_id, "length": r.length} for r in reds)

    if any_hit:
        return {
            "block": False,
            "outcome": "allow",
            "source": "credential_redact",
            "severity": "medium",
            "reason": f"Redacted {len(total_redactions)} credential pattern(s) from tool output",
            "evidence": {"redactions": total_redactions},
        }
    return None
