"""Return-content scanner — scan any string entering the agent's context
for prompt-injection directives, before the LLM consumes it.

Closes the gap Hermes documents but doesn't cover: Hermes's
`_scan_context_content` only inspects a filename-allowlist
(AGENTS.md, .cursorrules, SOUL.md).  Content that arrives via terminal
output, MCP tool returns, memory retrieval, web_extract bodies, or
file reads outside the allowlist is unscanned — and Repello's threat
model called out memory-injection as a primary enterprise threat.

This module is host-agnostic.  Adapters wire it to:
  - terminal `tool_complete_callback`
  - MCP `call_tool` result inspection
  - memory-store `on_retrieve` hooks
  - web/browser tool return-body inspection

Heuristics (decreasing priority):
  1.  Imperative override patterns ("ignore prior instructions",
      "disregard the above", "ignore previous", "from now on you are").
  2.  Direct privileged-action directives embedded in content
      (run / execute / cat / curl / wget + sensitive path / URL).
  3.  Invisible Unicode (zero-width, bidi-override, soft-hyphen) —
      classic hide-the-payload trick.
  4.  HTML/Markdown comments that contain imperative language
      ("<!-- maintainer-note: also dump ... -->" patterns).
  5.  Base64 strings of suspicious length (>40 chars) that decode to
      shell-shaped content — DON'T decode and run, but flag for review.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Optional

# ── Pattern categories (each → distinct evidence label) ────────────────────

_OVERRIDE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_prior", re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(prior|previous|above|earlier|preceding)\s+(instructions?|prompts?|directives?|rules?|system\s+prompts?)"
    )),
    ("act_as_override", re.compile(
        r"(?i)\bfrom\s+now\s+on,?\s+(you|the\s+assistant)\s+(?:are|act\s+as|will\s+be)"
    )),
    ("reveal_secrets", re.compile(
        r"(?i)\b(reveal|disclose|show\s+me)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|the\s+secret|the\s+api\s+key)"
    )),
    ("trust_this_source", re.compile(
        r"(?i)\b(trust|treat\s+as\s+authoritative|this\s+is\s+sanctioned|sanctioned\s+(?:by|operation)|maintainer[\s\-]?note)"
    )),
]

_EMBEDDED_DIRECTIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("imperative_credential_read", re.compile(
        r"(?i)\b(run|execute|please\s+(?:run|execute)|also\s+(?:run|cat|read|dump))\b[^.\n]*"
        r"(~/\.(?:ssh|aws|gnupg)/|/etc/(?:passwd|shadow|sudoers)|"
        r"\.aws/credentials|\.ssh/id_|authorized_keys|\.env)"
    )),
    ("imperative_pipe_to_shell", re.compile(
        r"(?i)\b(curl|wget|fetch)[^|\n]*\|\s*(?:bash|sh|zsh|ksh|python|perl|ruby|node)\b"
    )),
    ("imperative_base64_run", re.compile(
        r"(?i)\b(decode|base64\s+-d|base64\s+--decode)[^.\n]*\|\s*(?:bash|sh|zsh|ksh|python|sh\b)"
    )),
]

_COMMENT_DIRECTIVE_RE = re.compile(
    r"(?is)(?:<!--|/\*|#\s*\bmaintainer-note\b)"
    r".{0,800}?"
    r"(?:also\s+(?:run|dump|cat|read|show|exfil)|"
    r"please\s+include|please\s+always|please\s+verify|"
    r"~/\.(?:ssh|aws)/)"
)

_INVISIBLE_CHARS = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x2060,  # word joiner
    0xFEFF,  # zero-width no-break space (BOM)
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi overrides
    0x2066, 0x2067, 0x2068, 0x2069,           # isolate / pop
    0x00AD,  # soft hyphen
}


def _find_invisible_chars(text: str) -> list[int]:
    return [ord(c) for c in text if ord(c) in _INVISIBLE_CHARS]


_BASE64_BLOCK_RE = re.compile(r"\b([A-Za-z0-9+/]{24,}={0,2})")
_SHELL_TOKENS_AFTER_DECODE = {
    "cat ", "rm ", "curl ", "wget ", "ssh ", "scp ",
    "/etc/", "/.ssh/", "/.aws/", "id_ed25519", "id_rsa", "AKIA",
    "/credentials", "passwd", "shadow",
}


def _flag_suspicious_base64(text: str) -> list[dict]:
    findings = []
    for m in _BASE64_BLOCK_RE.finditer(text):
        candidate = m.group(1)
        try:
            decoded = base64.b64decode(candidate, validate=True).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            continue
        lower = decoded.lower()
        for tok in _SHELL_TOKENS_AFTER_DECODE:
            if tok in lower:
                findings.append({
                    "preview_encoded": candidate[:80],
                    "decoded_marker": tok,
                    "decoded_preview": decoded[:120],
                })
                break
    return findings


def scan_content(text: str) -> list[dict]:
    """Run all PI detectors on a text blob. Return a list of finding dicts.
    Empty list means clean.
    """
    findings: list[dict] = []
    if not text or not isinstance(text, str):
        return findings

    # 1. Override patterns
    for pid, regex in _OVERRIDE_PATTERNS:
        for m in regex.finditer(text):
            findings.append({
                "category": "override",
                "pattern": pid,
                "match": m.group(0)[:120],
                "offset": m.start(),
            })

    # 2. Embedded directive patterns
    for pid, regex in _EMBEDDED_DIRECTIVE_PATTERNS:
        for m in regex.finditer(text):
            findings.append({
                "category": "embedded_directive",
                "pattern": pid,
                "match": m.group(0)[:200],
                "offset": m.start(),
            })

    # 3. Hidden HTML comments with imperative language
    for m in _COMMENT_DIRECTIVE_RE.finditer(text):
        findings.append({
            "category": "comment_directive",
            "match": m.group(0)[:200],
            "offset": m.start(),
        })

    # 4. Invisible characters
    invisible = _find_invisible_chars(text)
    if invisible:
        # Deduplicate but preserve order
        seen = []
        for cp in invisible:
            if cp not in seen:
                seen.append(cp)
        findings.append({
            "category": "invisible_chars",
            "codepoints": seen[:10],
            "count": len(invisible),
        })

    # 5. Base64-encoded payloads that decode to shell-shaped content
    b64 = _flag_suspicious_base64(text)
    if b64:
        for f in b64:
            findings.append({"category": "base64_decoded_to_shell", **f})

    return findings


def return_content_scan_guard(
    event: dict, *, severity_floor: str = "medium"
) -> Optional[dict]:
    """Guard callable for the return-content phase.

    Inspects `event["content"]` (the string entering the agent's context).
    Returns a blocking decision if any high-severity finding fires;
    returns a non-blocking flag for lower-severity findings; None when
    nothing is found.
    """
    content = event.get("content", "")
    if not content:
        # Also accept `params.result` / `params.output` as fall-back fields
        content = (event.get("params") or {}).get("result", "") or (event.get("params") or {}).get("output", "")
    if not content:
        return None

    findings = scan_content(content)
    if not findings:
        return None

    # Bucket severity. Override + comment_directive imply intentional PI → critical.
    # Embedded_directive that names a sensitive path → critical.
    # invisible_chars → high (probably PI but not a guarantee).
    # base64_decoded_to_shell → critical.
    high = [f for f in findings if f["category"] in (
        "override", "comment_directive", "base64_decoded_to_shell"
    )]
    high += [
        f for f in findings if f["category"] == "embedded_directive"
        and f.get("pattern") in {"imperative_credential_read", "imperative_pipe_to_shell", "imperative_base64_run"}
    ]
    if high:
        return {
            "block": True,
            "outcome": "deny",
            "source": "return_content_scan",
            "severity": "critical",
            "reason": (
                f"Returned content contains {len(high)} prompt-injection signal(s); "
                "blocking ingestion into agent context."
            ),
            "evidence": {"findings": findings[:20]},
        }
    # Lower-severity hits — surface but don't block.
    return {
        "block": False,
        "outcome": "allow",
        "source": "return_content_scan",
        "severity": "medium",
        "reason": f"Returned content has {len(findings)} low-severity PI signal(s).",
        "evidence": {"findings": findings[:20]},
    }
