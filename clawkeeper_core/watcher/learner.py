"""Pattern synthesis and persistence for ClawKeeper self-improvement.

When the Watcher's LLM catches a bypass that deterministic guards missed,
this module synthesizes a minimal regex, validates it against a benign
corpus, persists it locally, and optionally pushes an anonymized fingerprint
upstream (opt-in via CK_LEARN_ENDPOINT).

Zero setup required for local learning. Upstream sharing requires setting
CK_LEARN_ENDPOINT to a URL that accepts POST JSON.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import tempfile
import threading
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clawkeeper_core.bounded_regex import (
    MAX_PATTERN_SET_CHARS,
    MAX_PATTERNS,
    MAX_TEXT_CHARS,
    MAX_TEXTS,
)
from clawkeeper_core.guards.credential_redact import redact
from clawkeeper_core.learned_rules import (
    BENIGN_COMMANDS,
    LearnedRule,
    audit,
    rule_id,
    target_texts,
    validate_rule,
)

_STORE_PATH = Path.home() / ".clawkeeper" / "learned_patterns.json"
_CANDIDATE_CONFIDENCE = 0.6
_MAX_STORE_BYTES = 8 * 1024 * 1024

_BENIGN_CORPUS = list(BENIGN_COMMANDS)

_SYNTHESIS_PROMPT = """\
You are a security pattern extractor for ClawKeeper.

A command bypassed all deterministic guards but was flagged by the Watcher:
  tool: {tool_name}
  command: {command}
  normalized candidate paths: {paths}
  watcher reason: {reason}

Extract a minimal Python regex (re.IGNORECASE) that:
1. Matches this command and close variants
2. Does NOT match any of: {benign}
3. Is as specific as possible — anchor to the dangerous part, not generic tokens
4. Target semantics: exec_gate searches command text; script_body_scan searches the
   command body as regex (not a literal marker); path_guard searches normalized
   absolute paths extracted from arguments, not the surrounding shell command.

Output ONLY JSON (no prose, no fence):
{{"pattern": "...", "guard_target": "exec_gate|script_body_scan|path_guard", "confidence": 0.0}}

Output the JSON null literal if no reliable pattern can be extracted.
"""

_JSON_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


@dataclass
class PatternCandidate:
    pattern: str
    source_command: str  # source sample; never included in rule snapshots
    guard_target: str    # "exec_gate" | "script_body_scan" | "path_guard"
    confidence: float
    created_at: str      # ISO-8601 UTC
    source_tool_name: str = "terminal"
    source_args: dict | None = None
    source_texts: list[str] | None = None


_PRIVATE_KEYS = frozenset({"env", "environment", "headers", "body"})
_CREDENTIAL_SUFFIXES = (
    "authorization", "cookie", "apikey", "token", "password", "passwd", "secret", "credentials",
)


def minimal_params(args: dict | None, command: str) -> dict:
    """Preserve generic/nested guard inputs while masking private fields."""
    if args is None:
        return {"command": scrub_sample(command)}
    if not isinstance(args, dict):
        raise ValueError("invalid source arguments")
    remaining = MAX_TEXTS

    def sanitize(value):
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("too many source inputs")
        if isinstance(value, str):
            return scrub_sample(value)
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = re.sub(r"[^a-z]", "", key.lower())
                private = normalized in _PRIVATE_KEYS or normalized.endswith(_CREDENTIAL_SUFFIXES)
                result[key] = "[REDACTED]" if private else sanitize(item)
            return result
        return value

    return sanitize(args)


_SHORT_SECRET = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|password|passwd|secret|authorization|cookie)\b['\"]?\s*[:=]\s*)"
    r"(?:'[^'\n]*'|\"[^\"\n]*\"|[^\s;&,'\"]+)"
)
_AUTH_HEADER = re.compile(r"(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/'\"]+@")


def scrub_sample(text: str) -> str:
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        raise ValueError("invalid source sample size")
    text = _AUTH_HEADER.sub("[REDACTED]", text)
    text = _URL_USERINFO.sub(r"\1[REDACTED]@", text)
    return _SHORT_SECRET.sub(r"\1[REDACTED]", redact(text)[0])


def minimize_candidate(candidate: PatternCandidate) -> PatternCandidate:
    if candidate.source_texts is None:
        texts = target_texts(candidate.guard_target, {
            "toolName": candidate.source_tool_name,
            "params": minimal_params(candidate.source_args, candidate.source_command),
        })
    else:
        texts = candidate.source_texts
    if (not isinstance(texts, list) or not texts or len(texts) > MAX_TEXTS
            or any(not isinstance(t, str) or len(t) > MAX_TEXT_CHARS for t in texts)):
        raise ValueError("invalid source sample")
    return replace(candidate, source_command="", source_args=None,
                   source_texts=[scrub_sample(text) for text in texts])


class StoreUnavailableError(ValueError):
    """Unreadable stores must not be overwritten or treated as clean policy."""


class StoreCapacityError(ValueError):
    """A new record must not make the existing store unreadable."""


def validate_candidate(candidate: PatternCandidate) -> LearnedRule:
    if (isinstance(candidate.confidence, bool) or not isinstance(candidate.confidence, (float, int))
            or not math.isfinite(candidate.confidence)):
        raise ValueError("invalid candidate confidence")
    if not _CANDIDATE_CONFIDENCE <= candidate.confidence <= 1.0:
        raise ValueError("candidate confidence below threshold or outside range")
    candidate = minimize_candidate(candidate)
    if scrub_sample(candidate.pattern) != candidate.pattern:
        raise ValueError("credential-shaped pattern rejected")
    return validate_rule(candidate.pattern, candidate.guard_target, source_texts=candidate.source_texts)


class LearnedPatternStore:
    """Thread-safe JSON store at ~/.clawkeeper/learned_patterns.json."""

    def __init__(self, path: Path = _STORE_PATH):
        self._path = path
        self._lock = threading.Lock()

    def _load(self) -> list[dict]:
        try:
            with self._path.open("rb") as stream:
                data = stream.read(_MAX_STORE_BYTES + 1)
            if len(data) > _MAX_STORE_BYTES:
                raise ValueError("learned store exceeds byte limit")
            records = json.loads(data)
            if not isinstance(records, list):
                raise ValueError("learned store must contain a JSON array")
            if len(records) > MAX_PATTERNS:
                raise ValueError("too many learned records")
            return records
        except FileNotFoundError:
            return []
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            raise StoreUnavailableError("learned store unavailable") from exc

    def _save(self, records: list[dict]) -> None:
        serialized = json.dumps(records, indent=2)
        if len(serialized.encode("utf-8")) > _MAX_STORE_BYTES:
            raise StoreCapacityError("learned store exceeds byte limit")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Readers always see a complete JSON document, including across processes.
        descriptor, name = tempfile.mkstemp(dir=self._path.parent, prefix=".learned-")
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(serialized)
            os.replace(name, self._path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def all(self) -> list[PatternCandidate]:
        with self._lock:
            candidates = []
            records = self._load()
            migrated = []
            for record in records:
                try:
                    candidate = PatternCandidate(**record)
                except (TypeError, ValueError):
                    audit("rejected", level=logging.WARNING, skip_reason="invalid stored record")
                    if isinstance(record, dict):
                        sanitized_record = dict(record)
                        for field, empty in (("source_args", None), ("source_command", ""), ("source_texts", [])):
                            if field in sanitized_record:
                                sanitized_record[field] = empty
                        migrated.append(sanitized_record)
                    else:
                        migrated.append(record)
                    continue
                try:
                    safe = minimize_candidate(candidate)
                except (TypeError, ValueError, AttributeError, RecursionError):
                    safe = replace(candidate, source_command="", source_args=None, source_texts=[])
                candidates.append(safe)
                migrated.append(asdict(safe))
            if migrated != records:
                try:
                    self._save(migrated)
                except (OSError, StoreCapacityError) as exc:
                    raise StoreUnavailableError("source privacy migration failed") from exc
            return candidates

    def contains_equivalent(self, pattern: str, guard_target: str | None = None) -> bool:
        """Compatibility query; actual admission uses target-aware validation."""
        try:
            validate_rule(pattern, guard_target or "exec_gate")
        except (TypeError, ValueError):
            return True
        with self._lock:
            return any(r.get("pattern") == pattern and
                       (guard_target is None or r.get("guard_target") == guard_target)
                       for r in self._load() if isinstance(r, dict))

    def add(self, candidate: PatternCandidate) -> bool:
        try:
            candidate = minimize_candidate(candidate)
            rule = validate_candidate(candidate)
        except (TypeError, ValueError) as exc:
            audit("rejected", level=logging.WARNING, skip_reason=str(exc))
            return False
        audit("validated", rule_id=rule.id, guard_target=rule.guard_target)
        with self._lock:
            records = self._load()
            pattern_chars = sum(len(r["pattern"]) for r in records
                                if isinstance(r, dict) and isinstance(r.get("pattern"), str))
            if len(records) >= MAX_PATTERNS or pattern_chars + len(candidate.pattern) > MAX_PATTERN_SET_CHARS:
                audit("rejected", rule_id=rule.id, skip_reason="store_capacity")
                return False
            if any(isinstance(r, dict) and r.get("pattern") == candidate.pattern and
                   r.get("guard_target") == candidate.guard_target for r in records):
                audit("rejected", rule_id=rule.id, skip_reason="duplicate")
                return False
            records.append(asdict(candidate))
            try:
                self._save(records)
            except StoreCapacityError:
                audit("rejected", rule_id=rule.id, skip_reason="store_byte_capacity")
                return False
        audit("stored", rule_id=rule.id, guard_target=rule.guard_target)
        return True

    def remove(self, pattern_hash: str) -> bool:
        with self._lock:
            records = self._load()
            before = len(records)
            records = [r for r in records
                       if not (isinstance(r, dict) and isinstance(r.get("pattern"), str) and
                               (hashlib.sha256(r["pattern"].encode()).hexdigest() == pattern_hash or
                                rule_id(r.get("guard_target", ""), r["pattern"]) == pattern_hash))]
            if len(records) == before:
                return False
            self._save(records)
        return True


# Module-level singleton
STORE = LearnedPatternStore()


def synthesize_pattern(
    command: str,
    reason: str,
    model: Any,
    *,
    tool_name: str = "terminal",
    args: dict | None = None,
) -> PatternCandidate | None:
    """Ask the LLM to extract a minimal regex from a bypassing command."""
    safe_params = minimal_params(args, command)
    prompt = _SYNTHESIS_PROMPT.format(
        tool_name=tool_name,
        command=json.dumps(safe_params)[:1500],
        paths=json.dumps(target_texts("path_guard", {
            "toolName": tool_name, "params": safe_params,
        })),
        reason=redact(reason)[0][:300],
        benign=", ".join(f'"{b}"' for b in _BENIGN_CORPUS),
    )
    try:
        messages = [{"role": "user", "content": prompt}]
        response = model(messages)
        raw = getattr(response, "content", str(response))
    except Exception:
        return None

    # Parse JSON from response
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if raw.lower() in ("null", "none", ""):
        return None
    obj: dict | None = None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        m = _JSON_RE.search(raw)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    if not isinstance(obj, dict):
        return None

    try:
        candidate = PatternCandidate(
            pattern=obj.get("pattern", ""), source_command=command,
            guard_target=obj.get("guard_target", ""),
            confidence=float(obj.get("confidence", 0.0)),
            created_at=datetime.now(UTC).isoformat(),
            source_tool_name=tool_name, source_args=args,
        )
        candidate = minimize_candidate(candidate)
        validate_candidate(candidate)
    except (TypeError, ValueError) as exc:
        audit("rejected", skip_reason=str(exc))
        return None
    return candidate


def maybe_push_upstream(candidate: PatternCandidate) -> None:
    """Fire-and-forget POST of anonymized fingerprint to CK_LEARN_ENDPOINT."""
    endpoint = os.environ.get("CK_LEARN_ENDPOINT", "").strip()
    if not endpoint:
        return
    import threading as _t  # noqa: PLC0415 -- opt-in sharing only
    def _push():
        try:
            import httpx  # noqa: PLC0415 -- opt-in sharing only
            httpx.post(
                endpoint,
                json={
                    "pattern_hash": hashlib.sha256(candidate.pattern.encode()).hexdigest(),
                    "guard_target": candidate.guard_target,
                    "confidence": candidate.confidence,
                },
                timeout=3.0,
            )
        except Exception:
            pass
    _t.Thread(target=_push, daemon=True).start()
