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
    RegexResourceError,
)
from clawkeeper_core.command_facts import FACT_VERSION
from clawkeeper_core.execution import analysis_scope
from clawkeeper_core.guards.credential_redact import redact, scrub_context
from clawkeeper_core.learned_rules import (
    BENIGN_COMMANDS,
    VALIDATION_VERSION,
    LearnedRule,
    audit,
    checked_subject,
    rule_id,
    target_texts,
    validate_rule,
)

_STORE_PATH = Path.home() / ".clawkeeper" / "learned_patterns.json"
_CANDIDATE_CONFIDENCE = 0.6
_MAX_STORE_BYTES = 8 * 1024 * 1024
_NAME_ONLY_VIEW_VERSION = 3

_BENIGN_CORPUS = list(BENIGN_COMMANDS)

_SYNTHESIS_PROMPT = """\
You are a security pattern extractor for ClawKeeper.

A command bypassed all deterministic guards but was flagged by the Watcher:
  tool: {tool_name}
  command: {command}
  normalized candidate paths: {paths}
  normalized invocation/operation views: {views}
  stable fact fields (same parser as enforcement): {facts}
  watcher reason: {reason}

Extract a minimal Python regex (re.IGNORECASE) that:
1. Matches this command and close variants
2. Does NOT match any of: {benign}
3. Is as specific as possible — anchor to the dangerous part, not generic tokens
4. Choose a stable subject: program.name, python.module, script.path,
   python.operation (script_body_scan only), or path (path_guard only).
   Names/modules/operation names use fullmatch; paths use search.
   invocation is a compatibility projection and should only be used for rules
   that need several argv fields together. It matches from the complete program
   name; raw source text is never a matching subject.
   exec_gate matches normalized executable invocations, not raw source text.
   script_body_scan also includes Python operations such as `python:open '/path'`.
   For both targets the regex MUST start at the invocation/operation name and
   cover the whole name. Data arguments, comments and inline source are masked;
   nested executed code is represented as separate invocations. Never learn a
   rule from documentation or print data alone.
   path_guard searches normalized absolute paths, with substring search.

Output ONLY JSON (no prose, no fence):
{{"pattern": "...", "guard_target": "exec_gate|script_body_scan|path_guard", "subject": "program.name|python.module|script.path|python.operation|path|invocation", "confidence": 0.0}}

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
    source_view_version: int = 0  # 0: historical raw samples; current: normalized views
    subject: str | None = None
    source_facts: list[dict] | None = None
    inactive_reason: str | None = None
    legacy_ids: list[str] | None = None


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


def scrub_sample(text: str) -> str:
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        raise ValueError("invalid source sample size")
    return scrub_context(text)


def minimize_candidate(candidate: PatternCandidate) -> PatternCandidate:  # noqa: PLR0912 -- explicit schema migrations
    if candidate.inactive_reason:
        raise ValueError(candidate.inactive_reason)
    subject = checked_subject(candidate.guard_target, candidate.subject)
    legacy_ids = candidate.legacy_ids or []
    if not isinstance(legacy_ids, list) or any(i != rule_id(candidate.guard_target, candidate.pattern) for i in legacy_ids):
        raise ValueError("invalid legacy rule identities")
    if candidate.source_facts is not None:
        if not isinstance(candidate.source_facts, list) or len(candidate.source_facts) > MAX_TEXTS:
            raise ValueError("invalid source facts")
        texts = []
        for fact in candidate.source_facts:
            if (not isinstance(fact, dict) or fact.get("subject") != subject
                    or type(fact.get("subject_version")) is not int or fact["subject_version"] != FACT_VERSION):
                raise ValueError("incompatible source fact schema")
            texts.append(fact.get("value"))
    elif candidate.source_texts is None:
        texts = target_texts(candidate.guard_target, {
            "toolName": candidate.source_tool_name,
            "params": minimal_params(candidate.source_args, candidate.source_command),
        }, subject)
    elif candidate.source_view_version in (3, 4, VALIDATION_VERSION) or candidate.guard_target == "path_guard":
        texts = candidate.source_texts
        if candidate.source_view_version == _NAME_ONLY_VIEW_VERSION and candidate.subject is None and candidate.guard_target != "path_guard":
            if isinstance(texts, list) and texts and all(isinstance(t, str) and re.fullmatch(r"[\w.+:-]+", t) and not t.startswith("python:") for t in texts):
                # v3 erased interpreter argv. A bare-name view describes the
                # program subject, not today's invocation-with-argv projection.
                subject = "program.name"
                legacy_ids = [rule_id(candidate.guard_target, candidate.pattern)]
            elif any(t in {"bash", "sh", "python", "python3", "node", "perl", "ruby", "php"} for t in texts):
                raise ValueError("v3 source roles cannot be reconstructed")
    elif candidate.source_view_version in (0, 2):
        # Historical samples retained raw shell/Python text. Reparse rather
        # than trusting old false-positive matches as normalized invocations.
        texts = [view for source in candidate.source_texts for view in target_texts(
            candidate.guard_target, {"toolName": candidate.source_tool_name,
                                     "params": {"command": scrub_sample(source)}}, subject)]
    else:
        raise ValueError("unsupported learned source view version")
    if (not isinstance(texts, list) or not texts or len(texts) > MAX_TEXTS
            or any(not isinstance(t, str) or len(t) > MAX_TEXT_CHARS for t in texts)):
        raise ValueError("invalid source sample")
    return replace(candidate, source_command="", source_args=None,
                   source_texts=[scrub_sample(text) for text in texts],
                   source_view_version=VALIDATION_VERSION, subject=subject, legacy_ids=legacy_ids,
                   source_facts=[{"subject": subject, "subject_version": FACT_VERSION, "value": scrub_sample(t)} for t in texts])


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
    return validate_rule(candidate.pattern, candidate.guard_target, source_texts=candidate.source_texts, subject=candidate.subject)


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
                        for field, empty in (("source_args", None), ("source_command", ""), ("source_texts", []), ("source_facts", [])):
                            if field in sanitized_record:
                                sanitized_record[field] = empty
                        migrated.append(sanitized_record)
                    else:
                        migrated.append(record)
                    continue
                try:
                    safe = minimize_candidate(candidate)
                except (TypeError, ValueError, AttributeError, RecursionError) as exc:
                    safe = replace(candidate, source_command="", source_args=None, source_texts=[], source_facts=[],
                                   inactive_reason=str(exc) if isinstance(exc, ValueError) else "invalid source sample")
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
            retained = []
            for record in records:
                same = (isinstance(record, dict) and record.get("pattern") == candidate.pattern
                        and record.get("guard_target") == candidate.guard_target)
                if same:
                    try:
                        stored_subject = minimize_candidate(PatternCandidate(**record)).subject
                    except (TypeError, ValueError):
                        stored_subject = record.get("subject") or ("path" if candidate.guard_target == "path_guard" else "invocation")
                    same = stored_subject == candidate.subject
                if not same:
                    retained.append(record)
                    continue
                try:
                    validate_candidate(PatternCandidate(**record))
                except RegexResourceError:
                    # A transient worker failure cannot establish that an
                    # existing rule is invalid or authorize replacing it.
                    audit("rejected", rule_id=rule.id, skip_reason="existing_validation_unavailable")
                    return False
                except (TypeError, ValueError):
                    continue  # replace inactive same-identity records atomically
                audit("rejected", rule_id=rule.id, skip_reason="duplicate")
                return False
            records = retained
            pattern_chars = sum(len(r["pattern"]) for r in records
                                if isinstance(r, dict) and isinstance(r.get("pattern"), str))
            if len(records) >= MAX_PATTERNS or pattern_chars + len(candidate.pattern) > MAX_PATTERN_SET_CHARS:
                audit("rejected", rule_id=rule.id, skip_reason="store_capacity")
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
                                pattern_hash in (r.get("legacy_ids") or []) or
                                rule_id(r.get("guard_target", ""), r["pattern"], r.get("subject")) == pattern_hash))]
            if len(records) == before:
                return False
            self._save(records)
        return True


# Module-level singleton
STORE = LearnedPatternStore()


@analysis_scope()
def synthesize_pattern(  # noqa: PLR0911 -- admission rejects invalid or incomplete samples
    command: str,
    reason: str,
    model: Any,
    *,
    tool_name: str = "terminal",
    args: dict | None = None,
) -> PatternCandidate | None:
    """Ask the LLM to extract a minimal regex from a bypassing command."""
    safe_params = minimal_params(args, command)
    source_event = {"toolName": tool_name, "params": safe_params}
    try:
        views = {target: target_texts(target, source_event)
                 for target in ("exec_gate", "script_body_scan")}
    except ValueError:
        return None  # incomplete source is not a learnable negative sample
    prompt = _SYNTHESIS_PROMPT.format(
        tool_name=tool_name,
        command=json.dumps(safe_params)[:1500],
        paths=json.dumps(target_texts("path_guard", {
            "toolName": tool_name, "params": safe_params,
        })),
        views=json.dumps(views),
        facts=json.dumps({subject: target_texts("script_body_scan" if subject == "python.operation" else "exec_gate", source_event, subject)
                          for subject in ("program.name", "python.module", "script.path", "python.operation")}),
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
            subject=obj.get("subject"),
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
