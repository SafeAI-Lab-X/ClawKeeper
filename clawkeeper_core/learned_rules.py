"""Validated, process-local learned rules, separate from built-in policy.

Snapshots are immutable. A guard chain pins one snapshot so concurrent reloads
cannot change policy halfway through an evaluation. No model or store imports.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from clawkeeper_core.bounded_regex import MAX_PATTERN_SET_CHARS, MAX_PATTERNS, search_groups
from clawkeeper_core.command_facts import FACT_VERSION, SUBJECTS
from clawkeeper_core.execution import analysis_scope

PROTOCOL_VERSION = 2
VALIDATION_VERSION = 5
TARGETS = frozenset({"exec_gate", "path_guard", "script_body_scan"})
INSTANCE_ID = str(uuid.uuid4())
_LOG = logging.getLogger(__name__)
_audit_fields: ContextVar[dict | None] = ContextVar("clawkeeper_learning_audit", default=None)

# Inert examples: these strings are inspected, never executed. Include realistic
# programming workflows and mentions of sensitive paths in documentation.
BENIGN_COMMANDS = (
    "ls -la",
    "git status",
    "git diff HEAD",
    "git log --oneline -5",
    "git checkout -b feature/example",
    "git grep TODO",
    "echo hello",
    "pytest tests/",
    "python -m pytest -q",
    "python -m unittest discover",
    "ruff check .",
    "ruff format --check .",
    "mypy src/",
    "npm test",
    "npm run build",
    "make build",
    "cmake --build build",
    "cargo check",
    "pip install requests",
    "python -m pip install -e '.[dev]'",
    "uv sync",
    "npm install",
    "npm ci",
    "python -c 'print(1)'",
    "python - <<'PY'\nfrom pathlib import Path\nprint(Path('README.md').read_text())\nPY",
    'python -c "import json; print(json.loads(\'{\\"ok\\": true}\'))"',
    "cat README.md",
    "cat .env.example",
    "cp config.example.json /tmp/config.json",
    "mkdir -p /tmp/build-output",
    "find src -name '*.py'",
    "head -n 20 docs/setup.md",
    "curl -fsSL https://example.com/docs -o /tmp/docs.html",
    "printf '%s\\n' 'Documentation: ~/.ssh/id_rsa and ~/.aws/credentials are private'",
    "python -c \"print('Never read /etc/shadow or ~/.aws/credentials')\"",
    "python -c \"open('/tmp/guide.txt', 'w').write('Do not share ~/.ssh/id_rsa')\"",
)
_BENIGN_PATHS = (
    "/tmp/project/README.md",
    "/tmp/project/src/main.py",
    "/tmp/project/.env.example",
    "/tmp/project/config.example.json",
    "/tmp/project/docs/ssh.md",
    "/tmp/project/tests/fixtures/aws_example.json",
    "/tmp/build-output/result.txt",
    "./README.md",
    "./docs/setup.md",
    "../project/pyproject.toml",
)


def audit(stage: str, *, level: int = logging.INFO, **fields: Any) -> None:
    """Emit an inspectable record without logging source commands or arguments."""
    record = {
        "stage": stage,
        "pid": os.getpid(),
        "instance_id": INSTANCE_ID,
        "rules_version": _snapshot.version,
        **(_audit_fields.get() or {}),
        **fields,
    }
    if record.get("authority"):
        try:
            parsed = urlsplit(record["authority"])
            record["authority"] = f"{parsed.scheme}://{parsed.hostname}"
        except ValueError:
            record["authority"] = "configured_watcher"
    _LOG.log(level, json.dumps(record, sort_keys=True), extra=record)


@contextmanager
def audit_context(**fields: Any):
    token = _audit_fields.set(fields)
    try:
        yield
    finally:
        _audit_fields.reset(token)


def default_subject(target: str) -> str:
    return "path" if target == "path_guard" else "invocation"


def rule_id(target: str, pattern: str, subject: str | None = None) -> str:
    # Preserve historical identities for the compatibility projection. New
    # subjects are distinct rules even when their regex and guard are equal.
    key = f"{target}\0{pattern}" if subject in (None, default_subject(target)) else f"{target}\0{subject}\0{pattern}"
    return hashlib.sha256(key.encode()).hexdigest()


def subject_mode(subject: str) -> str:
    if subject == "invocation":
        return "invocation"
    return "search" if subject in {"path", "script.path"} else "full"


def checked_subject(target: str, subject: str | None) -> str:
    subject = default_subject(target) if subject is None else subject
    if not isinstance(subject, str) or subject not in SUBJECTS:
        raise ValueError("unsupported rule subject")
    if (target == "path_guard") != (subject == "path") or (subject == "python.operation" and target != "script_body_scan"):
        raise ValueError("subject does not belong to target guard")
    return subject


@dataclass(frozen=True)
class LearnedRule:
    id: str
    guard_target: str
    pattern: str
    subject: str = "invocation"

    def as_dict(self) -> dict:
        return {"id": self.id, "guard_target": self.guard_target, "pattern": self.pattern,
                "subject": self.subject, "subject_version": FACT_VERSION}


@dataclass(frozen=True)
class RuleSnapshot:
    version: str
    rules: tuple[LearnedRule, ...]

    def as_dict(self) -> dict:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "validation_version": VALIDATION_VERSION,
            "version": self.version,
            "instance_id": INSTANCE_ID,
            "pid": os.getpid(),
            "rules": [r.as_dict() for r in self.rules],
        }


def make_snapshot(rules: list[LearnedRule]) -> RuleSnapshot:
    if len(rules) > MAX_PATTERNS:
        raise ValueError("too many learned rules")
    if sum(len(r.pattern) for r in rules) > MAX_PATTERN_SET_CHARS:
        raise ValueError("learned pattern set exceeds character limit")
    ordered = tuple(sorted({r.id: r for r in rules}.values(), key=lambda r: r.id))
    encoded = json.dumps(
        {
            "validation_version": VALIDATION_VERSION,
            "rules": [r.as_dict() for r in ordered],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return RuleSnapshot(hashlib.sha256(encoded.encode()).hexdigest(), ordered)


_snapshot = make_snapshot([])
_authority: str | None = None
_policy_error: str | None = None
_lock = threading.RLock()
_pinned: ContextVar[RuleSnapshot | None] = ContextVar("clawkeeper_rules", default=None)


def current_snapshot() -> RuleSnapshot:
    return _snapshot


def policy_error() -> str | None:
    return _policy_error


def mark_policy_unavailable(reason: str = "learned_store_unavailable") -> None:
    global _policy_error  # noqa: PLW0603
    with _lock:
        _policy_error = reason
    audit("degraded", level=logging.WARNING, skip_reason=_policy_error)


@contextmanager
def pin_snapshot(snapshot: RuleSnapshot | None = None):
    token = _pinned.set(snapshot if snapshot is not None else (_pinned.get() or _snapshot))
    try:
        yield _pinned.get()
    finally:
        _pinned.reset(token)


def install_snapshot(snapshot: RuleSnapshot, *, authority: str | None = None) -> int:
    """Atomically replace learned policy, including removals. Built-ins stay put."""
    global _snapshot, _authority, _policy_error  # noqa: PLW0603 -- serialized process-local registry
    with _lock:
        if _authority is not None and authority != _authority:
            raise ValueError("only one Watcher rule authority is supported per process")
        if authority is not None:
            _authority = authority
        previous = _snapshot
        _snapshot = snapshot
        _policy_error = None
        added = len({r.id for r in snapshot.rules} - {r.id for r in previous.rules})
    if snapshot.version != previous.version:
        audit(
            "applied",
            rules_version=snapshot.version,
            added=added,
            removed=len({r.id for r in previous.rules} - {r.id for r in snapshot.rules}),
            authority=authority,
        )
    return added


def target_texts(target: str, event: dict, subject: str | None = None) -> list[str]:
    """The exact same target view is used in validation and enforcement."""
    subject = checked_subject(target, subject)
    params = event.get("params") or {}
    if target in {"exec_gate", "script_body_scan"}:
        from clawkeeper_core.guards.exec_gate import execution_contexts  # noqa: PLC0415 -- guards use this module

        contexts = execution_contexts(event)
        if any(c.errors for c in contexts):
            raise ValueError("execution context analysis incomplete")
        return [v for c in contexts for v in c.values(subject, script=target == "script_body_scan")]
    if target == "path_guard":
        from clawkeeper_core.guards.path_guard import extract_paths_from_params, normalize_path  # noqa: PLC0415

        return [
            p
            for candidate in extract_paths_from_params(event.get("toolName"), params)
            if (p := normalize_path(candidate))
        ]
    raise ValueError(f"unsupported guard target: {target!r}")


@analysis_scope()
def validate_rule(
    pattern: str,
    target: str,
    *,
    source_event: dict | None = None,
    source_texts: list[str] | None = None,
    subject: str | None = None,
) -> LearnedRule:
    if not isinstance(target, str) or target not in TARGETS:
        raise ValueError("unsupported guard target")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a nonempty string")
    subject = checked_subject(target, subject)
    events = [{"toolName": "terminal", "params": {"command": c}} for c in BENIGN_COMMANDS]
    events.extend({"toolName": "read_file", "params": {"path": p}} for p in _BENIGN_PATHS)
    benign = [text for e in events for text in target_texts(target, e, subject)]
    source = target_texts(target, source_event, subject) if source_event is not None else source_texts
    groups = [source, benign] if source is not None else [benign]
    matches = search_groups([pattern], groups, modes=[subject_mode(subject)])
    if source is not None and matches[0] is None:
        raise ValueError("pattern does not match the source in its target guard")
    if matches[-1] is not None:
        raise ValueError("pattern matches a benign programming task")
    return LearnedRule(rule_id(target, pattern, subject), target, pattern, subject)


@analysis_scope()
def snapshot_from_wire(payload: dict) -> RuleSnapshot:
    """Reject the entire response on any invalid rule; never partially apply."""
    if (
        not isinstance(payload, dict)
        or type(payload.get("protocol_version")) is not int
        or payload["protocol_version"] != PROTOCOL_VERSION
    ):
        raise ValueError("unsupported rules protocol")
    if (
        type(payload.get("validation_version")) is not int
        or payload["validation_version"] != VALIDATION_VERSION
    ):
        raise ValueError("incompatible rules validator")
    if not isinstance(payload.get("instance_id"), str) or not payload["instance_id"]:
        raise ValueError("missing server instance")
    if not isinstance(payload.get("rules"), list):
        raise ValueError("invalid rules list")
    if len(payload["rules"]) > MAX_PATTERNS:
        raise ValueError("too many learned rules")
    rules = []
    deadline = time.monotonic() + 5
    for item in payload["rules"]:
        if time.monotonic() > deadline:
            raise ValueError("rules validation budget exhausted")
        if not isinstance(item, dict):
            raise ValueError("invalid rule entry")
        if type(item.get("subject_version")) is not int or item["subject_version"] != FACT_VERSION or not isinstance(item.get("subject"), str):
            raise ValueError("incompatible rule subject schema")
        rule = validate_rule(item.get("pattern"), item.get("guard_target"), subject=item["subject"])
        if item.get("id") != rule.id:
            raise ValueError("rule identity mismatch")
        rules.append(rule)
    snapshot = make_snapshot(rules)
    if snapshot.version != payload.get("version") or len(snapshot.rules) != len(rules):
        raise ValueError("rules version mismatch or duplicate rule")
    return snapshot


@analysis_scope()
def match_learned(target: str, event: dict) -> dict | None:
    snapshot = _pinned.get() or _snapshot
    rules = [r for r in snapshot.rules if r.guard_target == target]
    if not rules and not policy_error():
        return None
    try:
        if policy_error():
            raise ValueError("learned policy unavailable")
        subjects = list(dict.fromkeys(r.subject for r in rules))
        groups = [target_texts(target, event, subject) for subject in subjects]
        matches = search_groups([r.pattern for r in rules], groups,
                                modes=[subject_mode(r.subject) for r in rules],
                                pattern_groups=[subjects.index(r.subject) for r in rules])
        matched = min((index for index in matches if index is not None), default=None)
    except Exception as exc:
        audit(
            "match_failed",
            level=logging.WARNING,
            rules_version=snapshot.version,
            guard_target=target,
            skip_reason=type(exc).__name__,
        )
        return {
            "block": True,
            "outcome": "ask",
            "severity": "high",
            "source": f"learned:{target}:error",
            "error": "learned_rule_evaluation_failed",
            "reason": "Learned rules could not evaluate this call; ask operator",
        }
    if matched is None:
        return None
    rule = rules[matched]
    audit("matched", rule_id=rule.id, rules_version=snapshot.version, guard_target=target)
    return {
        "block": True,
        "outcome": "deny",
        "severity": "high",
        "source": f"learned:{target}",
        "matched": rule.id,
        "reason": f"Matches a validated learned {target} rule",
        "evidence": {"rule_id": rule.id, "rules_version": snapshot.version, "subject": rule.subject, "subject_version": FACT_VERSION},
    }
