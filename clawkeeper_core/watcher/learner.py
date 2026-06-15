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
import os
import re
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_STORE_PATH = Path.home() / ".clawkeeper" / "learned_patterns.json"

_BENIGN_CORPUS = [
    "ls -la",
    "git status",
    "git diff HEAD",
    "python -c 'print(1)'",
    "cat README.md",
    "echo hello",
    "pip install requests",
    "pytest tests/",
    "npm install",
    "make build",
]

_SYNTHESIS_PROMPT = """\
You are a security pattern extractor for ClawKeeper.

A command bypassed all deterministic guards but was flagged by the Watcher:
  command: {command}
  watcher reason: {reason}

Extract a minimal Python regex (re.IGNORECASE) that:
1. Matches this command and close variants
2. Does NOT match any of: {benign}
3. Is as specific as possible — anchor to the dangerous part, not generic tokens

Output ONLY JSON (no prose, no fence):
{{"pattern": "...", "guard_target": "exec_gate|script_body_scan|path_guard", "confidence": 0.0}}

Output the JSON null literal if no reliable pattern can be extracted.
"""

_JSON_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


@dataclass
class PatternCandidate:
    pattern: str
    source_command: str  # truncated to 200 chars
    guard_target: str    # "exec_gate" | "script_body_scan" | "path_guard"
    confidence: float
    created_at: str      # ISO-8601 UTC


class LearnedPatternStore:
    """Thread-safe JSON store at ~/.clawkeeper/learned_patterns.json."""

    def __init__(self, path: Path = _STORE_PATH):
        self._path = path
        self._lock = threading.Lock()

    def _load(self) -> list[dict]:
        try:
            return json.loads(self._path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save(self, records: list[dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(records, indent=2))

    def all(self) -> list[PatternCandidate]:
        with self._lock:
            return [PatternCandidate(**r) for r in self._load()]

    def contains_equivalent(self, pattern: str) -> bool:
        """True if pattern already exists or matches any benign command."""
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return True  # invalid regex — treat as duplicate/bad
        if any(rx.search(b) for b in _BENIGN_CORPUS):
            return True  # too broad
        with self._lock:
            for r in self._load():
                if r.get("pattern") == pattern:
                    return True
        return False

    def add(self, candidate: PatternCandidate) -> bool:
        """Persist candidate. Returns False if rejected (duplicate/overbroad)."""
        if self.contains_equivalent(candidate.pattern):
            return False
        with self._lock:
            records = self._load()
            records.append(asdict(candidate))
            self._save(records)
        return True

    def remove(self, pattern_hash: str) -> bool:
        with self._lock:
            records = self._load()
            before = len(records)
            records = [r for r in records
                       if hashlib.sha256(r["pattern"].encode()).hexdigest() != pattern_hash]
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
) -> PatternCandidate | None:
    """Ask the LLM to extract a minimal regex from a bypassing command."""
    prompt = _SYNTHESIS_PROMPT.format(
        command=command[:500],
        reason=reason[:300],
        benign=", ".join(f'"{b}"' for b in _BENIGN_CORPUS[:5]),
    )
    try:
        messages = [{"role": "user", "content": prompt}]
        response = model(messages)
        raw = getattr(response, "content", str(response))
    except Exception:  # noqa: BLE001
        return None

    # Parse JSON from response
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

    pattern = obj.get("pattern", "")
    guard_target = obj.get("guard_target", "exec_gate")
    confidence = float(obj.get("confidence", 0.0) or 0.0)

    if not pattern or confidence < 0.6:
        return None
    # Validate regex compiles
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None

    return PatternCandidate(
        pattern=pattern,
        source_command=command[:200],
        guard_target=guard_target if guard_target in ("exec_gate", "script_body_scan", "path_guard") else "exec_gate",
        confidence=confidence,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def maybe_push_upstream(candidate: PatternCandidate) -> None:
    """Fire-and-forget POST of anonymized fingerprint to CK_LEARN_ENDPOINT."""
    endpoint = os.environ.get("CK_LEARN_ENDPOINT", "").strip()
    if not endpoint:
        return
    import threading as _t
    def _push():
        try:
            import httpx
            httpx.post(
                endpoint,
                json={
                    "pattern_hash": hashlib.sha256(candidate.pattern.encode()).hexdigest(),
                    "guard_target": candidate.guard_target,
                    "confidence": candidate.confidence,
                },
                timeout=3.0,
            )
        except Exception:  # noqa: BLE001
            pass
    _t.Thread(target=_push, daemon=True).start()
