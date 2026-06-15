"""Hot-reload bridge — applies learned patterns to live guard modules.

Called at daemon startup and after each new pattern is persisted.
Idempotent: tracks loaded pattern hashes so re-running is safe.
"""

from __future__ import annotations

import hashlib
import re

from clawkeeper_core.watcher.learner import STORE

_loaded_hashes: set[str] = set()


def apply_learned_patterns() -> int:
    """Load new patterns from store into live guard module globals.

    Returns the number of newly applied patterns.
    """
    import clawkeeper_core.security_rules as _rules
    from clawkeeper_core.guards import script_body_scan as _sbs
    from clawkeeper_core.guards.exec_gate import reset_exec_gate_cache

    added = 0
    for candidate in STORE.all():
        h = hashlib.sha256(candidate.pattern.encode()).hexdigest()
        if h in _loaded_hashes:
            continue
        try:
            rx = re.compile(candidate.pattern, re.IGNORECASE)
        except re.error:
            continue

        target = candidate.guard_target
        if target == "exec_gate":
            _rules.DANGEROUS_COMMAND_PATTERNS.append(rx)
            reset_exec_gate_cache()
        elif target == "script_body_scan":
            # script_body_scan uses string lists; append the raw pattern as a marker
            _sbs._SENSITIVE_DIR_MARKERS.append(candidate.pattern)
        elif target == "path_guard":
            _rules.DANGEROUS_COMMAND_PATTERNS.append(rx)
            reset_exec_gate_cache()

        _loaded_hashes.add(h)
        added += 1

    return added
