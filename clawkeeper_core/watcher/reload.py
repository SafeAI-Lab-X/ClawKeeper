"""Revalidate persisted candidates and atomically replace process-local policy."""
from __future__ import annotations

import logging
import threading
import time

from clawkeeper_core.bounded_regex import RegexResourceError
from clawkeeper_core.learned_rules import (
    audit,
    install_snapshot,
    make_snapshot,
    mark_policy_unavailable,
)
from clawkeeper_core.watcher.learner import STORE, StoreUnavailableError, validate_candidate

_reload_lock = threading.RLock()


def apply_learned_patterns() -> int:
    """Newly installed count, local to this process. Also applies removals.

    Invalid historical records remain stored for inspection. This is not an
    acknowledgement of Adapter synchronization.
    """
    with _reload_lock:
        try:
            candidates = STORE.all()
        except StoreUnavailableError:
            mark_policy_unavailable()
            return 0
        deadline = time.monotonic() + 5
        rules = []
        for candidate in candidates:
            if time.monotonic() > deadline:
                mark_policy_unavailable("learned_validation_unavailable")
                return 0
            try:
                rule = validate_candidate(candidate)
            except RegexResourceError:
                mark_policy_unavailable("learned_validation_unavailable")
                return 0
            except (TypeError, ValueError) as exc:
                audit("rejected", level=logging.WARNING, guard_target=candidate.guard_target,
                      skip_reason=str(exc))
                continue
            rules.append(rule)
            audit("validated", rule_id=rule.id, guard_target=rule.guard_target)
        try:
            return install_snapshot(make_snapshot(rules))
        except ValueError:
            mark_policy_unavailable()
            return 0
