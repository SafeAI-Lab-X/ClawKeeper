"""Keep process-global learned policy and user stores out of test fixtures."""

# Import optional Watcher dependencies only in fixtures that need them.
# ruff: noqa: PLC0415

import pytest


@pytest.fixture(autouse=True)
def isolated_regex_workers():
    from clawkeeper_core import bounded_regex

    bounded_regex._close_workers()
    yield
    bounded_regex._close_workers()


@pytest.fixture(autouse=True)
def isolated_rule_runtime(monkeypatch):
    from clawkeeper_core import learned_rules as rules

    monkeypatch.setattr(rules, "_snapshot", rules.make_snapshot([]))
    monkeypatch.setattr(rules, "_authority", None)
    monkeypatch.setattr(rules, "_policy_error", None)


@pytest.fixture
def isolated_learning(tmp_path, monkeypatch):
    from clawkeeper_core.watcher import agent, daemon, learner, reload

    store = learner.LearnedPatternStore(tmp_path / "learned.json")
    for module in (agent, daemon, learner, reload):
        monkeypatch.setattr(module, "STORE", store)
    return store
