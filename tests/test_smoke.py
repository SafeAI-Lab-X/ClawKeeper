"""Package-level sanity checks. Real behavior coverage lives in
test_drift.py, test_risk.py, test_judge.py, and others.
"""

from __future__ import annotations

import clawkeeper_core


def test_package_imports():
    assert clawkeeper_core.__version__.startswith("0.2")


def test_top_level_reexports_present():
    from clawkeeper_core import Decision, Judge, JudgeContext, Policy
    assert all(callable(t) or hasattr(t, "model_fields") for t in (Decision, Judge, JudgeContext, Policy))
