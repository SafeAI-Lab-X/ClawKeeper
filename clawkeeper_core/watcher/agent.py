"""The Watcher agent — single-LLM-call evaluator.

For v1 we use smolagents only as the LLM-client abstraction
(`OpenAIServerModel`). The reasoning is a single structured call: gather
data → render prompt → call LLM → parse JSON → return proposal. A future
v2 may upgrade to smolagents' multi-step `ToolCallingAgent` so the
Watcher can interactively pull more context.

Why single-call for v1: predictable, testable, ~1.5 s per evaluation,
no multi-step parse failures on models that don't speak the
tool-calling JSON format natively.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from typing import Any

# UA patch for api.scode.chat — applied at import so smolagents' inner
# openai client respects it. Idempotent if already patched.
import openai as _openai_pkg

_BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
if not getattr(_openai_pkg.OpenAI, "_ck_ua_patched", False):
    _orig_oai_init = _openai_pkg.OpenAI.__init__

    def _patched_oai_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        headers = dict(kwargs.get("default_headers") or {})
        headers.setdefault("User-Agent", _BROWSER_UA)
        kwargs["default_headers"] = headers
        return _orig_oai_init(self, *args, **kwargs)

    _openai_pkg.OpenAI.__init__ = _patched_oai_init
    _openai_pkg.OpenAI._ck_ua_patched = True


from clawkeeper_core.watcher.policy import apply_post_filter
from clawkeeper_core.watcher.prompts import (
    SYSTEM_PROMPT,
    render_evaluation_prompt,
)
from clawkeeper_core.watcher.tools import (
    HISTORY,
    gather_deterministic_findings,
)


@dataclass
class WatcherDecision:
    decision: str  # "allow" | "ask" | "deny"
    reason: str
    severity: str
    signals: list[str]
    confidence: float
    post_filter_overrode: bool
    watcher_latency_ms: int
    raw_watcher_proposal: dict
    deterministic_findings: list[dict]


# ── JSON extraction (LLMs sometimes wrap in markdown fences) ───────────────


_JSON_OBJ_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


def _extract_first_json(text: str) -> dict | None:
    """Find the first balanced {...} in `text` and try to parse it."""
    # Fast path: text is JSON itself
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    # Strip markdown fence if present
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text or "", re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    # Find any balanced-brace block and try to parse
    for m in _JSON_OBJ_RE.finditer(text or ""):
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
    return None


def _make_default_model():
    """Construct an OpenAIServerModel from env."""
    from smolagents import OpenAIServerModel
    return OpenAIServerModel(
        model_id=os.environ.get("CK_WATCHER_MODEL", "gpt-5.5"),
        api_base=os.environ.get("CK_WATCHER_BASE_URL", os.environ.get("OPENAI_BASE_URL", "https://api.scode.chat/v1")),
        api_key=os.environ.get("CK_WATCHER_API_KEY", os.environ.get("OPENAI_API_KEY", "")),
    )


# ── Main Watcher class ─────────────────────────────────────────────────────


class Watcher:
    """LLM-driven safety supervisor. One instance per daemon."""

    def __init__(self, *, model=None, history=None, fail_safe: str = "ask"):
        self.model = model if model is not None else _make_default_model()
        self.history = history if history is not None else HISTORY
        # When the LLM call fails / output is unparseable, we fall back to
        # this decision. "ask" is the most conservative useful default —
        # surfacing to the operator rather than silently denying valid work
        # or silently allowing potential exfil.
        self.fail_safe = fail_safe

    def remember_intent(self, session_id: str, intent: str) -> None:
        self.history.set_intent(session_id, intent)

    def remember_call(self, session_id: str, tool_name: str, args: dict | None) -> None:
        self.history.remember_call(session_id, tool_name, args)

    def evaluate(
        self,
        *,
        session_id: str,
        tool_name: str,
        args: dict | None,
        stated_intent: str | None = None,
    ) -> WatcherDecision:
        """Evaluate one proposed tool call.

        Side effect: this DOES update session history with the proposed call
        (so the next evaluation sees it as 'recent'). Adapters that want to
        suppress the side effect should call `evaluate(...,
        session_id="ephemeral-...")`.
        """
        t0 = time.perf_counter()

        if stated_intent:
            self.history.set_intent(session_id, stated_intent)

        # 1) Gather deterministic findings
        det = gather_deterministic_findings(tool_name=tool_name, args=args)

        # 2) Build prompt
        user_block = render_evaluation_prompt(
            stated_intent=self.history.stated_intent(session_id),
            recent_calls=self.history.recent_calls(session_id, n=10),
            proposed_call={"tool_name": tool_name, "command": (args or {}).get("command", str(args)[:1500])},
            deterministic_findings=det,
        )

        # 3) Single LLM call asking for JSON
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_block},
        ]
        raw_text = ""
        proposal: dict | None = None
        try:
            response = self.model(messages)
            raw_text = getattr(response, "content", str(response))
            proposal = _extract_first_json(raw_text)
        except Exception as e:  # noqa: BLE001
            proposal = None
            raw_text = f"<<LLM call failed: {e!r}>>"

        if not isinstance(proposal, dict) or proposal.get("decision") not in {"allow", "ask", "deny"}:
            proposal = {
                "decision": self.fail_safe,
                "reason": (
                    f"Watcher LLM output was not parseable as a decision; failing to {self.fail_safe}. "
                    f"Raw preview: {raw_text[:200]!r}"
                ),
                "severity": "medium",
                "signals": ["watcher_parse_failure"],
                "confidence": 0.0,
            }

        # 4) Post-filter (deterministic override)
        final = apply_post_filter(
            watcher_proposal=proposal,
            deterministic_findings=det,
        )

        # 5) Remember this call AFTER deciding (so the next call sees it as recent)
        self.history.remember_call(session_id, tool_name, args)

        latency_ms = int((time.perf_counter() - t0) * 1000)
        return WatcherDecision(
            decision=final["decision"],
            reason=final["reason"],
            severity=str(final.get("severity", "medium")),
            signals=list(final.get("signals") or []),
            confidence=float(final.get("confidence", 0.0) or 0.0),
            post_filter_overrode=bool(final.get("post_filter_overrode", False)),
            watcher_latency_ms=latency_ms,
            raw_watcher_proposal=proposal,
            deterministic_findings=det,
        )

    def as_dict(self, decision: WatcherDecision) -> dict:
        return asdict(decision)
