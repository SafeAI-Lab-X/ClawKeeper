"""HTTP client used by per-host adapters to post events to the Watcher daemon.

Lightweight, single-purpose. Built on `httpx` (already a transitive dep of
fastmcp / openai). Configurable timeout; falls back to a safe default
decision when the daemon is unreachable or slow.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx


class WatcherClient:
    """Synchronous client. One instance per host adapter is fine."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout_s: float = 10.0,
        on_unavailable: str = "ask",
    ):
        self.base_url = (base_url or os.environ.get(
            "CK_WATCHER_URL", "http://127.0.0.1:9099"
        )).rstrip("/")
        self.timeout_s = timeout_s
        # If the daemon is down or times out, return this decision so the host
        # has something to act on. "ask" surfaces to operator; "deny" is the
        # paranoid choice; "allow" is unsafe and not recommended.
        if on_unavailable not in {"allow", "ask", "deny"}:
            on_unavailable = "ask"
        self.on_unavailable = on_unavailable
        self._client = httpx.Client(timeout=timeout_s)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ─── Public API ────────────────────────────────────────────────────────

    def health(self) -> dict[str, Any]:
        try:
            r = self._client.get(f"{self.base_url}/watcher/health")
            r.raise_for_status()
            return r.json()
        except Exception as e:  # noqa: BLE001
            return {"status": "unreachable", "error": repr(e)}

    def remember_intent(self, session_id: str, intent: str) -> bool:
        try:
            r = self._client.post(
                f"{self.base_url}/watcher/intent",
                json={"session_id": session_id, "intent": intent},
            )
            r.raise_for_status()
            return True
        except Exception:  # noqa: BLE001
            return False

    def evaluate(
        self,
        *,
        session_id: str,
        tool_name: str,
        args: dict | None,
        stated_intent: str | None = None,
    ) -> dict:
        """POST /watcher/evaluate. On failure, return a fail-safe decision dict."""
        try:
            r = self._client.post(
                f"{self.base_url}/watcher/evaluate",
                json={
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "args": args or {},
                    "stated_intent": stated_intent,
                },
            )
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            return {
                "decision": self.on_unavailable,
                "reason": (
                    f"Watcher daemon unreachable or returned malformed response — "
                    f"failing to '{self.on_unavailable}'. error={e!r}"
                ),
                "severity": "high",
                "signals": ["watcher_unreachable"],
                "confidence": 0.0,
                "post_filter_overrode": False,
                "watcher_latency_ms": 0,
                "deterministic_findings": [],
                "raw_watcher_proposal": {},
            }
