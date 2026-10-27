"""HTTP client used by per-host adapters to post events to the Watcher daemon.

Lightweight, single-purpose. Built on `httpx` (already a transitive dep of
fastmcp / openai). Configurable timeout; falls back to a safe default
decision when the daemon is unreachable or slow.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from http import HTTPStatus
from typing import Any

import httpx

from clawkeeper_core.learned_rules import (
    RuleSnapshot,
    audit,
    install_snapshot,
    snapshot_from_wire,
)


class RuleSyncError(RuntimeError):
    """The Adapter cannot establish a validated rule snapshot for this call."""


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
        self._rules: RuleSnapshot | None = None
        self._rules_lock = threading.Lock()
        self._server_instance: str | None = None

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ─── Public API ────────────────────────────────────────────────────────

    def sync_rules(self) -> RuleSnapshot:
        """Pull a complete policy or retain the last one on failure.

        The caller must defer the current tool call on RuleSyncError; retaining
        old policy does not claim that a synchronization succeeded.
        """
        with self._rules_lock:
            try:
                headers = {"Accept-Encoding": "identity"}
                if self._rules:
                    headers["If-None-Match"] = f'"{self._rules.version}"'
                deadline = time.monotonic() + self.timeout_s
                with self._client.stream("GET", f"{self.base_url}/watcher/rules", headers=headers) as response:
                    if response.status_code == HTTPStatus.NOT_MODIFIED:
                        if self._rules is None:
                            raise ValueError("304 without a validated local snapshot")
                        if response.headers.get("etag") != f'"{self._rules.version}"':
                            raise ValueError("304 rules ETag mismatch")
                        snapshot = self._rules
                        server_instance = response.headers.get("x-clawkeeper-instance")
                        if not server_instance:
                            raise ValueError("304 missing server instance")
                    else:
                        response.raise_for_status()
                        if response.headers.get("content-encoding", "identity") != "identity":
                            raise ValueError("compressed rule snapshots are unsupported")
                        body = bytearray()
                        chunks = [response.content] if response.is_stream_consumed else response.iter_raw()
                        for chunk in chunks:
                            if len(body) + len(chunk) > 1024 * 1024:
                                raise ValueError("rule snapshot exceeds byte limit")
                            if time.monotonic() > deadline:
                                raise ValueError("rule download budget exhausted")
                            body.extend(chunk)
                        payload = json.loads(body)
                        snapshot = snapshot_from_wire(payload)
                        if response.headers.get("etag") != f'"{snapshot.version}"':
                            raise ValueError("rules ETag mismatch")
                        server_instance = payload["instance_id"]
                install_snapshot(snapshot, authority=self.base_url)
                self._rules = snapshot
                self._server_instance = server_instance
                audit("synchronized", rules_version=snapshot.version,
                      server_instance_id=self._server_instance, authority=self.base_url)
                return snapshot
            except Exception as exc:
                audit("sync_failed", level=logging.WARNING, authority=self.base_url,
                      rules_version=self._rules.version if self._rules else None,
                      skip_reason=type(exc).__name__)
                raise RuleSyncError("Watcher rule synchronization failed; defer tool call") from exc

    def health(self) -> dict[str, Any]:
        try:
            r = self._client.get(f"{self.base_url}/watcher/health")
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"status": "unreachable", "error": repr(e)}

    def remember_intent(self, session_id: str, intent: str) -> bool:
        try:
            r = self._client.post(
                f"{self.base_url}/watcher/intent",
                json={"session_id": session_id, "intent": intent},
            )
            r.raise_for_status()
            return True
        except Exception:
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
