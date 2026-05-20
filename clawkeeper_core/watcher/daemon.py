"""FastAPI daemon hosting the Watcher.

Exposes:
  POST /watcher/evaluate    — evaluate one proposed tool call, return a decision
  POST /watcher/intent      — register a session's stated user intent
  GET  /watcher/health      — liveness probe (model OK, history size)
  GET  /watcher/sessions    — debug: list known session IDs

Designed for local-host deployment only. Binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from clawkeeper_core.watcher.agent import Watcher, WatcherDecision


class EvaluateRequest(BaseModel):
    session_id: str
    tool_name: str
    args: dict[str, Any] | None = None
    stated_intent: str | None = None


class EvaluateResponse(BaseModel):
    decision: str = Field(description="allow | ask | deny")
    reason: str
    severity: str
    signals: list[str]
    confidence: float
    post_filter_overrode: bool
    watcher_latency_ms: int
    deterministic_findings: list[dict]
    raw_watcher_proposal: dict


class IntentRequest(BaseModel):
    session_id: str
    intent: str


def build_app(watcher: Watcher | None = None) -> FastAPI:
    app = FastAPI(title="ClawKeeper Watcher", version="0.2.0")
    app.state.watcher = watcher or Watcher()

    @app.get("/watcher/health")
    def health():
        w: Watcher = app.state.watcher
        return {
            "status": "ok",
            "model_id": getattr(w.model, "model_id", "?"),
            "known_sessions": len(getattr(w.history, "_calls", {})),
        }

    @app.post("/watcher/intent")
    def remember_intent(req: IntentRequest):
        app.state.watcher.remember_intent(req.session_id, req.intent)
        return {"ok": True}

    @app.post("/watcher/evaluate", response_model=EvaluateResponse)
    def evaluate(req: EvaluateRequest):
        try:
            d: WatcherDecision = app.state.watcher.evaluate(
                session_id=req.session_id,
                tool_name=req.tool_name,
                args=req.args,
                stated_intent=req.stated_intent,
            )
        except Exception as e:  # noqa: BLE001 — never let the daemon crash a host
            raise HTTPException(status_code=500, detail=f"watcher error: {e!r}")
        return EvaluateResponse(
            decision=d.decision,
            reason=d.reason,
            severity=d.severity,
            signals=d.signals,
            confidence=d.confidence,
            post_filter_overrode=d.post_filter_overrode,
            watcher_latency_ms=d.watcher_latency_ms,
            deterministic_findings=d.deterministic_findings,
            raw_watcher_proposal=d.raw_watcher_proposal,
        )

    @app.get("/watcher/sessions")
    def list_sessions():
        w: Watcher = app.state.watcher
        return {
            "sessions": [
                {
                    "id": sid,
                    "calls": len(calls),
                    "intent": w.history.stated_intent(sid)[:200],
                }
                for sid, calls in getattr(w.history, "_calls", {}).items()
            ]
        }

    return app


def main() -> None:
    """Console entry point — `clawkeeper-watcher`."""
    import uvicorn

    app = build_app()
    host = os.environ.get("CK_WATCHER_HOST", "127.0.0.1")
    port = int(os.environ.get("CK_WATCHER_PORT", "9099"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
