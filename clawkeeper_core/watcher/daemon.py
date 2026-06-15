"""FastAPI daemon hosting the Watcher.

Exposes:
  POST /watcher/evaluate    — evaluate one proposed tool call, return a decision
  POST /watcher/intent      — register a session's stated user intent
  GET  /watcher/health      — liveness probe (model OK, history size)
  GET  /watcher/sessions    — debug: list known session IDs

Designed for local-host deployment only. Binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from clawkeeper_core.watcher.agent import Watcher, WatcherDecision
from clawkeeper_core.watcher.learner import STORE
from clawkeeper_core.watcher.reload import apply_learned_patterns
from clawkeeper_core.watcher.dashboard import DASHBOARD_HTML

# ── Live event bus (SSE broadcast) ─────────────────────────────────────────
_event_bus: list[asyncio.Queue] = []
_start_time = time.time()

def _broadcast(event: dict) -> None:
    data = json.dumps(event)
    for q in list(_event_bus):
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            pass


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
    apply_learned_patterns()  # load persisted patterns from previous runs
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
        _broadcast({"type": "intent", "ts": int(time.time()), "session_id": req.session_id, "intent": req.intent})
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
        resp = EvaluateResponse(
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
        _broadcast({
            "type": "eval",
            "ts": int(time.time()),
            "session_id": req.session_id,
            "tool_name": req.tool_name,
            "command": str((req.args or {}).get("command", str(req.args or "")[:300])),
            "decision": d.decision,
            "reason": d.reason,
            "severity": d.severity,
            "confidence": d.confidence,
            "signals": d.signals,
            "det_findings": d.deterministic_findings,
            "watcher_used": bool(d.raw_watcher_proposal),
            "latency_ms": d.watcher_latency_ms,
            "post_filter_overrode": d.post_filter_overrode,
        })
        return resp

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


    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return HTMLResponse(content=DASHBOARD_HTML)

    @app.get("/watcher/stream")
    async def event_stream(request: Request):
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        _event_bus.append(q)
        async def gen():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        data = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"data: {data}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                if q in _event_bus:
                    _event_bus.remove(q)
        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/watcher/learned")
    def list_learned():
        return [c.__dict__ for c in STORE.all()]

    @app.delete("/watcher/learned/{pattern_hash}")
    def remove_learned(pattern_hash: str):
        removed = STORE.remove(pattern_hash)
        return {"removed": removed}

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
