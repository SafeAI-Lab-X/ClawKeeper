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
import logging
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from clawkeeper_core.bounded_regex import MAX_PATTERN_CHARS
from clawkeeper_core.learned_rules import INSTANCE_ID, current_snapshot, policy_error
from clawkeeper_core.watcher.agent import Watcher, WatcherDecision
from clawkeeper_core.watcher.dashboard import DASHBOARD_HTML
from clawkeeper_core.watcher.learner import STORE, StoreUnavailableError, scrub_sample
from clawkeeper_core.watcher.reload import apply_learned_patterns

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


def build_app(watcher: Watcher | None = None) -> FastAPI:  # noqa: PLR0915 -- route registrations
    app = FastAPI(title="ClawKeeper Watcher", version="0.2.0")
    apply_learned_patterns()  # load persisted patterns from previous runs
    app.state.watcher = watcher or Watcher()

    @app.get("/watcher/health")
    def health():
        w: Watcher = app.state.watcher
        return {
            "status": "degraded" if policy_error() else "ok",
            "rules_error": policy_error(),
            "model_id": getattr(w.model, "model_id", "?"),
            "known_sessions": len(getattr(w.history, "_calls", {})),
            **{k: v for k, v in current_snapshot().as_dict().items() if k != "rules"},
        }

    @app.get("/watcher/rules")
    def rules(req: Request):
        if policy_error():
            raise HTTPException(status_code=503, detail="learned policy unavailable")
        snapshot = current_snapshot()
        etag = f'"{snapshot.version}"'
        headers = {"ETag": etag, "Cache-Control": "no-cache",
                   "X-ClawKeeper-Instance": INSTANCE_ID}
        if req.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        return JSONResponse(snapshot.as_dict(), headers=headers)

    @app.post("/watcher/rules/reload")
    def reload_rules():
        apply_learned_patterns()
        if policy_error():
            raise HTTPException(status_code=503, detail="learned policy unavailable")
        return {"version": current_snapshot().version, "status": "ok"}

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
        except Exception as e:
            raise HTTPException(status_code=500, detail="watcher evaluation failed") from e
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
                    except TimeoutError:
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
        try:
            candidates = STORE.all()
        except StoreUnavailableError as exc:
            raise HTTPException(status_code=503, detail="learned store unavailable") from exc
        return [{"pattern": scrub_sample(c.pattern) if isinstance(c.pattern, str) and len(c.pattern) <= MAX_PATTERN_CHARS else "[rejected]",
                 "guard_target": c.guard_target, "confidence": c.confidence,
                 "subject": c.subject, "inactive_reason": c.inactive_reason,
                 "created_at": c.created_at, "source_command": "",
                 "source_args": None} for c in candidates]

    @app.delete("/watcher/learned/{pattern_hash}")
    def remove_learned(pattern_hash: str):
        try:
            removed = STORE.remove(pattern_hash)
        except StoreUnavailableError as exc:
            raise HTTPException(status_code=503, detail="learned store unavailable") from exc
        if removed:
            apply_learned_patterns()
        return {"removed": removed}

    return app


def main() -> None:
    """Console entry point — `clawkeeper-watcher`."""
    import uvicorn  # noqa: PLC0415 -- CLI-only dependency initialization

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    app = build_app()
    host = os.environ.get("CK_WATCHER_HOST", "127.0.0.1")
    port = int(os.environ.get("CK_WATCHER_PORT", "9099"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
