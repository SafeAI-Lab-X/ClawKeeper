"""FastAPI HTTP surface — the bridge to non-Python adapters (notably the JS OpenClaw shim)."""

from __future__ import annotations

from fastapi import FastAPI

from clawkeeper_core import __version__
from clawkeeper_core.judge import Judge
from clawkeeper_core.schemas import Decision, JudgeContext

app = FastAPI(title="clawkeeper-core", version=__version__)
_judge = Judge()


@app.get("/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/v1/judge", response_model=Decision)
async def judge(ctx: JudgeContext) -> Decision:
    return await _judge.evaluate_async(ctx)


def main() -> None:
    import uvicorn

    uvicorn.run("clawkeeper_core.server:app", host="127.0.0.1", port=7474, reload=False)


if __name__ == "__main__":
    main()
