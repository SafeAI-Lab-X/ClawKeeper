# ClawKeeper v0.2 (refactor in progress on branch `v0.2-refactor`)

This branch turns ClawKeeper into a framework-agnostic Python core with thin adapters.
See [DESIGN.md](DESIGN.md) for the full plan and [docs/HERMES_INTEGRATION.md](docs/HERMES_INTEGRATION.md)
for the first reference adapter.

## Status

Phase 0 (scaffold) — done.
Phase 1 (port JS logic to Python) — next.

## Quick start (developer)

```bash
conda activate clawkeeper       # or your venv of choice
pip install -e ".[dev]"
pytest                          # smoke tests must pass
clawkeeper-server               # HTTP API on 127.0.0.1:7474
```

## Layout

- `clawkeeper_core/`  — the new Python package (this is where new work lands).
- `legacy/`           — verbatim v0.1 JS, kept for porting reference.
- `adapters_js/openclaw/` — the slimmed JS OpenClaw plugin (HTTP-shim only).
- `DESIGN.md`         — architectural source of truth.
