# ClawKeeper v0.2 — Design

> Status: draft (Phase 0). Living document — expect rapid revision through Phase 1.

## 1. What changes in v0.2

ClawKeeper v0.1 is structured as **an OpenClaw plugin**. The 13 KLOC of safety logic
(judge, fingerprint, drift, profile, memory, controls, hardening, …) sits inside the
~80 KLOC OpenClaw runtime and depends on its plugin SDK (`api.on('before_tool_call', …)`).
That bakes in two limitations:

1. **Lock-in.** ClawKeeper only protects OpenClaw-hosted agents. Hermes, Claude Code,
   Cursor, Cline, OpenAI Agents SDK, custom LangChain rigs, etc. are all out of reach.
2. **Weight.** The 6:1 framework-to-logic ratio means a deploy ships ~80 KLOC of code
   nobody asked for.

v0.2 turns ClawKeeper into:

- A **framework-agnostic Python core** (`clawkeeper-core`) that owns all decisions.
- A **small set of adapters** that translate framework-specific events into core calls.

```
┌──────────────────────────────────────────────────────────────────┐
│                        clawkeeper-core                            │
│                  (Python, framework-agnostic)                     │
│                                                                   │
│  judge · risk · drift · profile · memory · controls · audit       │
│  scanner · permission · maintenance · guards/{exec,path,input}    │
│                                                                   │
│  Exposed as:  Python library  +  FastAPI HTTP server              │
│               (POST /judge, /audit, /event, /scan)                │
└─────────────────────┬─────────────────────────────────────────────┘
                      │
       ┌──────────────┼───────────────┬────────────────┐
       │              │               │                │
  ┌────▼─────┐  ┌────▼─────┐   ┌─────▼──────┐   ┌─────▼──────┐
  │  Hermes  │  │  MCP     │   │  LiteLLM   │   │  OpenClaw  │
  │  Adapter │  │ Gateway  │   │  Proxy     │   │  Adapter   │
  │ (Python) │  │ (Python) │   │ (Python)   │   │ (JS shim → │
  │          │  │          │   │            │   │  HTTP /judge) │
  └──────────┘  └──────────┘   └────────────┘   └────────────┘
```

## 2. Goals & non-goals

**Goals**
- Zero framework imports in `clawkeeper-core/`. Adapters depend on the core; the core
  never imports an adapter.
- Public Python API stable enough that any agent framework can wire in by writing a
  ~200 LOC adapter.
- Same decision logic regardless of which adapter forwarded the event.
- Existing OpenClaw users keep working through an HTTP-thin adapter (no breaking
  behavior change in v0.2.0).
- Adversarial self-evolving layer (Smolagents-based Attack/Defense) feeds discovered
  patterns into the same `risk` rule store — no separate pipeline.

**Non-goals (for v0.2)**
- Cross-machine distributed deployment of the core. Single-process is fine; HTTP is
  used to bridge JS adapter, not for scale.
- Persistence backends other than the filesystem. JSONL + atomic-rename is fine.
- A new UI. The CLI stays; web UI can wait.
- Replacing the LLM the judge uses. Keep it provider-pluggable via LiteLLM.

## 3. Public API surface

The core exposes one class per concern. All inputs/outputs are Pydantic models so
adapters get type-checked at the boundary.

### 3.1 `clawkeeper_core.judge.Judge`

```python
class Judge:
    def __init__(self, policy: Policy | None = None, memory: DecisionMemory | None = None): ...

    def evaluate(self, ctx: JudgeContext) -> Decision:
        """Synchronous decision: allow | ask | deny + reason + risk."""

    async def evaluate_async(self, ctx: JudgeContext) -> Decision: ...
```

`JudgeContext` (Pydantic):

```python
class JudgeContext(BaseModel):
    tool_name: str
    tool_args: dict[str, Any]
    messages: list[Message]            # recent conversation slice
    agent_id: str | None = None
    session_id: str | None = None
    workspace: Path | None = None
    metadata: dict[str, Any] = {}      # adapter-specific extras
```

`Decision`:

```python
class Decision(BaseModel):
    outcome: Literal["allow", "ask", "deny"]
    scope:   Literal["once", "session", "always"] = "once"
    risk:    Literal["low", "medium", "high", "critical"]
    reason:  str
    evidence: dict[str, Any] = {}
    signals: list[Signal] = []         # which sub-detectors contributed
```

### 3.2 `clawkeeper_core.risk.RiskEngine`

```python
class RiskEngine:
    def fingerprint(self, ctx: JudgeContext) -> RiskScore: ...
    def add_pattern(self, pattern: Pattern) -> None: ...
    def load_corpus(self, path: Path) -> int: ...     # adversarial loop feeds this
```

### 3.3 `clawkeeper_core.drift.IntentDrift`

```python
class IntentDrift:
    def detect(self, intent: Intent, tool_chain: list[ToolCall]) -> DriftReport: ...
    def extract_intent(self, messages: list[Message]) -> Intent: ...
```

### 3.4 `clawkeeper_core.profile.AgentProfiler`

```python
class AgentProfiler:
    def update(self, event: AgentEvent) -> None: ...
    def baseline(self, agent_id: str) -> Profile: ...
    def deviation(self, agent_id: str, recent: WindowedEvents) -> Deviation: ...
```

### 3.5 `clawkeeper_core.memory.DecisionMemory`

```python
class DecisionMemory:
    def append(self, ctx: JudgeContext, decision: Decision) -> None: ...
    def lookup(self, fingerprint: str) -> Decision | None: ...   # for ALWAYS_ALLOW
    def history(self, since: datetime, until: datetime) -> Iterator[DecisionRecord]: ...
```

### 3.6 `clawkeeper_core.maintenance` — hardening + rollback

```python
def harden(state_dir: Path, config: HardenConfig) -> HardenReport: ...
def list_backups(state_dir: Path) -> list[Backup]: ...
def rollback(state_dir: Path, backup_name: str) -> RollbackReport: ...
```

### 3.7 Guards (`clawkeeper_core.guards.*`)

Stay narrow — one concern each.

```python
guards.exec_gate.guard(event: ToolCallEvent) -> GuardOutcome
guards.path_guard.guard(event: ToolCallEvent) -> GuardOutcome
guards.input_validator.validate(tool_name: str, params: dict) -> ValidationResult
guards.budget.check(usage: TokenUsage) -> BudgetOutcome
```

### 3.8 HTTP surface (`clawkeeper_core.server`)

FastAPI app. Same payload as the in-process methods — adapters that can't import
Python (the JS OpenClaw adapter) talk to this.

```
POST /v1/judge          -> Decision
POST /v1/audit          -> AuditReport       (startup audit, harden suggestions)
POST /v1/event          -> {ok: true}        (fire-and-forget telemetry)
POST /v1/scan/skill     -> SkillScanReport
POST /v1/scan/logs      -> LogScanReport
GET  /v1/health         -> {status: "ok", version: "0.2.0"}
GET  /v1/policy         -> Policy
PUT  /v1/policy         -> Policy            (admin only)
```

## 4. Adapter contract

An adapter is a Python (or other-language) module that:

1. Subscribes to its host framework's tool-call / message events.
2. Builds a `JudgeContext` from the framework's payload.
3. Calls `judge.evaluate(ctx)` (or HTTP `POST /v1/judge`).
4. Translates `Decision.outcome` back into the framework's enforcement primitive.

That's it. No adapter is allowed to keep its own copy of decision logic.

### 4.1 Hermes Agent (v0.2.0 primary)

Hermes exposes:

- `set_approval_callback(cb)` on `tools.terminal_tool` and `tools.computer_use.tool`.
  The callback returns one of `"once" | "session" | "always" | "deny"` — *exactly*
  matching ClawKeeper's `Decision.outcome × scope`. One-to-one mapping, no glue.
- `AIAgent.__init__` accepts ~10 observation callbacks (`tool_start_callback`,
  `tool_complete_callback`, `step_callback`, etc.). These feed the profiler, drift
  detector, and decision memory.

Wiring (sketch):

```python
from clawkeeper_core.judge import Judge
from clawkeeper_core.adapters.hermes import install
from hermes_agent.run_agent import AIAgent

judge = Judge.from_workspace(workspace)
agent = AIAgent(..., tool_start_callback=..., tool_complete_callback=...)
install(judge, agent)     # registers approval + observation callbacks
```

User-facing change: one import + one call.

### 4.2 MCP Gateway (v0.2.1)

A Python MCP server (`mcp` SDK) that registers as a downstream proxy. Forwards
`tools/list` from upstreams; intercepts `tools/call`. For every call, build a
`JudgeContext` and route the result.

### 4.3 LiteLLM Proxy (v0.2.2)

Implement `litellm.CustomLogger` with `async_pre_call_hook` and
`async_post_call_success_hook`. Posts the request to `/v1/judge` and blocks (or
modifies) based on the response.

### 4.4 OpenClaw (existing JS plugin, soft port)

The JS plugin keeps its `before_tool_call` subscription but its handler is now a
thin HTTP client — `POST http://127.0.0.1:7474/v1/judge`. Decision logic moves to
the core; only the OpenClaw event-loop binding stays JS.

## 5. Package layout

```
ClawKeeper/
├── pyproject.toml                # uv- and pip-friendly
├── README.md
├── DESIGN.md                     # this file
├── clawkeeper_core/
│   ├── __init__.py
│   ├── schemas.py                # all Pydantic models
│   ├── policy.py                 # Policy + defaults
│   ├── judge.py                  # Judge
│   ├── risk.py                   # RiskEngine, fingerprints
│   ├── drift.py                  # IntentDrift
│   ├── profile.py                # AgentProfiler
│   ├── memory.py                 # DecisionMemory
│   ├── controls.py               # control catalogue
│   ├── audit.py                  # startup/runtime audit
│   ├── scanner.py                # log + skill scanners
│   ├── permission.py             # ALLOW/DENY + scope handling
│   ├── maintenance.py            # harden + rollback
│   ├── state.py                  # workspace state files (SOUL.md, etc.)
│   ├── server.py                 # FastAPI app
│   ├── guards/
│   │   ├── __init__.py
│   │   ├── exec_gate.py
│   │   ├── path_guard.py
│   │   ├── input_validator.py
│   │   └── budget.py
│   └── adapters/
│       ├── __init__.py
│       ├── hermes.py             # v0.2.0
│       ├── mcp.py                # v0.2.1
│       ├── litellm.py            # v0.2.2
│       └── openclaw_http.py      # HTTP-client mirror of the JS plugin's needs
├── adapters_js/
│   └── openclaw/                 # the existing JS plugin, slimmed to an HTTP shim
├── tests/
│   ├── test_judge.py
│   ├── test_risk.py
│   ├── test_drift.py
│   └── ...
├── legacy/                       # untouched copy of v0.1 JS for diffing
│   ├── clawkeeper-plugin/
│   ├── clawkeeper-skill/
│   └── clawkeeper-watcher/
└── docs/
    └── HERMES_INTEGRATION.md
```

## 6. Dependencies (locked)

- `pydantic >= 2.6`
- `fastapi >= 0.110`
- `uvicorn >= 0.27`
- `httpx >= 0.27`
- `litellm >= 1.50`         (proxy adapter + judge LLM calls)
- `mcp >= 1.0`              (MCP gateway adapter)
- `smolagents`              (adversarial layer only, kept optional via extras)
- `pytest`, `pytest-asyncio`, `ruff`, `mypy`  (dev)

Python: **3.11+** (matches Hermes Agent's minimum).

## 7. Test strategy

- Each ported JS module gets an isomorphic Python test that ports the existing test
  case set. Goal: every `*.test.js` has a matching `tests/test_*.py` with the same
  assertions, so behavior parity is provable.
- Adapter tests: spin up a stub `AIAgent` (Hermes test fixture) and a real `Judge`,
  drive a synthetic conversation, assert decisions match expectations.
- HTTP server tests via `httpx.AsyncClient` against the FastAPI app.

## 8. Open questions

These need to be resolved before/during Phase 1:

- **Async vs sync.** Hermes mixes both. Default to sync `Judge.evaluate` with an
  `async` variant; the FastAPI route always uses `evaluate_async`.
- **LLM in the judge or pure rules?** v0.1's judge is rule-based. We probably keep
  that; LLM-judges go in `risk.llm_classifier` as an optional signal.
- **Schema versioning.** Pydantic models will evolve. Stamp every persisted record
  with `schema_version: int` and write migrations.
- **Backwards-compat tool naming.** v0.1 uses `Bash`, `Read`, `Write` etc.
  (Claude Code tool names); Hermes uses its own. Adapter layer normalizes; core
  uses canonical tool taxonomy in `schemas.ToolName`.
