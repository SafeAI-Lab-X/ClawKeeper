# ClawKeeper integration surfaces

How ClawKeeper attaches to different agent runtimes, what each integration gives us, and where the blind spots are.

This doc deliberately avoids the question "can ClawKeeper observe X?" — most agent systems leak enough telemetry that observation is always possible. The question that decides whether ClawKeeper is *useful* on a given runtime is: **at how many points can we actually block, and how reliably?**

> This document describes the **architecture and integration strategy**. Implementation availability varies by branch — check the relevant branch for which adapters currently exist as code.

---

## 1. Why this matters

A "safety framework" that can only observe is a logger with extra steps. To matter, ClawKeeper has to be able to:

1. **Block individual tool calls** (the pre-tool-call decision point).
2. **Scrub or replace content entering the agent's context** (tool results, retrieved memory, MCP returns, web fetches).
3. **Quarantine artifacts the agent persists** (skill installs, written files, cron jobs, memory writes).
4. **Refuse trajectory-level patterns** that no individual call would reveal.

Different runtimes expose those decision points at very different qualities. Some give us first-class pre-execution gates; some only let us watch from the sidelines.

---

## 2. Integration-surface taxonomy

For every agent runtime, the same questions:

| Surface | What it is | When useful |
|---|---|---|
| **Plugin hooks / event-bus** | A documented extension API the runtime fires at well-known lifecycle points | Best case — first-class blocking & observation |
| **Callback registration** | The runtime accepts function pointers / observer objects via constructor or setter | Good for telemetry; blocking depends on whether exceptions are honored |
| **MCP gateway position** | We run as the MCP server the runtime connects to | First-class blocking *for tools we own*; nothing for tools the runtime has natively |
| **Config injection** | A YAML/JSON the runtime reads at startup that names extension points | Limited — usually controls what's enabled, not how it runs |
| **Process-level interception** | LD_PRELOAD, syscall filter, container sandboxing, FUSE, eBPF | Catches *everything* the agent does, but cannot reason about agent intent; high false-positive risk |
| **Stdio / RPC proxy** | We sit between the agent and an LLM provider, or between the agent and the user | Full visibility of conversation; tool calls are visible as text patterns; blocking is by text rewrite or refusal |
| **Source-level fork** | Embed CK inside the runtime's source tree | Maximum power but defeats portability — we want to *not* be a fork |

The order roughly corresponds to **decreasing leverage per unit-of-coupling**: a plugin hook gives precise control without owning the runtime; LD_PRELOAD owns the OS surface but knows nothing about agent state.

---

## 3. Per-runtime surface map

### 3.1 Hermes Agent (NousResearch)

A first-class integration target — Hermes exposes a rich plugin event-bus that supports both blocking and observation.

| Integration point | Type | What it gives us | Source |
|---|---|---|---|
| `hermes_cli/plugins.py::invoke_hook("pre_tool_call", ...)` | Plugin event-bus | **Blocking** pre-tool-call interception. Return `{"action": "block", "message": ...}` → tool execution skipped, message surfaces as tool error to LLM. Fires for **every** tool call (not just regex-flagged) | `hermes_cli/plugins.py` |
| `invoke_hook("post_tool_call", ...)` | Plugin event-bus | Observation after every tool result | Same |
| `invoke_hook("transform_tool_result", ...)` | Plugin event-bus | **Mutate** tool result before LLM sees it (credential redaction, PI-string replacement) | Same |
| `invoke_hook("transform_terminal_output", ...)` | Plugin event-bus | Mutate terminal stdout before tool return path | Same |
| `invoke_hook("pre_llm_call", ...)` / `post_llm_call` | Plugin event-bus | Observe + mutate request/response payloads to the model provider | Same |
| `invoke_hook("pre_api_request", ...)` / `post_api_request` | Plugin event-bus | Lower-level than `pre_llm_call` — raw HTTP body | Same |
| `invoke_hook("on_session_start" \| "on_session_end" \| "on_session_finalize" \| "on_session_reset")` | Plugin event-bus | Wire up profile/memory/audit-log scaffolding per session | Same |
| `invoke_hook("pre_gateway_dispatch", ...)` | Plugin event-bus | Block / rewrite incoming messaging-platform messages (Discord, Telegram, Slack DMs) **before** auth/pairing checks | `gateway/run.py` |
| `agent.tool_start_callback` / `tool_complete_callback` | Instance-level observer | Observation only. **Hermes silently swallows callback exceptions**; raising does NOT block. Useful for telemetry; useless for enforcement | `run_agent.py` |
| `tools.terminal_tool.set_approval_callback()` / `tools.computer_use.tool.set_approval_callback()` | Module-level callback | **Blocking, but only fires when Hermes's `tools/approval.py` regex flags the command.** Bypassed by Python heredocs and most non-bash-shaped tool calls (empirically: 0 fires across 56 tool calls in realistic adversarial runs) | `tools/approval.py`, `tools/terminal_tool.py` |
| `self._tool_guardrails.before_call(...)` | Agent-internal | Native blocking API parallel to plugin hooks. Lives at `agent/tool_guardrails.py::ToolGuardrailDecision`. Used internally; documented but harder to extend from outside | `agent/tool_guardrails.py` |
| MCP servers configured in `cli-config.yaml::mcp_servers` | External subprocess | Hermes calls them via stdio MCP; ClawKeeper can be one. **First-class blocking for tools we own**. Hermes's MCP env filter is server-side hardening that doesn't affect us | `gateway/config.py` |
| Skill loader (`tools/skills_tool.py` + `~/.hermes/skills/`) | Filesystem + loader | Skills are .md files Hermes ingests; ClawKeeper can scan the skills directory before/after install. Issue #7072 (Skills Guard bypass via importlib) is documented; a sensitive-marker co-occurrence scan over script bodies catches most variants | `tools/skills_tool.py` |
| ACP server (`acp_adapter/`) | Stdio JSON-RPC | Hermes can serve itself to IDEs (Zed-style) over ACP. Provides another stdio-proxy seam if needed | `acp_adapter/server.py` |
| Messaging gateway (`gateway/run.py` + `gateway/platforms/*.py`) | Long-lived service + adapters | Per-platform auth, allowlists, DM pairing already exist. Wrap entries via `pre_gateway_dispatch` | `gateway/run.py` |

**Blind spots on Hermes:** content the agent generates that never traverses a tool call (e.g., free-text replies the LLM sends back through the messaging adapter without invoking tools first) only reaches us via `transform_llm_output` or `post_llm_call`. Reasoning-chain content (`ResponseReasoningItem` etc.) is not exposed through public hooks — it's an opaque internal stream.

### 3.2 Claude Code (Anthropic CLI)

Mostly observation-only, with a *spawn-the-Python-process* style block path.

Claude Code is a CLI binary; there is no Python SDK to subclass. All integration goes through `~/.claude/settings.json` and external executables / MCP servers.

| Integration point | Type | What it gives us |
|---|---|---|
| `hooks.PreToolUse` in `~/.claude/settings.json` | Shell-command hook | **Blocking** — the hook script runs before Claude Code calls a tool; non-zero exit *or* a JSON `{"hookEventName": "PreToolUse", "permissionDecision": "deny"}` reply on stdout aborts the call. ClawKeeper would ship as a small `clawkeeper-hook` binary that pipes the call to a long-running ClawKeeper daemon (avoid Python startup cost). |
| `hooks.PostToolUse` | Shell-command hook | Observation only. Same wire shape. |
| `hooks.UserPromptSubmit` | Shell-command hook | **Mutate or block** the prompt the user typed. Useful for redacting secrets before the LLM sees them. |
| `hooks.Notification` / `Stop` / `SubagentStop` / `SessionStart` / `SessionEnd` / `PreCompact` | Shell-command hook | Telemetry boundary points. |
| MCP servers in settings.json | External subprocess | Same as Hermes — ClawKeeper can be the MCP server. **First-class blocking for tools we own.** |
| `settings.json::permissions.allow` / `deny` | Static config | Native allow/deny patterns; useful baseline but no dynamic context-aware decisions. ClawKeeper should *generate* these from policy, not replace them. |
| Subagents (`~/.claude/agents/*.md`) | File-based | Ship a `clawkeeper-reviewer` subagent the user invokes manually. Useful for ad-hoc audits, not real-time blocking. |
| `~/.claude/skills/*` | File-based | Same — skills as a delivery vehicle for reusable policies. |

**Blind spots:** no in-process Python attachment. The block path is *cross-process*: Claude Code → hook script → ClawKeeper daemon → reply. Per-call IPC roundtrip latency (~1–10 ms). For interactive use that's invisible; for high-throughput automation it's the dominant cost.

### 3.3 OpenClaw (the v0.1 origin)

The original ClawKeeper integration target. The reference implementation embeds ClawKeeper as plugins inside an OpenClaw runtime, with a separate OpenClaw instance acting as the Watcher over WebSocket.

| Integration point | Type | What it gives us |
|---|---|---|
| OpenClaw plugin API (TypeScript) | In-process JS | First-class blocking — same as Hermes plugin hooks but in JS. |
| Watcher pattern (separate OpenClaw instance over WebSocket) | External supervisor | The "decoupled supervisor" architecture from the ClawKeeper paper. A second OpenClaw observing the first. |
| HTTP / RPC shim | Cross-language bridge | Lets a non-JS ClawKeeper core enforce policy for an OpenClaw agent. Adds a small request roundtrip per tool call. |

### 3.4 Codex (OpenAI Codex CLI)

Treat as MCP-host for now.

Codex CLI supports MCP servers and has a hook-like notion. Specifics shift between releases.

| Integration point | Type | What it gives us |
|---|---|---|
| MCP servers (in `~/.codex/config.toml`) | External subprocess | First-class blocking for tools-we-own. Same shape as Claude Code MCP. |
| `~/.codex/hooks/*.sh` (if/when stable) | Shell-command hooks | Reportedly similar to Claude Code's PreToolUse but the contract is less mature; do not depend on it for hard safety. |
| Codex ACP support | Stdio JSON-RPC | If Codex exposes ACP server-style, ClawKeeper can sit in the stdio path. Speculative. |

**Recommended adapter shape:** MCP-gateway only until Codex stabilizes a documented hook API.

### 3.5 LangGraph (LangChain)

Straightforward in-process integration via callbacks + middleware.

LangGraph is Python-native and explicitly designed around extension. The blocking patterns are different from Hermes but well-defined.

| Integration point | Type | What it gives us |
|---|---|---|
| `BaseCallbackHandler` (LangChain core) | Class to subclass | Fires on tool start / tool error / tool end / LLM call. **Cannot block from inside a callback** — same shape as Hermes's tool_start_callback. Telemetry only. |
| Tool wrapping via `BaseTool` subclass | Class-level | Wrap each tool to intercept `_run`. Allows blocking by raising or returning a sentinel. Requires walking the graph and wrapping each `ToolNode`. |
| Graph middleware / `interrupt_before` / `interrupt_after` | Graph-level config | LangGraph supports interrupting execution before a specified node. Use this to *force human-in-the-loop on policy-uncertain tools* — exactly what an `ask_user` decision means. |
| Checkpointer | State persistence layer | Store ClawKeeper's per-session decision log alongside the graph state. Lets session-scoped allowlists survive checkpoints. |

**Recommended adapter shape (LangGraph):** wrap every `ToolNode` at graph-construction time with a pre-dispatch wrapper that calls the guard chain and either lets the node execute or returns a blocked state. For `ask_user` decisions, set `interrupt_before` on the wrapped node and surface the decision through the checkpointer.

### 3.6 AutoGPT-style (AutoGPT itself, BabyAGI, AgentGPT, SmolAgents)

This family of agents typically does not expose a plugin/hook API. Tool dispatch is a hard-coded loop calling Python functions. To get first-class blocking, you either:

| Integration point | Type | What it gives us |
|---|---|---|
| Forking the agent's executor loop | Source-level | Maximum power but defeats portability. Realistic only for one-off engagements. |
| Monkey-patching the tool registry at import time | Hack | Works for AutoGPT proper. Brittle across versions. Document but don't ship as default. |
| MCP gateway position (if the agent supports MCP — some forks do) | External subprocess | Same MCP-server pattern. Works only for tools the agent reaches through MCP, not for its built-in `execute_python_file` / `read_file` etc. |
| Network proxy (sit on the egress path) | Process-level | Catches network-bound side effects (curl-style exfil). Blind to local-filesystem damage. |

**Recommended:** for AutoGPT-class agents, ClawKeeper should ship as an **observation-only Watcher** that follows the agent's filesystem + network activity and surfaces audits *after the fact*. Not real-time blocking. Promising blocking on a runtime that doesn't expose a gate would be misleading.

### 3.7 Generic MCP clients (Claude Desktop, Cursor, Continue, Aider, Zed, et al.)

ClawKeeper's strongest position. Anything that speaks MCP can plug into a ClawKeeper-as-MCP-gateway and get full pre-tool-call routing through the Judge. The decision boundary is the MCP message itself — we own the wire.

| Integration point | Type | What it gives us |
|---|---|---|
| MCP server gateway | Server we run | **Blocking** — every `tools/call` routes through `Judge.evaluate()`. Returns `isError=true` with a blocked reason for `stop`/`ask_user`. |
| MCP resources (read-only context the agent fetches) | Server-side | Interpose: serve resources only after running PI scan. |
| MCP prompts (templates the client offers) | Server-side | Control the prompt templates' provenance; can pin SHA-256 to known-good versions. |

**Caveat:** we only see tools the MCP client reaches through MCP. If the client *also* has native tools (Claude Code's `Bash`, `Edit`, `Read`), we don't see those.

---

## 4. Hermes deep-dive — what combination gives pre-tool-call interception without forking?

Short answer:

> **Register a plugin that wires a `pre_tool_call` hook + optionally a `transform_tool_result` hook + (if MCP servers are in play) deploy ClawKeeper as the MCP gateway.**

Long answer:

### What works on its own

- `pre_tool_call` plugin hook. **Blocks every tool call**, including Python-heredoc cases that Hermes's own regex misses. The documented, supported way to add policy without forking Hermes. ✅

### What doesn't work alone but is useful in combination

- `tool_start_callback` + `tool_complete_callback` on the AIAgent instance. Observation only — Hermes silently swallows exceptions. Use them for *additional* telemetry (correlating call IDs, recording timestamps in a trace store) but never as the blocking path.
- `set_approval_callback` on `tools.terminal_tool`. Fires only when Hermes's `tools/approval.py` regex matches. In realistic red-team runs, this fired **zero times across 56 tool calls** — agents preferred Python-heredoc-style commands the regex doesn't cover. Keep this hooked for any case where Hermes *does* flag something (mostly bare `rm -rf`-class commands), but don't rely on it as the primary path.

### What gives additional surface

- `transform_tool_result` hook lets us *rewrite* tool returns before the LLM consumes them. This is where credential redaction and PI scrubbing belong on a Hermes deployment — Hermes itself only redacts MCP errors.
- `transform_llm_output` hook intercepts what the agent says back to the user. Useful for the *outbound* leg of a credential — if the agent has a token in its working memory and tries to write it into a reply, we can scrub it server-side.
- `pre_gateway_dispatch` hook on the messaging gateway lets us refuse / rewrite *inbound* messages before the agent even sees them. Useful when the bot is invoked by a not-fully-trusted operator (e.g., shared server).

### What we explicitly don't get

- No visibility into Hermes's internal reasoning stream (`ResponseReasoningItem` etc.). The "thinking" the model emits before producing a tool call is opaque. We can only act on what becomes a tool call or a user-facing message.
- No way to influence smart-mode aux-LLM approval. That decision happens inside `tools/approval.py` between the dangerous-command match and the user prompt. If Hermes is configured `approvals.mode: smart`, the aux LLM makes the call — our hook still fires for the underlying tool call (so we're not bypassed), but we don't see the smart-mode reasoning. Recommendation: deployments that care about safety should set `approvals.mode: manual` and let ClawKeeper handle the dynamic decisions instead.

### Recommended Hermes-deployment stack

```
        ┌─ Discord / Telegram / Slack ──┐
        │                               │
   pre_gateway_dispatch hook  ──────────┤  ClawKeeper
        │                               │
   AIAgent.chat()  ────────────────────────┐
        │                                  │
   pre_tool_call hook  ──────────────── ClawKeeper ──→ deny / allow
        │
   tool execution
        │
   transform_tool_result hook  ────── ClawKeeper credential redaction
        │
   transform_llm_output hook  ──────── ClawKeeper credential redaction (outbound)
        │
   reply to user
```

Plus, **MCP servers as the second moat**: every MCP server Hermes is configured to use should itself be a ClawKeeper gateway. The MCP Judge runs even when the in-process plugin hook somehow misfires.

---

## 5. Adapter shape per runtime — recommendation summary

| Runtime | Recommended adapter shape | Blocking quality |
|---|---|---|
| **Hermes Agent** | Plugin that registers `pre_tool_call` + `post_tool_call` + `transform_tool_result` + `pre_gateway_dispatch` hooks. Optional: also be the MCP gateway. | **A+** (every tool call gated) |
| **MCP clients (Claude Desktop, Cursor, Continue, Aider, Zed)** | A gateway server every tool routes through. | **A** (every MCP tool gated; native client tools invisible) |
| **Claude Code** | A small native binary that Claude Code spawns as a `PreToolUse` hook; the binary talks to a long-running ClawKeeper daemon over Unix socket. Plus MCP server for MCP-routed tools. | **A** (every tool call gated) |
| **OpenClaw** | In-process TypeScript plugins (the v0.1 reference architecture), or HTTP shim to a non-JS ClawKeeper core. | **B+** (limited by plugin API granularity) |
| **LangGraph** | `ToolNode` wrapper installed at graph-construction time + `interrupt_before` for ask_user outcomes. | **A** (every wrapped tool gated; un-wrapped tools invisible) |
| **Codex CLI** | MCP gateway only until Codex stabilizes a hook API. | **B** (only MCP-routed tools gated) |
| **AutoGPT family** | Observation-only Watcher — filesystem + network proxy + post-hoc audit. **Don't promise blocking.** | **D** (observation only) |
| **Generic OpenAI-API-compatible** | LLM-stream proxy: sit between the agent and the model provider, scrub credentials & PI in the response stream before they reach the agent. | **C** (observation + content rewrite; cannot block tool execution because we don't see the dispatcher) |

---

## 6. Coverage matrix (what each runtime gives ClawKeeper)

| | Pre-tool block | Post-tool result rewrite | LLM I/O rewrite | Skill / tool-registry scan | Inbound message gate | Memory/context scan |
|---|---|---|---|---|---|---|
| Hermes Agent | ✅ plugin hook | ✅ `transform_tool_result` | ✅ `transform_llm_output` | 🟡 partial (skill loader) | ✅ `pre_gateway_dispatch` | 🛑 not exposed |
| MCP gateway | ✅ all gateway tools | ✅ rewrite return | n/a (no LLM) | 🛑 client-side | n/a | n/a |
| Claude Code | ✅ `PreToolUse` hook | ✅ `PostToolUse` hook (rewrite via stdout) | ✅ `UserPromptSubmit` | 🛑 not exposed | n/a (one-user-CLI) | 🛑 |
| OpenClaw | ✅ TS plugin | ✅ TS plugin | 🟡 partial | ✅ skill scanner | n/a | ✅ behavioral scan |
| Codex CLI | 🟡 MCP only | 🟡 MCP only | 🛑 | 🛑 | n/a | 🛑 |
| LangGraph | ✅ ToolNode wrap | 🟡 ToolNode wrap (rewrite needs custom) | 🛑 not directly | 🛑 | n/a | 🟡 checkpointer |
| AutoGPT family | 🛑 | 🛑 | 🛑 | 🛑 | 🛑 | 🛑 |
| LLM-stream proxy | 🛑 | 🛑 | ✅ | n/a | n/a | 🛑 |

**Reading the matrix:** ClawKeeper is *full-strength* on Hermes, MCP, and Claude Code. *Limited-but-useful* on OpenClaw and LangGraph. *Observation-only* on AutoGPT-class and bare LLM-proxy. The honest pitch to a security team is: pick a runtime in the top half if you can.

---

## 7. Design implications

Three things this survey implies about how ClawKeeper should evolve:

1. **A guard-chain abstraction over a normalised event dict is the only sane way to cover many hosts.** Guards stay agent-agnostic; per-host adapters translate native events → standard events → adapter-specific block returns. Otherwise we end up with four copies of `path_guard`.

2. **The "Watcher" concept from the ClawKeeper paper maps naturally onto AutoGPT-class adapters** — a separate process tailing the agent's filesystem + network activity, producing audit reports. Promising real-time blocking on those runtimes isn't honest. The paper's "decoupled supervisor" framing fits this gracefully.

3. **MCP-gateway position should be the default deployment recommendation.** It's the only adapter shape that works the same way regardless of host. Even on Hermes — where first-class plugin hooks exist — running ClawKeeper *also* as the MCP gateway provides a second moat. Defense-in-depth across the wire and the host.

---

## 8. Open questions

- **Codex CLI:** when its hook API stabilises, does it allow blocking pre-tool-call? If yes, promote Codex to "A".
- **LangGraph subagent boundaries:** when a graph node delegates to a subagent (`Send` mechanic), does a `ToolNode` wrap see the subagent's tool calls or only the parent's? Needs verification.
- **Claude Code daemon protocol:** the recommended deployment requires a long-running daemon that Claude Code's hook script talks to (for sub-millisecond per-call cost). What's the IPC surface — Unix socket + JSON-RPC? FastAPI on localhost? Worth its own design doc when building the adapter.
- **Multi-host federation:** when one user runs Hermes on a server *and* Claude Code on a laptop *and* both talk to the same Discord channel, do they share a ClawKeeper decision store? Real question for a team deployment.
