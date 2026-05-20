# ClawKeeper integration surfaces

How ClawKeeper attaches to different agent runtimes, what each integration gives us, and where the blind spots are.

This doc deliberately avoids the question "can ClawKeeper observe X?" — most agent systems leak enough telemetry that observation is always possible. The question that decides whether ClawKeeper is *useful* on a given runtime is: **at how many points can we actually block, and how reliably?**

---

## 1. Why this matters

A "safety framework" that can only observe is a logger with extra steps. To matter, ClawKeeper has to be able to:

1. **Block individual tool calls** (the `pre_tool_call` decision point).
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
| **Source-level fork** | Embed CK inside the runtime's source tree | Maximum power but defeats the point — we wanted to *not* be a fork |

The order roughly corresponds to **decreasing leverage per unit-of-coupling**: a plugin hook gives precise control without owning the runtime; LD_PRELOAD owns the OS surface but knows nothing about agent state.

---

## 3. Per-runtime surface map

### 3.1 Hermes Agent (NousResearch)

Status: **first-class**. We have a working adapter at `clawkeeper_core/adapters/hermes.py`.

| Integration point | Type | What it gives us | Source |
|---|---|---|---|
| `hermes_cli/plugins.py::invoke_hook("pre_tool_call", ...)` | Plugin event-bus | **Blocking** pre-tool-call interception. Return `{"action": "block", "message": ...}` → tool execution skipped, message surfaces as tool error to LLM. Fires for **every** tool call (not just regex-flagged) | `hermes_cli/plugins.py:1385` |
| `invoke_hook("post_tool_call", ...)` | Plugin event-bus | Observation after every tool result | Same |
| `invoke_hook("transform_tool_result", ...)` | Plugin event-bus | **Mutate** tool result before LLM sees it (credential redaction, PI-string replacement) | Same |
| `invoke_hook("transform_terminal_output", ...)` | Plugin event-bus | Mutate terminal stdout before tool return path | Same |
| `invoke_hook("pre_llm_call", ...)` / `post_llm_call` | Plugin event-bus | Observe + mutate request/response payloads to the model provider | Same |
| `invoke_hook("pre_api_request", ...)` / `post_api_request` | Plugin event-bus | Lower-level than `pre_llm_call` — raw HTTP body | Same |
| `invoke_hook("on_session_start" \| "on_session_end" \| "on_session_finalize" \| "on_session_reset")` | Plugin event-bus | Wire up profile/memory/audit-log scaffolding per session | Same |
| `invoke_hook("pre_gateway_dispatch", ...)` | Plugin event-bus | Block / rewrite incoming messaging-platform messages (Discord, Telegram, Slack DMs) **before** auth/pairing checks | `gateway/run.py` |
| `agent.tool_start_callback` / `tool_complete_callback` | Instance-level observer | Observation only. **Hermes silently swallows callback exceptions**; raising does NOT block. Useful for telemetry; useless for enforcement | `run_agent.py:10831, 11225` |
| `tools.terminal_tool.set_approval_callback()` / `tools.computer_use.tool.set_approval_callback()` | Module-level callback | **Blocking, but only fires when Hermes's `tools/approval.py` regex flags the command.** Bypassed by Python heredocs and most non-bash-shaped tool calls (see Task-1 finding 3: 0 fires across 56 tool calls in red-team scenarios) | `tools/approval.py`, `tools/terminal_tool.py` |
| `self._tool_guardrails.before_call(...)` | Agent-internal | Native blocking API parallel to plugin hooks. Lives at `agent/tool_guardrails.py::ToolGuardrailDecision`. Used internally; documented but harder to extend from outside | `agent/tool_guardrails.py:241` |
| MCP servers configured in `cli-config.yaml::mcp_servers` | External subprocess | Hermes calls them via stdio MCP; we can be one. **First-class blocking for tools we own**. Hermes's MCP env filter is server-side hardening that doesn't affect us | `gateway/config.py` |
| Skill loader (`tools/skills_tool.py` + `~/.hermes/skills/`) | Filesystem + loader | Skills are .md files Hermes ingests; CK can scan the skills directory before/after install. **Issue #7072 (Skills Guard bypass via importlib)** is documented; CK's `script_body_scan` already catches most variants | `tools/skills_tool.py` |
| ACP server (`acp_adapter/`) | Stdio JSON-RPC | Hermes can serve itself to IDEs (Zed-style) over ACP. Gives us another stdio-proxy seam if needed | `acp_adapter/server.py` |
| Messaging gateway (`gateway/run.py` + `gateway/platforms/*.py`) | Long-lived service + adapters | Per-platform auth, allowlists, DM pairing already exist. We can wrap entries via `pre_gateway_dispatch` | `gateway/run.py` |

**Blind spots on Hermes:** content the agent generates that never traverses a tool call (e.g., free-text replies the LLM sends back through the messaging adapter without invoking tools first) only reaches us via `transform_llm_output` or `post_llm_call`. Reasoning-chain content (`ResponseReasoningItem` etc.) is not exposed through public hooks — it's an opaque internal stream.

### 3.2 Claude Code (Anthropic CLI)

Status: **mostly observation-only**, with a *spawn-the-Python-process* style block path.

Claude Code is a CLI binary; there is no Python SDK to subclass. All integration goes through `~/.claude/settings.json` and external executables / MCP servers.

| Integration point | Type | What it gives us |
|---|---|---|
| `hooks.PreToolUse` in `~/.claude/settings.json` | Shell-command hook | **Blocking** — the hook script runs before Claude Code calls a tool; non-zero exit *or* a JSON `{"hookEventName": "PreToolUse", "permissionDecision": "deny"}` reply on stdout aborts the call. ClawKeeper would ship as a small `clawkeeper-hook` binary that pipes the call to a long-running CK daemon (avoid Python startup cost). |
| `hooks.PostToolUse` | Shell-command hook | Observation only. Same wire shape. |
| `hooks.UserPromptSubmit` | Shell-command hook | **Mutate or block** the prompt the user typed. Useful for redacting secrets before the LLM sees them. |
| `hooks.Notification` / `Stop` / `SubagentStop` / `SessionStart` / `SessionEnd` / `PreCompact` | Shell-command hook | Telemetry boundary points. |
| MCP servers in settings.json | External subprocess | Same as Hermes — CK can be the MCP server. **First-class blocking for tools we own.** |
| `settings.json::permissions.allow` / `deny` | Static config | Native allow/deny patterns; useful baseline but no dynamic context-aware decisions. CK should *generate* these from policy, not replace them. |
| Subagents (`~/.claude/agents/*.md`) | File-based | We can ship a `clawkeeper-reviewer` subagent that the user invokes manually. Useful for ad-hoc audits, not real-time blocking. |
| `~/.claude/skills/*` | File-based | Same — skills as a delivery vehicle for CK's reusable policies. |

**Blind spots:** no in-process Python attachment. The block path is *cross-process*: Claude Code → hook script → ClawKeeper daemon → reply. Means a per-call IPC roundtrip latency (~1–10 ms). For interactive use that's invisible; for high-throughput automation it's the dominant cost.

### 3.3 OpenClaw (the v0.1 origin)

Status: **legacy supported**, in maintenance mode for ClawKeeper v0.2.

OpenClaw was TypeScript-first; ClawKeeper v0.1 was deeply embedded as plugins. v0.2's `adapters_js/openclaw` ships a thin HTTP shim so a Python ClawKeeper can be the policy decision point for an OpenClaw instance.

| Integration point | Type | What it gives us |
|---|---|---|
| OpenClaw plugin API (TypeScript) | In-process JS | First-class blocking — same as Hermes plugin hooks but in JS. Legacy approach. |
| HTTP shim (`adapters_js/openclaw/`) | TS-to-Python bridge | Lets a v0.2 Python core enforce policy for an OpenClaw v0.1 agent. Adds a small request roundtrip per tool call. |
| Watcher pattern (separate OpenClaw instance over WebSocket) | External supervisor | The original "Watcher" architecture from ClawKeeper's paper. Provides the "decoupled supervisor" argument vs Hermes's in-process design. v0.2 keeps this conceptually; the Watcher is one Python agent observing another. |

**Recommended in v0.2:** maintain the HTTP shim, don't try to ship new TS code. New customers should use Hermes; OpenClaw integration is for existing users.

### 3.4 Codex (OpenAI Codex CLI)

Status: **needs investigation**; treat as MCP-host for now.

Codex CLI (the 2026 incarnation of OpenAI's terminal agent) supports MCP servers and has a hook-like notion. Specifics shift between releases, and at time of writing CK doesn't have an adapter.

| Integration point | Type | What it gives us |
|---|---|---|
| MCP servers (in `~/.codex/config.toml`) | External subprocess | First-class blocking for tools-we-own. Same shape as Claude Code MCP. |
| `~/.codex/hooks/*.sh` (if/when stable) | Shell-command hooks | Reportedly similar to Claude Code's PreToolUse but the contract is less mature; do not depend on it for hard safety. |
| Codex ACP support (`codex_responses_adapter.py` in Hermes) | Stdio JSON-RPC | If Codex exposes ACP server-style, CK can sit in the stdio path. Speculative. |

**Recommended adapter shape:** MCP-gateway only until Codex stabilizes a documented hook API.

### 3.5 LangGraph (LangChain)

Status: **straightforward in-process integration** via callbacks + middleware.

LangGraph is Python-native and explicitly designed around extension. The blocking patterns are different from Hermes but well-defined.

| Integration point | Type | What it gives us |
|---|---|---|
| `BaseCallbackHandler` (LangChain core) | Class to subclass | Fires on tool start / tool error / tool end / LLM call. **Cannot block from inside a callback** — same shape as Hermes's tool_start_callback. Telemetry only. |
| Tool wrapping via `BaseTool` subclass | Class-level | Wrap each tool to intercept `_run`. Allows blocking by raising or returning a sentinel. Requires walking the graph and wrapping each `ToolNode`. |
| Graph middleware / `interrupt_before` / `interrupt_after` | Graph-level config | LangGraph supports interrupting execution before a specified node. Use this to *force human-in-the-loop on policy-uncertain tools* — exactly what CK's `Judge.ask_user` outcome should do. |
| Checkpointer | State persistence layer | We can store CK's per-session decision log alongside the graph state. Lets `[s]ession`-scoped allowlists survive checkpoints. |

**Recommended adapter shape (LangGraph):** wrap every `ToolNode` at graph-construction time with a `clawkeeper_pre_dispatch` wrapper that calls our guard chain and either lets the node execute or returns a `clawkeeper_blocked` state. For `ask_user` decisions, set `interrupt_before` on the wrapped node and surface the decision through the checkpointer.

### 3.6 AutoGPT-style (AutoGPT itself, BabyAGI, AgentGPT, SmolAgents)

Status: **fork-or-MCP-gateway**.

This family of agents typically does not expose a plugin/hook API. Tool dispatch is a hard-coded loop calling Python functions. To get first-class blocking, you either:

| Integration point | Type | What it gives us |
|---|---|---|
| Forking the agent's executor loop | Source-level | Maximum power but defeats portability. Realistic only for one-off engagements. |
| Monkey-patching the tool registry at import time | Hack | Works for AutoGPT proper. Brittle across versions. Document but don't ship as default. |
| MCP gateway position (if the agent supports MCP — some forks do) | External subprocess | Same MCP-server pattern. Works only for tools the agent reaches through MCP, not for its built-in `execute_python_file` / `read_file` etc. |
| Network proxy (sit on the egress path) | Process-level | Catches network-bound side effects (curl-style exfil). Blind to local-filesystem damage. |

**Recommended:** for AutoGPT-class agents in 2026, ClawKeeper ships an **observation-only Watcher** that follows the agent's filesystem + network activity and surfaces audits *after the fact*. Not real-time blocking. Document this honestly — promising blocking on a runtime that doesn't expose a gate would be misleading.

### 3.7 Generic MCP clients (Claude Desktop, Cursor, Continue, Aider, Zed, et al.)

Status: **first-class** as long as the client connects to our gateway.

This is ClawKeeper's strongest position. Anything that speaks MCP can plug into our `clawkeeper_core.adapters.mcp.GatewayServer` and get full pre-tool-call routing through `Judge`. The decision boundary is the MCP message itself — we own the wire.

| Integration point | Type | What it gives us |
|---|---|---|
| MCP server gateway (`adapters/mcp.py::GatewayServer`) | Server we run | **Blocking** — every `tools/call` routes through `Judge.evaluate()`. Returns `isError=true` with a blocked reason for `stop`/`ask_user`. |
| MCP resources (read-only context the agent fetches) | Server-side | We can interpose: serve resources only after running PI scan. |
| MCP prompts (templates the client offers) | Server-side | We control the prompt templates' provenance; can pin SHA-256 like Tirith does for its binary. |

**Caveat:** we only see tools the MCP client reaches through MCP. If the client *also* has native tools (Claude Code's `Bash`, `Edit`, `Read`), we don't see those.

---

## 4. Hermes deep-dive: what combination = pre-tool-call interception without forking?

This is the question the user asked specifically. Short answer:

> **Register a Python plugin that registers a `pre_tool_call` hook + optionally a `transform_tool_result` hook + (if MCP servers are in play) deploy ClawKeeper as the MCP gateway.**

Long answer:

### What works on its own

- `pre_tool_call` plugin hook (the one we wired in Task 2). **Blocks every tool call**, including the Python-heredoc cases that Hermes's own regex misses. This is the documented, supported way to add policy without forking Hermes. ✅

### What doesn't work alone but is useful in combination

- `tool_start_callback` + `tool_complete_callback` on the AIAgent instance. Observation only — Hermes silently swallows exceptions. Use them for *additional* telemetry (correlating call IDs, recording timestamps in our trace store) but never as the blocking path. (Task 2 finding.)
- `set_approval_callback` on `tools.terminal_tool`. Fires only when Hermes's `tools/approval.py` regex matches. In Task-1 red-team runs across 56 tool calls, this fired **zero times** — agents preferred Python-heredoc-style commands the regex doesn't cover. Keep this hooked for any case where Hermes *does* flag something (mostly bare `rm -rf`-class commands), but don't rely on it as the primary path.

### What gives us additional surface

- `transform_tool_result` hook lets us *rewrite* tool returns before the LLM consumes them. This is where credential redaction (`credential_redact_guard`) and PI scrubbing belong on a Hermes deployment — Hermes itself only redacts MCP errors.
- `transform_llm_output` hook intercepts what the agent says back to the user. Useful for the *outbound* leg of a credential — if the agent has a token in its working memory and tries to write it into a reply, we can scrub it server-side.
- `pre_gateway_dispatch` hook on the messaging gateway lets us refuse / rewrite *inbound* messages before the agent even sees them. Useful when the Discord bot is invoked by a not-fully-trusted operator (e.g., shared server).

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
   transform_tool_result hook  ────── ClawKeeper.credential_redact
        │
   transform_llm_output hook  ──────── ClawKeeper.credential_redact (outbound)
        │
   reply to user
```

Plus, **MCP servers as the second moat**: every MCP server Hermes is configured to use should itself be a ClawKeeper gateway. The MCP `Judge` runs even when the in-process plugin hook somehow misfires.

---

## 5. Adapter shape per runtime — recommendation summary

| Runtime | Adapter shape | Blocking quality | Code | Code lives at |
|---|---|---|---|---|
| **Hermes Agent** | Python plugin: register `pre_tool_call` + `post_tool_call` + `transform_tool_result` + `pre_gateway_dispatch` hooks via `_register_hook`. Optional: also be the MCP gateway. | **A+** (every tool call gated) | done | `clawkeeper_core/adapters/hermes.py` |
| **MCP clients (Claude Desktop, Cursor, Continue, Aider, Zed)** | `GatewayServer` — a FastMCP server every tool routes through. | **A** (every MCP tool gated; native client tools invisible) | done | `clawkeeper_core/adapters/mcp.py` |
| **Claude Code** | A small native binary that Claude Code spawns as a `PreToolUse` hook; the binary talks to a long-running CK daemon over Unix socket. Plus MCP server for MCP-routed tools. | **A** (every tool call gated) | not started | `clawkeeper_core/adapters/claude_code/` (pending) |
| **OpenClaw v0.1** | HTTP shim — OpenClaw plugin calls into Python ClawKeeper. | **B+** (limited by plugin API granularity) | maintained | `adapters_js/openclaw/` |
| **LangGraph** | `ToolNode` wrapper installed at graph-construction time + `interrupt_before` for ask_user outcomes. | **A** (every wrapped tool gated; un-wrapped tools invisible) | not started | `clawkeeper_core/adapters/langgraph/` (pending) |
| **Codex CLI** | MCP gateway only until Codex stabilizes a hook API. | **B** (only MCP-routed tools gated) | not started | `clawkeeper_core/adapters/codex/` (pending) |
| **AutoGPT family** | Observation-only Watcher — filesystem + network proxy + post-hoc audit. **Don't promise blocking.** | **D** (observation only) | not started | `clawkeeper_core/adapters/watcher/` (pending) |
| **Generic OpenAI-API-compatible** | LLM-stream proxy: sit between the agent and the model provider, scrub credentials & PI in the response stream before they reach the agent. | **C** (observation + content rewrite; cannot block tool execution because we don't see the dispatcher) | not started | `clawkeeper_core/adapters/llm_proxy/` (pending) |

---

## 6. Coverage matrix (what each runtime gives ClawKeeper)

| | Pre-tool block | Post-tool result rewrite | LLM I/O rewrite | Skill / tool-registry scan | Inbound message gate | Memory/context scan |
|---|---|---|---|---|---|---|
| Hermes Agent | ✅ plugin hook | ✅ `transform_tool_result` | ✅ `transform_llm_output` | 🟡 partial (skill loader) | ✅ `pre_gateway_dispatch` | 🛑 not exposed |
| MCP gateway | ✅ all gateway tools | ✅ rewrite return | n/a (no LLM) | 🛑 client-side | n/a | n/a |
| Claude Code | ✅ `PreToolUse` hook | ✅ `PostToolUse` hook (rewrite via stdout) | ✅ `UserPromptSubmit` | 🛑 not exposed | n/a (one-user-CLI) | 🛑 |
| OpenClaw v0.1 | ✅ TS plugin | ✅ TS plugin | 🟡 partial | ✅ skill scanner exists | n/a | ✅ behavioral scan ports |
| Codex CLI | 🟡 MCP only | 🟡 MCP only | 🛑 | 🛑 | n/a | 🛑 |
| LangGraph | ✅ ToolNode wrap | 🟡 ToolNode wrap (rewrite needs custom) | 🛑 not directly | 🛑 | n/a | 🟡 checkpointer |
| AutoGPT family | 🛑 | 🛑 | 🛑 | 🛑 | 🛑 | 🛑 |
| LLM-stream proxy | 🛑 | 🛑 | ✅ | n/a | n/a | 🛑 |

**Reading the matrix:** ClawKeeper is *full-strength* on Hermes, MCP, and Claude Code. *Limited-but-useful* on OpenClaw and LangGraph. *Observation-only* on AutoGPT-class and bare LLM-proxy. The honest pitch to a security team is: pick a runtime in the top half if you can.

---

## 7. Design implications for ClawKeeper

Three things this survey implies about how the rest of the codebase should evolve:

1. **The guard-chain abstraction in `clawkeeper_core/adapters/base.py` is correct.** Guards are agent-agnostic functions over a normalised event dict. Adapters translate native events → standard events → adapter-specific block returns. This is the only design that lets us cover Hermes/MCP/Claude Code/LangGraph without writing four copies of `path_guard`.

2. **The "Watcher" concept from ClawKeeper v0.1 should be repurposed as the AutoGPT-class adapter** — a separate process tailing the agent's filesystem + network activity, producing audit reports. Promising real-time blocking on those runtimes isn't honest.

3. **MCP-gateway position should be the default deployment recommendation.** It's the only adapter shape that works the same way regardless of host. Even on Hermes — where we have first-class plugin hooks — running CK *also* as the MCP gateway provides a second moat. Defense-in-depth across the wire and the host.

---

## 8. Open questions

- **Codex CLI:** when its hook API stabilises, does it allow blocking pre-tool-call? If yes, promote Codex to "A".
- **LangGraph subagent boundaries:** when a graph node delegates to a subagent (`Send` mechanic), does our `ToolNode` wrap see the subagent's tool calls or only the parent's? Need to verify.
- **Claude Code daemon protocol:** the recommended deployment requires a long-running Python daemon Claude Code's hook script talks to (for sub-millisecond per-call cost). What's the IPC surface — Unix socket + JSON-RPC? FastAPI on localhost? Worth its own design doc when we build the adapter.
- **Multi-host federation:** when one user runs Hermes on a server *and* Claude Code on a laptop *and* both talk to the same Discord channel, do they share a CK decision store? Out of scope for now but a real question for a team deployment.

---

*Audit trail:* every `pending` adapter in §5 is listed in `docs/internal/hermes-distillation.md` (the audit doc) so we don't lose them.
