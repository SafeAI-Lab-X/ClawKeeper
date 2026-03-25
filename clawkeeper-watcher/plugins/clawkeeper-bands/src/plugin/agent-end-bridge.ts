import { randomUUID } from "crypto";
import { appendFile, writeFile } from "fs/promises";
import os from "os";
import path from "path";
import { CLAWKEEPER_BANDS_DATA_DIR, logger } from "../core/Logger";
import { clearPendingDecision, setPendingDecision } from "./pending-decision-store";

export interface AgentEndEvent {
  messages: unknown[];
  success: boolean;
  error?: string;
  durationMs?: number;
}

export interface AgentEndContext {
  agentId?: string;
  sessionId?: string;
  sessionKey?: string;
  workspaceDir?: string;
}

export interface BridgePolicy {
  maxRiskBeforeStop?: "low" | "medium" | "high" | "critical";
  requireUserConfirmationFor?: string[];
  autoContinueAllowed?: boolean;
  maxToolStepsWithoutUserTurn?: number;
  treatCommandExecutionAsHighRisk?: boolean;
}

export interface BridgeConfig {
  enabled?: boolean;
  url?: string;
  token?: string;
  /** @deprecated Ignored by the context-judge bridge. */
  model?: string;
  judgePath?: string;
  /** @deprecated Ignored by the context-judge bridge. */
  systemPrompt?: string;
  /** @deprecated Ignored by the context-judge bridge. */
  userPrompt?: string;
  timeoutMs?: number;
  maxContextChars?: number;
  policy?: BridgePolicy;
}

export interface BridgeHookPluginConfig {
  bridge?: BridgeConfig;
}

type JudgeResponse = {
  version: number;
  decision: "continue" | "stop" | "ask_user";
  stopReason: string;
  shouldContinue: boolean;
  needsUserDecision: boolean;
  userQuestion: string | null;
  summary: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  evidence: string[];
  nextAction: "continue_run" | "ask_user" | "stop_run";
  continueHint: string | null;
};

type DeliveryContext = {
  channel?: string;
  to?: string;
  accountId?: string;
  threadId?: string | number;
};

type SessionEntry = {
  channel?: string;
  deliveryContext?: DeliveryContext;
  lastChannel?: string;
  lastTo?: string;
  lastAccountId?: string;
  lastThreadId?: string | number;
  origin?: { threadId?: string | number };
};

type RouteReplyFn = (params: {
  payload: { text: string };
  channel: string;
  to: string;
  accountId?: string;
  threadId?: string | number;
  sessionKey?: string;
  cfg: unknown;
  mirror?: boolean;
}) => Promise<{ ok: boolean; messageId?: string; error?: string }>;

type RuntimeHelpers = {
  routeReply: RouteReplyFn;
};

const BRIDGE_EVENTS_PATH = path.join(CLAWKEEPER_BANDS_DATA_DIR, "bridge-events.jsonl");
const BRIDGE_LAST_REQUEST_PATH = path.join(CLAWKEEPER_BANDS_DATA_DIR, "bridge-last-request.json");
const DEFAULT_MAX_CONTEXT_CHARS = 120_000;
const DEFAULT_JUDGE_PATH = "/plugins/clawkeeper-watcher/context-judge";
const DEFAULT_AGENT_ID = "main";

let runtimeHelpersPromise: Promise<RuntimeHelpers> | null = null;

function resolveBridgeConfig(
  pluginConfig: { bridge?: BridgeConfig } | undefined,
): Required<BridgeConfig> | null {
  const raw = pluginConfig?.bridge ?? {};
  const enabled = raw.enabled ?? process.env.CLAWKEEPER_BANDS_BRIDGE_ENABLED !== "false";
  const url = raw.url ?? process.env.CLAWKEEPER_BANDS_BRIDGE_URL ?? "";
  const token = raw.token ?? process.env.CLAWKEEPER_BANDS_BRIDGE_TOKEN ?? "";

  if (!enabled || !url || !token) {
    return null;
  }

  return {
    enabled: true,
    url: url.replace(/\/$/, ""),
    token,
    judgePath:
      raw.judgePath ?? process.env.CLAWKEEPER_BANDS_BRIDGE_JUDGE_PATH ?? DEFAULT_JUDGE_PATH,
    model: raw.model ?? process.env.CLAWKEEPER_BANDS_BRIDGE_MODEL ?? "",
    systemPrompt: raw.systemPrompt ?? process.env.CLAWKEEPER_BANDS_BRIDGE_SYSTEM_PROMPT ?? "",
    userPrompt: raw.userPrompt ?? process.env.CLAWKEEPER_BANDS_BRIDGE_USER_PROMPT ?? "",
    timeoutMs: raw.timeoutMs ?? Number(process.env.CLAWKEEPER_BANDS_BRIDGE_TIMEOUT_MS ?? 15000),
    maxContextChars:
      raw.maxContextChars ??
      Number(process.env.CLAWKEEPER_BANDS_BRIDGE_MAX_CONTEXT_CHARS ?? DEFAULT_MAX_CONTEXT_CHARS),
    policy: raw.policy ?? {},
  };
}

function stringifyUnknown(value: unknown, maxChars: number): string {
  if (value == null) {
    return "";
  }
  if (typeof value === "string") {
    return value.length > maxChars ? `${value.slice(0, maxChars)}\n...[truncated]` : value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    const json = JSON.stringify(
      value,
      (_key, nested) => {
        if (typeof nested === "string") {
          return nested.length > 12_000 ? `${nested.slice(0, 12_000)}...[truncated]` : nested;
        }
        return nested;
      },
      2,
    );
    return json.length > maxChars ? `${json.slice(0, maxChars)}\n...[truncated]` : json;
  } catch {
    return "[unserializable]";
  }
}

function extractText(value: unknown, maxChars: number): string {
  if (typeof value === "string") {
    return stringifyUnknown(value, maxChars);
  }
  if (!Array.isArray(value)) {
    return stringifyUnknown(value, maxChars);
  }
  return value
    .map((entry) => {
      if (!entry || typeof entry !== "object") {
        return stringifyUnknown(entry, Math.min(maxChars, 500));
      }
      const text = (entry as { text?: unknown }).text;
      return typeof text === "string" ? text : stringifyUnknown(entry, Math.min(maxChars, 2000));
    })
    .filter(Boolean)
    .join("\n");
}

function normalizeMessageRecord(entry: unknown, maxChars: number): Record<string, unknown> | null {
  if (!entry || typeof entry !== "object") {
    return null;
  }

  const record = entry as {
    role?: unknown;
    content?: unknown;
    type?: unknown;
    name?: unknown;
    toolName?: unknown;
    toolCallId?: unknown;
    tool_call_id?: unknown;
    id?: unknown;
    error?: unknown;
    result?: unknown;
    details?: unknown;
    tool_calls?: unknown;
    toolCalls?: unknown;
  };

  const role =
    typeof record.role === "string"
      ? record.role
      : typeof record.type === "string"
        ? record.type
        : "unknown";
  const normalized: Record<string, unknown> = {
    role,
    content: extractText(record.content, Math.min(20_000, maxChars)),
  };

  if (typeof record.name === "string") {
    normalized.name = record.name;
  }
  if (typeof record.toolName === "string") {
    normalized.toolName = record.toolName;
  }
  if (typeof record.toolCallId === "string") {
    normalized.toolCallId = record.toolCallId;
  }
  if (typeof record.tool_call_id === "string") {
    normalized.toolCallId = record.tool_call_id;
  }
  if (typeof record.id === "string") {
    normalized.id = record.id;
  }
  if (record.details !== undefined) {
    normalized.details = stringifyUnknown(record.details, Math.min(20_000, maxChars));
  }
  if (record.tool_calls !== undefined) {
    normalized.toolCalls = stringifyUnknown(record.tool_calls, Math.min(20_000, maxChars));
  }
  if (record.toolCalls !== undefined) {
    normalized.toolCalls = stringifyUnknown(record.toolCalls, Math.min(20_000, maxChars));
  }
  if (record.result !== undefined) {
    normalized.result = stringifyUnknown(record.result, Math.min(20_000, maxChars));
  }
  if (record.error !== undefined) {
    normalized.error = stringifyUnknown(record.error, Math.min(8000, maxChars));
  }

  const raw = stringifyUnknown(entry, Math.min(20_000, maxChars));
  if (raw) {
    normalized.raw = raw;
  }

  return normalized;
}

async function appendBridgeEvent(event: Record<string, unknown>): Promise<void> {
  await appendFile(BRIDGE_EVENTS_PATH, `${JSON.stringify(event)}\n`, "utf8");
}

async function writeLastBridgeRequest(payload: Record<string, unknown>): Promise<void> {
  await writeFile(BRIDGE_LAST_REQUEST_PATH, JSON.stringify(payload, null, 2), "utf8");
}

function normalizeJudgeResponse(rawPayload: unknown): JudgeResponse {
  if (!rawPayload || typeof rawPayload !== "object" || Array.isArray(rawPayload)) {
    return {
      version: 1,
      decision: "stop",
      stopReason: "invalid_response",
      shouldContinue: false,
      needsUserDecision: false,
      userQuestion: null,
      summary: "Remote context-judge did not return a valid JSON object.",
      riskLevel: "medium",
      evidence: [],
      nextAction: "stop_run",
      continueHint: null,
    };
  }

  const parsed = rawPayload as Partial<JudgeResponse> & {
    decision?: string;
    summary?: string;
    userQuestion?: string | null;
    continueHint?: string | null;
    stopReason?: string;
  };

  const decision =
    parsed.decision === "continue" || parsed.decision === "stop" || parsed.decision === "ask_user"
      ? parsed.decision
      : "stop";

  return {
    version: Number.isFinite(parsed.version) ? Number(parsed.version) : 1,
    decision,
    stopReason: typeof parsed.stopReason === "string" ? parsed.stopReason : "unknown",
    shouldContinue:
      typeof parsed.shouldContinue === "boolean" ? parsed.shouldContinue : decision === "continue",
    needsUserDecision:
      typeof parsed.needsUserDecision === "boolean"
        ? parsed.needsUserDecision
        : decision === "ask_user",
    userQuestion: typeof parsed.userQuestion === "string" ? parsed.userQuestion : null,
    summary:
      typeof parsed.summary === "string"
        ? parsed.summary
        : "Remote context-judge did not provide a summary.",
    riskLevel:
      parsed.riskLevel === "low" ||
      parsed.riskLevel === "medium" ||
      parsed.riskLevel === "high" ||
      parsed.riskLevel === "critical"
        ? parsed.riskLevel
        : decision === "continue"
          ? "low"
          : "medium",
    evidence: Array.isArray(parsed.evidence)
      ? parsed.evidence.filter((item): item is string => typeof item === "string")
      : [],
    nextAction:
      parsed.nextAction === "continue_run" ||
      parsed.nextAction === "ask_user" ||
      parsed.nextAction === "stop_run"
        ? parsed.nextAction
        : decision === "continue"
          ? "continue_run"
          : decision === "ask_user"
            ? "ask_user"
            : "stop_run",
    continueHint: typeof parsed.continueHint === "string" ? parsed.continueHint : null,
  };
}

function resolveAgentIdFromSessionKey(sessionKey?: string): string | undefined {
  if (!sessionKey || !sessionKey.startsWith("agent:")) {
    return undefined;
  }
  const parts = sessionKey.split(":");
  return parts.length >= 2 ? parts[1] : undefined;
}

function normalizeAgentId(raw?: string): string {
  const trimmed = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  return trimmed || DEFAULT_AGENT_ID;
}

function expandHomePath(input: string, env: NodeJS.ProcessEnv = process.env): string {
  if (input === "~") {
    return env.HOME || os.homedir();
  }
  if (input.startsWith("~/")) {
    return path.join(env.HOME || os.homedir(), input.slice(2));
  }
  return input;
}

function resolveLocalStorePath(
  store?: string,
  opts?: { agentId?: string; env?: NodeJS.ProcessEnv },
): string {
  const env = opts?.env ?? process.env;
  const agentId = normalizeAgentId(opts?.agentId);
  const stateDir =
    env.OPENCLAW_STATE_DIR || env.OPENCLAW_HOME || path.join(env.HOME || os.homedir(), ".openclaw");

  if (!store) {
    return path.join(stateDir, "agents", agentId, "sessions", "sessions.json");
  }

  if (store.includes("{agentId}")) {
    return path.resolve(expandHomePath(store.replaceAll("{agentId}", agentId), env));
  }

  return path.resolve(expandHomePath(store, env));
}

async function importRuntimeHelpers(): Promise<RuntimeHelpers> {
  if (!runtimeHelpersPromise) {
    runtimeHelpersPromise = (async () => {
      const fs = require("fs");
      const candidateRoots = new Set<string>();
      let cursor = process.cwd();
      candidateRoots.add(cursor);
      cursor = __dirname;
      for (let i = 0; i < 10; i += 1) {
        candidateRoots.add(cursor);
        const parent = path.dirname(cursor);
        if (parent === cursor) {
          break;
        }
        cursor = parent;
      }

      const rootDir = Array.from(candidateRoots).find((candidate) => {
        return fs.existsSync(path.join(candidate, "dist"));
      });

      if (!rootDir) {
        throw new Error("Unable to locate OpenClaw dist/ runtime from clawkeeper-bands bridge");
      }

      const loadModule = <T>(relativePath: string): T => {
        const fullPath = path.join(rootDir, relativePath);
        return require(fullPath) as T;
      };

      const findNamedExport = <T extends Function>(
        relativePath: string,
        targetName: string,
      ): T | null => {
        const mod = loadModule<Record<string, unknown>>(relativePath);
        for (const value of Object.values(mod)) {
          if (typeof value === "function" && value.name === targetName) {
            return value as T;
          }
        }
        return null;
      };

      const distDir = path.join(rootDir, "dist");
      const distEntries = fs.readdirSync(distDir).filter((entry: string) => entry.endsWith(".js"));
      const replyRuntimeEntry = distEntries.find((entry: string) =>
        /^route-reply\.runtime-.*\.js$/.test(entry),
      );

      if (!replyRuntimeEntry) {
        throw new Error("Unable to locate route-reply runtime bundle from OpenClaw dist");
      }

      const routeReply = findNamedExport<RuntimeHelpers["routeReply"]>(
        `dist/${replyRuntimeEntry}`,
        "routeReply",
      );

      if (typeof routeReply !== "function") {
        throw new Error(`Unable to resolve routeReply from OpenClaw ${replyRuntimeEntry}`);
      }

      return {
        routeReply,
      };
    })();
  }

  return runtimeHelpersPromise;
}

async function loadSessionStoreFromDisk(storePath: string): Promise<Record<string, SessionEntry>> {
  try {
    const { readFile } = await import("fs/promises");
    const raw = await readFile(storePath, "utf8");
    const parsed = JSON.parse(raw) as Record<string, SessionEntry>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function normalizeDeliveryField(value: unknown): string | undefined {
  return typeof value === "string" ? value.trim() || undefined : undefined;
}

function normalizeThreadId(value: unknown): string | number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  return typeof value === "string" ? value.trim() || undefined : undefined;
}

function deliveryContextFromSessionEntry(entry?: SessionEntry): DeliveryContext | undefined {
  if (!entry) {
    return undefined;
  }

  const direct = entry.deliveryContext;
  const channel = normalizeDeliveryField(direct?.channel ?? entry.lastChannel ?? entry.channel);
  const to = normalizeDeliveryField(direct?.to ?? entry.lastTo);
  const accountId = normalizeDeliveryField(direct?.accountId ?? entry.lastAccountId);
  const threadId = normalizeThreadId(
    direct?.threadId ?? entry.lastThreadId ?? entry.origin?.threadId,
  );

  if (!channel && !to && !accountId && threadId == null) {
    return undefined;
  }

  return {
    channel,
    to,
    accountId,
    ...(threadId != null ? { threadId } : {}),
  };
}

async function loadCurrentDeliveryContext(params: {
  cfg: unknown;
  sessionKey?: string;
}): Promise<{ delivery?: DeliveryContext; reason?: string }> {
  if (!params.sessionKey) {
    return { reason: "missing sessionKey" };
  }

  try {
    await importRuntimeHelpers();
    const agentId = resolveAgentIdFromSessionKey(params.sessionKey);
    const storePath = resolveLocalStorePath(
      (params.cfg as { session?: { store?: string } }).session?.store,
      {
        agentId,
        env: process.env,
      },
    );
    const store = await loadSessionStoreFromDisk(storePath);
    const entry = store[params.sessionKey.toLowerCase()] ?? store[params.sessionKey];
    const delivery = deliveryContextFromSessionEntry(entry);
    if (!delivery?.channel || !delivery.to) {
      return { reason: "no deliveryContext on current session" };
    }
    return { delivery };
  } catch (error) {
    return { reason: error instanceof Error ? error.message : String(error) };
  }
}

async function replyToCurrentChannel(params: {
  cfg: unknown;
  sessionKey?: string;
  text?: string | null;
}): Promise<{ ok: boolean; reason?: string }> {
  if (!params.text?.trim()) {
    return { ok: false, reason: "missing text" };
  }

  try {
    const helpers = await importRuntimeHelpers();
    const loaded = await loadCurrentDeliveryContext({
      cfg: params.cfg,
      sessionKey: params.sessionKey,
    });
    if (!loaded.delivery?.channel || !loaded.delivery.to) {
      return { ok: false, reason: loaded.reason ?? "missing deliveryContext" };
    }

    const result = await helpers.routeReply({
      payload: { text: params.text },
      channel: loaded.delivery.channel,
      to: loaded.delivery.to,
      accountId: loaded.delivery.accountId,
      threadId: loaded.delivery.threadId,
      sessionKey: params.sessionKey,
      cfg: params.cfg,
      mirror: true,
    });

    if (!result.ok) {
      return { ok: false, reason: result.error ?? "routeReply failed" };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

export function createAgentEndBridgeHook(
  pluginConfig: BridgeHookPluginConfig | undefined,
  openclawConfig: unknown,
) {
  return async (event: AgentEndEvent, ctx: AgentEndContext): Promise<void> => {
    const bridge = resolveBridgeConfig(pluginConfig);
    if (!bridge) {
      return;
    }

    const requestId = randomUUID();
    const delivery = await loadCurrentDeliveryContext({
      cfg: openclawConfig,
      sessionKey: ctx.sessionKey,
    });

    const normalizedMessages = (event.messages ?? [])
      .map((message) => normalizeMessageRecord(message, bridge.maxContextChars))
      .filter((message): message is Record<string, unknown> => Boolean(message));

    const forwardedContext = {
      source: "openclaw-a-agent_end-bridge",
      metadata: {
        agentId: ctx.agentId ?? null,
        sessionId: ctx.sessionId ?? null,
        sessionKey: ctx.sessionKey ?? null,
        workspaceDir: ctx.workspaceDir ?? null,
        success: event.success,
        error: event.error ?? null,
        durationMs: event.durationMs ?? null,
        messageCount: normalizedMessages.length,
        channel: delivery.delivery?.channel ?? null,
        to: delivery.delivery?.to ?? null,
        accountId: delivery.delivery?.accountId ?? null,
        threadId: delivery.delivery?.threadId ?? null,
      },
      messages: normalizedMessages,
    };

    const requestPayload = {
      requestId,
      forwardedContext,
      policy: bridge.policy,
    };

    const startedAt = Date.now();

    try {
      await writeLastBridgeRequest({
        ts: new Date().toISOString(),
        url: `${bridge.url}${bridge.judgePath}`,
        sessionKey: ctx.sessionKey,
        request: requestPayload,
      });

      const response = await fetch(`${bridge.url}${bridge.judgePath}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${bridge.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestPayload),
        signal: AbortSignal.timeout(bridge.timeoutMs),
      });

      const payload = await response.json();
      const judge = normalizeJudgeResponse(payload);

      if (!response.ok) {
        throw new Error(
          `remote context-judge returned ${response.status}: ${judge.summary || "request failed"}`,
        );
      }

      if (judge.decision === "ask_user") {
        await setPendingDecision(ctx.sessionKey, {
          pendingDecision: true,
          origin: "clawkeeper-context-judge",
          requestId,
          question: judge.userQuestion ?? judge.summary,
          continueHint: judge.continueHint ?? undefined,
          createdAt: new Date().toISOString(),
        });
      } else {
        await clearPendingDecision(ctx.sessionKey);
      }

      let deliveryResult: { ok: boolean; reason?: string } | undefined;
      if (judge.decision === "ask_user") {
        deliveryResult = await replyToCurrentChannel({
          cfg: openclawConfig,
          sessionKey: ctx.sessionKey,
          text: judge.userQuestion ?? judge.summary,
        });
      } else if (judge.decision === "stop" && judge.summary) {
        deliveryResult = await replyToCurrentChannel({
          cfg: openclawConfig,
          sessionKey: ctx.sessionKey,
          text: judge.summary,
        });
      }

      const bridgeEvent = {
        ts: new Date().toISOString(),
        ok: response.ok,
        status: response.status,
        url: `${bridge.url}${bridge.judgePath}`,
        requestId,
        agentId: ctx.agentId,
        sessionId: ctx.sessionId,
        sessionKey: ctx.sessionKey,
        durationMs: Date.now() - startedAt,
        payload,
        judge,
        deliveredToChannel: deliveryResult?.ok ?? false,
        deliveryReason: deliveryResult?.reason,
      };

      await appendBridgeEvent(bridgeEvent);
      logger.info("[bridge] agent_end context judge completed", bridgeEvent);
    } catch (error) {
      const bridgeEvent = {
        ts: new Date().toISOString(),
        ok: false,
        url: `${bridge.url}${bridge.judgePath}`,
        requestId,
        agentId: ctx.agentId,
        sessionId: ctx.sessionId,
        sessionKey: ctx.sessionKey,
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      };

      await appendBridgeEvent(bridgeEvent);
      logger.warn("[bridge] agent_end context judge failed", bridgeEvent);
    }
  };
}
