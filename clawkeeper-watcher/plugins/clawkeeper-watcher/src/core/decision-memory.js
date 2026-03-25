import fs from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "./state.js";

const PERSIST_RISK_LEVELS = new Set(["medium", "high", "critical"]);

function isRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function truncate(value, maxLength = 240) {
  if (typeof value !== "string") {
    return "";
  }
  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

export function getBeijingDateStamp(date = new Date()) {
  const beijingTime = new Date(date.getTime() + 8 * 60 * 60 * 1000);
  return beijingTime.toISOString().split("T")[0];
}

function shouldPersistDecision(decision) {
  if (!isRecord(decision)) {
    return false;
  }

  if (decision.decision && decision.decision !== "continue") {
    return true;
  }

  return PERSIST_RISK_LEVELS.has(String(decision.riskLevel || "").toLowerCase());
}

function summarizeForwardedContext(body = {}) {
  const forwardedContext = isRecord(body.forwardedContext) ? body.forwardedContext : {};
  const metadata = isRecord(forwardedContext.metadata) ? forwardedContext.metadata : {};
  const messages = Array.isArray(forwardedContext.messages) ? forwardedContext.messages : [];

  const normalizedMessages = messages.filter((message) => isRecord(message));
  let lastUserContent = "";
  const toolNames = [];

  for (const message of normalizedMessages) {
    const role = typeof message.role === "string" ? message.role : "";
    if (role === "user" && typeof message.content === "string") {
      lastUserContent = message.content;
    }

    const toolName =
      typeof message.toolName === "string"
        ? message.toolName
        : typeof message.name === "string"
          ? message.name
          : "";
    if (toolName) {
      toolNames.push(toolName);
    }
  }

  return {
    requestId: typeof body.requestId === "string" ? body.requestId : null,
    sessionKey: typeof metadata.sessionKey === "string" ? metadata.sessionKey : null,
    messageCount: normalizedMessages.length,
    toolCount: toolNames.length,
    toolNames: [...new Set(toolNames)].slice(0, 8),
    lastUserMessage: truncate(lastUserContent),
  };
}

function buildDecisionMemoryRecord({ mode, body, decision }) {
  const contextSummary = summarizeForwardedContext(body);

  return {
    timestamp: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(),
    mode,
    requestId: contextSummary.requestId,
    sessionKey: contextSummary.sessionKey,
    decision: decision.decision,
    stopReason: decision.stopReason,
    riskLevel: decision.riskLevel,
    nextAction: decision.nextAction,
    needsUserDecision: !!decision.needsUserDecision,
    shouldContinue: !!decision.shouldContinue,
    localEnhanced: !!decision.localEnhanced,
    summary: typeof decision.summary === "string" ? decision.summary : "",
    evidence: Array.isArray(decision.evidence) ? decision.evidence.slice(0, 8) : [],
    messageCount: contextSummary.messageCount,
    toolCount: contextSummary.toolCount,
    toolNames: contextSummary.toolNames,
    lastUserMessage: contextSummary.lastUserMessage,
  };
}

export async function resolveDecisionMemoryDir() {
  const stateDir = await resolveStateDir();
  const memoryDir = path.join(stateDir, ".clawkeeper-watcher", "decision-memory");
  await fs.mkdir(memoryDir, { recursive: true });
  return memoryDir;
}

async function resolveTodayDecisionMemoryFile() {
  const memoryDir = await resolveDecisionMemoryDir();
  return path.join(memoryDir, `${getBeijingDateStamp()}.jsonl`);
}

export async function appendDecisionMemory({ mode, body, decision, logger = console }) {
  if (mode !== "remote" || !shouldPersistDecision(decision)) {
    return { saved: false, reason: "skipped" };
  }

  const record = buildDecisionMemoryRecord({ mode, body, decision });
  const memoryFile = await resolveTodayDecisionMemoryFile();
  await fs.appendFile(memoryFile, `${JSON.stringify(record)}\n`, "utf-8");

  if (typeof logger?.debug === "function") {
    logger.debug(
      `[Clawkeeper-Watcher] decision memory saved decision=${record.decision} risk=${record.riskLevel}`,
    );
  }

  return { saved: true, path: memoryFile, record };
}

export const _testExports = {
  buildDecisionMemoryRecord,
  shouldPersistDecision,
  summarizeForwardedContext,
  getBeijingDateStamp,
  resolveDecisionMemoryDir,
};
