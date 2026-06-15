/**
 * Clawkeeper Event Logger
 * Unified logging system for all OpenClaw events:
 * - before_tool_call (工具执行)
 * - message_received (消息接收)
 * - message_sending (消息发送)
 * - llm_input (LLM 输入)
 * - llm_output (LLM 输出)
 *
 * Logs are stored in: $OPENCLAW_WORKSPACE/log/YYYY-MM-DD.jsonl
 */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

let debugLogger = null;

/**
 * Set debug logger for troubleshooting
 */
export function setDebugLogger(logger) {
  debugLogger = logger;
  if (debugLogger) {
    debugLogger.debug("[Clawkeeper-Watcher Logger] Debug logger initialized");
  }
}

/**
 * Resolve the OpenClaw workspace directory
 */
async function resolveWorkspaceDir() {
  const candidates = [
    process.env.OPENCLAW_WORKSPACE,
    path.join(os.homedir(), ".openclaw", "workspace"),
    path.join(os.homedir(), ".openclaw"),
  ].filter(Boolean);

  if (debugLogger) {
    debugLogger.debug(
      "[Clawkeeper-Watcher Logger] Resolving workspace from candidates:",
      candidates,
    );
  }

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] ✓ Found workspace at:", candidate);
      }
      return candidate;
    } catch {
      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] ✗ Candidate not accessible:", candidate);
      }
    }
  }

  // Default fallback
  const fallback = path.join(os.homedir(), ".openclaw", "workspace");
  if (debugLogger) {
    debugLogger.debug("[Clawkeeper-Watcher Logger] Using fallback workspace:", fallback);
  }
  return fallback;
}

/**
 * Get the log file path for today and ensure directory exists
 */
async function getTodayLogFile() {
  try {
    const workspaceDir = await resolveWorkspaceDir();
    const logDir = path.join(workspaceDir, "log");

    if (debugLogger) {
      debugLogger.debug("[Clawkeeper-Watcher Logger] Creating log directory:", logDir);
    }

    // Ensure log directory exists
    await fs.mkdir(logDir, { recursive: true });

    // Create filename: YYYY-MM-DD.jsonl (使用北京时间)
    const now = new Date();
    const beijingTime = new Date(now.getTime() + 8 * 60 * 60 * 1000);
    const today = beijingTime.toISOString().split("T")[0];
    const logFile = path.join(logDir, `${today}.jsonl`);

    if (debugLogger) {
      debugLogger.debug("[Clawkeeper-Watcher Logger] Log file path:", logFile);
    }

    return logFile;
  } catch (error) {
    console.error("[Clawkeeper-Watcher] Error resolving log file:", error.message);
    if (debugLogger) {
      debugLogger.error(
        "[Clawkeeper-Watcher Logger] getTodayLogFile error:",
        error.message,
        error.stack,
      );
    }
    throw error;
  }
}

/**
 * Write event to log file
 */
async function logEvent(eventType, eventData = {}) {
  try {
    const logFile = await getTodayLogFile();

    const record = {
      // timestamp: new Date().toISOString(),
      timestamp: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(),
      type: eventType,
      ...eventData,
    };

    const line = JSON.stringify(record) + "\n";
    await fs.appendFile(logFile, line, "utf-8");

    if (debugLogger) {
      debugLogger.debug(`[Clawkeeper-Watcher Logger] ✓ Logged ${eventType} event to ${logFile}`);
    }
  } catch (error) {
    console.error(`[Clawkeeper-Watcher] ✗ Failed to log ${eventType} event:`, error.message);
    if (debugLogger) {
      debugLogger.error(
        `[Clawkeeper-Watcher Logger] ✗ Logging error for ${eventType}:`,
        error.message,
      );
    }
  }
}

/**
 * Hook: before_tool_call
 * Event structure: { toolName, params, runId?, toolCallId? }
 * Context: PluginHookToolContext
 */
export function createToolLoggerHook(logger = null) {
  if (logger) {
    setDebugLogger(logger);
  }

  return async (event, ctx) => {
    try {
      const { toolName, params, runId, toolCallId } = event;

      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] Hook triggered: before_tool_call", {
          toolName,
        });
      }

      await logEvent("before_tool_call", {
        toolName: toolName || "unknown",
        paramsCount: Object.keys(params || {}).length,
        params: params || {},
        runId: runId || null,
        toolCallId: toolCallId || null,
        agentId: ctx?.agentId || null,
        sessionKey: ctx?.sessionKey || null,
        sessionId: ctx?.sessionId || null,
      });
    } catch (error) {
      console.error("[Clawkeeper-Watcher] ✗ before_tool_call hook error:", error.message);
      if (debugLogger) {
        debugLogger.error(
          "[Clawkeeper-Watcher Logger] ✗ before_tool_call hook failed:",
          error.message,
        );
      }
    }

    return {};
  };
}

/**
 * Hook: message_received
 * Event structure: { from, content, metadata? }
 * Context: PluginHookMessageContext
 */
export function createMessageReceivedHook(logger = null) {
  if (logger) {
    setDebugLogger(logger);
  }

  return async (event, ctx) => {
    try {
      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] Hook triggered: message_received");
      }

      const content = event.content || event.message || "";
      await logEvent("message_received", {
        from: event.from || null,
        contentLength: content.length,
        content: content.substring(0, 1000), // 记录前1000字符
        metadata: event.metadata || null,
        channelId: ctx?.channelId || null,
        accountId: ctx?.accountId || null,
        conversationId: ctx?.conversationId || null,
      });
    } catch (error) {
      console.error("[Clawkeeper-Watcher] ✗ message_received hook error:", error.message);
      if (debugLogger) {
        debugLogger.error(
          "[Clawkeeper-Watcher Logger] ✗ message_received hook failed:",
          error.message,
        );
      }
    }

    return {};
  };
}

/**
 * Hook: message_sending
 * Event structure: { to, content, metadata? }
 * Context: PluginHookMessageContext
 */
export function createMessageSendingHook(logger = null) {
  if (logger) {
    setDebugLogger(logger);
  }

  return async (event, ctx) => {
    try {
      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] Hook triggered: message_sending");
      }

      const content = event.content || event.message || "";
      await logEvent("message_sending", {
        to: event.to || null,
        contentLength: content.length,
        content: content.substring(0, 1000), // 记录前2000字符
        metadata: event.metadata || null,
        channelId: ctx?.channelId || null,
        accountId: ctx?.accountId || null,
        conversationId: ctx?.conversationId || null,
      });
    } catch (error) {
      console.error("[Clawkeeper-Watcher] ✗ message_sending hook error:", error.message);
      if (debugLogger) {
        debugLogger.error(
          "[Clawkeeper-Watcher Logger] ✗ message_sending hook failed:",
          error.message,
        );
      }
    }

    return {};
  };
}

/**
 * Hook: llm_input
 * Event structure: { runId, sessionId, provider, model, systemPrompt?, prompt, historyMessages, imagesCount }
 * Context: PluginHookAgentContext
 */
export function createLLMInputHook(logger = null) {
  if (logger) {
    setDebugLogger(logger);
  }

  return async (event, ctx) => {
    try {
      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] Hook triggered: llm_input");
      }

      const prompt = event.prompt || "";
      const systemPrompt = event.systemPrompt || "";

      await logEvent("llm_input", {
        runId: event.runId || null,
        sessionId: event.sessionId || null,
        provider: event.provider || "unknown",
        model: event.model || "unknown",
        systemPrompt: systemPrompt.substring(0, 1000), // 记录系统提示词
        prompt: prompt.substring(0, 2000), // 记录用户提示词
        promptLength: prompt.length,
        systemPromptLength: systemPrompt.length,
        historyMessagesCount: Array.isArray(event.historyMessages)
          ? event.historyMessages.length
          : 0,
        imagesCount: event.imagesCount || 0,
        agentId: ctx?.agentId || null,
        sessionKey: ctx?.sessionKey || null,
      });
    } catch (error) {
      console.error("[Clawkeeper-Watcher] ✗ llm_input hook error:", error.message);
      if (debugLogger) {
        debugLogger.error("[Clawkeeper-Watcher Logger] ✗ llm_input hook failed:", error.message);
      }
    }

    return {};
  };
}

/**
 * Hook: llm_output
 * Event structure: { runId, sessionId, provider, model, assistantTexts?, usage? }
 * Context: PluginHookAgentContext
 */
export function createLLMOutputHook(logger = null) {
  if (logger) {
    setDebugLogger(logger);
  }

  return async (event, ctx) => {
    try {
      if (debugLogger) {
        debugLogger.debug("[Clawkeeper-Watcher Logger] Hook triggered: llm_output");
      }

      // Process assistant texts
      let assistantTexts = [];
      let totalResponseLength = 0;

      if (Array.isArray(event.assistantTexts)) {
        assistantTexts = event.assistantTexts.map(
          (text) => (text ? text.substring(0, 2000) : ""), // 截断至2000字符保留完整内容
        );
        totalResponseLength = event.assistantTexts.reduce(
          (sum, text) => sum + (text?.length || 0),
          0,
        );
      }

      await logEvent("llm_output", {
        runId: event.runId || null,
        sessionId: event.sessionId || null,
        provider: event.provider || "unknown",
        model: event.model || "unknown",
        assistantTexts: assistantTexts, // ← 记录实际的文本响应
        totalResponseLength: totalResponseLength,
        hasLastAssistant: !!event.lastAssistant,
        inputTokens: event.usage?.input || null,
        outputTokens: event.usage?.output || null,
        cacheReadTokens: event.usage?.cacheRead || null,
        cacheWriteTokens: event.usage?.cacheWrite || null,
        totalTokens: event.usage?.total || null,
        agentId: ctx?.agentId || null,
        sessionKey: ctx?.sessionKey || null,
      });
    } catch (error) {
      console.error("[Clawkeeper-Watcher] ✗ llm_output hook error:", error.message);
      if (debugLogger) {
        debugLogger.error("[Clawkeeper-Watcher Logger] ✗ llm_output hook failed:", error.message);
      }
    }

    return {};
  };
}

/**
 * Get log files for a date range
 */
export async function getLogFiles(_startDate = null, _endDate = null) {
  const workspaceDir = await resolveWorkspaceDir();
  const logDir = path.join(workspaceDir, "log");

  try {
    const files = await fs.readdir(logDir);
    return files
      .filter((f) => f.endsWith(".jsonl"))
      .toSorted()
      .toReversed(); // newest first
  } catch {
    return [];
  }
}

/**
 * Read log file and return all records
 */
export async function readLogFile(filename) {
  const workspaceDir = await resolveWorkspaceDir();
  const logFile = path.join(workspaceDir, "log", filename);

  try {
    const content = await fs.readFile(logFile, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);
    return lines.map((line) => JSON.parse(line));
  } catch (error) {
    console.error("[Clawkeeper-Watcher] Failed to read log file:", error.message);
    return [];
  }
}

/**
 * Get today's log file path (for reference)
 */
export async function getTodayLogPath() {
  return await getTodayLogFile();
}
