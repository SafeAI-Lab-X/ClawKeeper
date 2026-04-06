/**
 * Clawkeeper Event Logger
 * Unified logging system for all OpenClaw events:
 * - before_tool_call
 * - message_received
 * - message_sending
 * - llm_input
 * - llm_output
 * 
 * Logs are stored in: $OPENCLAW_WORKSPACE/log/YYYY-MM-DD.jsonl (in UTC/Beijing timezone)
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import { guardBeforeToolCall } from './path-guard.js';

let debugLogger = null;

/**
 * Set debug logger for troubleshooting
 */
export function setDebugLogger(logger) {
  debugLogger = logger;
  if (debugLogger) {
    debugLogger.debug('[Clawkeeper Logger] Debug logger initialized');
  }
}

/**
 * Resolve the OpenClaw workspace directory
 */
async function resolveWorkspaceDir() {
  const candidates = [
    process.env.OPENCLAW_WORKSPACE,
    path.join(os.homedir(), '.openclaw', 'workspace'),
    path.join(os.homedir(), '.openclaw'),
  ].filter(Boolean);

  if (debugLogger) {
    debugLogger.debug('[Clawkeeper Logger] Resolving workspace from candidates:', candidates);
  }

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      if (debugLogger) {
        debugLogger.debug('[Clawkeeper Logger] ✓ Found workspace at:', candidate);
      }
      return candidate;
    } catch (error) {
      if (debugLogger) {
        debugLogger.debug('[Clawkeeper Logger] ✗ Candidate not accessible:', candidate);
      }
    }
  }

  // Default fallback
  const fallback = path.join(os.homedir(), '.openclaw', 'workspace');
  if (debugLogger) {
    debugLogger.debug('[Clawkeeper Logger] Using fallback workspace:', fallback);
  }
  return fallback;
}

/**
 * Get the log file path for today and ensure directory exists
 */
async function getTodayLogFile() {
  try {
    const workspaceDir = await resolveWorkspaceDir();
    const logDir = path.join(workspaceDir, 'log');
    
    if (debugLogger) {
      debugLogger.debug('[Clawkeeper Logger] Creating log directory:', logDir);
    }
    
    // Ensure log directory exists
    await fs.mkdir(logDir, { recursive: true });
    
    // Create filename: YYYY-MM-DD.jsonl (using UTC/Beijing timezone)
    const now = new Date();
    const beijingTime = new Date(now.getTime() + 8 * 60 * 60 * 1000);
    const today = beijingTime.toISOString().split('T')[0];
    const logFile = path.join(logDir, `${today}.jsonl`);
    
    if (debugLogger) {
      debugLogger.debug('[Clawkeeper Logger] Log file path:', logFile);
    }
    
    return logFile;
  } catch (error) {
    console.error('[Clawkeeper] Error resolving log file:', error.message);
    if (debugLogger) {
      debugLogger.error('[Clawkeeper Logger] getTodayLogFile error:', error.message, error.stack);
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
    
    const line = JSON.stringify(record) + '\n';
    await fs.appendFile(logFile, line, 'utf-8');
    
    if (debugLogger) {
      debugLogger.debug(`[Clawkeeper Logger] ✓ Logged ${eventType} event to ${logFile}`);
    }
  } catch (error) {
    console.error(`[Clawkeeper] ✗ Failed to log ${eventType} event:`, error.message);
    if (debugLogger) {
      debugLogger.error(`[Clawkeeper Logger] ✗ Logging error for ${eventType}:`, error.message);
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
    const { toolName, params, runId, toolCallId } = event;
    let guardResult = { block: false };

    try {
      guardResult = guardBeforeToolCall({ toolName, params });
    } catch (error) {
      console.error('[Clawkeeper] path-guard error:', error.message);
      if (debugLogger) debugLogger.error('[Clawkeeper Logger] path-guard threw:', error.message);
    }

    try {
      if (debugLogger) debugLogger.debug('[Clawkeeper Logger] Hook triggered: before_tool_call', { toolName });
      await logEvent(guardResult.block ? 'blocked_tool_call' : 'before_tool_call', {
        toolName: toolName || 'unknown',
        paramsCount: Object.keys(params || {}).length,
        params: params || {},
        runId: runId || null,
        toolCallId: toolCallId || null,
        agentId: ctx?.agentId || null,
        sessionKey: ctx?.sessionKey || null,
        sessionId: ctx?.sessionId || null,
        ...(guardResult.block ? {
          guard: {
            rule: 'protected-path',
            pattern: guardResult.matched,
            candidate: guardResult.candidate,
            resolved: guardResult.resolved,
            severity: guardResult.severity,
            reason: guardResult.reason,
          }
        } : {}),
      });
    } catch (error) {
      console.error('[Clawkeeper] before_tool_call hook error:', error.message);
      if (debugLogger) debugLogger.error('[Clawkeeper Logger] before_tool_call hook failed:', error.message);
    }

    if (guardResult.block) {
      const reason = `Clawkeeper blocked access to protected path (${guardResult.severity || 'HIGH'}): ${guardResult.reason || guardResult.matched}. Candidate=${guardResult.candidate} Resolved=${guardResult.resolved}`;
      console.warn(`[Clawkeeper] BLOCKED ${reason}`);
      return { block: true, blockReason: reason };
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
        debugLogger.debug('[Clawkeeper Logger] Hook triggered: message_received');
      }
      
      const content = event.content || event.message || '';
      await logEvent('message_received', {
        from: event.from || null,
        contentLength: content.length,
        content: content.substring(0, 1000), // Log first 1000 characters
        metadata: event.metadata || null,
        channelId: ctx?.channelId || null,
        accountId: ctx?.accountId || null,
        conversationId: ctx?.conversationId || null,
      });
    } catch (error) {
      console.error('[Clawkeeper] ✗ message_received hook error:', error.message);
      if (debugLogger) {
        debugLogger.error('[Clawkeeper Logger] ✗ message_received hook failed:', error.message);
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
        debugLogger.debug('[Clawkeeper Logger] Hook triggered: message_sending');
      }
      
      const content = event.content || event.message || '';
      await logEvent('message_sending', {
        to: event.to || null,
        contentLength: content.length,
        content: content.substring(0, 1000), // Log first 2000 characters
        metadata: event.metadata || null,
        channelId: ctx?.channelId || null,
        accountId: ctx?.accountId || null,
        conversationId: ctx?.conversationId || null,
      });
    } catch (error) {
      console.error('[Clawkeeper] ✗ message_sending hook error:', error.message);
      if (debugLogger) {
        debugLogger.error('[Clawkeeper Logger] ✗ message_sending hook failed:', error.message);
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
        debugLogger.debug('[Clawkeeper Logger] Hook triggered: llm_input');
      }
      
      const prompt = event.prompt || '';
      const systemPrompt = event.systemPrompt || '';
      
      await logEvent('llm_input', {
        runId: event.runId || null,
        sessionId: event.sessionId || null,
        provider: event.provider || 'unknown',
        model: event.model || 'unknown',
        systemPrompt: systemPrompt.substring(0, 1000),  // Log system prompt
        prompt: prompt.substring(0, 2000),             // Log user prompt
        promptLength: prompt.length,
        systemPromptLength: systemPrompt.length,
        historyMessagesCount: Array.isArray(event.historyMessages) ? event.historyMessages.length : 0,
        imagesCount: event.imagesCount || 0,
        agentId: ctx?.agentId || null,
        sessionKey: ctx?.sessionKey || null,
      });
    } catch (error) {
      console.error('[Clawkeeper] ✗ llm_input hook error:', error.message);
      if (debugLogger) {
        debugLogger.error('[Clawkeeper Logger] ✗ llm_input hook failed:', error.message);
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
        debugLogger.debug('[Clawkeeper Logger] Hook triggered: llm_output');
      }
      
      // Process assistant texts
      let assistantTexts = [];
      let totalResponseLength = 0;
      
      if (Array.isArray(event.assistantTexts)) {
        assistantTexts = event.assistantTexts.map(text => 
          text ? text.substring(0, 2000) : ''  // Truncate to 2000 characters to preserve content
        );
        totalResponseLength = event.assistantTexts.reduce((sum, text) => sum + (text?.length || 0), 0);
      }
      
      await logEvent('llm_output', {
        runId: event.runId || null,
        sessionId: event.sessionId || null,
        provider: event.provider || 'unknown',
        model: event.model || 'unknown',
        assistantTexts: assistantTexts,  // Log actual text responses
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
      console.error('[Clawkeeper] ✗ llm_output hook error:', error.message);
      if (debugLogger) {
        debugLogger.error('[Clawkeeper Logger] ✗ llm_output hook failed:', error.message);
      }
    }
    
    return {};
  };
}

/**
 * Get log files for a date range
 */
export async function getLogFiles(startDate = null, endDate = null) {
  const workspaceDir = await resolveWorkspaceDir();
  const logDir = path.join(workspaceDir, 'log');
  
  try {
    const files = await fs.readdir(logDir);
    return files
      .filter((f) => f.endsWith('.jsonl'))
      .sort()
      .reverse(); // newest first
  } catch {
    return [];
  }
}

/**
 * Read log file and return all records
 */
export async function readLogFile(filename) {
  const workspaceDir = await resolveWorkspaceDir();
  const logFile = path.join(workspaceDir, 'log', filename);
  
  try {
    const content = await fs.readFile(logFile, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    return lines.map((line) => JSON.parse(line));
  } catch (error) {
    console.error('[Clawkeeper] Failed to read log file:', error.message);
    return [];
  }
}

/**
 * Get today's log file path (for reference)
 */
export async function getTodayLogPath() {
  return await getTodayLogFile();
}
