/**
 * OpenClaw plugin entry — wires before_tool_call (and a handful of
 * observation hooks) to the Python core via HTTP.
 *
 * The plugin is intentionally thin: no local decision logic, no
 * pattern caches, no log scanners. Everything substantive lives in
 * clawkeeper-core. If you need to change a rule, edit Python; do not
 * fork this JS file.
 */

import { judge } from "./judge.js";

const PLUGIN_ID = "clawkeeper-shim";
const PLUGIN_NAME = "ClawKeeper Shim";
const PLUGIN_VERSION = "0.2.0";

export const clawkeeperShimPlugin = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  version: PLUGIN_VERSION,
  configSchema: {
    parse(value) {
      if (value && typeof value === "object" && !Array.isArray(value)) return value;
      return {};
    },
  },
  register(api) {
    const config = api.config || {};
    const options = {
      serverUrl: config.serverUrl,
      failurePolicy: config.failurePolicy,
      timeoutMs: config.timeoutMs,
    };
    const mode = config.mode || "local";

    api.on("before_tool_call", async (event) => {
      const payload = {
        mode,
        requestId: event?.requestId || event?.callId,
        forwardedContext: {
          messages: _buildMessagesFromEvent(event),
          metadata: { sessionKey: event?.sessionKey },
        },
      };
      const decision = await judge(payload, options);

      if (decision?.decision === "stop") {
        return {
          block: true,
          reason: decision.summary || decision.stopReason,
          severity: decision.riskLevel,
          source: "clawkeeper-shim",
        };
      }
      if (decision?.decision === "ask_user") {
        return {
          ask: true,
          question: decision.userQuestion || decision.summary,
          severity: decision.riskLevel,
          source: "clawkeeper-shim",
        };
      }
      return { block: false };
    });

    api.logger?.info?.(`[${PLUGIN_ID}] registered — forwarding to ${options.serverUrl || "default server"}`);
  },
};


/**
 * Build a forwardedContext.messages slice from whatever shape OpenClaw
 * gave us. The plugin SDK has evolved over time; defensively support
 * both `event.messages` and `event.history`.
 */
function _buildMessagesFromEvent(event) {
  if (!event) return [];
  const history = event.messages || event.history || event.conversationHistory || [];
  const recent = Array.isArray(history) ? history.slice(-20) : [];
  const toolCall = {
    role: "tool",
    toolName: event.toolName || event.name,
    raw: typeof event.params === "object" ? JSON.stringify(event.params) : String(event.params ?? ""),
  };
  return [...recent, toolCall];
}


export default clawkeeperShimPlugin;
