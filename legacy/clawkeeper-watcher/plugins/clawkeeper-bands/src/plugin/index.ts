/**
 * Clawkeeper-Bands Plugin Entry Point
 * OpenClaw plugin integration.
 *
 * IMPORTANT: register() must be SYNCHRONOUS — the OpenClaw gateway
 * ignores async plugin registration (the returned promise is not awaited).
 *
 * Hooks:
 *  before_tool_call → api.on() (tool interception)
 */

import { Interceptor } from "../core/Interceptor";
import { logger } from "../core/Logger";
import { PolicyStore } from "../storage/PolicyStore";
import { createAgentEndBridgeHook, type BridgeConfig } from "./agent-end-bridge";
import { createPendingDecisionPromptHook } from "./pending-decision-hook";
import { createClawkeeperStartupAuditRoute } from "./startup-audit-route";
import { createToolCallHook, CLAWKEEPER_BANDS_RESPOND_TOOL } from "./tool-interceptor";

export interface ClawkeeperBandsConfig {
  enabled?: boolean;
  defaultAction?: "ALLOW" | "DENY" | "ASK";
  bridge?: BridgeConfig;
}

/**
 * OpenClaw plugin API surface used by Clawkeeper-Bands.
 * Both methods are optional — the gateway may not support all of them.
 */
interface OpenClawPluginApi {
  config?: unknown;
  pluginConfig?: ClawkeeperBandsConfig;
  runtime?: {
    system?: {
      enqueueSystemEvent?: (
        text: string,
        opts: { sessionKey: string; contextKey?: string | null },
      ) => boolean;
      requestHeartbeatNow?: (opts?: { reason?: string; sessionKey?: string }) => void;
    };
  };
  on?(hookName: string, handler: (...args: unknown[]) => void): void;
  registerHttpRoute?(params: {
    path: string;
    auth: "gateway" | "plugin";
    handler: (req: unknown, res: unknown) => Promise<boolean | void> | boolean | void;
  }): void;
  registerTool?(spec: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    execute: (...args: unknown[]) => Promise<unknown>;
  }): void;
}

/**
 * Attempt to register the clawkeeper_bands_respond tool via api.registerTool().
 * Returns true if the call succeeded, false if the API is not available.
 */
function tryRegisterTool(api: OpenClawPluginApi): boolean {
  try {
    if (!api.registerTool) {
      logger.info("[plugin] api.registerTool not available — fallback retry-as-approval");
      return false;
    }
    api.registerTool({
      name: CLAWKEEPER_BANDS_RESPOND_TOOL,
      description:
        "Respond to a Clawkeeper-Bands security prompt. Call after the user says YES, NO, or ALLOW.",
      parameters: {
        type: "object",
        properties: {
          decision: {
            type: "string",
            enum: ["yes", "no", "allow"],
            description:
              'The user decision: "yes" to approve once, "no" to deny, "allow" to auto-approve for 15 minutes.',
          },
        },
        required: ["decision"],
      },
      // The actual logic runs in before_tool_call (tool-interceptor.ts).
      // This execute handler exists only because the gateway requires it.
      execute: async () => ({ result: "Handled by Clawkeeper-Bands hook." }),
    });
    logger.info(`[plugin] Registered tool: ${CLAWKEEPER_BANDS_RESPOND_TOOL}`);
    return true;
  } catch (err) {
    logger.warn(`[plugin] api.registerTool() threw`, { error: err });
    return false;
  }
}

/**
 * Safely attempt to register a hook via api.on().
 * Returns true if the call succeeded (no throw), false otherwise.
 */
function tryOn(
  api: OpenClawPluginApi,
  hookName: string,
  handler: (...args: unknown[]) => void,
  label: string,
): boolean {
  try {
    if (!api.on) {
      logger.debug(`[plugin] ${label}: api.on not available`);
      return false;
    }
    api.on(hookName, handler);
    logger.info(`[plugin] ${label}: api.on('${hookName}') succeeded`);
    return true;
  } catch (err) {
    logger.warn(`[plugin] ${label}: api.on('${hookName}') threw`, { error: err });
    return false;
  }
}

function tryRegisterHttpRoute(
  api: OpenClawPluginApi,
  params: {
    path: string;
    auth: "gateway" | "plugin";
    handler: (req: unknown, res: unknown) => Promise<boolean | void> | boolean | void;
  },
  label: string,
): boolean {
  try {
    if (!api.registerHttpRoute) {
      logger.debug(`[plugin] ${label}: api.registerHttpRoute not available`);
      return false;
    }
    api.registerHttpRoute(params);
    logger.info(`[plugin] ${label}: api.registerHttpRoute('${params.path}') succeeded`);
    return true;
  } catch (err) {
    logger.warn(`[plugin] ${label}: api.registerHttpRoute('${params.path}') threw`, { error: err });
    return false;
  }
}

export default {
  id: "clawkeeper-bands",
  name: "Clawkeeper-Bands",

  register(api: OpenClawPluginApi): void {
    logger.info("Clawkeeper-Bands plugin loading...");

    try {
      const policy = PolicyStore.loadSync();
      logger.info("Security policy loaded", {
        defaultAction: policy.defaultAction,
        moduleCount: Object.keys(policy.modules).length,
      });

      const interceptor = new Interceptor(policy);

      // -----------------------------------------------------------------------
      // Hook: before_tool_call — tool interception
      // -----------------------------------------------------------------------
      const toolHook = createToolCallHook(interceptor);
      tryOn(api, "before_tool_call", toolHook as (...args: unknown[]) => void, "before_tool_call");

      const agentEndHook = createAgentEndBridgeHook(
        api.pluginConfig,
        (api as { config?: unknown }).config,
      );
      tryOn(api, "agent_end", agentEndHook as (...args: unknown[]) => void, "agent_end");

      const pendingDecisionHook = createPendingDecisionPromptHook();
      tryOn(
        api,
        "before_prompt_build",
        pendingDecisionHook as (...args: unknown[]) => void,
        "before_prompt_build",
      );

      const startupAuditRoute = createClawkeeperStartupAuditRoute({
        config: api.config,
        logger,
        runtime: api.runtime,
      });
      tryRegisterHttpRoute(
        api,
        {
          path: "/plugins/clawkeeper-bands/clawkeeper-startup-audit",
          auth: "gateway",
          handler: startupAuditRoute as (req: unknown, res: unknown) => Promise<boolean | void>,
        },
        "clawkeeper_startup_audit",
      );

      // -----------------------------------------------------------------------
      // Tool registration: clawkeeper_bands_respond
      // If available, the LLM sees this tool and calls it with { decision: "yes"|"no"|"allow" }.
      // The actual logic is intercepted in before_tool_call (tool-interceptor.ts).
      // -----------------------------------------------------------------------
      const toolRegistered = tryRegisterTool(api);
      interceptor.respondToolAvailable = toolRegistered;

      logger.info("Clawkeeper-Bands: hook registration complete", {
        respondToolAvailable: toolRegistered,
      });
    } catch (error) {
      logger.error("Failed to initialize Clawkeeper-Bands plugin", { error });
      throw error;
    }
  },
};
