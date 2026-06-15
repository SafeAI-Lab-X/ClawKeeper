import { invalidateProfileCache } from "../core/agent-profiler.js";
import { createAuditContext, runAudit } from "../core/audit-engine.js";
import { startDriftMonitor, stopDriftMonitor } from "../core/drift-monitor.js";
import { harden } from "../core/hardening.js";
import {
  createToolLoggerHook,
  createMessageReceivedHook,
  createMessageSendingHook,
  createLLMInputHook,
  createLLMOutputHook,
} from "../core/interceptor.js";
import { PLUGIN_DESCRIPTION, PLUGIN_ID, PLUGIN_NAME, VERSION } from "../core/metadata.js";
import { startSkillGuard, stopSkillGuard } from "../core/skill-guard.js";
import { notifyStartupAuditToUserBridge } from "../core/startup-audit-notify.js";
import { resolveUserOpenClawStateDir } from "../core/state.js";
import { registerCliCommands } from "./cli.js";
import { createContextJudgeHttpHandler } from "./context-judge-http.js";

const VALID_MODES = new Set(["remote", "local"]);

/**
 * Resolve the active clawkeeper mode.
 * Priority: pluginConfig.mode → CLAWKEEPER_MODE env → 'local' (backward-compat default).
 */
function resolveMode(pluginConfig) {
  const fromConfig = pluginConfig.mode;
  if (typeof fromConfig === "string" && VALID_MODES.has(fromConfig)) {
    return fromConfig;
  }
  const fromEnv = process.env.CLAWKEEPER_MODE;
  if (typeof fromEnv === "string" && VALID_MODES.has(fromEnv)) {
    return fromEnv;
  }
  return "local";
}

export const clawkeeperPlugin = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  version: VERSION,
  description: PLUGIN_DESCRIPTION,
  configSchema: {
    parse(value) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        return value;
      }
      return {};
    },
  },
  register(api) {
    const pluginConfig = api.pluginConfig ?? {};
    const mode = resolveMode(pluginConfig);

    api.logger.info(`[${PLUGIN_NAME}] mode=${mode}`);

    api.registerCli((ctx) => registerCliCommands(ctx), {
      commands: [PLUGIN_ID],
    });

    api.registerHttpRoute({
      path: "/plugins/clawkeeper-watcher/context-judge",
      auth: "gateway",
      handler: createContextJudgeHttpHandler({
        logger: api.logger,
        defaultPolicy: pluginConfig.contextJudge ?? {},
        mode,
        contextJudgeConfig: pluginConfig.contextJudge ?? {},
      }),
    });

    // ========== Event Loggers - Hook Registration ==========
    // Log all events to: workspace/log/YYYY-MM-DD.jsonl

    // 1. Tool Call Logger
    try {
      const toolHook = createToolLoggerHook(api.logger);
      api.on("before_tool_call", toolHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ before_tool_call logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  before_tool_call logger failed: ${error.message}`);
    }

    // 2. Message Received Logger
    try {
      const messageReceivedHook = createMessageReceivedHook(api.logger);
      api.on("message_received", messageReceivedHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ message_received logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  message_received logger failed: ${error.message}`);
    }

    // 3. Message Sending Logger
    try {
      const messageSendingHook = createMessageSendingHook(api.logger);
      api.on("message_sending", messageSendingHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ message_sending logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  message_sending logger failed: ${error.message}`);
    }

    // 4. LLM Input Logger
    try {
      const llmInputHook = createLLMInputHook(api.logger);
      api.on("llm_input", llmInputHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ llm_input logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  llm_input logger failed: ${error.message}`);
    }

    // 5. LLM Output Logger
    try {
      const llmOutputHook = createLLMOutputHook(api.logger);
      api.on("llm_output", llmOutputHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ llm_output logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  llm_output logger failed: ${error.message}`);
    }

    api.on("gateway_start", async () => {
      // Audit, harden, and drift monitor are local-only operations
      if (mode !== "local") {
        api.logger.info(
          `[${PLUGIN_NAME}] mode=${mode}, skipping local-only operations (audit/harden/drift)`,
        );
        return;
      }

      const userOpenClawStateDir = await resolveUserOpenClawStateDir();
      const context = await createAuditContext(userOpenClawStateDir, pluginConfig);
      const report = await runAudit(context);
      api.logger.info(`[${PLUGIN_NAME}] score=${report.score}/100`);

      try {
        const notifyResult = await notifyStartupAuditToUserBridge({
          pluginConfig,
          report,
          logger: api.logger,
          mode,
        });
        if (notifyResult.sent) {
          api.logger.info(`[${PLUGIN_NAME}] startup audit notification sent to user bridge`);
        }
      } catch (error) {
        api.logger.warn(`[${PLUGIN_NAME}] startup audit notification failed: ${error.message}`);
      }

      if (pluginConfig.autoHarden) {
        const result = await harden(userOpenClawStateDir, pluginConfig);
        api.logger.info(`[${PLUGIN_NAME}] auto harden actions=${result.actions.length}`);
      }

      if (pluginConfig.driftMonitor) {
        await startDriftMonitor(userOpenClawStateDir, pluginConfig, api.logger);
        api.logger.info(`[${PLUGIN_NAME}] drift monitor started for user OpenClaw`);
      }

      if (pluginConfig.skillGuard?.enabled) {
        await startSkillGuard(pluginConfig, api.logger);
        api.logger.info(`[${PLUGIN_NAME}] skill guard started`);
      }
    });

    api.on("gateway_stop", async () => {
      invalidateProfileCache();
      await stopDriftMonitor();
      await stopSkillGuard();
    });

    api.logger.info(`[${PLUGIN_NAME}] v${VERSION} registered`);
  },
};
