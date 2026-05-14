import { createAuditContext, runAudit } from '../core/audit-engine.js';
import { harden } from '../core/hardening.js';
import { startDriftMonitor, stopDriftMonitor } from '../core/drift-monitor.js';
import { PLUGIN_DESCRIPTION, PLUGIN_ID, PLUGIN_NAME, VERSION } from '../core/metadata.js';
import { installBundledSkill, registerCliCommands } from './cli.js';
import { resolveStateDir } from '../core/state.js';
import {
  createToolLoggerHook,
  createMessageReceivedHook,
  createMessageSendingHook,
  createLLMInputHook,
  createLLMOutputHook,
  createBeforeAgentReplyHook,
} from '../core/interceptor.js';
import { resetSessionPermissions } from '../core/permission-store.js';

export const clawkeeperPlugin = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  version: VERSION,
  description: PLUGIN_DESCRIPTION,
  configSchema: {
    parse(value) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return value;
      }
      return {};
    }
  },
  register(api) {
    api.registerCli((ctx) => registerCliCommands(ctx), {
      commands: [PLUGIN_ID]
    });

    // Wipe session-scope permissions on every plugin load so they don't
    // leak across runs. Forever-scope entries persist by design.
    try {
      resetSessionPermissions();
      api.logger.info(`[${PLUGIN_NAME}] session permissions reset`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] session permissions reset failed: ${error.message}`);
    }

    // ========== Event Loggers - Hook Registration ==========
    // Log all events to: workspace/log/YYYY-MM-DD.jsonl
    
    // 1. Tool Call Logger
    try {
      const toolHook = createToolLoggerHook(api.logger);
      api.on('before_tool_call', toolHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ before_tool_call logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  before_tool_call logger failed: ${error.message}`);
    }

    // 2. Message Received Logger
    try {
      const messageReceivedHook = createMessageReceivedHook(api.logger);
      api.on('message_received', messageReceivedHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ message_received logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  message_received logger failed: ${error.message}`);
    }

    // 3. Message Sending Logger
    try {
      const messageSendingHook = createMessageSendingHook(api.logger);
      api.on('message_sending', messageSendingHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ message_sending logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  message_sending logger failed: ${error.message}`);
    }

    // 4. LLM Input Logger
    try {
      const llmInputHook = createLLMInputHook(api.logger);
      api.on('llm_input', llmInputHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ llm_input logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  llm_input logger failed: ${error.message}`);
    }

    // 5. LLM Output Logger
    try {
      const llmOutputHook = createLLMOutputHook(api.logger);
      api.on('llm_output', llmOutputHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ llm_output logger registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  llm_output logger failed: ${error.message}`);
    }

    // 6. Token Budget Guard (before_agent_reply)
    try {
      const budgetHook = createBeforeAgentReplyHook(api.logger);
      api.on('before_agent_reply', budgetHook);
      api.logger.info(`[${PLUGIN_NAME}] ✅ before_agent_reply budget guard registered`);
    } catch (error) {
      api.logger.warn(`[${PLUGIN_NAME}] ⚠️  before_agent_reply budget guard failed: ${error.message}`);
    }

    api.on('gateway_start', async () => {
      const stateDir = await resolveStateDir();
      const pluginConfig = api.pluginConfig ?? {};
      let context = await createAuditContext(stateDir, pluginConfig);
      if (!context.skillInstalled) {
        try {
          await installBundledSkill();
          context = await createAuditContext(stateDir, pluginConfig);
          api.logger.info(`[${PLUGIN_NAME}] bundled skill installed`);
        } catch (error) {
          api.logger.warn(`[${PLUGIN_NAME}] failed to install bundled skill: ${(error).message}`);
        }
      }
      const report = await runAudit(context);
      api.logger.info(`[${PLUGIN_NAME}] score=${report.score}/100`);
      api.logger.info(`[${PLUGIN_NAME}] layered=${context.skillInstalled ? 'plugin+skill' : 'plugin-only'}`);

      if (pluginConfig.autoHarden) {
        const result = await harden(stateDir, pluginConfig);
        api.logger.info(`[${PLUGIN_NAME}] auto harden actions=${result.actions.length}`);
      }

      if (pluginConfig.driftMonitor) {
        await startDriftMonitor(stateDir, pluginConfig, api.logger);
        api.logger.info(`[${PLUGIN_NAME}] drift monitor started`);
      }
    });

    api.on('gateway_stop', async () => {
      await stopDriftMonitor();
    });

    api.logger.info(`[${PLUGIN_NAME}] v${VERSION} registered`);
  }
};
