/**
 * Clawkeeper-Bands - Put safety bands on OpenClaw
 * Public API Exports
 */

// Core Components
export { Interceptor } from "./core/Interceptor";
export { Arbitrator } from "./core/Arbitrator";
export { approvalQueue } from "./core/ApprovalQueue";
export { logger, LOG_PATH, CLAWKEEPER_BANDS_DATA_DIR } from "./core/Logger";

// Storage
export { PolicyStore, PersistedPolicy } from "./storage/PolicyStore";
export { DecisionLog, DecisionRecord } from "./storage/DecisionLog";
export { StatsTracker, Stats } from "./storage/StatsTracker";

// Plugin
export { default as ClawkeeperBandsPlugin, type ClawkeeperBandsConfig } from "./plugin/index";
export {
  createToolCallHook,
  getToolMapping,
  getProtectedModules,
  CLAWKEEPER_BANDS_RESPOND_TOOL,
} from "./plugin/tool-interceptor";

export {
  isOpenClawInstalled,
  loadOpenClawConfig,
  saveOpenClawConfig,
  registerPlugin,
  unregisterPlugin,
  isPluginRegistered,
} from "./plugin/config-manager";

// Configuration
export { DEFAULT_POLICY } from "./config";
export { DEFAULT_WS_CONFIG } from "./config";
export { DEFAULT_CMD_CONFIG } from "./config";

// Types
export * from "./types";
