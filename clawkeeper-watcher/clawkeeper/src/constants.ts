/**
 * Shared constants for the clawkeeper launcher.
 */
import type { ClawkeeperMode } from "./types.js";

/** Default root directory for installed/runtime Clawkeeper state. */
export const DEFAULT_ROOT_DIR = "~/.clawkeeper";

/** Subdirectories created within each mode directory. */
export const MODE_SUBDIRS = ["workspace", "logs", "state", "runtime"] as const;

/** Config filename within each mode directory. */
export const CONFIG_FILENAME = "config.json";

/** Default gateway ports per mode — offset from OpenClaw's default 18789. */
export const DEFAULT_GATEWAY_PORTS: Record<ClawkeeperMode, number> = {
  remote: 18790,
  local: 18791,
};

/** Watcher plugin ID. */
export const WATCHER_PLUGIN_ID = "clawkeeper-watcher";

/** Watcher context-judge route. */
export const CONTEXT_JUDGE_ROUTE = `/plugins/${WATCHER_PLUGIN_ID}/context-judge`;

/** Workspace template files that get bootstrapped. */
export const WORKSPACE_TEMPLATE_FILES = ["AGENTS.md", "TOOLS.md", "SOUL.md"] as const;

/** Environment variable names used to redirect OpenClaw paths. */
export const ENV_KEYS = {
  stateDir: "OPENCLAW_STATE_DIR",
  configPath: "OPENCLAW_CONFIG_PATH",
  gatewayPort: "OPENCLAW_GATEWAY_PORT",
  clawkeeperMode: "CLAWKEEPER_MODE",
  clawkeeperRoot: "CLAWKEEPER_ROOT",
} as const;
