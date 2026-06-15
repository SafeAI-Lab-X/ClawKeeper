/**
 * Default config generation for clawkeeper modes.
 *
 * Generates a real OpenClawConfig-shaped config.json so OpenClaw can consume
 * it directly — setting the agent workspace, gateway port, and loading the
 * bundled clawkeeper-watcher plugin.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WATCHER_PLUGIN_ID } from "./constants.js";
import type { ClawkeeperConfig, ClawkeeperModeConfig } from "./types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Resolve path to the bundled clawkeeper-watcher plugin.
 *
 * Layout:
 *   repo-root/clawkeeper/src/config.ts   ← __dirname (dev)
 *   repo-root/clawkeeper/dist/config.js  ← __dirname (compiled)
 *   repo-root/plugins/clawkeeper-watcher ← target
 *
 * Both src/ and dist/ are two levels below repo root:
 *   __dirname  →  ..  →  clawkeeper/  →  ..  →  repo-root/
 */
function resolvePluginPath(): string {
  return path.resolve(__dirname, "..", "..", "plugins", "clawkeeper-watcher");
}

/**
 * Generate a default config object for the given mode.
 * The output conforms to OpenClawConfig so OpenClaw can consume it directly.
 */
export function generateDefaultConfig(modeConfig: ClawkeeperModeConfig): ClawkeeperConfig {
  return {
    agents: {
      defaults: {
        workspace: modeConfig.workspaceDir,
      },
    },
    gateway: {
      port: modeConfig.gatewayPort,
    },
    plugins: {
      enabled: true,
      load: {
        paths: [resolvePluginPath()],
      },
      entries: {
        [WATCHER_PLUGIN_ID]: {
          enabled: true,
          config: {
            mode: modeConfig.mode,
          },
        },
      },
    },
  };
}

/**
 * Write the default config.json for a mode if it doesn't already exist.
 * Returns true if a new config was written, false if it already existed.
 */
export function ensureConfig(modeConfig: ClawkeeperModeConfig): boolean {
  if (fs.existsSync(modeConfig.configPath)) {
    return false;
  }

  const config = generateDefaultConfig(modeConfig);
  fs.writeFileSync(modeConfig.configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  return true;
}

/**
 * Read the config.json for a mode. Returns null if it doesn't exist.
 */
export function readConfig(modeConfig: ClawkeeperModeConfig): ClawkeeperConfig | null {
  if (!fs.existsSync(modeConfig.configPath)) {
    return null;
  }

  const raw = fs.readFileSync(modeConfig.configPath, "utf-8");
  return JSON.parse(raw) as ClawkeeperConfig;
}
