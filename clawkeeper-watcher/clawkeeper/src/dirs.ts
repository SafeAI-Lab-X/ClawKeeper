/**
 * Directory resolution and creation for clawkeeper modes.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CONFIG_FILENAME, DEFAULT_GATEWAY_PORTS, DEFAULT_ROOT_DIR } from "./constants.js";
import type { ClawkeeperMode, ClawkeeperModeConfig } from "./types.js";

function expandRootDir(rootDir: string): string {
  if (rootDir === "~") {
    return os.homedir();
  }
  if (rootDir.startsWith("~/")) {
    return path.join(os.homedir(), rootDir.slice(2));
  }
  return rootDir;
}

/**
 * Resolve the full mode config from a mode name and optional root override.
 * All paths are resolved to absolute paths anchored to CWD.
 */
export function resolveModeConfig(
  mode: ClawkeeperMode,
  rootDir: string = DEFAULT_ROOT_DIR,
): ClawkeeperModeConfig {
  const absRoot = path.resolve(process.cwd(), expandRootDir(rootDir));
  const modeDir = path.join(absRoot, mode);

  return {
    mode,
    rootDir: absRoot,
    modeDir,
    configPath: path.join(modeDir, CONFIG_FILENAME),
    workspaceDir: path.join(modeDir, "workspace"),
    logsDir: path.join(modeDir, "logs"),
    stateDir: path.join(modeDir, "state"),
    runtimeDir: path.join(modeDir, "runtime"),
    gatewayPort: DEFAULT_GATEWAY_PORTS[mode],
  };
}

/**
 * Ensure all required directories exist for a mode.
 * Returns the list of directories that were newly created.
 */
export function ensureModeDirectories(modeConfig: ClawkeeperModeConfig): string[] {
  const created: string[] = [];

  const dirs = [
    modeConfig.modeDir,
    modeConfig.workspaceDir,
    modeConfig.logsDir,
    modeConfig.stateDir,
    modeConfig.runtimeDir,
  ];

  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      created.push(dir);
    }
  }

  return created;
}

/**
 * Check whether a mode directory has been initialized.
 */
export function isModeInitialized(modeConfig: ClawkeeperModeConfig): boolean {
  return fs.existsSync(modeConfig.modeDir) && fs.existsSync(modeConfig.configPath);
}
