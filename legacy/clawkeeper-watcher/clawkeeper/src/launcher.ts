/**
 * Core launcher logic — prepares the environment and delegates to OpenClaw.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { bootstrapWorkspace } from "./bootstrap.js";
import { ensureConfig } from "./config.js";
import { ENV_KEYS } from "./constants.js";
import { ensureModeDirectories, resolveModeConfig } from "./dirs.js";
import type { ClawkeeperMode, ClawkeeperModeConfig, LauncherPrepareResult } from "./types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Discriminated target describing how to invoke OpenClaw. */
type OpenClawTarget =
  | { kind: "node-script"; scriptPath: string }
  | { kind: "cli-command"; command: string };

/**
 * Prepare a mode for launch: create directories, write default config, bootstrap workspace.
 * Returns the resolved config and environment variables without actually launching.
 */
export function prepare(mode: ClawkeeperMode, rootDir?: string): LauncherPrepareResult {
  const modeConfig = resolveModeConfig(mode, rootDir);
  const createdDirs = ensureModeDirectories(modeConfig);
  const createdFiles: string[] = [];

  if (ensureConfig(modeConfig)) {
    createdFiles.push(modeConfig.configPath);
  }

  const bootstrappedFiles = bootstrapWorkspace(modeConfig);
  createdFiles.push(...bootstrappedFiles);

  const env = buildEnv(modeConfig);

  return {
    modeConfig,
    env,
    created: {
      dirs: createdDirs,
      files: createdFiles,
    },
  };
}

/**
 * Build the environment variable overrides for OpenClaw.
 */
function buildEnv(modeConfig: ClawkeeperModeConfig): Record<string, string> {
  return {
    [ENV_KEYS.stateDir]: modeConfig.stateDir,
    [ENV_KEYS.configPath]: modeConfig.configPath,
    [ENV_KEYS.gatewayPort]: String(modeConfig.gatewayPort),
    [ENV_KEYS.clawkeeperMode]: modeConfig.mode,
    [ENV_KEYS.clawkeeperRoot]: modeConfig.rootDir,
  };
}

/**
 * Resolve the OpenClaw launch target.
 * Tries (in order):
 *  1. The repo-local openclaw.mjs (for dev) → node-script
 *  2. `openclaw` on PATH (falls back to bare command) → cli-command
 */
function resolveOpenClawTarget(): OpenClawTarget {
  // In the repo, openclaw.mjs is at the repo root.
  // From clawkeeper/src/, that's ../../openclaw.mjs
  const repoLocal = path.resolve(__dirname, "..", "..", "openclaw.mjs");
  if (fs.existsSync(repoLocal)) {
    return { kind: "node-script", scriptPath: repoLocal };
  }
  return { kind: "cli-command", command: "openclaw" };
}

/**
 * Launch OpenClaw with the given mode and arguments.
 * This replaces the current process (exec semantics via synchronous spawn + exit).
 */
export function launch(
  mode: ClawkeeperMode,
  args: string[],
  options?: { rootDir?: string },
): never {
  const result = prepare(mode, options?.rootDir);
  const target = resolveOpenClawTarget();

  const mergedEnv: Record<string, string | undefined> = {
    ...process.env,
    ...result.env,
  };

  // Print a brief banner so the user knows which mode is active.
  const banner = formatBanner(result.modeConfig);
  process.stderr.write(banner + "\n");

  try {
    // Use execFileSync to maintain stdio passthrough and signal forwarding.
    // The child inherits stdio, so the user sees openclaw output directly.
    if (target.kind === "node-script") {
      execFileSync(process.execPath, [target.scriptPath, ...args], {
        env: mergedEnv,
        stdio: "inherit",
        cwd: process.cwd(),
      });
    } else {
      execFileSync(target.command, args, {
        env: mergedEnv,
        stdio: "inherit",
        cwd: process.cwd(),
      });
    }
    process.exit(0);
  } catch (err: unknown) {
    // execFileSync throws on non-zero exit. Extract the exit code.
    const spawnErr = err as { status?: number | null };
    const exitCode = spawnErr.status ?? 1;
    process.exit(exitCode);
  }
}

/**
 * Format a brief banner line for the launcher.
 */
function formatBanner(modeConfig: ClawkeeperModeConfig): string {
  const modeLabel = modeConfig.mode.toUpperCase();
  return [
    `[clawkeeper] mode=${modeLabel} port=${modeConfig.gatewayPort}`,
    `[clawkeeper] state=${modeConfig.stateDir}`,
    `[clawkeeper] workspace=${modeConfig.workspaceDir}`,
  ].join("\n");
}
