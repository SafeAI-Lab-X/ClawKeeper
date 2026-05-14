#!/usr/bin/env node
/**
 * clawkeeper — isolated runtime launcher for OpenClaw watcher modes.
 *
 * Usage:
 *   clawkeeper remote [openclaw-args...]   Run in remote mode
 *   clawkeeper local [openclaw-args...]    Run in local mode
 *   clawkeeper init <mode>                 Initialize mode directory without running
 *   clawkeeper status                      Show status of both modes
 */
import path from "node:path";
import process from "node:process";
import { DEFAULT_ROOT_DIR } from "./constants.js";
import { isModeInitialized, resolveModeConfig } from "./dirs.js";
import { launch, prepare } from "./launcher.js";
import { VALID_MODES, type ClawkeeperMode } from "./types.js";

const VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function printHelp(): void {
  const help = `
clawkeeper — isolated runtime launcher for OpenClaw watcher modes

USAGE
  clawkeeper <mode> [openclaw-args...]
  clawkeeper init <mode>
  clawkeeper status

MODES
  remote    Remote second brain — read-only review, risk judgment, confirmation gating
  local     Local enhanced second brain — local audit, skill scanning, log analysis

COMMANDS
  init <mode>   Initialize a mode directory without launching
  status        Show initialization status of both modes

OPTIONS
  --root <path>   Override root directory (default: ${DEFAULT_ROOT_DIR})
  --version       Show version
  --help          Show this help

EXAMPLES
  clawkeeper remote gateway run       Start gateway in remote mode
  clawkeeper local gateway run        Start gateway in local mode
  clawkeeper init remote              Initialize remote mode directory
  clawkeeper remote config set ...    Configure remote mode
  clawkeeper status                   Check which modes are initialized
`.trim();

  console.log(help);
}

function printVersion(): void {
  console.log(`clawkeeper ${VERSION}`);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdInit(mode: ClawkeeperMode, rootDir: string): void {
  const result = prepare(mode, rootDir);

  console.log(`[clawkeeper] Initialized ${mode} mode`);
  console.log(`  directory: ${result.modeConfig.modeDir}`);
  console.log(`  config:    ${result.modeConfig.configPath}`);
  console.log(`  workspace: ${result.modeConfig.workspaceDir}`);
  console.log(`  port:      ${result.modeConfig.gatewayPort}`);

  if (result.created.dirs.length > 0) {
    console.log(
      `  created ${result.created.dirs.length} director${result.created.dirs.length === 1 ? "y" : "ies"}`,
    );
  }
  if (result.created.files.length > 0) {
    console.log(
      `  created ${result.created.files.length} file${result.created.files.length === 1 ? "" : "s"}`,
    );
  }
}

function cmdStatus(rootDir: string): void {
  console.log("[clawkeeper] Status\n");

  const absRoot = path.resolve(process.cwd(), rootDir);
  console.log(`  root: ${absRoot}\n`);

  for (const mode of VALID_MODES) {
    const modeConfig = resolveModeConfig(mode, rootDir);
    const initialized = isModeInitialized(modeConfig);
    const status = initialized ? "initialized" : "not initialized";
    const icon = initialized ? "+" : "-";

    console.log(`  [${icon}] ${mode}`);
    console.log(`      directory: ${modeConfig.modeDir}`);
    console.log(`      status:    ${status}`);
    console.log(`      port:      ${modeConfig.gatewayPort}`);
    console.log();
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function isMode(value: string): value is ClawkeeperMode {
  return VALID_MODES.includes(value as ClawkeeperMode);
}

function main(): void {
  const argv = process.argv.slice(2);

  // Extract --root option (can appear anywhere).
  let rootDir = DEFAULT_ROOT_DIR;
  const rootIndex = argv.indexOf("--root");
  if (rootIndex !== -1) {
    const rootValue = argv[rootIndex + 1];
    if (!rootValue || rootValue.startsWith("-")) {
      console.error("Error: --root requires a path argument");
      process.exit(1);
    }
    rootDir = rootValue;
    argv.splice(rootIndex, 2);
  }

  // Handle global flags.
  if (argv.includes("--version") || argv.includes("-V")) {
    printVersion();
    return;
  }
  if (argv.includes("--help") || argv.includes("-h") || argv.length === 0) {
    printHelp();
    if (argv.length === 0) {
      process.exit(1);
    }
    return;
  }

  const command = argv[0];
  if (!command) {
    printHelp();
    process.exit(1);
  }

  // Handle 'init' command.
  if (command === "init") {
    const mode = argv[1];
    if (!mode || !isMode(mode)) {
      console.error(`Error: init requires a mode argument (${VALID_MODES.join(" | ")})`);
      process.exit(1);
    }
    cmdInit(mode, rootDir);
    return;
  }

  // Handle 'status' command.
  if (command === "status") {
    cmdStatus(rootDir);
    return;
  }

  // Handle mode commands (remote / local).
  if (isMode(command)) {
    const modeArgs = argv.slice(1);
    if (modeArgs.length === 0) {
      console.error(`Error: clawkeeper ${command} requires at least one argument`);
      console.error(`  Example: clawkeeper ${command} gateway run`);
      console.error(`  Example: clawkeeper ${command} config set ...`);
      process.exit(1);
    }
    // launch() calls process.exit() — never returns.
    launch(command, modeArgs, { rootDir });
  }

  // Unknown command.
  console.error(`Error: unknown command "${command}"`);
  console.error(`  Valid modes: ${VALID_MODES.join(", ")}`);
  console.error(`  Valid commands: init, status`);
  console.error(`  Run "clawkeeper --help" for usage`);
  process.exit(1);
}

main();
