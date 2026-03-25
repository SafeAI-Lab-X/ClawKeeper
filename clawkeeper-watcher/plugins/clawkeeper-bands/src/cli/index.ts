#!/usr/bin/env node

/**
 * Clawkeeper-Bands CLI Entry Point
 */

import { Command } from "commander";
import { auditCommand } from "./commands/audit";
import { policyCommand } from "./commands/policy";
import { resetCommand } from "./commands/reset";
import { statsCommand } from "./commands/stats";
import { disableCommand, enableCommand } from "./commands/toggle";
import { initWizard } from "./init";

const program = new Command();

program.name("clawkeeper-bands").description("🦞 Put safety bands on OpenClaw").version("1.0.0");

// Initialize Clawkeeper-Bands with OpenClaw
program
  .command("init")
  .description("Setup Clawkeeper-Bands with OpenClaw (interactive wizard)")
  .action(initWizard);

// Manage security policies
program.command("policy").description("Manage security policies").action(policyCommand);

// View statistics
program.command("stats").description("View security statistics").action(statsCommand);

// View audit trail
program
  .command("audit")
  .description("View decision audit trail")
  .option("-n, --lines <number>", "Number of recent decisions to show", "50")
  .action(auditCommand);

// Reset stats
program.command("reset").description("Reset statistics").action(resetCommand);

// Disable Clawkeeper-Bands
program
  .command("disable")
  .description("Temporarily disable Clawkeeper-Bands")
  .action(disableCommand);

// Enable Clawkeeper-Bands
program.command("enable").description("Re-enable Clawkeeper-Bands").action(enableCommand);

program.parse();
