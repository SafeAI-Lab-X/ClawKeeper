/**
 * Clawkeeper-Bands Enable/Disable Commands
 */

import chalk from "chalk";
import { logger } from "../../core/Logger";
import { loadOpenClawConfig, saveOpenClawConfig } from "../../plugin/config-manager";

export async function disableCommand(): Promise<void> {
  try {
    const config = await loadOpenClawConfig();

    if (!config?.plugins?.entries?.["clawkeeper-bands"]) {
      console.log(
        chalk.yellow("Clawkeeper-Bands is not registered in OpenClaw. Run: clawkeeper-bands init"),
      );
      process.exit(0);
    }

    config.plugins.entries["clawkeeper-bands"].enabled = false;
    await saveOpenClawConfig(config);

    console.log(chalk.green("Clawkeeper-Bands disabled"));
  } catch (error) {
    console.error(chalk.red("Failed to disable Clawkeeper-Bands:"), error);
    logger.error("Disable command failed", { error });
    process.exit(1);
  }
}

export async function enableCommand(): Promise<void> {
  try {
    const config = await loadOpenClawConfig();

    if (!config?.plugins?.entries?.["clawkeeper-bands"]) {
      console.log(
        chalk.yellow("Clawkeeper-Bands is not registered in OpenClaw. Run: clawkeeper-bands init"),
      );
      process.exit(0);
    }

    config.plugins.entries["clawkeeper-bands"].enabled = true;
    await saveOpenClawConfig(config);

    console.log(chalk.green("Clawkeeper-Bands enabled"));
  } catch (error) {
    console.error(chalk.red("Failed to enable Clawkeeper-Bands:"), error);
    logger.error("Enable command failed", { error });
    process.exit(1);
  }
}
