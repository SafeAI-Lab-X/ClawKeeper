/**
 * Clawkeeper-Bands Reset Command
 */

import chalk from "chalk";
import inquirer from "inquirer";
import { logger } from "../../core/Logger";
import { StatsTracker } from "../../storage/StatsTracker";

export async function resetCommand(): Promise<void> {
  console.log("");
  console.log(chalk.bold.yellow("⚠️  Reset Statistics"));
  console.log("");

  try {
    const { confirm } = await inquirer.prompt([
      {
        type: "confirm",
        name: "confirm",
        message: chalk.red("Are you sure you want to reset all statistics?"),
        default: false,
      },
    ]);

    if (confirm) {
      await StatsTracker.reset();
      console.log(chalk.green("✅ Statistics reset successfully"));
      console.log("");
    } else {
      console.log(chalk.dim("Reset cancelled"));
      console.log("");
    }
  } catch (error) {
    console.error(chalk.red("❌ Failed to reset statistics:"), error);
    logger.error("Reset command failed", { error });
    process.exit(1);
  }
}
