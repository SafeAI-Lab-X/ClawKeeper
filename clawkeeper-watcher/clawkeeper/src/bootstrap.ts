/**
 * Workspace bootstrap — copies default template files into the mode workspace.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WORKSPACE_TEMPLATE_FILES } from "./constants.js";
import type { ClawkeeperModeConfig } from "./types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Resolve the path to a workspace template file for the given mode.
 * Templates live at clawkeeper/workspace/<mode>/<filename>.
 */
function resolveTemplatePath(mode: string, filename: string): string {
  // From src/ go up one level to clawkeeper/, then into workspace/<mode>/
  return path.join(__dirname, "..", "workspace", mode, filename);
}

/**
 * Bootstrap workspace files for a mode.
 * Copies template files into the mode's workspace directory if they don't already exist.
 * Returns the list of files that were newly created.
 */
export function bootstrapWorkspace(modeConfig: ClawkeeperModeConfig): string[] {
  const created: string[] = [];

  for (const filename of WORKSPACE_TEMPLATE_FILES) {
    const targetPath = path.join(modeConfig.workspaceDir, filename);
    if (fs.existsSync(targetPath)) {
      continue;
    }

    const templatePath = resolveTemplatePath(modeConfig.mode, filename);
    if (!fs.existsSync(templatePath)) {
      // Template not found — write a minimal placeholder.
      fs.writeFileSync(
        targetPath,
        `# ${filename.replace(".md", "")}\n\n<!-- clawkeeper ${modeConfig.mode} mode -->\n`,
        "utf-8",
      );
      created.push(targetPath);
      continue;
    }

    fs.copyFileSync(templatePath, targetPath);
    created.push(targetPath);
  }

  return created;
}
