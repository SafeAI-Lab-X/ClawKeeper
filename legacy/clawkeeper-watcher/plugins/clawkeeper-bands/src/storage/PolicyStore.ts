/**
 * Clawkeeper-Bands PolicyStore
 * Manages persistence of security policies in ~/.openclaw/clawkeeper-bands/policy.json
 */

import { readFileSync, existsSync, mkdirSync, writeFileSync } from "fs";
import path from "path";
import fs from "fs-extra";
import { DEFAULT_POLICY } from "../config";
import { CLAWKEEPER_BANDS_DATA_DIR, logger } from "../core/Logger";
import { SecurityPolicy } from "../types";

const POLICY_FILE = path.join(CLAWKEEPER_BANDS_DATA_DIR, "policy.json");

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : JSON.stringify(error);
}

export interface PersistedPolicy extends SecurityPolicy {
  version: string;
  createdAt: string;
  updatedAt: string;
}

export class PolicyStore {
  /**
   * Load the policy from disk, or create default if doesn't exist
   */
  static async load(): Promise<PersistedPolicy> {
    try {
      // Ensure directory exists
      await fs.ensureDir(CLAWKEEPER_BANDS_DATA_DIR);

      if (await fs.pathExists(POLICY_FILE)) {
        const data = await fs.readJson(POLICY_FILE);
        logger.info("Policy loaded from disk", { path: POLICY_FILE });
        return data;
      } else {
        // Create default policy
        logger.info("No existing policy found, creating default");
        const defaultPolicy: PersistedPolicy = {
          ...DEFAULT_POLICY,
          version: "1.0.0",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        await this.save(defaultPolicy);
        return defaultPolicy;
      }
    } catch (error) {
      logger.error("Failed to load policy", { error });
      throw new Error(`Failed to load policy: ${describeError(error)}`, { cause: error });
    }
  }

  /**
   * Save the policy to disk
   */
  static async save(policy: PersistedPolicy): Promise<void> {
    try {
      await fs.ensureDir(CLAWKEEPER_BANDS_DATA_DIR);
      policy.updatedAt = new Date().toISOString();
      await fs.writeJson(POLICY_FILE, policy, { spaces: 2 });
      logger.info("Policy saved to disk", { path: POLICY_FILE });
    } catch (error) {
      logger.error("Failed to save policy", { error });
      throw new Error(`Failed to save policy: ${describeError(error)}`, { cause: error });
    }
  }

  /**
   * Reset policy to defaults
   */
  static async reset(): Promise<void> {
    const defaultPolicy: PersistedPolicy = {
      ...DEFAULT_POLICY,
      version: "1.0.0",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await this.save(defaultPolicy);
    logger.info("Policy reset to defaults");
  }

  /**
   * Load the policy synchronously (for plugin register which must be sync)
   */
  static loadSync(): PersistedPolicy {
    try {
      if (!existsSync(CLAWKEEPER_BANDS_DATA_DIR)) {
        mkdirSync(CLAWKEEPER_BANDS_DATA_DIR, { recursive: true });
      }

      if (existsSync(POLICY_FILE)) {
        const data = JSON.parse(readFileSync(POLICY_FILE, "utf-8"));
        logger.info("Policy loaded from disk (sync)", { path: POLICY_FILE });
        return data;
      } else {
        const defaultPolicy: PersistedPolicy = {
          ...DEFAULT_POLICY,
          version: "1.0.0",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        writeFileSync(POLICY_FILE, JSON.stringify(defaultPolicy, null, 2), "utf-8");
        logger.info("Created default policy (sync)", { path: POLICY_FILE });
        return defaultPolicy;
      }
    } catch (error) {
      logger.error("Failed to load policy (sync)", { error });
      throw new Error(`Failed to load policy: ${describeError(error)}`, { cause: error });
    }
  }

  /**
   * Get the policy file path
   */
  static getPath(): string {
    return POLICY_FILE;
  }
}
