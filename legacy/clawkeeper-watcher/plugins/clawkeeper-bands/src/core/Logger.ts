/**
 * Clawkeeper-Bands Logger
 * Production-grade logging with Winston
 */

import { existsSync, mkdirSync } from "fs";
import os from "os";
import path from "path";
import winston from "winston";

// Determine Clawkeeper-Bands home directory
const OPENCLAW_HOME = process.env.OPENCLAW_HOME || path.join(os.homedir(), ".openclaw");
const CLAWKEEPER_BANDS_HOME = path.join(OPENCLAW_HOME, "clawkeeper-bands");

// Ensure the data directory exists
if (!existsSync(CLAWKEEPER_BANDS_HOME)) {
  mkdirSync(CLAWKEEPER_BANDS_HOME, { recursive: true });
}

const LOG_FILE = path.join(CLAWKEEPER_BANDS_HOME, "clawkeeper-bands.log");

function formatLogScalar(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return String(value);
  }
  return "";
}

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  defaultMeta: { service: "clawkeeper-bands" },
  transports: [
    // Console transport (colorized for development)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf((info) => {
          const { timestamp, level, message, ...meta } = info as {
            timestamp?: unknown;
            level?: unknown;
            message?: unknown;
            [key: string]: unknown;
          };
          const metaStr = Object.keys(meta).length > 0 ? JSON.stringify(meta) : "";
          return `[${formatLogScalar(timestamp)}] ${formatLogScalar(level)}: ${formatLogScalar(message)} ${metaStr}`;
        }),
      ),
    }),

    // File transport (structured JSON logs)
    new winston.transports.File({
      filename: LOG_FILE,
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      format: winston.format.json(),
    }),
  ],
});

// Export the log file path for reference
export const LOG_PATH = LOG_FILE;
export const CLAWKEEPER_BANDS_DATA_DIR = CLAWKEEPER_BANDS_HOME;
