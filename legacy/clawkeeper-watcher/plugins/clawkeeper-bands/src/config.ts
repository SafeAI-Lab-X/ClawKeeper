/**
 * Clawkeeper-Bands Default Security Policy
 * Philosophy: "Secure by Default"
 */

import { SecurityPolicy, WebSocketConfig, CommandConfig } from "./types";

export const DEFAULT_POLICY: SecurityPolicy = {
  // PARANOIA MODE: If a tool is unknown, ask the human.
  defaultAction: "ASK",

  modules: {
    FileSystem: {
      read: {
        action: "ALLOW",
        description: "Read-only access is generally safe",
      },
      write: {
        action: "ASK",
        description: "Modification of files requires approval",
      },
      delete: {
        action: "DENY",
        description: "Deletion is strictly prohibited",
      },
    },
    Shell: {
      bash: {
        action: "ASK",
        description: "Shell command execution risk",
      },
      exec: {
        action: "ASK",
        description: "Arbitrary Code Execution (RCE) risk",
      },
      spawn: {
        action: "ASK",
        description: "Process spawning risk",
      },
    },
    Network: {
      fetch: {
        action: "ASK",
        description: "Potential data exfiltration",
      },
      request: {
        action: "ASK",
        description: "HTTP request may leak data",
      },
    },
  },
};

/**
 * Default WebSocket configuration for external AI agent approval
 */
export const DEFAULT_WS_CONFIG: WebSocketConfig = {
  url: "ws://localhost:8080",
  timeout: 300000,
  enabled: false,
};

/**
 * Default Command configuration for external script approval
 */
export const DEFAULT_CMD_CONFIG: CommandConfig = {
  command: "./ask-approval.sh",
  timeout: 30000,
  enabled: false,
};
