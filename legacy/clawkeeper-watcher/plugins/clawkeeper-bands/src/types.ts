/**
 * Clawkeeper-Bands Type Definitions
 * The strict vocabulary of the security system
 */

/**
 * Security decision types
 * - ALLOW: Execute immediately without prompting
 * - DENY: Block execution and throw error
 * - ASK: Pause and request human decision
 */
export type Decision = "ALLOW" | "DENY" | "ASK";

/**
 * Rule definition for a specific method
 */
export interface SecurityRule {
  action: Decision;
  description?: string; // Optional reasoning for logs and UI
}

/**
 * Complete security policy structure
 */
export interface SecurityPolicy {
  defaultAction: Decision; // Fallback if no rule exists (Paranoia mode)
  modules: {
    [moduleName: string]: {
      [methodName: string]: SecurityRule;
    };
  };
}

/**
 * Execution context passed to the Arbitrator
 */
export interface ExecutionContext {
  moduleName: string;
  methodName: string;
  args: unknown[];
  rule: SecurityRule;
  /** OpenClaw session key (e.g. "agent:main:whatsapp:dm:+1555…"). Present in daemon/channel mode. */
  sessionKey?: string;
}

/**
 * WebSocket configuration for external AI agent approval
 */
export interface WebSocketConfig {
  /** WebSocket server URL, e.g., ws://localhost:8080 */
  url: string;
  /** Connection timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Whether WebSocket mode is enabled */
  enabled?: boolean;
}

/**
 * Command-line configuration for external script approval
 */
export interface CommandConfig {
  /** Path to the command/script to execute */
  command: string;
  /** Whether command mode is enabled */
  enabled?: boolean;
  /** Timeout for command execution in milliseconds (default: 30000) */
  timeout?: number;
}
