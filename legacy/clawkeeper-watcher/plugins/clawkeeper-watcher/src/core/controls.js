import { ensureRuleBlock, readSoul, writeJson } from "./state.js";

const RISKY_SANDBOX_MODES = new Set(["disabled", "off"]);
const RISKY_EXEC_SECURITY = new Set(["full"]);
const TRUSTED_GATEWAY_BINDS = new Set(["127.0.0.1", "localhost", "loopback"]);

export function getControls() {
  return [
    {
      id: "network.local-gateway",
      category: "network",
      severity: "HIGH",
      threat: "exposure",
      intent: "shrink-reachable-surface",
      title: "Shrink gateway exposure surface",
      describe: (context) => {
        const bind = normalizeLowerString(context.config?.gateway?.bind);
        if (!bind || TRUSTED_GATEWAY_BINDS.has(bind)) {
          return null;
        }
        return {
          description: `gateway.bind is currently ${bind}, exposing the gateway to a wider reachable surface.`,
          evidence: { currentBind: bind, expected: [...TRUSTED_GATEWAY_BINDS] },
          remediation: "Restrict gateway.bind to 127.0.0.1",
          autoFixable: true,
        };
      },
      remediate: async (context) => {
        if (!context.config.gateway) {
          context.config.gateway = {};
        }
        context.config.gateway.bind = "loopback";
        await writeJson(context.configPath, context.config);
        return "gateway.bind -> loopback";
      },
    },
    {
      id: "identity.operator-auth",
      category: "identity",
      severity: "HIGH",
      threat: "unauthorized-access",
      intent: "preserve-operator-boundary",
      title: "Preserve authentication boundary for operator gateway",
      describe: (context) => {
        const gateway = context.config?.gateway ?? {};
        const hasAuth = Boolean(gateway.authToken || gateway.auth?.token || gateway.auth?.password);
        if (hasAuth) {
          return null;
        }
        return {
          description:
            "No gateway token or password authentication detected for operator entry point.",
          evidence: {
            hasAuthToken: Boolean(gateway.authToken),
            hasNestedToken: Boolean(gateway.auth?.token),
            hasPassword: Boolean(gateway.auth?.password),
          },
          remediation:
            "Configure token or password for gateway before exposing the control interface.",
          autoFixable: false,
          severity: context.strictMode ? "CRITICAL" : "HIGH",
        };
      },
    },
    {
      id: "execution.bounded-filesystem",
      category: "execution",
      severity: "HIGH",
      threat: "filesystem-overreach",
      intent: "restore-execution-boundaries",
      title: "Keep filesystem boundary protected",
      describe: (context) => {
        const mode = normalizeLowerString(context.config?.agents?.defaults?.sandbox?.mode);
        if (!mode || !RISKY_SANDBOX_MODES.has(mode)) {
          return null;
        }
        return {
          description: `agents.defaults.sandbox.mode=${mode}, so filesystem/runtime containment is effectively disabled by default.`,
          evidence: { sandboxMode: mode, configPath: "agents.defaults.sandbox.mode" },
          remediation: 'Adjust agents.defaults.sandbox.mode to "all"',
          autoFixable: true,
        };
      },
      remediate: async (context) => {
        if (!context.config.agents) {
          context.config.agents = {};
        }
        if (!context.config.agents.defaults) {
          context.config.agents.defaults = {};
        }
        if (!context.config.agents.defaults.sandbox) {
          context.config.agents.defaults.sandbox = {};
        }
        context.config.agents.defaults.sandbox.mode = "all";
        await writeJson(context.configPath, context.config);
        return "agents.defaults.sandbox.mode -> all";
      },
    },
    {
      id: "execution.human-checkpoint",
      category: "execution",
      severity: "MEDIUM",
      threat: "unreviewed-side-effects",
      intent: "require-human-gates-for-risk",
      title: "Keep human gates for high-risk execution",
      describe: (context) => {
        const security = normalizeLowerString(context.config?.tools?.exec?.security);
        if (!security || !RISKY_EXEC_SECURITY.has(security)) {
          return null;
        }
        return {
          description: `tools.exec.security=${security}, so host exec is not constrained to an allowlist boundary.`,
          evidence: { security, configPath: "tools.exec.security" },
          remediation: 'Set tools.exec.security to "allowlist"',
          autoFixable: true,
        };
      },
      remediate: async (context) => {
        if (!context.config.tools) {
          context.config.tools = {};
        }
        if (!context.config.tools.exec) {
          context.config.tools.exec = {};
        }
        context.config.tools.exec.security = "allowlist";
        await writeJson(context.configPath, context.config);
        return "tools.exec.security -> allowlist";
      },
    },
    {
      id: "behavior.runtime-constitution",
      category: "behavior",
      severity: "MEDIUM",
      threat: "prompt-injection",
      intent: "keep-behavioral-guardrails-loaded",
      title: "Agent requires minimal runtime constitution",
      describe: async (context) => {
        const content = await readSoul(context.stateDir);
        if (content.includes("clawkeeper-watcher:rules:start")) {
          return null;
        }
        return {
          description: "AGENTS.md lacks a clear runtime boundary rules section.",
          evidence: { soulPath: context.soulPath, rulesLoaded: false },
          remediation: "Inject Clawkeeper-Watcher runtime constitution into AGENTS.md",
          autoFixable: true,
        };
      },
      remediate: async (context) => {
        const result = await ensureRuleBlock(context.stateDir);
        return result.changed ? "AGENTS.md injected with runtime constitution" : null;
      },
    },
  ];
}

function normalizeLowerString(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}
