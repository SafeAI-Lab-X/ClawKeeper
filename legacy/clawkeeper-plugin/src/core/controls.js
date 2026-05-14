import { ensureRuleBlock, readSoul, writeJson } from './state.js';

const RISKY_SANDBOX_MODES = new Set(['danger-full-access', 'disabled', 'off']);
const OPEN_APPROVAL_MODES = new Set(['never', 'auto']);
const TRUSTED_GATEWAY_BINDS = new Set(['127.0.0.1', 'localhost']);

export function getControls() {
  return [
    {
      id: 'network.local-gateway',
      category: 'network',
      severity: 'HIGH',
      threat: 'exposure',
      intent: 'shrink-reachable-surface',
      title: 'Shrink gateway exposure surface',
      describe: (context) => {
        const bind = context.config?.gateway?.bind;
        if (!bind || TRUSTED_GATEWAY_BINDS.has(bind)) return null;
        return {
          description: `gateway.bind is currently ${bind}, exposing the gateway to a wider reachable surface.`,
          evidence: { currentBind: bind, expected: [...TRUSTED_GATEWAY_BINDS] },
          remediation: 'Restrict gateway.bind to 127.0.0.1',
          autoFixable: true
        };
      },
      remediate: async (context) => {
        if (!context.config.gateway) context.config.gateway = {};
        context.config.gateway.bind = '127.0.0.1';
        await writeJson(context.configPath, context.config);
        return 'gateway.bind -> 127.0.0.1';
      }
    },
    {
      id: 'identity.operator-auth',
      category: 'identity',
      severity: 'HIGH',
      threat: 'unauthorized-access',
      intent: 'preserve-operator-boundary',
      title: 'Preserve authentication boundary for operator gateway',
      describe: (context) => {
        const gateway = context.config?.gateway ?? {};
        const hasAuth = Boolean(gateway.authToken || gateway.auth?.token || gateway.auth?.password);
        if (hasAuth) return null;
        return {
          description: 'No gateway token or password authentication detected for operator entry point.',
          evidence: {
            hasAuthToken: Boolean(gateway.authToken),
            hasNestedToken: Boolean(gateway.auth?.token),
            hasPassword: Boolean(gateway.auth?.password)
          },
          remediation: 'Configure token or password for gateway before exposing the control interface.',
          autoFixable: false,
          severity: context.strictMode ? 'CRITICAL' : 'HIGH'
        };
      }
    },
    {
      id: 'execution.bounded-filesystem',
      category: 'execution',
      severity: 'HIGH',
      threat: 'filesystem-overreach',
      intent: 'restore-execution-boundaries',
      title: 'Keep filesystem boundary protected',
      describe: (context) => {
        const mode = context.config?.sandbox?.mode;
        if (!mode || !RISKY_SANDBOX_MODES.has(mode)) return null;
        return {
          description: `sandbox.mode=${mode}, the agent has overly wide filesystem capabilities.`,
          evidence: { sandboxMode: mode },
          remediation: 'Adjust sandbox.mode to workspace-write',
          autoFixable: true
        };
      },
      remediate: async (context) => {
        if (!context.config.sandbox) context.config.sandbox = {};
        context.config.sandbox.mode = 'workspace-write';
        await writeJson(context.configPath, context.config);
        return 'sandbox.mode -> workspace-write';
      }
    },
    {
      id: 'execution.human-checkpoint',
      category: 'execution',
      severity: 'MEDIUM',
      threat: 'unreviewed-side-effects',
      intent: 'require-human-gates-for-risk',
      title: 'Keep human gates for high-risk execution',
      describe: (context) => {
        const approvals = context.config?.exec?.approvals;
        if (!approvals || !OPEN_APPROVAL_MODES.has(approvals)) return null;
        return {
          description: `exec.approvals=${approvals}, dangerous actions lack human confirmation.`,
          evidence: { approvals },
          remediation: 'Set exec.approvals to on-request',
          autoFixable: true
        };
      },
      remediate: async (context) => {
        if (!context.config.exec) context.config.exec = {};
        context.config.exec.approvals = 'on-request';
        await writeJson(context.configPath, context.config);
        return 'exec.approvals -> on-request';
      }
    },
    {
      id: 'behavior.runtime-constitution',
      category: 'behavior',
      severity: 'MEDIUM',
      threat: 'prompt-injection',
      intent: 'keep-behavioral-guardrails-loaded',
      title: 'Agent requires minimal runtime constitution',
      describe: async (context) => {
        const content = await readSoul(context.stateDir);
        if (content.includes('clawkeeper:rules:start')) return null;
        return {
          description: 'AGENTS.md lacks a clear runtime boundary rules section.',
          evidence: { soulPath: context.soulPath, rulesLoaded: false },
          remediation: 'Inject Clawkeeper runtime constitution into AGENTS.md',
          autoFixable: true
        };
      },
      remediate: async (context) => {
        const result = await ensureRuleBlock(context.stateDir);
        return result.changed ? 'AGENTS.md injected with runtime constitution' : null;
      }
    }
  ];
}
