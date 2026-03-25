import { invalidateProfileCache, resolveAgentAnomaly } from "../core/agent-profiler.js";
import { judgeForwardedContext } from "../core/context-judge.js";
import { appendDecisionMemory } from "../core/decision-memory.js";
import { resolveIntentDrift } from "../core/intent-drift.js";
import {
  invalidateFingerprintCache,
  resolveFingerprint,
  RISK_RANK,
} from "../core/risk-fingerprint.js";

function writeJson(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(payload));
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    return {};
  }
  return JSON.parse(raw);
}

export function createContextJudgeHttpHandler({
  logger,
  defaultPolicy = {},
  mode = "local",
  contextJudgeConfig = {},
}) {
  return async function contextJudgeHttpHandler(req, res) {
    if (req.method !== "POST") {
      writeJson(res, 405, { error: "Method Not Allowed" });
      return true;
    }

    try {
      const body = await readJsonBody(req);
      const decision = judgeForwardedContext({
        ...body,
        mode,
        policy: {
          ...defaultPolicy,
          ...(body.policy && typeof body.policy === "object" ? body.policy : {}),
        },
      });

      // ── Cross-session risk fingerprint matching (remote mode only) ──
      if (mode === "remote") {
        try {
          const fingerprint = await resolveFingerprint({
            body,
            decision,
            config: contextJudgeConfig,
          });
          if (fingerprint) {
            decision.fingerprint = fingerprint;
          }
        } catch (error) {
          logger.warn(`[Clawkeeper-Watcher] fingerprint matching failed: ${error.message}`);
        }
      }

      // ── Agent behavioral anomaly detection ──
      if (contextJudgeConfig.agentProfiling?.enabled) {
        try {
          const anomaly = await resolveAgentAnomaly({
            body,
            decision,
            config: contextJudgeConfig,
          });
          if (anomaly) {
            decision.agentAnomaly = anomaly;
            if ((RISK_RANK[anomaly.severity] ?? 0) > (RISK_RANK[decision.riskLevel] ?? 0)) {
              decision.riskLevel = anomaly.severity;
            }
          }
        } catch (error) {
          logger.warn(`[Clawkeeper-Watcher] agent profiling failed: ${error.message}`);
        }
      }

      // ── Semantic intent drift detection ──
      if (contextJudgeConfig.intentDrift?.enabled) {
        try {
          const intentDrift = resolveIntentDrift({
            body,
            config: contextJudgeConfig,
          });
          if (intentDrift) {
            decision.intentDrift = intentDrift;
            if ((RISK_RANK[intentDrift.severity] ?? 0) > (RISK_RANK[decision.riskLevel] ?? 0)) {
              decision.riskLevel = intentDrift.severity;
            }
          }
        } catch (error) {
          logger.warn(`[Clawkeeper-Watcher] intent drift detection failed: ${error.message}`);
        }
      }

      logger.info(
        `[Clawkeeper-Watcher] context-judge decision=${decision.decision} stopReason=${decision.stopReason}`,
      );
      try {
        const memoryResult = await appendDecisionMemory({
          mode,
          body,
          decision,
          logger,
        });
        if (memoryResult.saved) {
          invalidateFingerprintCache();
          invalidateProfileCache();
        }
      } catch (error) {
        logger.warn(`[Clawkeeper-Watcher] decision memory write failed: ${error.message}`);
      }
      writeJson(res, 200, decision);
    } catch (error) {
      logger.warn(`[Clawkeeper-Watcher] context-judge request failed: ${error.message}`);
      writeJson(res, 400, {
        version: 1,
        decision: "stop",
        stopReason: "missing_input",
        shouldContinue: false,
        needsUserDecision: false,
        userQuestion: null,
        summary: `Invalid context-judge request: ${error.message}`,
        riskLevel: "medium",
        evidence: [],
        nextAction: "stop_run",
        continueHint: null,
      });
    }

    return true;
  };
}
