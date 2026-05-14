import fs from "node:fs/promises";
import path from "node:path";
import { getBeijingDateStamp, resolveDecisionMemoryDir } from "./decision-memory.js";
import { getLogFiles, readLogFile } from "./interceptor.js";

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_TOOL_DEVIATION_THRESHOLD = 3;
const DEFAULT_TOKEN_DEVIATION_THRESHOLD = 2.5;
const DEFAULT_NOVEL_TOOL_SEVERITY = "medium";
const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

function isRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function normalizePositiveNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function normalizeThresholdNumber(value, fallback) {
  const parsed = Number.parseFloat(String(value));
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function normalizeToolName(value) {
  return typeof value === "string" && value.trim() ? value.trim().toLowerCase() : "";
}

function normalizeAgentId(value) {
  return typeof value === "string" && value.trim() ? value.trim().toLowerCase() : "";
}

function parseAgentIdFromSessionKey(sessionKey) {
  if (typeof sessionKey !== "string") {
    return "";
  }
  const match = sessionKey.trim().match(/^agent:([^:]+):/i);
  return match ? normalizeAgentId(match[1]) : "";
}

function resolveAgentIdFromRecord(record) {
  if (!isRecord(record)) {
    return "";
  }
  return normalizeAgentId(record.agentId) || parseAgentIdFromSessionKey(record.sessionKey);
}

function resolveSessionIdentifier(record) {
  if (!isRecord(record)) {
    return "";
  }
  if (typeof record.sessionKey === "string" && record.sessionKey.trim()) {
    return record.sessionKey.trim();
  }
  if (typeof record.sessionId === "string" && record.sessionId.trim()) {
    return `session:${record.sessionId.trim()}`;
  }
  return "";
}

function getLookbackDateStamps(lookbackDays, referenceDate = new Date()) {
  const safeLookbackDays = Math.max(1, Number.parseInt(String(lookbackDays), 10) || 7);
  const stamps = [];
  const baseMs = referenceDate.getTime();
  for (let i = 0; i < safeLookbackDays; i += 1) {
    stamps.push(getBeijingDateStamp(new Date(baseMs - i * 86_400_000)));
  }
  return stamps;
}

function buildDistributionFromCounts(counts, total) {
  if (!(counts instanceof Map) || total <= 0) {
    return {};
  }

  return Object.fromEntries(
    [...counts.entries()]
      .toSorted(([leftTool], [rightTool]) => leftTool.localeCompare(rightTool))
      .map(([tool, count]) => [tool, count / total]),
  );
}

function createEmptyProfile(agentId) {
  return {
    agentId,
    toolDistribution: {},
    toolCallCount: 0,
    avgInputTokensPerCall: 0,
    avgOutputTokensPerCall: 0,
    avgTotalTokensPerCall: 0,
    totalTokens: 0,
    sessionCount: 0,
    avgToolCallsPerSession: 0,
    riskDecisionCount: 0,
    riskRatio: 0,
    judgeDecisionCount: 0,
    knownTools: new Set(),
    firstSeen: "",
    lastSeen: "",
    dataPointCount: 0,
    _toolCounts: new Map(),
    _sessionKeys: new Set(),
    _inputTokenSum: 0,
    _inputTokenSamples: 0,
    _outputTokenSum: 0,
    _outputTokenSamples: 0,
    _totalTokenSum: 0,
    _totalTokenSamples: 0,
  };
}

function ensureProfile(profileMap, agentId) {
  const existing = profileMap.get(agentId);
  if (existing) {
    return existing;
  }

  const created = createEmptyProfile(agentId);
  profileMap.set(agentId, created);
  return created;
}

function updateTimestampRange(profile, timestamp) {
  if (typeof timestamp !== "string" || !timestamp) {
    return;
  }
  if (!profile.firstSeen || timestamp < profile.firstSeen) {
    profile.firstSeen = timestamp;
  }
  if (!profile.lastSeen || timestamp > profile.lastSeen) {
    profile.lastSeen = timestamp;
  }
}

function recordTokenSample(profile, record) {
  if (record.type !== "llm_output") {
    return;
  }

  const inputTokens = normalizePositiveNumber(record.inputTokens);
  if (inputTokens !== null) {
    profile._inputTokenSum += inputTokens;
    profile._inputTokenSamples += 1;
  }

  const outputTokens = normalizePositiveNumber(record.outputTokens);
  if (outputTokens !== null) {
    profile._outputTokenSum += outputTokens;
    profile._outputTokenSamples += 1;
  }

  const totalTokens =
    normalizePositiveNumber(record.totalTokens) ??
    [
      normalizePositiveNumber(record.inputTokens),
      normalizePositiveNumber(record.outputTokens),
      normalizePositiveNumber(record.cacheReadTokens),
      normalizePositiveNumber(record.cacheWriteTokens),
    ].reduce((sum, value) => sum + (value ?? 0), 0);

  if (totalTokens > 0) {
    profile._totalTokenSum += totalTokens;
    profile._totalTokenSamples += 1;
    profile.totalTokens += totalTokens;
  }
}

function normalizeKnownTools(value, distribution = {}) {
  if (value instanceof Set) {
    return new Set([...value].map((tool) => normalizeToolName(tool)).filter(Boolean));
  }
  if (Array.isArray(value)) {
    return new Set(value.map((tool) => normalizeToolName(tool)).filter(Boolean));
  }
  return new Set(
    Object.keys(distribution)
      .map((tool) => normalizeToolName(tool))
      .filter(Boolean),
  );
}

function normalizeBehaviorSummary(summary = {}) {
  const toolDistribution = isRecord(summary.toolDistribution) ? summary.toolDistribution : {};
  const knownTools = normalizeKnownTools(summary.knownTools, toolDistribution);
  const toolCallCount =
    normalizePositiveNumber(summary.toolCallCount) ?? Object.keys(toolDistribution).length;

  return {
    agentId: normalizeAgentId(summary.agentId),
    toolDistribution,
    toolCallCount,
    avgInputTokensPerCall: normalizePositiveNumber(summary.avgInputTokensPerCall),
    avgOutputTokensPerCall: normalizePositiveNumber(summary.avgOutputTokensPerCall),
    avgTotalTokensPerCall:
      normalizePositiveNumber(summary.avgTotalTokensPerCall) ??
      (() => {
        const input = normalizePositiveNumber(summary.avgInputTokensPerCall) ?? 0;
        const output = normalizePositiveNumber(summary.avgOutputTokensPerCall) ?? 0;
        return input > 0 || output > 0 ? input + output : null;
      })(),
    sessionCount: normalizePositiveNumber(summary.sessionCount) ?? 0,
    riskDecisionCount: normalizePositiveNumber(summary.riskDecisionCount) ?? 0,
    judgeDecisionCount: normalizePositiveNumber(summary.judgeDecisionCount) ?? 0,
    knownTools,
  };
}

function safeLog2(value) {
  return value > 0 ? Math.log2(value) : 0;
}

function calculateJensenShannonDivergence(left = {}, right = {}) {
  const tools = new Set([...Object.keys(left), ...Object.keys(right)]);
  if (tools.size === 0) {
    return 0;
  }

  let divergence = 0;
  for (const tool of tools) {
    const leftValue = normalizePositiveNumber(left[tool]) ?? 0;
    const rightValue = normalizePositiveNumber(right[tool]) ?? 0;
    const midpoint = (leftValue + rightValue) / 2;
    if (leftValue > 0) {
      divergence += 0.5 * leftValue * (safeLog2(leftValue) - safeLog2(midpoint));
    }
    if (rightValue > 0) {
      divergence += 0.5 * rightValue * (safeLog2(rightValue) - safeLog2(midpoint));
    }
  }
  return divergence;
}

function summarizeForwardedContextForProfiling(body = {}, decision = {}) {
  const forwardedContext = isRecord(body.forwardedContext) ? body.forwardedContext : {};
  const metadata = isRecord(forwardedContext.metadata) ? forwardedContext.metadata : {};
  const messages = Array.isArray(forwardedContext.messages)
    ? forwardedContext.messages.filter((message) => isRecord(message))
    : [];

  let lastUserIndex = -1;
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === "user") {
      lastUserIndex = i;
      break;
    }
  }

  const activeMessages = lastUserIndex >= 0 ? messages.slice(lastUserIndex) : messages;
  const toolCounts = new Map();
  for (const message of activeMessages) {
    const toolName = normalizeToolName(message.toolName || message.name);
    if (!toolName || toolName === "clawbands_respond" || toolName === "clawkeeper_bands_respond") {
      continue;
    }
    toolCounts.set(toolName, (toolCounts.get(toolName) ?? 0) + 1);
  }

  const toolCallCount = [...toolCounts.values()].reduce((sum, count) => sum + count, 0);
  const usage = isRecord(metadata.usage) ? metadata.usage : isRecord(body.usage) ? body.usage : {};
  const inputTokens =
    normalizePositiveNumber(usage.input) ??
    normalizePositiveNumber(usage.inputTokens) ??
    normalizePositiveNumber(metadata.inputTokens) ??
    normalizePositiveNumber(body.inputTokens);
  const outputTokens =
    normalizePositiveNumber(usage.output) ??
    normalizePositiveNumber(usage.outputTokens) ??
    normalizePositiveNumber(metadata.outputTokens) ??
    normalizePositiveNumber(body.outputTokens);
  const totalTokens =
    normalizePositiveNumber(usage.total) ??
    normalizePositiveNumber(usage.totalTokens) ??
    normalizePositiveNumber(metadata.totalTokens) ??
    normalizePositiveNumber(body.totalTokens) ??
    (() => {
      if (inputTokens === null && outputTokens === null) {
        return null;
      }
      return (inputTokens ?? 0) + (outputTokens ?? 0);
    })();

  const sessionKey =
    typeof metadata.sessionKey === "string"
      ? metadata.sessionKey
      : typeof body.sessionKey === "string"
        ? body.sessionKey
        : "";
  const agentId =
    normalizeAgentId(metadata.agentId) ||
    normalizeAgentId(body.agentId) ||
    parseAgentIdFromSessionKey(sessionKey);
  const riskDecisionCount = decision?.decision && decision.decision !== "continue" ? 1 : 0;

  return {
    agentId,
    toolDistribution: buildDistributionFromCounts(toolCounts, toolCallCount),
    toolCallCount,
    avgInputTokensPerCall: inputTokens,
    avgOutputTokensPerCall: outputTokens,
    avgTotalTokensPerCall: totalTokens,
    totalTokens: totalTokens ?? 0,
    sessionCount: sessionKey || activeMessages.length > 0 ? 1 : 0,
    avgToolCallsPerSession: toolCallCount,
    riskDecisionCount,
    riskRatio: riskDecisionCount,
    judgeDecisionCount: decision?.decision ? 1 : 0,
    knownTools: new Set(toolCounts.keys()),
  };
}

function buildWarningMessage(agentId, findings, lookbackDays) {
  const fragments = findings.slice(0, 2).map((finding) => {
    if (finding.type === "novel_tool") {
      return `using novel tool '${finding.tool}'`;
    }
    if (finding.type === "tool_frequency_spike") {
      return `${finding.multiplier.toFixed(1)}x spike in '${finding.tool}' usage`;
    }
    if (finding.type === "token_spike") {
      return `${finding.multiplier.toFixed(1)}x spike in ${finding.metric} tokens`;
    }
    return finding.message;
  });

  return `Agent ${agentId} is exhibiting behavior significantly different from its ${lookbackDays}-day baseline: ${fragments.join(" and ")}`;
}

function pickHigherSeverity(left, right) {
  return (SEVERITY_RANK[right] ?? 0) > (SEVERITY_RANK[left] ?? 0) ? right : left;
}

async function loadDecisionRecords(lookbackDays = 7) {
  const memoryDir = await resolveDecisionMemoryDir();
  const dateStamps = getLookbackDateStamps(lookbackDays);
  const records = [];

  for (const stamp of dateStamps) {
    const filePath = path.join(memoryDir, `${stamp}.jsonl`);
    let content = "";
    try {
      content = await fs.readFile(filePath, "utf-8");
    } catch {
      continue;
    }

    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      try {
        const parsed = JSON.parse(trimmed);
        if (isRecord(parsed)) {
          records.push(parsed);
        }
      } catch {
        // Skip corrupt lines.
      }
    }
  }

  return records;
}

export async function loadEventLogs(lookbackDays = 7) {
  const dateStamps = new Set(getLookbackDateStamps(lookbackDays).map((stamp) => `${stamp}.jsonl`));
  const files = await getLogFiles();
  const selectedFiles = files.filter((filename) => dateStamps.has(filename));
  const batches = await Promise.all(selectedFiles.map((filename) => readLogFile(filename)));
  return batches.flat().filter((record) => isRecord(record));
}

export function buildAgentProfiles(records, options = {}) {
  const decisionRecords = Array.isArray(options.decisionRecords) ? options.decisionRecords : [];
  const profileMap = new Map();

  for (const record of Array.isArray(records) ? records : []) {
    const agentId = resolveAgentIdFromRecord(record);
    if (!agentId) {
      continue;
    }

    const profile = ensureProfile(profileMap, agentId);
    profile.dataPointCount += 1;
    updateTimestampRange(profile, record.timestamp);

    const sessionIdentifier = resolveSessionIdentifier(record);
    if (sessionIdentifier) {
      profile._sessionKeys.add(sessionIdentifier);
    }

    if (record.type === "before_tool_call") {
      const toolName = normalizeToolName(record.toolName);
      if (toolName) {
        profile.toolCallCount += 1;
        profile.knownTools.add(toolName);
        profile._toolCounts.set(toolName, (profile._toolCounts.get(toolName) ?? 0) + 1);
      }
    }

    recordTokenSample(profile, record);
  }

  for (const record of decisionRecords) {
    const agentId = resolveAgentIdFromRecord(record);
    if (!agentId) {
      continue;
    }

    const profile = ensureProfile(profileMap, agentId);
    updateTimestampRange(profile, record.timestamp);

    const sessionIdentifier = resolveSessionIdentifier(record);
    if (sessionIdentifier) {
      profile._sessionKeys.add(sessionIdentifier);
    }

    profile.judgeDecisionCount += 1;
    if (record.decision && record.decision !== "continue") {
      profile.riskDecisionCount += 1;
    }
  }

  for (const profile of profileMap.values()) {
    profile.sessionCount = profile._sessionKeys.size;
    profile.avgToolCallsPerSession =
      profile.sessionCount > 0 ? profile.toolCallCount / profile.sessionCount : 0;
    profile.toolDistribution = buildDistributionFromCounts(
      profile._toolCounts,
      profile.toolCallCount,
    );
    profile.avgInputTokensPerCall =
      profile._inputTokenSamples > 0 ? profile._inputTokenSum / profile._inputTokenSamples : 0;
    profile.avgOutputTokensPerCall =
      profile._outputTokenSamples > 0 ? profile._outputTokenSum / profile._outputTokenSamples : 0;
    profile.avgTotalTokensPerCall =
      profile._totalTokenSamples > 0 ? profile._totalTokenSum / profile._totalTokenSamples : 0;
    profile.riskRatio =
      profile.judgeDecisionCount > 0 ? profile.riskDecisionCount / profile.judgeDecisionCount : 0;
    delete profile._toolCounts;
    delete profile._sessionKeys;
    delete profile._inputTokenSum;
    delete profile._inputTokenSamples;
    delete profile._outputTokenSum;
    delete profile._outputTokenSamples;
    delete profile._totalTokenSum;
    delete profile._totalTokenSamples;
  }

  return profileMap;
}

export function computeDeviation(currentBehavior = {}, baseline = null) {
  const current = normalizeBehaviorSummary(currentBehavior);
  const normalizedBaseline = baseline ? normalizeBehaviorSummary(baseline) : null;

  if (!normalizedBaseline) {
    return {
      agentId: current.agentId,
      hasBaseline: false,
      toolDistributionDivergence: 0,
      novelTools: [],
      toolFrequencyChanges: [],
      tokenDeviation: {},
      baseline: null,
      current,
    };
  }

  const novelTools = [...current.knownTools].filter(
    (tool) => !normalizedBaseline.knownTools.has(tool),
  );
  const toolFrequencyChanges = [];
  for (const tool of current.knownTools) {
    const currentFrequency = normalizePositiveNumber(current.toolDistribution[tool]) ?? 0;
    const baselineFrequency =
      normalizePositiveNumber(normalizedBaseline.toolDistribution[tool]) ?? 0;
    if (currentFrequency <= 0 || baselineFrequency <= 0) {
      continue;
    }
    toolFrequencyChanges.push({
      tool,
      baseline: baselineFrequency,
      current: currentFrequency,
      multiplier: currentFrequency / baselineFrequency,
      delta: currentFrequency - baselineFrequency,
    });
  }

  const tokenDeviation = {};
  const tokenPairs = [
    ["input", current.avgInputTokensPerCall, normalizedBaseline.avgInputTokensPerCall],
    ["output", current.avgOutputTokensPerCall, normalizedBaseline.avgOutputTokensPerCall],
    ["total", current.avgTotalTokensPerCall, normalizedBaseline.avgTotalTokensPerCall],
  ];

  for (const [metric, currentValue, baselineValue] of tokenPairs) {
    if (
      currentValue === null ||
      baselineValue === null ||
      baselineValue <= 0 ||
      currentValue <= 0
    ) {
      continue;
    }
    tokenDeviation[metric] = {
      current: currentValue,
      baseline: baselineValue,
      multiplier: currentValue / baselineValue,
    };
  }

  return {
    agentId: current.agentId || normalizedBaseline.agentId,
    hasBaseline: true,
    toolDistributionDivergence: calculateJensenShannonDivergence(
      normalizedBaseline.toolDistribution,
      current.toolDistribution,
    ),
    novelTools,
    toolFrequencyChanges: toolFrequencyChanges.toSorted(
      (left, right) => right.multiplier - left.multiplier,
    ),
    tokenDeviation,
    baseline: normalizedBaseline,
    current,
  };
}

export function detectAnomalies(deviations, thresholds = {}) {
  const safeThresholds = {
    lookbackDays: Math.max(1, Number.parseInt(String(thresholds.lookbackDays), 10) || 7),
    toolDeviationThreshold: normalizeThresholdNumber(
      thresholds.toolDeviationThreshold ?? DEFAULT_TOOL_DEVIATION_THRESHOLD,
      DEFAULT_TOOL_DEVIATION_THRESHOLD,
    ),
    tokenDeviationThreshold: normalizeThresholdNumber(
      thresholds.tokenDeviationThreshold ?? DEFAULT_TOKEN_DEVIATION_THRESHOLD,
      DEFAULT_TOKEN_DEVIATION_THRESHOLD,
    ),
    novelToolSeverity: ["low", "medium", "high"].includes(String(thresholds.novelToolSeverity))
      ? String(thresholds.novelToolSeverity)
      : DEFAULT_NOVEL_TOOL_SEVERITY,
  };

  if (!deviations?.hasBaseline || !deviations.baseline) {
    return {
      detected: false,
      agentId: deviations?.agentId ?? "",
      severity: "low",
      deviations: [],
      baselineSummary: null,
      warning: null,
    };
  }

  const findings = [];
  let severity = "low";

  for (const tool of deviations.novelTools) {
    severity = pickHigherSeverity(severity, safeThresholds.novelToolSeverity);
    findings.push({
      type: "novel_tool",
      tool,
      severity: safeThresholds.novelToolSeverity,
      message: `Agent has never used '${tool}' in ${safeThresholds.lookbackDays}-day baseline (${deviations.baseline.toolCallCount} historical calls)`,
    });
  }

  for (const change of deviations.toolFrequencyChanges) {
    if (change.multiplier < safeThresholds.toolDeviationThreshold) {
      continue;
    }
    const changeSeverity =
      change.multiplier >= safeThresholds.toolDeviationThreshold * 2 || change.current >= 0.5
        ? "high"
        : "medium";
    severity = pickHigherSeverity(severity, changeSeverity);
    findings.push({
      type: "tool_frequency_spike",
      tool: change.tool,
      baseline: change.baseline,
      current: change.current,
      multiplier: change.multiplier,
      severity: changeSeverity,
      message: `${change.tool} usage ${change.multiplier.toFixed(1)}x above baseline (${Math.round(change.baseline * 100)}% -> ${Math.round(change.current * 100)}%)`,
    });
  }

  for (const [metric, change] of Object.entries(deviations.tokenDeviation)) {
    if (change.multiplier < safeThresholds.tokenDeviationThreshold) {
      continue;
    }
    const changeSeverity =
      change.multiplier >= safeThresholds.tokenDeviationThreshold * 1.75 ? "high" : "medium";
    severity = pickHigherSeverity(severity, changeSeverity);
    findings.push({
      type: "token_spike",
      metric,
      baseline: change.baseline,
      current: change.current,
      multiplier: change.multiplier,
      severity: changeSeverity,
      message: `${metric} tokens ${change.multiplier.toFixed(1)}x above baseline (${Math.round(change.baseline)} -> ${Math.round(change.current)})`,
    });
  }

  if (findings.length === 0) {
    return {
      detected: false,
      agentId: deviations.agentId,
      severity: "low",
      deviations: [],
      baselineSummary: {
        sessionCount: deviations.baseline.sessionCount,
        toolCallCount: deviations.baseline.toolCallCount,
        knownTools: [...deviations.baseline.knownTools].toSorted((left, right) =>
          left.localeCompare(right),
        ),
        lookbackDays: safeThresholds.lookbackDays,
      },
      warning: null,
    };
  }

  return {
    detected: true,
    agentId: deviations.agentId,
    severity,
    deviations: findings,
    baselineSummary: {
      sessionCount: deviations.baseline.sessionCount,
      toolCallCount: deviations.baseline.toolCallCount,
      knownTools: [...deviations.baseline.knownTools].toSorted((left, right) =>
        left.localeCompare(right),
      ),
      lookbackDays: safeThresholds.lookbackDays,
    },
    warning: buildWarningMessage(deviations.agentId, findings, safeThresholds.lookbackDays),
  };
}

const _cache = {
  entries: new Map(),
  ttlMs: DEFAULT_CACHE_TTL_MS,
};

export async function getCachedProfiles(lookbackDays = 7) {
  const safeLookbackDays = Math.max(1, Number.parseInt(String(lookbackDays), 10) || 7);
  const now = Date.now();
  const cached = _cache.entries.get(safeLookbackDays);
  if (cached && now - cached.loadedAt < _cache.ttlMs) {
    return cached.profileMap;
  }

  const [records, decisionRecords] = await Promise.all([
    loadEventLogs(safeLookbackDays),
    loadDecisionRecords(safeLookbackDays),
  ]);
  const profileMap = buildAgentProfiles(records, { decisionRecords });
  _cache.entries.set(safeLookbackDays, { profileMap, loadedAt: now });
  return profileMap;
}

export function invalidateProfileCache() {
  _cache.entries.clear();
}

export async function resolveAgentAnomaly({ body, decision, config = {} }) {
  const profileConfig = isRecord(config.agentProfiling) ? config.agentProfiling : {};
  if (!profileConfig.enabled) {
    return null;
  }

  const lookbackDays = Math.max(1, Number.parseInt(String(profileConfig.lookbackDays), 10) || 7);
  const currentBehavior = summarizeForwardedContextForProfiling(body, decision);
  if (!currentBehavior.agentId) {
    return null;
  }

  const profileMap = await getCachedProfiles(lookbackDays);
  const baseline = profileMap.get(currentBehavior.agentId);
  if (!baseline) {
    return null;
  }

  const deviations = computeDeviation(currentBehavior, baseline);
  const anomaly = detectAnomalies(deviations, {
    ...profileConfig,
    lookbackDays,
  });

  return anomaly.detected ? anomaly : null;
}

export const _testExports = {
  _cache,
  calculateJensenShannonDivergence,
  getLookbackDateStamps,
  parseAgentIdFromSessionKey,
  summarizeForwardedContextForProfiling,
};
