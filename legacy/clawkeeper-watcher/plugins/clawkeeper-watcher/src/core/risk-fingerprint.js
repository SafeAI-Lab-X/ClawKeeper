/**
 * Cross-Session Risk Fingerprint
 *
 * Extracts recurring risk patterns from decision-memory history and matches
 * incoming context-judge requests against known fingerprints.
 *
 * A "fingerprint" is a normalized key derived from the tool combination and
 * stop reason of a non-continue decision. When the same fingerprint appears
 * repeatedly across sessions, it becomes a "known risk pattern" and triggers
 * a warning on subsequent matches.
 *
 * Storage: reads from ~/.openclaw/.clawkeeper-watcher/decision-memory/YYYY-MM-DD.jsonl
 * (same files written by decision-memory.js, remote mode only).
 */

import fs from "node:fs/promises";
import path from "node:path";
import { getBeijingDateStamp, resolveDecisionMemoryDir } from "./decision-memory.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const RISK_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const RANK_TO_LEVEL = ["low", "low", "medium", "high", "critical"];

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ---------------------------------------------------------------------------
// Fingerprint key generation
// ---------------------------------------------------------------------------

/**
 * Build a stable fingerprint key from a record-like object.
 * Format: "<sorted,tool,names>|<stopReason>"
 *
 * Examples:
 *   "bash,exec|tool_loop_limit"
 *   "write|waiting_user_confirmation"
 *   "|user_requested_stop"            (no tools)
 */
function buildFingerprintKey(record) {
  const tools = Array.isArray(record.toolNames)
    ? [...new Set(record.toolNames)].toSorted((a, b) => a.localeCompare(b)).join(",")
    : "";
  const reason = typeof record.stopReason === "string" ? record.stopReason : "unknown";
  return `${tools}|${reason}`;
}

// ---------------------------------------------------------------------------
// Date utilities (Beijing time, matching decision-memory convention)
// ---------------------------------------------------------------------------

/**
 * Generate an array of YYYY-MM-DD date stamps for the lookback window.
 * Most recent date first.
 */
function getLookbackDateStamps(lookbackDays, referenceDate = new Date()) {
  const stamps = [];
  const baseMs = referenceDate.getTime();
  for (let i = 0; i < lookbackDays; i++) {
    stamps.push(getBeijingDateStamp(new Date(baseMs - i * 86_400_000)));
  }
  return stamps;
}

// ---------------------------------------------------------------------------
// JSONL history reader
// ---------------------------------------------------------------------------

/**
 * Read and parse all decision records from JSONL files within the lookback
 * window. Silently skips missing files and unparseable lines.
 *
 * @param {number} lookbackDays - Number of days to look back (default 7).
 * @returns {Promise<object[]>} Parsed record objects.
 */
export async function loadDecisionHistory(lookbackDays = 7) {
  const memoryDir = await resolveDecisionMemoryDir();
  const dateStamps = getLookbackDateStamps(lookbackDays);
  const records = [];

  for (const stamp of dateStamps) {
    const filePath = path.join(memoryDir, `${stamp}.jsonl`);
    let raw;
    try {
      raw = await fs.readFile(filePath, "utf-8");
    } catch {
      continue; // file doesn't exist for this date
    }

    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      try {
        records.push(JSON.parse(trimmed));
      } catch {
        // skip corrupt line
      }
    }
  }

  return records;
}

// ---------------------------------------------------------------------------
// Fingerprint extraction
// ---------------------------------------------------------------------------

/**
 * Extract a fingerprint frequency map from historical decision records.
 * Only considers records where decision !== "continue" (stop or ask_user).
 *
 * @param {object[]} records - Decision memory records.
 * @returns {Map<string, object>} Map of fingerprint key → aggregated entry.
 *
 * Each entry: { key, count, maxRiskLevel, stopReason, toolNames, lastSeen, sessions: Set }
 */
export function extractFingerprints(records) {
  const map = new Map();

  for (const record of records) {
    if (!record || typeof record !== "object") {
      continue;
    }
    // Only process records with a valid non-continue decision
    if (!record.decision || record.decision === "continue") {
      continue;
    }

    const key = buildFingerprintKey(record);
    const existing = map.get(key);

    if (existing) {
      existing.count += 1;

      // Track highest observed risk level
      const incomingRank = RISK_RANK[record.riskLevel] ?? 0;
      const existingRank = RISK_RANK[existing.maxRiskLevel] ?? 0;
      if (incomingRank > existingRank) {
        existing.maxRiskLevel = RANK_TO_LEVEL[incomingRank] || record.riskLevel;
      }

      // Track latest timestamp
      if (record.timestamp && record.timestamp > existing.lastSeen) {
        existing.lastSeen = record.timestamp;
      }

      // Track unique sessions
      if (record.sessionKey) {
        existing.sessions.add(record.sessionKey);
      }
    } else {
      map.set(key, {
        key,
        count: 1,
        maxRiskLevel: record.riskLevel || "medium",
        stopReason: record.stopReason || "unknown",
        toolNames: Array.isArray(record.toolNames)
          ? [...new Set(record.toolNames)].toSorted((a, b) => a.localeCompare(b))
          : [],
        lastSeen: record.timestamp || "",
        sessions: new Set(record.sessionKey ? [record.sessionKey] : []),
      });
    }
  }

  return map;
}

// ---------------------------------------------------------------------------
// Fingerprint matching
// ---------------------------------------------------------------------------

/**
 * Check whether the current request context matches any known risk fingerprint.
 *
 * @param {object} currentContext - { toolNames: string[], stopReason: string }
 * @param {Map} fingerprintMap - From extractFingerprints().
 * @param {number} threshold - Minimum occurrences to qualify as a match.
 * @returns {object|null} Fingerprint match object or null.
 */
export function matchFingerprint(currentContext, fingerprintMap, threshold = 2) {
  if (!fingerprintMap || fingerprintMap.size === 0) {
    return null;
  }

  const currentKey = buildFingerprintKey(currentContext);
  const match = fingerprintMap.get(currentKey);

  if (!match || match.count < threshold) {
    return null;
  }

  return {
    matched: true,
    key: match.key,
    occurrences: match.count,
    maxRiskLevel: match.maxRiskLevel,
    sessionCount: match.sessions.size,
    lastSeen: match.lastSeen,
    toolNames: match.toolNames,
    stopReason: match.stopReason,
    warning: `This tool+reason combination has triggered ${match.count} non-continue decisions across ${match.sessions.size} session(s) in the lookback window.`,
  };
}

// ---------------------------------------------------------------------------
// In-memory cache
// ---------------------------------------------------------------------------

const _cache = {
  /** @type {Map<number, { fingerprintMap: Map, loadedAt: number }>} */
  entries: new Map(),
  ttlMs: DEFAULT_CACHE_TTL_MS,
};

/**
 * Get the fingerprint map, loading from disk if cache is stale or missing.
 *
 * @param {number} lookbackDays
 * @returns {Promise<Map>}
 */
export async function getCachedFingerprintMap(lookbackDays = 7) {
  const now = Date.now();
  const cached = _cache.entries.get(lookbackDays);
  if (cached && now - cached.loadedAt < _cache.ttlMs) {
    return cached.fingerprintMap;
  }

  const records = await loadDecisionHistory(lookbackDays);
  const fingerprintMap = extractFingerprints(records);
  _cache.entries.set(lookbackDays, { fingerprintMap, loadedAt: now });
  return fingerprintMap;
}

/**
 * Force-invalidate the cache (useful after a new decision is persisted,
 * or from tests).
 */
export function invalidateFingerprintCache() {
  _cache.entries.clear();
}

// ---------------------------------------------------------------------------
// Context summary helper (lightweight tool-name extraction)
// ---------------------------------------------------------------------------

function summarizeForwardedContextForFingerprint(body = {}) {
  const fc = body?.forwardedContext;
  if (!fc || !Array.isArray(fc.messages)) {
    return { toolNames: [] };
  }

  const toolNames = [];
  for (const msg of fc.messages) {
    if (!msg || typeof msg !== "object") {
      continue;
    }
    const name =
      typeof msg.toolName === "string"
        ? msg.toolName
        : typeof msg.name === "string"
          ? msg.name
          : "";
    if (name) {
      toolNames.push(name);
    }
  }
  return { toolNames: [...new Set(toolNames)].slice(0, 8) };
}

// ---------------------------------------------------------------------------
// Top-level convenience: resolveFingerprint
// ---------------------------------------------------------------------------

/**
 * High-level entry point for the HTTP handler. Checks config, loads
 * cached fingerprints, and returns a match object or null.
 *
 * @param {object} options
 * @param {object} options.body - Original HTTP request body.
 * @param {object} options.decision - Decision from judgeForwardedContext().
 * @param {object} options.config - The full contextJudge config block.
 * @returns {Promise<object|null>} Fingerprint match or null.
 */
export async function resolveFingerprint({ body, decision, config = {} }) {
  const fpConfig = config.fingerprint ?? {};
  if (!fpConfig.enabled) {
    return null;
  }

  const lookbackDays = Math.max(1, fpConfig.lookbackDays ?? 7);
  const minOccurrences = Math.max(1, fpConfig.minOccurrences ?? 2);

  const contextSummary = summarizeForwardedContextForFingerprint(body);
  const currentContext = {
    toolNames: contextSummary.toolNames,
    stopReason: decision.stopReason,
  };

  const fingerprintMap = await getCachedFingerprintMap(lookbackDays);
  return matchFingerprint(currentContext, fingerprintMap, minOccurrences);
}

// ---------------------------------------------------------------------------
// CLI report builder
// ---------------------------------------------------------------------------

/**
 * Build a human-readable report of known risk fingerprints.
 *
 * @param {Map} fingerprintMap
 * @param {number} threshold
 * @returns {string}
 */
export function buildFingerprintReport(fingerprintMap, threshold = 2) {
  const qualified = [...fingerprintMap.values()]
    .filter((fp) => fp.count >= threshold)
    .toSorted((a, b) => b.count - a.count);

  if (qualified.length === 0) {
    return "No recurring risk fingerprints found in the lookback window.";
  }

  const lines = [
    `\nRisk Fingerprints (${qualified.length} known patterns)\n`,
    "------------------------------------------------------------------------",
  ];

  for (const fp of qualified) {
    const tools = fp.toolNames.length > 0 ? fp.toolNames.join(", ") : "(none)";
    lines.push(`  Key:       ${fp.key}`);
    lines.push(`  Tools:     ${tools}`);
    lines.push(`  Reason:    ${fp.stopReason}`);
    lines.push(`  Count:     ${fp.count} occurrences across ${fp.sessions.size} session(s)`);
    lines.push(`  Max Risk:  ${fp.maxRiskLevel}`);
    lines.push(`  Last Seen: ${fp.lastSeen}`);
    lines.push("------------------------------------------------------------------------");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const _testExports = {
  buildFingerprintKey,
  getLookbackDateStamps,
  summarizeForwardedContextForFingerprint,
  _cache,
};
