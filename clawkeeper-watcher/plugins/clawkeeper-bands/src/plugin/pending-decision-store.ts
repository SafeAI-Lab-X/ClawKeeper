import { readFile, writeFile } from "fs/promises";
import path from "path";
import { CLAWKEEPER_BANDS_DATA_DIR } from "../core/Logger";

export interface PendingDecisionRecord {
  pendingDecision: true;
  origin: "clawkeeper-context-judge";
  requestId: string;
  question: string;
  continueHint?: string;
  createdAt: string;
}

type PendingDecisionMap = Record<string, PendingDecisionRecord>;

const PENDING_DECISIONS_PATH = path.join(CLAWKEEPER_BANDS_DATA_DIR, "pending-decisions.json");

async function loadPendingDecisionMap(): Promise<PendingDecisionMap> {
  try {
    const raw = await readFile(PENDING_DECISIONS_PATH, "utf8");
    const parsed = JSON.parse(raw) as PendingDecisionMap;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function savePendingDecisionMap(map: PendingDecisionMap): Promise<void> {
  await writeFile(PENDING_DECISIONS_PATH, JSON.stringify(map, null, 2), "utf8");
}

export async function getPendingDecision(
  sessionKey?: string,
): Promise<PendingDecisionRecord | null> {
  if (!sessionKey) {
    return null;
  }
  const map = await loadPendingDecisionMap();
  return map[sessionKey] ?? map[sessionKey.toLowerCase()] ?? null;
}

export async function setPendingDecision(
  sessionKey: string | undefined,
  decision: PendingDecisionRecord,
): Promise<void> {
  if (!sessionKey) {
    return;
  }
  const map = await loadPendingDecisionMap();
  map[sessionKey] = decision;
  if (sessionKey.toLowerCase() !== sessionKey) {
    map[sessionKey.toLowerCase()] = decision;
  }
  await savePendingDecisionMap(map);
}

export async function clearPendingDecision(sessionKey?: string): Promise<void> {
  if (!sessionKey) {
    return;
  }
  const map = await loadPendingDecisionMap();
  delete map[sessionKey];
  delete map[sessionKey.toLowerCase()];
  await savePendingDecisionMap(map);
}
