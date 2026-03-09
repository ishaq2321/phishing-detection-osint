/**
 * History store — localStorage-backed CRUD for past analysis results.
 *
 * Persists up to `MAX_ENTRIES` records using FIFO eviction.  Every
 * public function is synchronous and safe to call on the server
 * (returns empty data when `window` is unavailable).
 */

import type { AnalysisResponse, ThreatLevel } from "@/types";

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

const STORAGE_KEY = "phishguard:history";
const MAX_ENTRIES = 100;

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

/** A single persisted history row. */
export interface HistoryEntry {
  /** UUID-style identifier. */
  id: string;
  /** Original content the user submitted. */
  content: string;
  /** Content type used for the analysis. */
  contentType: string;
  /** Threat level verdict. */
  threatLevel: ThreatLevel;
  /** Overall confidence score (0 – 1). */
  score: number;
  /** Whether the content was classified as phishing. */
  isPhishing: boolean;
  /** ISO-8601 timestamp of the analysis. */
  analyzedAt: string;
  /** Full analysis response stored for the "view result" action. */
  response: AnalysisResponse;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function isClient(): boolean {
  return typeof window !== "undefined";
}

/** RFC-4122 v4 UUID (crypto-random when available). */
function generateId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

/* ------------------------------------------------------------------ */
/*  Read                                                              */
/* ------------------------------------------------------------------ */

/** Return all history entries (newest first). */
export function getHistory(): HistoryEntry[] {
  if (!isClient()) return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as HistoryEntry[];
  } catch {
    return [];
  }
}

/** Return a single entry by ID, or `null` if not found. */
export function getEntryById(id: string): HistoryEntry | null {
  return getHistory().find((e) => e.id === id) ?? null;
}

/* ------------------------------------------------------------------ */
/*  Write                                                             */
/* ------------------------------------------------------------------ */

/** Persist the current entries list. */
function persist(entries: HistoryEntry[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

/**
 * Add a new analysis result to history.
 *
 * - Generates a unique ID.
 * - Prepends to the list (newest first).
 * - Evicts the oldest entry when the cap is reached.
 */
export function addEntry(
  content: string,
  contentType: string,
  response: AnalysisResponse,
): HistoryEntry {
  const entry: HistoryEntry = {
    id: generateId(),
    content,
    contentType,
    threatLevel: response.verdict.threatLevel,
    score: response.verdict.confidenceScore,
    isPhishing: response.verdict.isPhishing,
    analyzedAt: response.analyzedAt,
    response,
  };

  const entries = getHistory();
  entries.unshift(entry);

  if (entries.length > MAX_ENTRIES) {
    entries.length = MAX_ENTRIES;
  }

  persist(entries);
  return entry;
}

/** Delete a single entry by ID.  Returns `true` if found & removed. */
export function deleteEntry(id: string): boolean {
  const entries = getHistory();
  const idx = entries.findIndex((e) => e.id === id);
  if (idx === -1) return false;
  entries.splice(idx, 1);
  persist(entries);
  return true;
}

/** Remove all history entries. */
export function clearHistory(): void {
  if (isClient()) {
    localStorage.removeItem(STORAGE_KEY);
  }
}

/* ------------------------------------------------------------------ */
/*  Export                                                             */
/* ------------------------------------------------------------------ */

/** Trigger a file download in the browser. */
function downloadFile(
  filename: string,
  content: string,
  mimeType: string,
): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/** Export the full history as a JSON file download. */
export function exportToJson(): void {
  const entries = getHistory();
  const json = JSON.stringify(entries, null, 2);
  downloadFile("phishguard-history.json", json, "application/json");
}

/** Export the history as a CSV file download. */
export function exportToCsv(): void {
  const entries = getHistory();
  const header = ["#", "Content", "Type", "Threat Level", "Score", "Date"];

  const rows = entries.map((entry, idx) => [
    String(idx + 1),
    `"${entry.content.replace(/"/g, '""')}"`,
    entry.contentType,
    entry.threatLevel,
    (entry.score * 100).toFixed(1),
    entry.analyzedAt,
  ]);

  const csv = [header.join(","), ...rows.map((r) => r.join(","))].join("\n");
  downloadFile("phishguard-history.csv", csv, "text/csv");
}

/** Number of entries currently stored. */
export function getHistoryCount(): number {
  return getHistory().length;
}
