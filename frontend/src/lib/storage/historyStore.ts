/**
 * History store — localStorage-backed CRUD for past analysis results.
 *
 * Respects `maxHistoryEntries` and `autoClearDays` from settingsStore.
 * Every public function is synchronous and safe to call on the server
 * (returns empty data when `window` is unavailable).
 */

import type { AnalysisResponse, ThreatLevel } from "@/types";
import { getSetting } from "@/lib/storage/settingsStore";

/* ------------------------------------------------------------------ */
/* Constants */
/* ------------------------------------------------------------------ */

const STORAGE_KEY = "phishguard:history";

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
/* Write */
/* ------------------------------------------------------------------ */

/** Persist the current entries list. */
function persist(entries: HistoryEntry[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

/**
 * Remove entries whose `analyzedAt` is older than the configured
 * `autoClearDays` setting.  Called automatically on every mutation.
 */
function purgeExpired(entries: HistoryEntry[]): HistoryEntry[] {
  const autoClearDays = getSetting("autoClearDays");
  if (autoClearDays === 0) return entries;

  const cutoff = Date.now() - autoClearDays * 24 * 60 * 60 * 1000;
  return entries.filter((e) => new Date(e.analyzedAt).getTime() >= cutoff);
}

/**
 * Enforce the `maxHistoryEntries` cap from settings.
 * Removes the oldest entries (at the end of the list) when over limit.
 */
function enforceMaxEntries(entries: HistoryEntry[]): HistoryEntry[] {
  const maxEntries = getSetting("maxHistoryEntries");
  if (entries.length > maxEntries) {
    return entries.slice(0, maxEntries);
  }
  return entries;
}

/**
 * Add a new analysis result to history.
 *
 * - Generates a unique ID.
 * - Prepends to the list (newest first).
 * - Purges expired entries based on `autoClearDays` setting.
 * - Enforces `maxHistoryEntries` cap from settings.
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

  let entries = getHistory();
  entries.unshift(entry);
  entries = purgeExpired(entries);
  entries = enforceMaxEntries(entries);

  persist(entries);
  return entry;
}

/** Delete a single entry by ID. Returns `true` if found & removed. */
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

/**
 * Immediately enforce the current `maxHistoryEntries` and
 * `autoClearDays` settings on the stored history.
 *
 * Call this whenever the user changes a history-related setting
 * so the effect is visible right away (not just on the next `addEntry`).
 *
 * Returns the number of entries removed.
 */
export function pruneHistory(): number {
  if (!isClient()) return 0;
  const before = getHistory();
  let entries = purgeExpired(before);
  entries = enforceMaxEntries(entries);
  const removed = before.length - entries.length;
  if (removed > 0) {
    persist(entries);
  }
  return removed;
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
