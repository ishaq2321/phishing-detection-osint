/**
 * Settings store — localStorage-backed CRUD for application settings.
 *
 * Every public function is synchronous and safe to call on the server
 * (returns defaults when `window` is unavailable).
 */

import { DEFAULT_API_URL } from "@/lib/constants";

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

const STORAGE_KEY = "phishguard:settings";

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

/** How much detail to show in analysis results. */
export type ResultsDetailLevel = "simple" | "detailed" | "expert";

/** Maximum history entries the user wants to keep. */
export type MaxHistoryEntries = 10 | 25 | 50 | 100;

/** Auto-clear history after N days (0 = never). */
export type AutoClearDays = 0 | 7 | 14 | 30;

/** Full settings shape persisted to localStorage. */
export interface AppSettings {
  /** Backend API base URL. */
  apiUrl: string;
  /** Level of detail in result displays. */
  resultsDetailLevel: ResultsDetailLevel;
  /** Maximum number of entries to keep in history. */
  maxHistoryEntries: MaxHistoryEntries;
  /** Auto-clear history entries older than N days (0 = never). */
  autoClearDays: AutoClearDays;
}

/* ------------------------------------------------------------------ */
/*  Defaults                                                          */
/* ------------------------------------------------------------------ */

export const DEFAULT_SETTINGS: Readonly<AppSettings> = {
  apiUrl: DEFAULT_API_URL,
  resultsDetailLevel: "detailed",
  maxHistoryEntries: 50,
  autoClearDays: 0,
} as const;

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function isClient(): boolean {
  return typeof window !== "undefined";
}

/* ------------------------------------------------------------------ */
/*  Read                                                              */
/* ------------------------------------------------------------------ */

/** Return the current persisted settings, merged with defaults. */
export function getSettings(): AppSettings {
  if (!isClient()) return { ...DEFAULT_SETTINGS };

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<AppSettings>;
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

/** Return the value of a single setting key. */
export function getSetting<K extends keyof AppSettings>(
  key: K,
): AppSettings[K] {
  return getSettings()[key];
}

/* ------------------------------------------------------------------ */
/*  Write                                                             */
/* ------------------------------------------------------------------ */

/** Persist the full settings object. */
function persist(settings: AppSettings): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

/** Update a single setting key and persist immediately. */
export function updateSetting<K extends keyof AppSettings>(
  key: K,
  value: AppSettings[K],
): AppSettings {
  const current = getSettings();
  const updated = { ...current, [key]: value };
  persist(updated);
  return updated;
}

/** Reset all settings to their defaults. */
export function resetSettings(): AppSettings {
  if (isClient()) {
    localStorage.removeItem(STORAGE_KEY);
  }
  return { ...DEFAULT_SETTINGS };
}
