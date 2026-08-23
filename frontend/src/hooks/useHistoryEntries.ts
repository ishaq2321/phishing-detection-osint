"use client";

/**
 * useHistoryEntries — reactive access to the localStorage history store.
 *
 * Backed by `useSyncExternalStore` so components re-render when entries
 * are added/removed anywhere in the app, with a stable server snapshot
 * (empty array) that keeps SSR/hydration deterministic. This replaces
 * the previous useEffect + setState pattern flagged by
 * react-hooks/set-state-in-effect.
 */

import { useSyncExternalStore } from "react";
import {
  getHistorySnapshot,
  subscribeHistory,
} from "@/lib/storage/historyStore";
import type { HistoryEntry } from "@/types";

export function useHistoryEntries(): HistoryEntry[] {
  return useSyncExternalStore(
    subscribeHistory,
    getHistorySnapshot,
    getServerSnapshot,
  );
}

function getServerSnapshot(): HistoryEntry[] {
  return getHistorySnapshot();
}
