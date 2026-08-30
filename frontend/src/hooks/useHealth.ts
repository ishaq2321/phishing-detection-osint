"use client";

/**
 * useHealth — React hook for polling the backend health endpoint.
 *
 * Calls `GET /api/health` on mount and then every `intervalMs`
 * milliseconds.  Stops polling when the component unmounts.
 *
 * @example
 * ```tsx
 * const { data, isLoading, error, refetch } = useHealth(15_000);
 * ```
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { checkHealthLive, friendlyErrorMessage } from "@/lib/api";
import type { LiveHealthResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Hook state                                                        */
/* ------------------------------------------------------------------ */

interface HealthState {
  data: LiveHealthResponse | null;
  isLoading: boolean;
  error: string | null;
  isColdStart: boolean;
}

/** Default polling interval: 30 seconds. */
const DEFAULT_INTERVAL_MS = 30_000;

/** Threshold for detecting cold starts (ms). */
const COLD_START_THRESHOLD_MS = 5_000;

/* ------------------------------------------------------------------ */
/*  Hook                                                              */
/* ------------------------------------------------------------------ */

export function useHealth(intervalMs: number = DEFAULT_INTERVAL_MS): { data: LiveHealthResponse | null; isLoading: boolean; error: string | null; isColdStart: boolean; refetch: () => Promise<void> } {
  const [state, setState] = useState<HealthState>({
    data: null,
    isLoading: true,
    error: null,
    isColdStart: false,
  });

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refetch = useCallback(async () => {
    setState((prev) => ({ ...prev, isLoading: true, error: null }));

    try {
      const data = await checkHealthLive();
      setState({ data, isLoading: false, error: null, isColdStart: false });
    } catch (err: unknown) {
      const message = friendlyErrorMessage(err);
      // Detect cold start: if we've been waiting for a while and get a network error
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: message,
        isColdStart: prev.isColdStart || (prev.error === null && message.includes("Cannot connect")),
      }));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    /** Fetch health once. */
    async function fetchHealth() {
      try {
        const result = await checkHealthLive();
        if (!cancelled) setState({ data: result, isLoading: false, error: null, isColdStart: false });
      } catch (err: unknown) {
        if (!cancelled) {
          const message = friendlyErrorMessage(err);
          setState((prev) => ({
            ...prev,
            isLoading: false,
            error: message,
            isColdStart: prev.isColdStart || (prev.error === null && message.includes("Cannot connect")),
          }));
        }
      }
    }

    /* Initial fetch. */
    fetchHealth();

    /* Start polling. */
    intervalRef.current = setInterval(fetchHealth, intervalMs);

    return () => {
      cancelled = true;
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [intervalMs]);

  return { ...state, refetch } as const;
}
