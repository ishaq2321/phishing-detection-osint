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
import { checkHealth, friendlyErrorMessage } from "@/lib/api";
import type { HealthResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Hook state                                                        */
/* ------------------------------------------------------------------ */

interface HealthState {
  data: HealthResponse | null;
  isLoading: boolean;
  error: string | null;
}

/** Default polling interval: 30 seconds. */
const DEFAULT_INTERVAL_MS = 30_000;

/* ------------------------------------------------------------------ */
/*  Hook                                                              */
/* ------------------------------------------------------------------ */

export function useHealth(intervalMs: number = DEFAULT_INTERVAL_MS) {
  const [state, setState] = useState<HealthState>({
    data: null,
    isLoading: true,
    error: null,
  });

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refetch = useCallback(async () => {
    setState((prev) => ({ ...prev, isLoading: true, error: null }));

    try {
      const data = await checkHealth();
      setState({ data, isLoading: false, error: null });
    } catch (err: unknown) {
      const message = friendlyErrorMessage(err);
      setState((prev) => ({ ...prev, isLoading: false, error: message }));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    /** Fetch health once. */
    async function fetchHealth() {
      try {
        const result = await checkHealth();
        if (!cancelled) setState({ data: result, isLoading: false, error: null });
      } catch (err: unknown) {
        if (!cancelled) {
          const message = friendlyErrorMessage(err);
          setState((prev) => ({ ...prev, isLoading: false, error: message }));
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
