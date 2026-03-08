"use client";

/**
 * useAnalysis — React hook for running phishing analysis.
 *
 * Provides a single `run` function, loading / error / data state,
 * and an `abort` function so users can cancel long-running requests.
 *
 * @example
 * ```tsx
 * const { run, data, isLoading, error, abort } = useAnalysis();
 * await run({ type: "url", payload: { url } });
 * ```
 */

import { useCallback, useRef, useState } from "react";
import {
  analyzeContent,
  analyzeUrl,
  analyzeEmail,
  friendlyErrorMessage,
} from "@/lib/api";
import type {
  AnalyzeRequest,
  AnalyzeUrlRequest,
  AnalyzeEmailRequest,
  AnalysisResponse,
} from "@/types";

/* ------------------------------------------------------------------ */
/*  Discriminated-union input                                         */
/* ------------------------------------------------------------------ */

type AnalysisInput =
  | { type: "content"; payload: AnalyzeRequest }
  | { type: "url"; payload: AnalyzeUrlRequest }
  | { type: "email"; payload: AnalyzeEmailRequest };

/* ------------------------------------------------------------------ */
/*  Hook state                                                        */
/* ------------------------------------------------------------------ */

interface AnalysisState {
  data: AnalysisResponse | null;
  isLoading: boolean;
  error: string | null;
}

/* ------------------------------------------------------------------ */
/*  Hook                                                              */
/* ------------------------------------------------------------------ */

export function useAnalysis() {
  const [state, setState] = useState<AnalysisState>({
    data: null,
    isLoading: false,
    error: null,
  });

  const controllerRef = useRef<AbortController | null>(null);

  /** Cancel an in-flight request. */
  const abort = useCallback(() => {
    controllerRef.current?.abort("Cancelled by user");
    controllerRef.current = null;
    setState((prev) => ({ ...prev, isLoading: false }));
  }, []);

  /** Dispatch an analysis request. */
  const run = useCallback(async (input: AnalysisInput) => {
    /* Abort any previous request that is still in flight. */
    controllerRef.current?.abort("Superseded by new request");

    const controller = new AbortController();
    controllerRef.current = controller;

    setState({ data: null, isLoading: true, error: null });

    try {
      const options = { signal: controller.signal };
      let result: AnalysisResponse;

      switch (input.type) {
        case "content":
          result = await analyzeContent(input.payload, options);
          break;
        case "url":
          result = await analyzeUrl(input.payload, options);
          break;
        case "email":
          result = await analyzeEmail(input.payload, options);
          break;
      }

      setState({ data: result, isLoading: false, error: null });
      return result;
    } catch (err: unknown) {
      /* Ignore abort errors caused by superseding requests. */
      if (controller.signal.aborted) return null;

      const message = friendlyErrorMessage(err);
      setState({ data: null, isLoading: false, error: message });
      throw err;
    }
  }, []);

  /** Reset the hook to its initial idle state. */
  const reset = useCallback(() => {
    controllerRef.current?.abort("Reset");
    controllerRef.current = null;
    setState({ data: null, isLoading: false, error: null });
  }, []);

  return { ...state, run, abort, reset } as const;
}
