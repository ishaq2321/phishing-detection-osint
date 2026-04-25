"use client";

/**
 * ResultsContext — shared state for passing analysis results between
 * the Analyse page and the Results page without needing a backend
 * history ID.
 *
 * The Analyse page calls `setResult()` after a successful API call,
 * then navigates to `/results`.  The Results page consumes the data
 * via `useResult()`.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { AnalysisResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Stored result shape                                               */
/* ------------------------------------------------------------------ */

export interface StoredResult {
  /** The analysis response from the backend. */
  response: AnalysisResponse;
  /** The original content the user submitted. */
  content: string;
  /** The content type that was used (url / email / text / auto). */
  contentType: string;
  /** Optional history entry ID for durable deep links. */
  historyId?: string;
}

/* ------------------------------------------------------------------ */
/*  Context                                                           */
/* ------------------------------------------------------------------ */

interface ResultsContextValue {
  result: StoredResult | null;
  setResult: (result: StoredResult) => void;
  clearResult: () => void;
}

const ResultsContext = createContext<ResultsContextValue | null>(null);

/* ------------------------------------------------------------------ */
/*  Provider                                                          */
/* ------------------------------------------------------------------ */

export function ResultsProvider({ children }: { children: ReactNode }) {
  const [result, setResultState] = useState<StoredResult | null>(null);

  const setResult = useCallback((r: StoredResult) => {
    setResultState(r);
  }, []);

  const clearResult = useCallback(() => {
    setResultState(null);
  }, []);

  const value = useMemo(
    () => ({ result, setResult, clearResult }),
    [result, setResult, clearResult],
  );

  return (
    <ResultsContext.Provider value={value}>
      {children}
    </ResultsContext.Provider>
  );
}

/* ------------------------------------------------------------------ */
/*  Hook                                                              */
/* ------------------------------------------------------------------ */

export function useResult(): ResultsContextValue {
  const ctx = useContext(ResultsContext);
  if (!ctx) {
    throw new Error("useResult must be used within a <ResultsProvider>");
  }
  return ctx;
}
