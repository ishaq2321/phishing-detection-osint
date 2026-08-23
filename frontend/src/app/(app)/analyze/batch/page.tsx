"use client";

/**
 * Batch Analysis page — analyse up to 50 URLs at once with parallel
 * processing, per-URL results, and export to CSV / JSON.
 *
 * The primary path is a single `POST /api/analyze/batch` round trip
 * (the backend runs all items concurrently and returns per-item
 * results).  If the batch endpoint is unavailable — e.g. a frontend
 * deployed ahead of the backend — the page transparently falls back
 * to the legacy chunked loop of individual `/api/analyze/url` calls.
 */

import { useCallback, useMemo, useRef, useState } from "react";
import { Layers, StopCircle, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageTransition } from "@/components/ui/pageTransition";
import { FadeIn } from "@/components/ui/animations";
import { BatchInput } from "@/components/analyze/batchInput";
import {
  BatchResults,
  type BatchEntry,
} from "@/components/analyze/batchResults";
import { analyzeBatch, analyzeUrl } from "@/lib/api/endpoints";
import { showError, showInfo, showSuccess } from "@/lib/toast";
import { validateBatch } from "@/lib/validation";
import { addEntry } from "@/lib/storage/historyStore";
import type { AnalysisResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

const MAX_URLS = 50;
const CONCURRENCY = 3;

/* ------------------------------------------------------------------ */
/*  Page                                                              */
/* ------------------------------------------------------------------ */

export default function BatchAnalysisPage() {
  const [rawInput, setRawInput] = useState("");
  const [entries, setEntries] = useState<BatchEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  /* ---- Parse URLs from textarea (validated, deduplicated) --------- */
  const { valid: urls } = useMemo(
    () => validateBatch(rawInput),
    [rawInput],
  );

  const validCount = Math.min(urls.length, MAX_URLS);
  const canSubmit = validCount > 0 && !isRunning;

  /* ---- Legacy fallback: chunked individual analyses --------------- */
  const runChunked = useCallback(
    async (batch: string[], controller: AbortController): Promise<boolean> => {
      // Returns `cancelled` — true when the user aborted mid-run.
      let cancelled = false;

      for (let i = 0; i < batch.length; i += CONCURRENCY) {
        if (controller.signal.aborted) {
          cancelled = true;
          break;
        }

        const chunk = batch.slice(i, i + CONCURRENCY);
        const promises = chunk.map(async (url, j) => {
          const index = i + j;

          setEntries((prev) => {
            const next = [...prev];
            next[index] = { ...next[index], status: "running" };
            return next;
          });

          try {
            const response = await analyzeUrl(
              { url },
              { signal: controller.signal },
            );
            setEntries((prev) => {
              const next = [...prev];
              next[index] = { ...next[index], status: "done", response };
              return next;
            });
          } catch (err) {
            if (controller.signal.aborted) return;
            setEntries((prev) => {
              const next = [...prev];
              next[index] = {
                ...next[index],
                status: "error",
                error: err instanceof Error ? err.message : "Unknown error",
              };
              return next;
            });
          }
        });

        await Promise.allSettled(promises);
      }

      return cancelled;
    },
    [],
  );

  /* ---- Run batch analysis ---------------------------------------- */
  const handleRun = useCallback(async () => {
    const batch = urls.slice(0, MAX_URLS);
    const controller = new AbortController();
    abortRef.current = controller;

    const initial: BatchEntry[] = batch.map((url) => ({
      url,
      status: "pending",
    }));
    setEntries(initial);
    setIsRunning(true);

    let cancelled = false;
    let completedViaBatch = false;
    /** Locally collected successes — `entries` state would be stale here. */
    const completed: { url: string; response: AnalysisResponse }[] = [];

    /* Primary path: one round trip to POST /api/analyze/batch.
       One retry absorbs transient failures (Render cold start returns
       503 while the instance spins up) before degrading to the
       per-URL fallback, which burns 50 separate rate-limited calls. */
    const items = batch.map((url) => ({ type: "url" as const, url }));
    const MAX_BATCH_ATTEMPTS = 2;

    for (let attempt = 1; attempt <= MAX_BATCH_ATTEMPTS && !completedViaBatch; attempt++) {
      try {
        const res = await analyzeBatch({ items }, { signal: controller.signal });

        completedViaBatch = true;

        const next: BatchEntry[] = batch.map((url, index) => {
          const result = res.results.find((r) => r.index === index);
          if (result?.status === "ok" && result.response) {
            completed.push({ url, response: result.response });
            return { url, status: "done", response: result.response };
          }
          return {
            url,
            status: "error",
            error:
              result?.error ?? "Analysis failed — no result returned",
          };
        });
        setEntries(next);
      } catch {
        if (controller.signal.aborted) {
          cancelled = true;
          break;
        }
        if (attempt < MAX_BATCH_ATTEMPTS) {
          showInfo("Batch endpoint hiccup — retrying once…");
        } else {
          /* Fallback: endpoint missing (deploy skew) or unreachable.
             Run the individual analyses instead so the page still works. */
          showInfo(
            "Batch endpoint unavailable — falling back to individual analysis.",
          );
          cancelled = await runChunked(batch, controller);
        }
      }
    }

    setIsRunning(false);
    abortRef.current = null;

    if (cancelled) {
      showError("Batch analysis cancelled.");
    } else if (completedViaBatch) {
      showSuccess(
        `Batch analysis complete — ${batch.length} URL${batch.length !== 1 ? "s" : ""} processed.`,
      );
      // Persist successful results to history so they appear alongside
      // single analyses (consistent with the analyse page behaviour).
      for (const { url, response } of completed) {
        addEntry(url, "url", response);
      }
      if (completed.length > 0) {
        showInfo(
          `${completed.length} result${completed.length !== 1 ? "s" : ""} saved to history.`,
        );
      }
    }
    /* In fallback mode runChunked surfaces no completion toast to
       avoid double-notification; the per-row results speak for
       themselves. */
  }, [urls, runChunked]);

  /* ---- Cancel ---------------------------------------------------- */
  const handleCancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  /* ---- Progress -------------------------------------------------- */
  const completedCount = entries.filter(
    (e) => e.status === "done" || e.status === "error",
  ).length;
  const progressPct =
    entries.length > 0 ? (completedCount / entries.length) * 100 : 0;

  return (
    <PageTransition>
      <div className="space-y-6">
        {/* Header */}
        <FadeIn>
          <div className="flex items-center gap-3">
            <div className="rounded-full border bg-muted p-3">
              <Layers className="h-6 w-6 text-primary" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                Batch Analysis
              </h1>
              <p className="text-muted-foreground">
                Analyse up to {MAX_URLS} URLs at once with parallel processing.
              </p>
            </div>
          </div>
        </FadeIn>

        {/* URL Input */}
        <FadeIn delay={0.05}>
          <BatchInput
            value={rawInput}
            onChange={setRawInput}
            disabled={isRunning}
          />
        </FadeIn>

        {/* Controls */}
        <FadeIn delay={0.1}>
          <div className="flex items-center gap-3">
            {!isRunning ? (
              <Button onClick={handleRun} disabled={!canSubmit} size="lg">
                <Play className="mr-2 h-4 w-4" aria-hidden="true" />
                Analyse {validCount} URL{validCount !== 1 ? "s" : ""}
              </Button>
            ) : (
              <Button
                variant="destructive"
                onClick={handleCancel}
                size="lg"
              >
                <StopCircle className="mr-2 h-4 w-4" aria-hidden="true" />
                Cancel
              </Button>
            )}

            {isRunning && (
              <div className="flex-1 space-y-1">
                {/* Indeterminate while the single batch request is in
                    flight; determinate once rows start completing (the
                    chunked fallback path). */}
                <Progress
                  value={completedCount === 0 ? null : progressPct}
                  className="h-2"
                />
                <p className="text-xs text-muted-foreground">
                  {completedCount > 0
                    ? `${completedCount} / ${entries.length} completed`
                    : `Analysing ${entries.length} URL${entries.length !== 1 ? "s" : ""}…`}
                </p>
              </div>
            )}
          </div>
        </FadeIn>

        {/* Results table */}
        {entries.length > 0 && (
          <FadeIn delay={0.15}>
            <BatchResults entries={entries} />
          </FadeIn>
        )}
      </div>
    </PageTransition>
  );
}
