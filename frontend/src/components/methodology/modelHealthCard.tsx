"use client";

/**
 * ModelHealthCard — live drift status from GET /api/model/drift.
 *
 * Surfaces the backend's PSI-based drift monitor in the UI: overall
 * model health plus the most-shifted features. Handles the cold-start
 * phase gracefully (the monitor needs ~200 logged analyses before it
 * can measure anything).
 */

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, Activity, Snowflake, AlertTriangle } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { getModelDrift } from "@/lib/api/endpoints";
import type { DriftReport } from "@/types";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, string> = {
  stable: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  moderate: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  significant: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
};

export function ModelHealthCard() {
  const [report, setReport] = useState<DriftReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await getModelDrift());
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Could not reach the drift endpoint.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Activity className="h-4 w-4 text-primary" aria-hidden="true" />
          Model Health — Live Drift Monitor
        </CardTitle>
        <CardDescription>
          Population Stability Index between live traffic and the reference
          window. Bands: stable &lt; 0.1 ≤ moderate &lt; 0.25 ≤ significant.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {loading && !report && (
          <p className="text-sm text-muted-foreground">Loading drift report…</p>
        )}

        {error && (
          <div className="flex items-center gap-2 text-sm text-destructive" role="alert">
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            {error}
          </div>
        )}

        {report && report.status === "cold_start" && (
          <div className="flex items-start gap-3 rounded-lg border px-3 py-3">
            <Snowflake className="mt-0.5 h-4 w-4 shrink-0 text-sky-500" aria-hidden="true" />
            <div className="text-sm">
              <p className="font-medium">Collecting reference data</p>
              <p className="text-muted-foreground">
                {report.sampleCount} of ~200 analyses logged so far. The monitor
                starts measuring drift once its baseline window is complete.
              </p>
            </div>
          </div>
        )}

        {report && report.status === "ok" && (
          <>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-muted-foreground">Overall:</span>
              <span
                className={cn(
                  "rounded-full px-2 py-0.5 text-xs font-medium capitalize",
                  STATUS_STYLES[report.overall] ?? "",
                )}
              >
                {report.overall}
              </span>
              <span className="text-xs text-muted-foreground">
                · {report.sampleCount} samples ·{" "}
                {report.baselineAt
                  ? `baseline ${new Date(report.baselineAt).toLocaleDateString()}`
                  : "no baseline"}
              </span>
            </div>

            <ul className="grid gap-1.5">
              {report.features.slice(0, 5).map((f) => (
                <li
                  key={f.name}
                  className="flex items-center justify-between rounded-lg border px-3 py-1.5 text-sm"
                >
                  <code className="text-xs text-muted-foreground">{f.name}</code>
                  <span className="flex items-center gap-2">
                    <span className="tabular-nums">{f.psi.toFixed(3)}</span>
                    <span
                      className={cn(
                        "rounded-full px-2 py-0.5 text-xs font-medium",
                        STATUS_STYLES[f.status] ?? "",
                      )}
                    >
                      {f.status}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}

        <Button
          variant="outline"
          size="sm"
          onClick={() => void refresh()}
          disabled={loading}
        >
          <RefreshCw className={cn("mr-1.5 h-3.5 w-3.5", loading && "animate-spin")} aria-hidden="true" />
          Refresh
        </Button>
      </CardContent>
    </Card>
  );
}
