"use client";

/**
 * BatchResults — table of batch URL analysis results with summary
 * stats, export, and per-row status indicators.
 */

import { Download, CheckCircle2, AlertTriangle, XCircle, Flame } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { ThreatLevel, AnalysisResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

export type BatchEntryStatus = "pending" | "running" | "done" | "error";

export interface BatchEntry {
  url: string;
  status: BatchEntryStatus;
  response?: AnalysisResponse;
  error?: string;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

const THREAT_CONFIG: Record<
  ThreatLevel,
  { variant: "default" | "secondary" | "destructive" | "outline"; label: string; icon: typeof CheckCircle2 }
> = {
  safe: { variant: "secondary", label: "Safe", icon: CheckCircle2 },
  suspicious: { variant: "outline", label: "Suspicious", icon: AlertTriangle },
  dangerous: { variant: "destructive", label: "Dangerous", icon: XCircle },
  critical: { variant: "destructive", label: "Critical", icon: Flame },
};

function ThreatBadge({ level }: { level: ThreatLevel }) {
  const cfg = THREAT_CONFIG[level];
  const Icon = cfg.icon;
  return (
    <Badge variant={cfg.variant} className="gap-1">
      <Icon className="h-3 w-3" aria-hidden="true" />
      {cfg.label}
    </Badge>
  );
}

/* ------------------------------------------------------------------ */
/*  Summary stats                                                     */
/* ------------------------------------------------------------------ */

function SummaryStats({ entries }: { entries: BatchEntry[] }) {
  const done = entries.filter((e) => e.status === "done");
  const counts: Record<ThreatLevel, number> = {
    safe: 0,
    suspicious: 0,
    dangerous: 0,
    critical: 0,
  };
  for (const e of done) {
    if (e.response) {
      const level = e.response.verdict.threatLevel as ThreatLevel;
      counts[level]++;
    }
  }
  const errors = entries.filter((e) => e.status === "error").length;

  return (
    <div className="flex flex-wrap gap-3">
      <Badge variant="secondary" className="gap-1">
        <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
        {counts.safe} Safe
      </Badge>
      <Badge variant="outline" className="gap-1">
        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        {counts.suspicious} Suspicious
      </Badge>
      <Badge variant="destructive" className="gap-1">
        <XCircle className="h-3 w-3" aria-hidden="true" />
        {counts.dangerous} Dangerous
      </Badge>
      <Badge variant="destructive" className="gap-1">
        <Flame className="h-3 w-3" aria-hidden="true" />
        {counts.critical} Critical
      </Badge>
      {errors > 0 && (
        <Badge variant="outline" className="gap-1 text-destructive border-destructive">
          {errors} Failed
        </Badge>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Export helpers                                                     */
/* ------------------------------------------------------------------ */

function exportBatchCsv(entries: BatchEntry[]) {
  const header = "URL,Status,Threat Level,Confidence,Is Phishing,Analysis Time (ms)\n";
  const rows = entries
    .filter((e) => e.status === "done" && e.response)
    .map((e) => {
      const r = e.response!;
      return [
        `"${e.url}"`,
        e.status,
        r.verdict.threatLevel,
        r.verdict.confidenceScore.toFixed(3),
        r.verdict.isPhishing,
        r.analysisTime.toFixed(0),
      ].join(",");
    })
    .join("\n");

  const blob = new Blob([header + rows], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard-batch-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportBatchJson(entries: BatchEntry[]) {
  const data = entries
    .filter((e) => e.status === "done" && e.response)
    .map((e) => ({
      url: e.url,
      threatLevel: e.response!.verdict.threatLevel,
      confidenceScore: e.response!.verdict.confidenceScore,
      isPhishing: e.response!.verdict.isPhishing,
      analysisTime: e.response!.analysisTime,
      reasons: e.response!.verdict.reasons,
    }));

  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard-batch-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ------------------------------------------------------------------ */
/*  BatchResults component                                            */
/* ------------------------------------------------------------------ */

interface BatchResultsProps {
  entries: BatchEntry[];
}

export function BatchResults({ entries }: BatchResultsProps) {
  const completedCount = entries.filter(
    (e) => e.status === "done" || e.status === "error",
  ).length;
  const hasResults = completedCount > 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>
              Results ({completedCount} / {entries.length})
            </CardTitle>
            <CardDescription>
              Analysis results for each URL in the batch.
            </CardDescription>
          </div>
          {hasResults && (
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => exportBatchCsv(entries)}
              >
                <Download className="mr-1 h-3 w-3" aria-hidden="true" />
                CSV
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => exportBatchJson(entries)}
              >
                <Download className="mr-1 h-3 w-3" aria-hidden="true" />
                JSON
              </Button>
            </div>
          )}
        </div>
        {hasResults && <SummaryStats entries={entries} />}
      </CardHeader>

      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">#</TableHead>
                <TableHead>URL</TableHead>
                <TableHead className="w-28">Status</TableHead>
                <TableHead className="w-32">Threat</TableHead>
                <TableHead className="w-24 text-right">Score</TableHead>
                <TableHead className="w-24 text-right">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.map((entry, i) => (
                <TableRow key={entry.url + i}>
                  <TableCell className="text-muted-foreground">{i + 1}</TableCell>
                  <TableCell className="font-mono text-xs max-w-[300px] truncate">
                    {entry.url}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={entry.status} />
                  </TableCell>
                  <TableCell>
                    {entry.status === "done" && entry.response ? (
                      <ThreatBadge
                        level={entry.response.verdict.threatLevel as ThreatLevel}
                      />
                    ) : entry.status === "error" ? (
                      <span className="text-xs text-destructive">
                        {entry.error ?? "Failed"}
                      </span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {entry.status === "done" && entry.response
                      ? `${(entry.response.verdict.confidenceScore * 100).toFixed(0)}%`
                      : "—"}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">
                    {entry.status === "done" && entry.response
                      ? `${entry.response.analysisTime.toFixed(2)}s`
                      : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  StatusBadge                                                       */
/* ------------------------------------------------------------------ */

function StatusBadge({ status }: { status: BatchEntryStatus }) {
  switch (status) {
    case "pending":
      return (
        <Badge variant="outline" className="text-muted-foreground">
          Pending
        </Badge>
      );
    case "running":
      return <Badge variant="default">Running…</Badge>;
    case "done":
      return <Badge variant="secondary">Done</Badge>;
    case "error":
      return <Badge variant="destructive">Error</Badge>;
  }
}
