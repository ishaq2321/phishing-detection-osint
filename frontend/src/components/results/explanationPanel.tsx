"use client";

/**
 * ExplanationPanel — deterministic "Why?" panel for URL verdicts.
 *
 * Renders the template-generated explanation report returned by the
 * backend (`explanation` field on AnalysisResponse). Every sentence is
 * derived from a concrete feature value or OSINT signal — no generative
 * model — so the panel is fully auditable.
 */

import { ShieldQuestion, Sparkles } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { ExplanationItem, ExplanationSeverity } from "@/types/analysis";
import { cn } from "@/lib/utils";

const severityStyles: Record<
  ExplanationSeverity,
  { badge: string; dot: string; label: string }
> = {
  critical: {
    badge: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
    dot: "bg-red-500",
    label: "Critical",
  },
  high: {
    badge:
      "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
    dot: "bg-orange-500",
    label: "High",
  },
  medium: {
    badge:
      "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
    dot: "bg-amber-500",
    label: "Medium",
  },
  low: {
    badge: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
    dot: "bg-sky-500",
    label: "Low",
  },
};

function SeverityBadge({ severity }: { severity: ExplanationSeverity }) {
  const style = severityStyles[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
        style.badge,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", style.dot)} aria-hidden="true" />
      {style.label}
    </span>
  );
}

interface ExplanationPanelProps {
  summary: string;
  items: ExplanationItem[];
}

export function ExplanationPanel({ summary, items }: ExplanationPanelProps) {
  if (!summary && items.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldQuestion className="h-4 w-4 text-primary" aria-hidden="true" />
          Why this verdict?
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3">
        <p className="flex items-start gap-2 rounded-lg border bg-muted/40 px-3 py-2.5 text-sm font-medium">
          <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
          {summary}
        </p>
        {items.map((item) => (
          <div
            key={`${item.signal}-${item.detail.slice(0, 24)}`}
            className="flex items-start justify-between gap-3 rounded-lg border px-3 py-2.5"
          >
            <div className="grid gap-1">
              <span className="text-sm">{item.detail}</span>
              <code className="text-xs text-muted-foreground">{item.signal}</code>
            </div>
            <SeverityBadge severity={item.severity} />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
