"use client";

/**
 * VerdictBanner — large, color-coded banner showing the analysis verdict.
 *
 * Displays isPhishing (YES/NO), threat-level badge, animated confidence
 * score, and recommendation text.
 */

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useCountUp } from "@/hooks/useCountUp";
import { THREAT_LEVEL_MAP } from "@/lib/constants";
import { cn } from "@/lib/utils";
import type { VerdictResult } from "@/types";

const GLOW_CLASS: Record<string, string> = {
  safe: "",
  suspicious: "",
  dangerous: "shadow-[0_0_24px_4px_rgba(239,68,68,0.15)] dark:shadow-[0_0_24px_4px_rgba(239,68,68,0.25)]",
  critical: "shadow-[0_0_32px_8px_rgba(139,92,246,0.2)] dark:shadow-[0_0_32px_8px_rgba(139,92,246,0.35)]",
};

/* ------------------------------------------------------------------ */
/* Component */
/* ------------------------------------------------------------------ */

interface VerdictBannerProps {
  verdict: VerdictResult;
}

export function VerdictBanner({ verdict }: VerdictBannerProps) {
  const meta = THREAT_LEVEL_MAP[verdict.threatLevel];
  const Icon = meta.icon;
  const animatedScore = useCountUp(verdict.confidenceScore * 100, 1200);

  return (
    <Card
      className={cn(
        "overflow-hidden border-2 transition-shadow",
        meta.borderClass,
        meta.bgClass,
        GLOW_CLASS[verdict.threatLevel],
      )}
    >
      <CardContent className="flex flex-col items-center gap-4 py-8 sm:flex-row sm:gap-8 sm:py-10">
        {/* Icon + phishing status */}
        <div className="flex flex-col items-center gap-2">
          <div
            className={cn(
              "rounded-full p-4",
              verdict.isPhishing
                ? "bg-red-100 dark:bg-red-900/50"
                : "bg-green-100 dark:bg-green-900/50",
            )}
          >
            <Icon
              className={cn(
                "h-12 w-12 sm:h-16 sm:w-16",
                meta.colorClass,
              )}
              aria-hidden="true"
            />
          </div>
          <span
            className={cn(
              "text-sm font-bold uppercase tracking-widest",
              verdict.isPhishing
                ? "text-red-600 dark:text-red-400"
                : "text-green-600 dark:text-green-400",
            )}
            aria-label={verdict.isPhishing ? "Phishing detected" : "Not phishing"}
          >
            {verdict.isPhishing ? "Phishing" : "Safe"}
          </span>
        </div>

        {/* Score + details */}
        <div className="flex flex-1 flex-col items-center gap-3 text-center sm:items-start sm:text-left">
          {/* Animated confidence score */}
          <div className="flex items-baseline gap-2">
            <span
              className={cn("text-5xl font-extrabold tabular-nums", meta.colorClass)}
              aria-label={`Confidence score: ${Math.round(verdict.confidenceScore * 100)} percent`}
            >
              {Math.round(animatedScore)}
            </span>
            <span className={cn("text-2xl font-bold", meta.colorClass)}>%</span>
          </div>

          {/* Threat level badge */}
          <Badge
            variant="outline"
            className={cn(
              "text-sm font-medium",
              meta.colorClass,
              meta.borderClass,
            )}
          >
            <Icon className="h-3.5 w-3.5" aria-hidden="true" /> {meta.label}
          </Badge>

          {/* Recommendation */}
          <p className="max-w-md text-sm text-muted-foreground">
            {verdict.recommendation}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
