"use client";

/**
 * ConfidenceBar — horizontal progress bar showing the model-assessed
 * phishing risk score.
 *
 * The bar always reads left→right as "no risk → certain risk", and the
 * caption is phrased so a low number can never be misread as "low safety".
 * Colour-coded by threat level and animated on mount.
 */

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Progress,
  ProgressIndicator,
  ProgressTrack,
} from "@/components/ui/progress";
import { useCountUp } from "@/hooks/useCountUp";
import { THREAT_LEVEL_MAP } from "@/lib/constants";
import { cn } from "@/lib/utils";
import type { ThreatLevel } from "@/types";

/* ------------------------------------------------------------------ */
/*  Colour helpers                                                    */
/* ------------------------------------------------------------------ */

/** Map threat level to a Tailwind bg class for the progress indicator. */
const INDICATOR_BG: Record<ThreatLevel, string> = {
  safe: "bg-green-500",
  suspicious: "bg-amber-500",
  dangerous: "bg-orange-500",
  critical: "bg-red-500",
};

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

interface ConfidenceBarProps {
  /** Confidence score 0–1. */
  confidenceScore: number;
  /** Current threat level — drives the bar colour. */
  threatLevel: ThreatLevel;
}

export function ConfidenceBar({
  confidenceScore,
  threatLevel,
}: ConfidenceBarProps) {
  const percent = useCountUp(confidenceScore * 100, 1000);
  const meta = THREAT_LEVEL_MAP[threatLevel];

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Risk Score</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Bar */}
        <Progress
          value={Math.round(percent)}
          aria-label={`Phishing risk: ${Math.round(confidenceScore * 100)} percent`}
        >
          <ProgressTrack className="h-3 rounded-full">
            <ProgressIndicator
              className={cn(
                "rounded-full transition-all duration-500",
                INDICATOR_BG[threatLevel],
              )}
            />
          </ProgressTrack>
        </Progress>

        {/* Risk caption — phrased so direction is unambiguous.
            (No threat-level chip here: the banner badge and the gauge
            label already carry it; repeating it three times per page
            is noise.) */}
        <p className="text-sm text-muted-foreground">
          {threatLevel === "safe" ? (
            <>
              Estimated phishing risk:{" "}
              <span className={cn("font-semibold", meta.colorClass)}>
                {Math.round(percent)}%
              </span>{" "}
              — no significant threat indicators were found.
            </>
          ) : (
            <>
              Estimated phishing risk:{" "}
              <span className={cn("font-semibold", meta.colorClass)}>
                {Math.round(percent)}%
              </span>{" "}
              — treat this content with caution.
            </>
          )}
        </p>

        {/* Gradient scale — ends labelled by meaning, not just number */}
        <div className="space-y-1">
          <div className="flex h-2 w-full overflow-hidden rounded-full">
            <div className="flex-[40] bg-green-500" />
            <div className="flex-[20] bg-amber-500" />
            <div className="flex-[20] bg-orange-500" />
            <div className="flex-[20] bg-red-500" />
          </div>
          <div className="flex justify-between text-[10px] text-muted-foreground">
            <span>0% · no risk</span>
            <span>50%</span>
            <span>100% · certain risk</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
