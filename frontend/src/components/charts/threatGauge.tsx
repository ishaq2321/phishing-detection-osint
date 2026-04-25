"use client";

/**
 * ThreatGauge — semi-circular gauge meter visualising the phishing
 * risk score.
 *
 * Colour zones:
 *   • Green  (0 – 0.4)  — Safe
 *   • Yellow (0.4 – 0.6) — Suspicious
 *   • Orange (0.6 – 0.8) — Dangerous
 *   • Red    (0.8 – 1.0) — Critical
 *
 * The needle animates from 0 to the final score on mount.
 * Pure SVG — no external chart library needed.
 */

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useCountUp } from "@/hooks/useCountUp";
import { useTheme } from "next-themes";
import { THREAT_LEVEL_MAP } from "@/lib/constants";
import { cn } from "@/lib/utils";
import type { ThreatLevel } from "@/types";

/* ------------------------------------------------------------------ */
/*  Gauge geometry                                                    */
/* ------------------------------------------------------------------ */

const CX = 120;
const CY = 110;
const RADIUS = 90;
const STROKE_WIDTH = 18;
const VIEW_BOX = "0 0 240 140";

/** Convert a value (0–1) to an angle on the semicircle (-180° to 0°). */
function valueToAngle(value: number): number {
  return -180 + value * 180;
}

/** Polar → Cartesian. */
function polarToXy(angleDeg: number, r: number): { x: number; y: number } {
  const rad = (angleDeg * Math.PI) / 180;
  return { x: CX + r * Math.cos(rad), y: CY + r * Math.sin(rad) };
}

/** Build an SVG arc path for a segment from startVal to endVal (0–1). */
function arcPath(startVal: number, endVal: number, r: number): string {
  const a1 = valueToAngle(startVal);
  const a2 = valueToAngle(endVal);
  const start = polarToXy(a1, r);
  const end = polarToXy(a2, r);
  const largeArc = Math.abs(a2 - a1) > 180 ? 1 : 0;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`;
}

/* ------------------------------------------------------------------ */
/*  Zones — light & dark palettes                                     */
/* ------------------------------------------------------------------ */

const ZONES_LIGHT: { start: number; end: number; color: string }[] = [
  { start: 0,   end: 0.4, color: "#22c55e" }, // green-500
  { start: 0.4, end: 0.6, color: "#eab308" }, // yellow-500
  { start: 0.6, end: 0.8, color: "#f97316" }, // orange-500
  { start: 0.8, end: 1.0, color: "#ef4444" }, // red-500
];

const ZONES_DARK: { start: number; end: number; color: string }[] = [
  { start: 0,   end: 0.4, color: "#4ade80" }, // green-400
  { start: 0.4, end: 0.6, color: "#facc15" }, // yellow-400
  { start: 0.6, end: 0.8, color: "#fb923c" }, // orange-400
  { start: 0.8, end: 1.0, color: "#f87171" }, // red-400
];

/* ------------------------------------------------------------------ */
/*  Threat-level label helper                                         */
/* ------------------------------------------------------------------ */

function threatLevelFromScore(score: number): ThreatLevel {
  if (score < 0.4) return "safe";
  if (score < 0.6) return "suspicious";
  if (score < 0.8) return "dangerous";
  return "critical";
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

interface ThreatGaugeProps {
  /** Risk score 0–1. */
  score: number;
}

export function ThreatGauge({ score }: ThreatGaugeProps) {
  const animatedScore = useCountUp(score, 1200);
  const { resolvedTheme } = useTheme();
  const zones = resolvedTheme === "dark" ? ZONES_DARK : ZONES_LIGHT;
  const needleAngle = valueToAngle(animatedScore);
  const needleTip = polarToXy(needleAngle, RADIUS - STROKE_WIDTH / 2 - 4);

  const level = threatLevelFromScore(score);
  const meta = THREAT_LEVEL_MAP[level];
  const LevelIcon = meta.icon;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Threat Gauge</CardTitle>
      </CardHeader>
      <CardContent>
        <div
          role="img"
          aria-label={`Threat gauge showing a risk score of ${Math.round(score * 100)} percent — classified as ${meta.label}.`}
          className="flex flex-col items-center"
        >
          <svg
            viewBox={VIEW_BOX}
            className="w-full max-w-[260px]"
            aria-hidden="true"
          >
            {/* Background track */}
            <path
              d={arcPath(0, 1, RADIUS)}
              fill="none"
              stroke="currentColor"
              strokeWidth={STROKE_WIDTH}
              className="text-muted/30"
              strokeLinecap="round"
            />

            {/* Colour zones */}
            {zones.map((zone) => (
              <path
                key={zone.start}
                d={arcPath(zone.start, zone.end, RADIUS)}
                fill="none"
                stroke={zone.color}
                strokeWidth={STROKE_WIDTH}
                strokeLinecap="butt"
                opacity={0.85}
              />
            ))}

            {/* Needle */}
            <line
              x1={CX}
              y1={CY}
              x2={needleTip.x}
              y2={needleTip.y}
              stroke="currentColor"
              strokeWidth={2.5}
              strokeLinecap="round"
              className="text-foreground"
            />

            {/* Centre dot */}
            <circle
              cx={CX}
              cy={CY}
              r={5}
              className="fill-foreground"
            />

            {/* Min / Max labels */}
            <text
              x={CX - RADIUS - 4}
              y={CY + 16}
              className="fill-muted-foreground text-[10px]"
              textAnchor="start"
            >
              0
            </text>
            <text
              x={CX + RADIUS + 4}
              y={CY + 16}
              className="fill-muted-foreground text-[10px]"
              textAnchor="end"
            >
              100
            </text>
          </svg>

          {/* Score + level label */}
          <div className="mt-1 flex flex-col items-center gap-0.5">
            <span
              className={cn(
                "text-2xl font-bold tabular-nums",
                meta.colorClass,
              )}
            >
              {Math.round(animatedScore * 100)}%
            </span>
            <span
              className={cn(
                "text-sm font-medium",
                meta.colorClass,
              )}
            >
              <LevelIcon className="h-4 w-4" aria-hidden="true" /> {meta.label}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
