"use client";

/**
 * ScoreBreakdown — donut chart showing how each pipeline component
 * contributed to the final phishing risk score.
 *
 * Segments are the *actual weighted contributions* for this specific
 * analysis (e.g. ML 72 pts + NLP 11 pts = 83% risk), not static
 * architecture weights. When a result predates component reporting,
 * an honest fallback is rendered instead of fabricated data.
 *
 * Uses Recharts `PieChart` for rendering.
 */

import { useMemo } from "react";
import { useTheme } from "next-themes";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
} from "recharts";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useCountUp } from "@/hooks/useCountUp";

/* ------------------------------------------------------------------ */
/*  Component metadata — label + colour, light + dark aware           */
/* ------------------------------------------------------------------ */

const COMPONENTS: Record<
  string,
  { label: string; fillLight: string; fillDark: string }
> = {
  ml: { label: "ML Model", fillLight: "#a855f7", fillDark: "#c084fc" },
  nlp: { label: "NLP Analysis", fillLight: "#3b82f6", fillDark: "#60a5fa" },
  urlFeatures: {
    label: "URL Features",
    fillLight: "#14b8a6",
    fillDark: "#2dd4bf",
  },
  osint: { label: "OSINT", fillLight: "#f59e0b", fillDark: "#fbbf24" },
};

/* ------------------------------------------------------------------ */
/*  Custom tooltip                                                    */
/* ------------------------------------------------------------------ */

interface TooltipPayloadEntry {
  name: string;
  value: number;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const entry = payload[0];

  return (
    <div className="rounded-md border bg-popover px-3 py-2 text-sm shadow-md">
      <p className="font-medium">{entry.name}</p>
      <p className="text-muted-foreground">
        Contribution to risk:{" "}
        <span className="font-semibold">{entry.value} pts</span>
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

interface ScoreBreakdownProps {
  /** The final confidence score (0–1). */
  confidenceScore: number;
  /** Weighted per-component contributions (keys per backend schema). */
  componentScores?: Record<string, number> | null;
}

export function ScoreBreakdown({
  confidenceScore,
  componentScores,
}: ScoreBreakdownProps) {
  const animatedScore = useCountUp(confidenceScore * 100, 1200);
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const data = useMemo(() => {
    if (!componentScores) return [];
    return Object.entries(componentScores)
      .filter(([key, value]) => COMPONENTS[key] && value > 0.0005)
      .map(([key, value]) => ({
        key,
        name: COMPONENTS[key].label,
        value: Math.round(value * 1000) / 10,
        fill: isDark ? COMPONENTS[key].fillDark : COMPONENTS[key].fillLight,
      }));
  }, [componentScores, isDark]);

  const hasComponents = data.length > 0;

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Score Breakdown</CardTitle>
      </CardHeader>
      <CardContent>
        {hasComponents ? (
          <>
            <div
              role="img"
              aria-label={`Score breakdown donut chart. Final phishing risk: ${Math.round(
                confidenceScore * 100,
              )} percent. ${data
                .map((d) => `${d.name}: ${d.value} points`)
                .join(", ")}.`}
              className="relative"
            >
              {/* Centre label overlay */}
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold tabular-nums text-foreground">
                  {Math.round(animatedScore)}%
                </span>
                <span className="text-xs text-muted-foreground">
                  Phishing risk
                </span>
              </div>

              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={data}
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                    startAngle={90}
                    endAngle={-270}
                    stroke="none"
                  >
                    {data.map((d) => (
                      <Cell key={d.key} fill={d.fill} />
                    ))}
                  </Pie>
                  <RechartsTooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Legend */}
            <div className="mt-2 flex flex-wrap justify-center gap-4">
              {data.map((d) => (
                <div key={d.key} className="flex items-center gap-1.5">
                  <span
                    className="inline-block h-3 w-3 rounded-full"
                    style={{ backgroundColor: d.fill }}
                    aria-hidden="true"
                  />
                  <span className="text-xs text-muted-foreground">
                    {d.name}{" "}
                    <span className="font-medium text-foreground">
                      +{d.value}%
                    </span>
                  </span>
                </div>
              ))}
            </div>
          </>
        ) : (
          /* Honest fallback: no component data for this result. */
          <div className="flex h-[220px] flex-col items-center justify-center gap-1 text-center">
            <span className="text-3xl font-bold tabular-nums text-foreground">
              {Math.round(confidenceScore * 100)}%
            </span>
            <span className="text-xs text-muted-foreground">
              Phishing risk
            </span>
            <p className="mt-3 max-w-[220px] text-xs text-muted-foreground">
              Per-component contributions are not available for this result.
              New analyses show exactly how much each signal added to the
              final score.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
