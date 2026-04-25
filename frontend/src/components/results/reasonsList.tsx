"use client";

/**
 * ReasonsList — displays each analysis reason with a relevant icon.
 *
 * Maps keyword patterns to icons for visual classification.
 */

import {
  Zap,
  Theater,
  KeyRound,
  Link2,
  Globe,
  AlertTriangle,
  ShieldCheck,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/*  Reason → icon mapping                                             */
/* ------------------------------------------------------------------ */

interface ReasonIconMeta {
  icon: LucideIcon;
  colorClass: string;
}

const reasonPatterns: { pattern: RegExp; meta: ReasonIconMeta }[] = [
  {
    pattern: /urgent|urgency|immediate|act now|hurry/i,
    meta: { icon: Zap, colorClass: "text-amber-500 dark:text-amber-400" },
  },
  {
    pattern: /brand|impersonat|spoof/i,
    meta: { icon: Theater, colorClass: "text-purple-500 dark:text-purple-400" },
  },
  {
    pattern: /credential|password|login|account|verif/i,
    meta: { icon: KeyRound, colorClass: "text-red-500 dark:text-red-400" },
  },
  {
    pattern: /url|link|domain|redirect|suspicious.*tld/i,
    meta: { icon: Link2, colorClass: "text-amber-600 dark:text-amber-400" },
  },
  {
    pattern: /osint|whois|dns|reputation|blacklist|age/i,
    meta: { icon: Globe, colorClass: "text-blue-500 dark:text-blue-400" },
  },
];

function resolveReasonMeta(reason: string): ReasonIconMeta {
  for (const { pattern, meta } of reasonPatterns) {
    if (pattern.test(reason)) return meta;
  }
  return { icon: AlertTriangle, colorClass: "text-muted-foreground" };
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

interface ReasonsListProps {
  reasons: string[];
}

export function ReasonsList({ reasons }: ReasonsListProps) {
  if (reasons.length === 0) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
          <ShieldCheck className="h-4 w-4 text-green-600 dark:text-green-400" aria-hidden="true" />
          No risk indicators found.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Risk Indicators ({reasons.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-2">
        {reasons.map((reason) => {
          const { icon: Icon, colorClass } = resolveReasonMeta(reason);
          return (
            <div
              key={reason}
              className="flex items-start gap-3 rounded-lg border px-3 py-2.5"
            >
              <Icon
                className={cn("mt-0.5 h-4 w-4 shrink-0", colorClass)}
                aria-hidden="true"
              />
              <span className="text-sm">{reason}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
