"use client";

/**
 * FeatureCards — displays ML feature extraction results and detected
 * phishing tactics.
 *
 * Sections:
 * 1. Feature Counts Card  — URL / Text / OSINT feature counts with
 *    animated count-up and total risk indicators.
 * 2. Detected Tactics Tags — each tactic rendered as a colour-coded
 *    badge with a tooltip explanation.
 *
 * Handles empty tactics list gracefully with a positive empty state.
 */

import type { LucideIcon } from "lucide-react";
import {
  Link2,
  FileText,
  Globe,
  AlertTriangle,
  ShieldCheck,
  Timer,
  UserX,
  Fingerprint,
  KeyRound,
  Siren,
  Heart,
  Banknote,
  Paperclip,
  MousePointerClick,
  Users,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useCountUp } from "@/hooks/useCountUp";
import { cn } from "@/lib/utils";
import type { FeatureSummary } from "@/types";

/* ------------------------------------------------------------------ */
/*  Tactic metadata map                                               */
/* ------------------------------------------------------------------ */

interface TacticMeta {
  label: string;
  description: string;
  icon: LucideIcon;
  colorClass: string;
  bgClass: string;
}

/**
 * Static map of every `PhishingTactic` enum value to its display
 * metadata.  Values match `backend/analyzer/base.py:PhishingTactic`.
 */
const TACTIC_META: Record<string, TacticMeta> = {
  urgency: {
    label: "Urgency",
    description: "Creates artificial time pressure to rush the victim into acting.",
    icon: Timer,
    colorClass: "text-orange-700 dark:text-orange-300",
    bgClass: "bg-orange-100 border-orange-300 dark:bg-orange-900/30 dark:border-orange-700",
  },
  authority_impersonation: {
    label: "Authority Impersonation",
    description: "Pretends to be a figure of authority (CEO, IT admin, government).",
    icon: UserX,
    colorClass: "text-purple-700 dark:text-purple-300",
    bgClass: "bg-purple-100 border-purple-300 dark:bg-purple-900/30 dark:border-purple-700",
  },
  brand_impersonation: {
    label: "Brand Impersonation",
    description: "Mimics a trusted brand (e.g. Microsoft, PayPal) to gain trust.",
    icon: Fingerprint,
    colorClass: "text-violet-700 dark:text-violet-300",
    bgClass: "bg-violet-100 border-violet-300 dark:bg-violet-900/30 dark:border-violet-700",
  },
  credential_request: {
    label: "Credential Request",
    description: "Asks for passwords, PINs, or other sensitive credentials.",
    icon: KeyRound,
    colorClass: "text-red-700 dark:text-red-300",
    bgClass: "bg-red-100 border-red-300 dark:bg-red-900/30 dark:border-red-700",
  },
  threat_warning: {
    label: "Threat / Warning",
    description: "Uses fear of account suspension, legal action, or security breach.",
    icon: Siren,
    colorClass: "text-rose-700 dark:text-rose-300",
    bgClass: "bg-rose-100 border-rose-300 dark:bg-rose-900/30 dark:border-rose-700",
  },
  emotional_manipulation: {
    label: "Emotional Manipulation",
    description: "Exploits emotions like sympathy, guilt, or excitement.",
    icon: Heart,
    colorClass: "text-pink-700 dark:text-pink-300",
    bgClass: "bg-pink-100 border-pink-300 dark:bg-pink-900/30 dark:border-pink-700",
  },
  monetary_request: {
    label: "Monetary Request",
    description: "Solicits money transfers, gift cards, or financial information.",
    icon: Banknote,
    colorClass: "text-amber-700 dark:text-amber-300",
    bgClass: "bg-amber-100 border-amber-300 dark:bg-amber-900/30 dark:border-amber-700",
  },
  attachment_malware: {
    label: "Attachment / Malware",
    description: "Encourages opening a suspicious attachment that may contain malware.",
    icon: Paperclip,
    colorClass: "text-slate-700 dark:text-slate-300",
    bgClass: "bg-slate-100 border-slate-300 dark:bg-slate-900/30 dark:border-slate-700",
  },
  link_manipulation: {
    label: "Link Manipulation",
    description: "Uses deceptive URLs, redirects, or homograph attacks.",
    icon: MousePointerClick,
    colorClass: "text-yellow-700 dark:text-yellow-300",
    bgClass: "bg-yellow-100 border-yellow-300 dark:bg-yellow-900/30 dark:border-yellow-700",
  },
  social_proof: {
    label: "Social Proof",
    description: "Claims others have already complied to pressure the victim.",
    icon: Users,
    colorClass: "text-sky-700 dark:text-sky-300",
    bgClass: "bg-sky-100 border-sky-300 dark:bg-sky-900/30 dark:border-sky-700",
  },
};

/** Fallback meta for any unknown tactic string. */
const UNKNOWN_TACTIC: TacticMeta = {
  label: "Unknown Tactic",
  description: "A phishing tactic not yet categorised.",
  icon: AlertTriangle,
  colorClass: "text-muted-foreground",
  bgClass: "bg-muted border-border",
};

/* ------------------------------------------------------------------ */
/*  Animated count chip                                               */
/* ------------------------------------------------------------------ */

interface CountChipProps {
  label: string;
  value: number;
  icon: LucideIcon;
  iconColor: string;
}

function CountChip({ label, value, icon: Icon, iconColor }: CountChipProps) {
  const animatedValue = useCountUp(value, 800);

  return (
    <div className="flex items-center gap-3 rounded-lg border bg-card p-3">
      <div className="rounded-md bg-muted p-2">
        <Icon className={cn("h-5 w-5", iconColor)} aria-hidden="true" />
      </div>
      <div>
        <p className="text-2xl font-bold tabular-nums leading-none">
          {Math.round(animatedValue)}
        </p>
        <p className="mt-0.5 text-xs text-muted-foreground">{label}</p>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Feature Counts Card                                               */
/* ------------------------------------------------------------------ */

interface FeatureCountsCardProps {
  features: FeatureSummary;
}

function FeatureCountsCard({ features }: FeatureCountsCardProps) {
  const hasRisk = features.totalRiskIndicators > 0;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Extracted Features</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2">
          <CountChip
            label="URL Features"
            value={features.urlFeatures}
            icon={Link2}
            iconColor="text-amber-500"
          />
          <CountChip
            label="Text Features"
            value={features.textFeatures}
            icon={FileText}
            iconColor="text-blue-500"
          />
          <CountChip
            label="OSINT Features"
            value={features.osintFeatures}
            icon={Globe}
            iconColor="text-green-500"
          />
          <CountChip
            label="Total Risk Indicators"
            value={features.totalRiskIndicators}
            icon={AlertTriangle}
            iconColor={hasRisk ? "text-red-500" : "text-muted-foreground"}
          />
        </div>
      </CardContent>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  Detected Tactics Card                                             */
/* ------------------------------------------------------------------ */

interface DetectedTacticsCardProps {
  tactics: string[];
}

function DetectedTacticsCard({ tactics }: DetectedTacticsCardProps) {
  if (tactics.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Detected Tactics</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-950">
            <ShieldCheck
              className="h-6 w-6 text-green-600 dark:text-green-400"
              aria-hidden="true"
            />
            <p className="text-sm font-medium text-green-700 dark:text-green-300">
              No suspicious tactics detected ✅
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">
          Detected Tactics
          <Badge variant="destructive" className="ml-2 text-xs">
            {tactics.length}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {tactics.map((tactic) => {
            const meta = TACTIC_META[tactic] ?? UNKNOWN_TACTIC;
            const Icon = meta.icon;

            return (
              <Tooltip key={tactic}>
                <TooltipTrigger
                  render={
                    <button
                      type="button"
                      className={cn(
                        "inline-flex cursor-default items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors hover:opacity-80",
                        meta.bgClass,
                        meta.colorClass,
                      )}
                      aria-label={`${meta.label}: ${meta.description}`}
                    />
                  }
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                  {meta.label}
                </TooltipTrigger>
                <TooltipContent side="bottom">
                  {meta.description}
                </TooltipContent>
              </Tooltip>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  Combined export                                                   */
/* ------------------------------------------------------------------ */

interface FeatureCardsProps {
  features: FeatureSummary;
}

export function FeatureCards({ features }: FeatureCardsProps) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <FeatureCountsCard features={features} />
      <DetectedTacticsCard tactics={features.detectedTactics} />
    </div>
  );
}
