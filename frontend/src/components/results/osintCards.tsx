"use client";

/**
 * OsintCards — three beautiful cards displaying OSINT intelligence data.
 *
 * 1. Domain Info Card  — domain name, age, registrar, privacy status
 * 2. DNS Status Card   — has valid DNS (✅ / ❌) with visual indicator
 * 3. Reputation Card   — reputation score as progress bar, blacklist status
 *
 * Handles `null` OSINT data gracefully with a "Not available" fallback.
 */

import {
  Globe,
  CalendarDays,
  Building2,
  Lock,
  Unlock,
  Network,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  HelpCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Progress,
  ProgressIndicator,
  ProgressTrack,
} from "@/components/ui/progress";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import type { OsintSummary } from "@/types";

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/** Format domain age into human-readable text. */
function formatDomainAge(days: number): string {
  if (days < 1) return "Less than a day";
  if (days === 1) return "1 day";
  if (days < 30) return `${days} days`;
  if (days < 365) {
    const months = Math.floor(days / 30);
    return months === 1 ? "1 month" : `${months} months`;
  }
  const years = Math.floor(days / 365);
  const remainingMonths = Math.floor((days % 365) / 30);
  if (remainingMonths === 0) {
    return years === 1 ? "1 year" : `${years} years`;
  }
  return `${years}y ${remainingMonths}m`;
}

/** Classify domain age into risk-awareness tiers. */
function domainAgeRisk(days: number | null): {
  label: string;
  colorClass: string;
} {
  if (days === null) return { label: "Unknown", colorClass: "text-muted-foreground" };
  if (days < 30) return { label: "Very New", colorClass: "text-red-600 dark:text-red-400" };
  if (days < 180) return { label: "New", colorClass: "text-amber-600 dark:text-amber-400" };
  return { label: "Established", colorClass: "text-green-600 dark:text-green-400" };
}

/** Map a reputation score (0–1) to a colour class for the progress bar. */
function reputationColor(score: number): string {
  if (score >= 0.7) return "bg-green-500";
  if (score >= 0.4) return "bg-amber-500";
  return "bg-red-500";
}

/** Map a reputation score (0–1) to a label. */
function reputationLabel(score: number): string {
  if (score >= 0.7) return "Good";
  if (score >= 0.4) return "Fair";
  return "Poor";
}

/* ------------------------------------------------------------------ */
/*  Tooltip info helper                                               */
/* ------------------------------------------------------------------ */

interface InfoTooltipProps {
  text: string;
}

function InfoTooltip({ text }: InfoTooltipProps) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <button
            type="button"
            className="ml-1 inline-flex cursor-help text-muted-foreground hover:text-foreground"
            aria-label={text}
          />
        }
      >
        <HelpCircle className="h-3.5 w-3.5" />
      </TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  );
}

/* ------------------------------------------------------------------ */
/*  Null state                                                        */
/* ------------------------------------------------------------------ */

function OsintUnavailable() {
  return (
    <Card>
      <CardHeader className="items-center text-center">
        <div className="rounded-full border bg-muted p-4">
          <Globe className="h-8 w-8 text-muted-foreground" />
        </div>
        <CardTitle className="text-base">OSINT Data Not Available</CardTitle>
        <CardDescription>
          No OSINT enrichment data was collected for this analysis. This can
          happen when the input does not contain a recognisable domain.
        </CardDescription>
      </CardHeader>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  Domain Info Card                                                  */
/* ------------------------------------------------------------------ */

interface DomainInfoCardProps {
  osint: OsintSummary;
}

function DomainInfoCard({ osint }: DomainInfoCardProps) {
  const ageRisk = domainAgeRisk(osint.domainAgeDays);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Globe className="h-4 w-4 text-blue-500" aria-hidden="true" />
          Domain Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Domain name */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Domain</span>
          <span className="max-w-[200px] truncate font-mono text-sm font-medium">
            {osint.domain}
          </span>
        </div>

        {/* Domain age */}
        <div className="flex items-center justify-between">
          <span className="flex items-center text-sm text-muted-foreground">
            <CalendarDays className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            Domain Age
            <InfoTooltip text="Newly registered domains are more likely to be used for phishing." />
          </span>
          <div className="flex items-center gap-2">
            {osint.domainAgeDays !== null ? (
              <>
                <span className="text-sm font-medium">
                  {formatDomainAge(osint.domainAgeDays)}
                </span>
                <Badge
                  variant="outline"
                  className={cn("text-xs", ageRisk.colorClass)}
                >
                  {ageRisk.label}
                </Badge>
              </>
            ) : (
              <span className="text-sm text-muted-foreground">Unknown</span>
            )}
          </div>
        </div>

        {/* Registrar */}
        <div className="flex items-center justify-between">
          <span className="flex items-center text-sm text-muted-foreground">
            <Building2 className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            Registrar
          </span>
          <span className="max-w-[200px] truncate text-sm font-medium">
            {osint.registrar ?? "Unknown"}
          </span>
        </div>

        {/* Privacy protection */}
        <div className="flex items-center justify-between">
          <span className="flex items-center text-sm text-muted-foreground">
            {osint.isPrivate ? (
              <Lock className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <Unlock className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            )}
            Privacy
            <InfoTooltip text="Privacy-protected WHOIS records can hide the true registrant." />
          </span>
          <Badge variant={osint.isPrivate ? "secondary" : "outline"}>
            {osint.isPrivate ? "Protected" : "Public"}
          </Badge>
        </div>
      </CardContent>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  DNS Status Card                                                   */
/* ------------------------------------------------------------------ */

interface DnsStatusCardProps {
  osint: OsintSummary;
}

function DnsStatusCard({ osint }: DnsStatusCardProps) {
  const valid = osint.hasValidDns;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4 text-indigo-500" aria-hidden="true" />
          DNS Status
          <InfoTooltip text="DNS records indicate whether the domain resolves to a valid server." />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center gap-3 py-2">
          <div
            className={cn(
              "rounded-full p-3",
              valid
                ? "bg-green-100 dark:bg-green-900/30"
                : "bg-red-100 dark:bg-red-900/30",
            )}
          >
            {valid ? (
              <CheckCircle2
                className="h-10 w-10 text-green-600 dark:text-green-400"
                aria-hidden="true"
              />
            ) : (
              <XCircle
                className="h-10 w-10 text-red-600 dark:text-red-400"
                aria-hidden="true"
              />
            )}
          </div>
          <span
            className={cn(
              "text-lg font-semibold",
              valid
                ? "text-green-600 dark:text-green-400"
                : "text-red-600 dark:text-red-400",
            )}
          >
            {valid ? "Valid DNS" : "No DNS Records"}
          </span>
          <p className="text-center text-sm text-muted-foreground">
            {valid
              ? "The domain has valid DNS records and resolves to a server."
              : "The domain has no valid DNS records, which is suspicious."}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  Reputation Card                                                   */
/* ------------------------------------------------------------------ */

interface ReputationCardProps {
  osint: OsintSummary;
}

function ReputationCard({ osint }: ReputationCardProps) {
  const scorePercent = Math.round(osint.reputationScore * 100);
  const label = reputationLabel(osint.reputationScore);
  const barColor = reputationColor(osint.reputationScore);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-4 w-4 text-teal-500" aria-hidden="true" />
          Reputation
          <InfoTooltip text="Aggregated reputation from OSINT sources (WHOIS age, DNS, blacklists)." />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Score bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Score</span>
            <span className="text-sm font-semibold tabular-nums">
              {scorePercent}%{" "}
              <span
                className={cn(
                  "text-xs font-medium",
                  osint.reputationScore >= 0.7
                    ? "text-green-600 dark:text-green-400"
                    : osint.reputationScore >= 0.4
                      ? "text-amber-600 dark:text-amber-400"
                      : "text-red-600 dark:text-red-400",
                )}
              >
                ({label})
              </span>
            </span>
          </div>
          <Progress value={scorePercent}>
            <ProgressTrack>
              <ProgressIndicator className={barColor} />
            </ProgressTrack>
          </Progress>
        </div>

        {/* Blacklist status */}
        <div className="flex items-center justify-between">
          <span className="flex items-center text-sm text-muted-foreground">
            <AlertTriangle className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            Blacklist Status
            <InfoTooltip text="Checks whether the domain appears on known phishing/malware blacklists." />
          </span>
          {osint.inBlacklists ? (
            <Badge
              variant="destructive"
              className="flex items-center gap-1"
            >
              <ShieldX className="h-3 w-3" aria-hidden="true" />
              Blacklisted
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="flex items-center gap-1 text-green-600 dark:text-green-400"
            >
              <ShieldCheck className="h-3 w-3" aria-hidden="true" />
              Clean
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/*  Combined export                                                   */
/* ------------------------------------------------------------------ */

interface OsintCardsProps {
  osint: OsintSummary | null;
}

export function OsintCards({ osint }: OsintCardsProps) {
  if (!osint) return <OsintUnavailable />;

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <DomainInfoCard osint={osint} />
      <DnsStatusCard osint={osint} />
      <ReputationCard osint={osint} />
    </div>
  );
}
