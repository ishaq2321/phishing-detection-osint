"use client";

import { useState } from "react";
import {
  Shield,
  Search,
  Globe,
  ArrowRight,
  Zap,
  Brain,
  Layers,
  BarChart3,
  Clock,
  Github,
  ExternalLink,
} from "lucide-react";
import { Logo } from "@/components/brand";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/linkButton";
import { PageTransition } from "@/components/ui/pageTransition";
import { StaggerGroup, StaggerItem, FadeIn } from "@/components/ui/animations";
import { APP_NAME, APP_TAGLINE, MODEL_METRICS, THREAT_LEVEL_MAP } from "@/lib/constants";
import { getHistory } from "@/lib/storage/historyStore";
import type { HistoryEntry } from "@/types";
import { cn } from "@/lib/utils";

const highlights = [
  {
    icon: Search,
    title: "URL Analysis",
    description:
      "Deep inspection of URL structure, domain reputation, and deceptive patterns.",
    accent: "text-blue-600 dark:text-blue-400",
    bgAccent: "bg-blue-50 dark:bg-blue-950/50",
  },
  {
    icon: Globe,
    title: "OSINT Enrichment",
    description:
      "Domain age, WHOIS data, DNS validation, and real-time blacklist checks.",
    accent: "text-green-600 dark:text-green-400",
    bgAccent: "bg-green-50 dark:bg-green-950/50",
  },
  {
    icon: Brain,
    title: "ML Classification",
    description:
      "XGBoost model achieving 96.4% accuracy across 21 engineered features.",
    accent: "text-purple-600 dark:text-purple-400",
    bgAccent: "bg-purple-50 dark:bg-purple-950/50",
  },
] as const;

const metrics = [
  {
    label: "Model Accuracy",
    value: `${(MODEL_METRICS.accuracy * 100).toFixed(1)}%`,
    icon: BarChart3,
    accent: "text-emerald-600 dark:text-emerald-400",
    caption: `${MODEL_METRICS.trainSamples.toLocaleString()} training samples`,
  },
  {
    label: "Features",
    value: String(MODEL_METRICS.featureCount),
    icon: Layers,
    accent: "text-blue-600 dark:text-blue-400",
    caption: "17 URL + 4 OSINT",
  },
  {
    label: "Threat Levels",
    value: "4",
    icon: Shield,
    accent: "text-amber-600 dark:text-amber-400",
    caption: "Safe · Suspicious · Dangerous · Critical",
  },
  {
    label: "Input Modes",
    value: "3",
    icon: Search,
    accent: "text-violet-600 dark:text-violet-400",
    caption: "URL · Email · Free text",
  },
] as const;

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function DashboardPage() {
  const recentEntries = useState<HistoryEntry[]>(() => {
    if (typeof window === "undefined") return [] as HistoryEntry[];
    return getHistory().slice(0, 5);
  })[0];

  return (
    <PageTransition>
      <div className="space-y-8">
        <FadeIn>
          <section className="relative overflow-hidden rounded-xl border bg-gradient-to-br from-primary/5 via-background to-accent/5 p-6 sm:p-8">
            <div className="relative z-10 flex flex-col items-center gap-5 text-center sm:items-start sm:text-left">
              <div className="flex items-center gap-3">
                <div className="rounded-xl border bg-background p-3 shadow-sm">
                  <Logo className="h-8 w-8" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
                    {APP_NAME}
                  </h1>
                  <p className="text-muted-foreground">{APP_TAGLINE}</p>
                </div>
              </div>

              <div className="flex flex-wrap gap-3">
                <LinkButton href="/analyze" size="lg">
                  <Zap className="mr-2 h-4 w-4" aria-hidden="true" />
                  Analyse Now
                </LinkButton>
                <LinkButton href="/how-it-works" variant="outline" size="lg">
                  How It Works
                  <ArrowRight className="ml-2 h-4 w-4" aria-hidden="true" />
                </LinkButton>
              </div>
            </div>
          </section>
        </FadeIn>

        <section>
          <h2 className="mb-4 text-lg font-semibold tracking-tight">Detection Capabilities</h2>
          <StaggerGroup className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {highlights.map(({ icon: Icon, title, description, accent, bgAccent }) => (
              <StaggerItem key={title}>
                <Card className="h-full shadow-sm transition-shadow hover:shadow-md">
                  <CardHeader className="flex flex-row items-center gap-3 space-y-0 pb-2">
                    <div className={cn("rounded-lg p-2.5", bgAccent)}>
                      <Icon className={cn("h-5 w-5", accent)} aria-hidden="true" />
                    </div>
                    <CardTitle className="text-base">{title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{description}</CardDescription>
                  </CardContent>
                </Card>
              </StaggerItem>
            ))}
          </StaggerGroup>
        </section>

        <section>
          <h2 className="mb-4 text-lg font-semibold tracking-tight">Performance at a Glance</h2>
          <StaggerGroup className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {metrics.map(({ label, value, icon: MetricIcon, accent }) => (
              <StaggerItem key={label}>
                <Card className="shadow-sm transition-shadow hover:shadow-md">
                  <CardContent className="flex flex-col items-center gap-2 pt-5 pb-4 text-center">
                    <div className={cn("rounded-lg bg-muted p-2.5", accent)}>
                      <MetricIcon className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <p className="text-2xl font-bold tracking-tight">{value}</p>
                    <p className="text-sm font-medium">{label}</p>
                  </CardContent>
                </Card>
              </StaggerItem>
            ))}
          </StaggerGroup>
        </section>

        {recentEntries.length > 0 && (
          <FadeIn delay={0.2}>
            <section>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold tracking-tight">Recent Analyses</h2>
                <LinkButton href="/history" variant="outline" size="sm">
                  View All
                  <ArrowRight className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
                </LinkButton>
              </div>
              <Card className="shadow-sm">
                <CardContent className="divide-y p-0">
                  {recentEntries.map((entry) => {
                    const meta = THREAT_LEVEL_MAP[entry.threatLevel];
                    const LevelIcon = meta.icon;
                    return (
                      <div key={entry.id} className="flex items-center gap-3 px-4 py-3">
                        <div className={cn("rounded-md p-1.5", meta.bgClass)}>
                          <LevelIcon className={cn("h-4 w-4", meta.colorClass)} aria-hidden="true" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="truncate text-sm font-medium font-mono">
                            {entry.content.length > 50
                              ? `${entry.content.slice(0, 47)}...`
                              : entry.content}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {entry.contentType.toUpperCase()} &middot; {formatRelativeTime(entry.analyzedAt)}
                          </p>
                        </div>
                        <Badge variant="secondary" className={cn("shrink-0", meta.colorClass)}>
                          {meta.label}
                        </Badge>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            </section>
          </FadeIn>
        )}

        {recentEntries.length === 0 && (
          <FadeIn delay={0.2}>
            <Card className="border-dashed shadow-sm">
              <CardContent className="flex flex-col items-center py-8 text-center">
                <Clock className="mb-2 h-8 w-8 text-muted-foreground" aria-hidden="true" />
                <p className="text-sm font-medium">No analyses yet</p>
                <p className="text-xs text-muted-foreground">
                  Submit a URL or email to start detecting phishing threats.
                </p>
              </CardContent>
            </Card>
          </FadeIn>
        )}

        <FadeIn delay={0.3}>
          <Card className="border-dashed shadow-sm">
            <CardContent className="flex items-center justify-between py-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-muted p-2.5">
                  <Github className="h-5 w-5 text-foreground" aria-hidden="true" />
                </div>
                <div>
                  <p className="text-sm font-medium">Open Source on GitHub</p>
                  <p className="text-xs text-muted-foreground">
                    Explore the code, report issues, and discover more projects.
                  </p>
                </div>
              </div>
              <a
                href="https://github.com/ishaq2321"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 rounded-lg border bg-background px-3 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
              >
                <Github className="h-4 w-4" aria-hidden="true" />
                ishaq2321
                <ExternalLink className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
              </a>
            </CardContent>
          </Card>
        </FadeIn>
      </div>
    </PageTransition>
  );
}