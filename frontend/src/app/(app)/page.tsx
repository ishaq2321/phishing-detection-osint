"use client";

import { useState, useMemo, useEffect } from "react";
import {
  Shield,
  ArrowRight,
  Zap,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Github,
  ExternalLink,
  TrendingUp,
  TrendingDown,
  Minus,
} from "lucide-react";
import { Logo } from "@/components/brand";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/linkButton";
import { PageTransition } from "@/components/ui/pageTransition";
import { FadeIn } from "@/components/ui/animations";
import { APP_NAME, THREAT_LEVEL_MAP } from "@/lib/constants";
import { getHistory } from "@/lib/storage/historyStore";
import type { HistoryEntry } from "@/types";
import { cn } from "@/lib/utils";

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

function formatDateGroup(iso: string): string {
  const date = new Date(iso);
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  if (date.toDateString() === today.toDateString()) return "Today";
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

// Simple sparkline component
function Sparkline({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return <div className="h-8 w-16" />;
  
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  
  const points = data.map((val, i) => {
    const x = (i / (data.length - 1)) * 100;
    const y = 100 - ((val - min) / range) * 100;
    return `${x},${y}`;
  }).join(" ");

  return (
    <svg viewBox="0 0 100 100" className="h-8 w-16" preserveAspectRatio="none">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function DashboardPage() {
  // SSR-safe: start with empty array, load data in useEffect
  const [recentEntries, setRecentEntries] = useState<HistoryEntry[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    setRecentEntries(getHistory().slice(0, 10));
  }, []);

  const stats = useMemo(() => {
    const total = recentEntries.length;
    const safe = recentEntries.filter((e) => e.threatLevel === "safe").length;
    const critical = recentEntries.filter((e) => e.threatLevel === "critical").length;
    const avgScore = total > 0 
      ? recentEntries.reduce((acc, e) => acc + e.score, 0) / total 
      : 0;
    
    return { total, safe, critical, avgScore };
  }, [recentEntries]);

  const trendData = useMemo(() => {
    return recentEntries.slice(0, 7).map((e) => e.score);
  }, [recentEntries]);

  // Group entries by date
  const groupedEntries = useMemo(() => {
    const groups: Record<string, HistoryEntry[]> = {};
    recentEntries.forEach((entry) => {
      const group = formatDateGroup(entry.analyzedAt);
      if (!groups[group]) groups[group] = [];
      groups[group].push(entry);
    });
    return groups;
  }, [recentEntries]);

  return (
    <PageTransition>
      <div className="space-y-10">
        {/* Hero - Compact, Professional */}
        <FadeIn>
          <section className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <div className="rounded-lg border bg-card p-2.5">
                <Logo className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight">{APP_NAME}</h1>
                <p className="text-sm text-muted-foreground">OSINT-Enhanced Phishing Detection</p>
              </div>
            </div>
            <div className="flex gap-2">
              <LinkButton href="/analyze" size="sm">
                <Zap className="mr-1.5 h-4 w-4" />
                Analyze
              </LinkButton>
              <LinkButton href="/how-it-works" variant="outline" size="sm">
                How It Works
                <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
              </LinkButton>
            </div>
          </section>
        </FadeIn>

        {/* Metrics - Real Data with Context */}
        <FadeIn delay={0.05}>
          <section>
            <div className="mb-4">
              <h2 className="text-xl font-semibold tracking-tight">Overview</h2>
              <p className="text-xs text-muted-foreground uppercase tracking-wide mt-1">
                Analysis activity and threat summary
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {/* Total Scans */}
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Total Analyses
                      </p>
                      <p className="mt-1 text-2xl font-bold">{stats.total}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {stats.total > 0 ? "Last 7 days" : "No data yet"}
                      </p>
                    </div>
                    <div className="rounded-md bg-primary/10 p-2">
                      <Activity className="h-4 w-4 text-primary" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Safe Ratio */}
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Safe Ratio
                      </p>
                      <div className="flex items-center gap-2 mt-1">
                        <p className="text-2xl font-bold">
                          {stats.total > 0 ? Math.round((stats.safe / stats.total) * 100) : 0}%
                        </p>
                        {stats.total > 0 && (
                          <TrendingUp className="h-4 w-4 text-emerald-500" />
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {stats.safe} of {stats.total} clean
                      </p>
                    </div>
                    <div className="rounded-md bg-emerald-500/10 p-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Average Threat Score */}
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Avg. Risk Score
                      </p>
                      <div className="flex items-center gap-2 mt-1">
                        <p className="text-2xl font-bold">
                          {stats.total > 0 ? Math.round(stats.avgScore * 100) : 0}%
                        </p>
                        {stats.total > 1 && (
                          <Minus className="h-4 w-4 text-muted-foreground" />
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {stats.total > 0 ? "Across all analyses" : "No data yet"}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-1">
                      <div className="rounded-md bg-amber-500/10 p-2">
                        <Activity className="h-4 w-4 text-amber-500" />
                      </div>
                      {trendData.length > 1 && (
                        <Sparkline 
                          data={trendData} 
                          color="hsl(var(--primary))" 
                        />
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Critical Alerts */}
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Critical Threats
                      </p>
                      <div className="flex items-center gap-2 mt-1">
                        <p className={cn(
                          "text-2xl font-bold",
                          stats.critical > 0 ? "text-red-500" : ""
                        )}>
                          {stats.critical}
                        </p>
                        {stats.critical > 0 && (
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {stats.critical > 0 ? "Action required" : "No critical alerts"}
                      </p>
                    </div>
                    <div className={cn(
                      "rounded-md p-2",
                      stats.critical > 0 ? "bg-red-500/10" : "bg-muted"
                    )}>
                      <Shield className={cn(
                        "h-4 w-4",
                        stats.critical > 0 ? "text-red-500" : "text-muted-foreground"
                      )} />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>
        </FadeIn>

        {/* Recent Activity */}
        {recentEntries.length > 0 ? (
          <FadeIn delay={0.1}>
            <section>
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-semibold tracking-tight">Recent Activity</h2>
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mt-1">
                    Latest analyses and results
                  </p>
                </div>
                <LinkButton href="/history" variant="outline" size="sm">
                  View All
                  <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
                </LinkButton>
              </div>
              <Card>
                <CardContent className="p-0">
                  {Object.entries(groupedEntries).map(([date, entries], groupIndex) => (
                    <div key={date}>
                      <div className="bg-muted/50 px-4 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        {date}
                      </div>
                      {entries.map((entry, index) => {
                        const meta = THREAT_LEVEL_MAP[entry.threatLevel];
                        const LevelIcon = meta.icon;
                        const isLast = index === entries.length - 1 && groupIndex === Object.keys(groupedEntries).length - 1;
                        
                        return (
                          <div
                            key={entry.id}
                            className={cn(
                              "flex items-center gap-4 px-4 py-3",
                              !isLast && "border-b"
                            )}
                          >
                            <div className={cn("rounded-md p-2", meta.bgClass)}>
                              <LevelIcon className={cn("h-4 w-4", meta.colorClass)} />
                            </div>
                            
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium font-mono truncate">
                                {entry.content.length > 45
                                  ? `${entry.content.slice(0, 42)}...`
                                  : entry.content}
                              </p>
                              <p className="text-xs text-muted-foreground">
                                {entry.contentType.charAt(0).toUpperCase() + entry.contentType.slice(1)} · {formatRelativeTime(entry.analyzedAt)}
                              </p>
                            </div>
                            
                            {/* Score Bar */}
                            <div className="hidden sm:flex items-center gap-3 w-32">
                              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                                <div
                                  className={cn("h-full rounded-full", 
                                    entry.threatLevel === "safe" ? "bg-emerald-500" :
                                    entry.threatLevel === "suspicious" ? "bg-amber-500" :
                                    entry.threatLevel === "dangerous" ? "bg-orange-500" :
                                    "bg-red-500"
                                  )}
                                  style={{ width: `${entry.score * 100}%` }}
                                />
                              </div>
                              <span className="text-xs font-medium tabular-nums w-8 text-right">
                                {Math.round(entry.score * 100)}%
                              </span>
                            </div>
                            
                            <Badge variant="secondary" className={cn("shrink-0 text-xs", meta.colorClass)}>
                              {meta.label}
                            </Badge>
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </CardContent>
              </Card>
            </section>
          </FadeIn>
        ) : (
          <FadeIn delay={0.1}>
            <section>
              <div className="mb-4">
                <h2 className="text-xl font-semibold tracking-tight">Recent Activity</h2>
                <p className="text-xs text-muted-foreground uppercase tracking-wide mt-1">
                  Start analyzing to see results here
                </p>
              </div>
              <Card className="border-dashed">
                <CardContent className="flex flex-col items-center py-12 text-center">
                  <div className="rounded-full bg-muted p-4 mb-4">
                    <Activity className="h-8 w-8 text-muted-foreground" />
                  </div>
                  <h3 className="text-base font-semibold">Ready to detect phishing</h3>
                  <p className="text-sm text-muted-foreground mt-1 max-w-sm">
                    Paste a suspicious URL or email to analyze it against our threat intelligence database.
                  </p>
                  <LinkButton href="/analyze" className="mt-4">
                    <Zap className="mr-1.5 h-4 w-4" />
                    Start Analysis
                  </LinkButton>
                  <p className="text-xs text-muted-foreground mt-4">
                    Try with: <code className="bg-muted px-1.5 py-0.5 rounded text-xs">suspicious-login.tk/verify</code>
                  </p>
                </CardContent>
              </Card>
            </section>
          </FadeIn>
        )}

        {/* GitHub Link - Footer Style */}
        <FadeIn delay={0.15}>
          <Card className="bg-muted/50">
            <CardContent className="flex flex-col sm:flex-row sm:items-center sm:justify-between py-4 gap-4">
              <div className="flex items-center gap-3">
                <div className="rounded-md bg-background p-2">
                  <Github className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-sm font-medium">Open Source</p>
                  <p className="text-xs text-muted-foreground">
                    View code, report issues, and contribute on GitHub
                  </p>
                </div>
              </div>
              <a
                href="https://github.com/ishaq2321/phishing-detection-osint"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 rounded-md border border-input bg-background px-3 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
              >
                ishaq2321
                <ExternalLink className="h-3 w-3" />
              </a>
            </CardContent>
          </Card>
        </FadeIn>
      </div>
    </PageTransition>
  );
}
