"use client";

/**
 * Settings page — API configuration, display preferences, history
 * management, and about section.
 *
 * All settings are persisted in localStorage and apply immediately
 * (no explicit save button needed).
 */

import { useCallback, useEffect, useState } from "react";
import {
  Globe,
  Palette,
  Database,
  Info,
  RotateCcw,
  Loader2,
  CheckCircle2,
  XCircle,
  Wifi,
} from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import {
  getSettings,
  updateSetting,
  resetSettings,
  DEFAULT_SETTINGS,
  type AppSettings,
  type ResultsDetailLevel,
  type MaxHistoryEntries,
  type AutoClearDays,
} from "@/lib/storage/settingsStore";
import { clearHistory, getHistoryCount, pruneHistory } from "@/lib/storage/historyStore";
import { showSuccess, showWarning, showError } from "@/lib/toast";
import { APP_NAME, APP_VERSION, APP_TAGLINE } from "@/lib/constants";
import { PageTransition } from "@/components/ui/pageTransition";
import { FadeIn } from "@/components/ui/animations";

/* ------------------------------------------------------------------ */
/*  Connection-status type                                            */
/* ------------------------------------------------------------------ */

type ConnectionStatus = "idle" | "testing" | "connected" | "failed";

/* ------------------------------------------------------------------ */
/*  Page component                                                    */
/* ------------------------------------------------------------------ */

export default function SettingsPage() {
  /* ---- State ----------------------------------------------------- */
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [mounted, setMounted] = useState(false);
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("idle");
  const [historyCount, setHistoryCount] = useState(0);
  const { theme, setTheme } = useTheme();

  /* ---- Hydrate from localStorage --------------------------------- */
  useEffect(() => {
    const id = requestAnimationFrame(() => {
      setMounted(true);
      setSettings(getSettings());
      setHistoryCount(getHistoryCount());
    });
    return () => cancelAnimationFrame(id);
  }, []);

  /* ---- Generic updater ------------------------------------------- */
  const handleUpdate = useCallback(
    <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
      const updated = updateSetting(key, value);
      setSettings(updated);

      if (key === "maxHistoryEntries" || key === "autoClearDays") {
        const removed = pruneHistory();
        if (removed > 0) {
          showWarning(
            "History pruned",
            `${removed} old ${removed === 1 ? "entry" : "entries"} removed to match the new setting.`,
          );
        }
        setHistoryCount(getHistoryCount());
      }
    },
    [],
  );

  /* ---- Test connection ------------------------------------------- */
  const testConnection = useCallback(async () => {
    setConnectionStatus("testing");
    try {
      const response = await fetch(`${settings.apiUrl}/api/health`, {
        method: "GET",
        signal: AbortSignal.timeout(5_000),
      });
      if (response.ok) {
        setConnectionStatus("connected");
        showSuccess("Connection successful", "Backend is reachable.");
      } else {
        setConnectionStatus("failed");
        showError(
          "Connection failed",
          `Server returned status ${response.status}.`,
        );
      }
    } catch {
      setConnectionStatus("failed");
      showError(
        "Connection failed",
        "Cannot reach the backend. Is the server running?",
      );
    }
  }, [settings.apiUrl]);

  /* ---- Clear history --------------------------------------------- */
  const handleClearHistory = useCallback(() => {
    clearHistory();
    setHistoryCount(0);
    showSuccess("History cleared", "All analysis records have been deleted.");
  }, []);

  /* ---- Reset all settings ---------------------------------------- */
  const handleReset = useCallback(() => {
    const defaults = resetSettings();
    setSettings(defaults);
    showWarning("Settings reset", "All settings restored to defaults.");
  }, []);

  /* ---- Connection status badge ----------------------------------- */
  const renderConnectionBadge = () => {
    switch (connectionStatus) {
      case "testing":
        return (
          <Badge variant="secondary" className="gap-1.5">
            <Loader2 className="h-3 w-3 animate-spin" />
            Testing…
          </Badge>
        );
      case "connected":
        return (
          <Badge variant="default" className="gap-1.5 bg-green-600">
            <CheckCircle2 className="h-3 w-3" />
            Connected
          </Badge>
        );
      case "failed":
        return (
          <Badge variant="destructive" className="gap-1.5">
            <XCircle className="h-3 w-3" />
            Failed
          </Badge>
        );
      default:
        return null;
    }
  };

  /* Don't render until mounted (avoid hydration mismatch) */
  if (!mounted) return null;

  return (
    <PageTransition>
      <div className="space-y-6">
        {/* ---- Page header ---------------------------------------- */}
        <FadeIn>
          <div>
            <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
              Settings
            </h1>
            <p className="text-sm text-muted-foreground sm:text-base">
              Configure API connection, display preferences, and history
              management.
            </p>
          </div>
        </FadeIn>

        {/* ---- API Configuration ---------------------------------- */}
        <FadeIn delay={0.05}>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
                <CardTitle>API Configuration</CardTitle>
              </div>
              <CardDescription>
                Set the backend server URL used for phishing analysis.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="apiUrl">Backend URL</Label>
                <div className="flex gap-2">
                  <Input
                    id="apiUrl"
                    type="url"
                    placeholder={DEFAULT_SETTINGS.apiUrl}
                    value={settings.apiUrl}
                    onChange={(e) => handleUpdate("apiUrl", e.target.value)}
                    className="flex-1"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={testConnection}
                    disabled={connectionStatus === "testing"}
                    className="shrink-0"
                  >
                    {connectionStatus === "testing" ? (
                      <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                    ) : (
                      <Wifi className="mr-1.5 h-4 w-4" />
                    )}
                    Test
                  </Button>
                </div>
                <div className="flex items-center gap-2">
                  <p className="text-xs text-muted-foreground">
                    Default: {DEFAULT_SETTINGS.apiUrl}
                  </p>
                  <span aria-live="polite">{renderConnectionBadge()}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </FadeIn>

        {/* ---- Display Preferences -------------------------------- */}
        <FadeIn delay={0.1}>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Palette className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
                <CardTitle>Display Preferences</CardTitle>
              </div>
              <CardDescription>
                Customise the appearance and detail level of the interface.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Theme */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Dark Mode</Label>
                  <p className="text-xs text-muted-foreground">
                    Toggle between light and dark themes.
                  </p>
                </div>
                <Switch
                  checked={theme === "dark"}
                  onCheckedChange={(checked) =>
                    setTheme(checked ? "dark" : "light")
                  }
                  aria-label="Toggle dark mode"
                />
              </div>

              <Separator />

              {/* Results detail level */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="detailLevel">Results Detail Level</Label>
                  <p className="text-xs text-muted-foreground">
                    Controls how much information is shown in analysis results.
                  </p>
                </div>
                <Select
                  value={settings.resultsDetailLevel}
                  onValueChange={(val) =>
                    handleUpdate(
                      "resultsDetailLevel",
                      val as ResultsDetailLevel,
                    )
                  }
                >
                  <SelectTrigger className="w-36" id="detailLevel">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="simple">Simple</SelectItem>
                    <SelectItem value="detailed">Detailed</SelectItem>
                    <SelectItem value="expert">Expert</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
        </FadeIn>

        {/* ---- History Management ---------------------------------- */}
        <FadeIn delay={0.15}>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Database className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
                <CardTitle>History Management</CardTitle>
              </div>
              <CardDescription>
                Control how analysis history is stored and retained.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Max history entries */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="maxEntries">Maximum Entries</Label>
                  <p className="text-xs text-muted-foreground">
                    Oldest entries are removed when the limit is reached.
                  </p>
                </div>
                <Select
                  value={String(settings.maxHistoryEntries)}
                  onValueChange={(val) =>
                    handleUpdate(
                      "maxHistoryEntries",
                      Number(val) as MaxHistoryEntries,
                    )
                  }
                >
                  <SelectTrigger className="w-24" id="maxEntries">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="10">10</SelectItem>
                    <SelectItem value="25">25</SelectItem>
                    <SelectItem value="50">50</SelectItem>
                    <SelectItem value="100">100</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Separator />

              {/* Auto-clear days */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="autoClear">Auto-Clear After</Label>
                  <p className="text-xs text-muted-foreground">
                    Automatically remove entries older than the selected period.
                  </p>
                </div>
                <Select
                  value={String(settings.autoClearDays)}
                  onValueChange={(val) =>
                    handleUpdate("autoClearDays", Number(val) as AutoClearDays)
                  }
                >
                  <SelectTrigger className="w-28" id="autoClear">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="0">Never</SelectItem>
                    <SelectItem value="7">7 days</SelectItem>
                    <SelectItem value="14">14 days</SelectItem>
                    <SelectItem value="30">30 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Separator />

              {/* Clear history */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Clear History</Label>
                  <p className="text-xs text-muted-foreground">
                    {historyCount === 0
                      ? "No entries stored."
                      : `${historyCount} ${historyCount === 1 ? "entry" : "entries"} stored.`}
                  </p>
                </div>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleClearHistory}
                  disabled={historyCount === 0}
                >
                  Clear All
                </Button>
              </div>
            </CardContent>
          </Card>
        </FadeIn>

        {/* ---- About ----------------------------------------------- */}
        <FadeIn delay={0.2}>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Info className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
                <CardTitle>About</CardTitle>
              </div>
              <CardDescription>
                Application information and credits.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                <dt className="font-medium text-muted-foreground">
                  Application
                </dt>
                <dd>{APP_NAME}</dd>

                <dt className="font-medium text-muted-foreground">Tagline</dt>
                <dd>{APP_TAGLINE}</dd>

                <dt className="font-medium text-muted-foreground">Version</dt>
                <dd>
                  <Badge variant="secondary">{APP_VERSION}</Badge>
                </dd>

                <dt className="font-medium text-muted-foreground">Author</dt>
                <dd>Ishaq Muhammad (PXPRGK)</dd>

                <dt className="font-medium text-muted-foreground">
                  Supervisor
                </dt>
                <dd>Md. Easin Arafat</dd>

                <dt className="font-medium text-muted-foreground">
                  University
                </dt>
                <dd>
                  Eötvös Loránd University (ELTE) — Faculty of Informatics
                </dd>

                <dt className="font-medium text-muted-foreground">
                  Documentation
                </dt>
                <dd>
                  <a
                    href="https://github.com/ishaq2321/phishing-detection-osint/tree/main/docs"
                    target="_blank"
                    rel="noreferrer"
                    className="text-primary underline-offset-4 hover:underline"
                  >
                    GitHub docs folder
                  </a>
                </dd>
              </dl>
            </CardContent>
          </Card>
        </FadeIn>

        {/* ---- Reset button --------------------------------------- */}
        <FadeIn delay={0.25}>
          <div className="flex justify-end">
            <Button variant="outline" onClick={handleReset}>
              <RotateCcw className="mr-2 h-4 w-4" />
              Reset to Defaults
            </Button>
          </div>
        </FadeIn>
      </div>
    </PageTransition>
  );
}
