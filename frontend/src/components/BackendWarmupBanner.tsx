"use client";

/**
 * BackendWarmupBanner — shows a friendly message when the backend is
 * waking up from a cold start (Render free tier spin-down).
 *
 * Displays a non-blocking banner with a spinner and estimated wait time.
 * Automatically hides once the backend responds.
 */

import { useEffect, useState } from "react";
import { Loader2, Clock, RefreshCw } from "lucide-react";
import { useHealth } from "@/hooks";
import { cn } from "@/lib/utils";

interface BackendWarmupBannerProps {
  /** Optional class name for the container. */
  className?: string;
}

/** Auto-hide after 60 seconds (give up). */
const WARMUP_TIMEOUT_MS = 60_000;

/** Estimated cold-start duration on Render free tier (seconds). */
const ESTIMATED_COLD_START_S = 45;

export function BackendWarmupBanner({ className }: BackendWarmupBannerProps) {
  const { data, isLoading, error } = useHealth(5_000); // Poll every 5s during warmup

  // Visibility is derived from health state + a user-dismiss flag,
  // so no setState-in-effect mirroring is needed.
  const backendAlive = data?.status === "alive";
  const backendDown = Boolean(error) && !isLoading;
  const [dismissed, setDismissed] = useState(false);
  const showBanner = backendDown && !dismissed;

  const [startTime, setStartTime] = useState<number | null>(null);
  const [now, setNow] = useState<number | null>(null);

  // Reset dismissal whenever the backend recovers, so the banner can
  // reappear on the next cold start.
  useEffect(() => {
    if (backendAlive && dismissed) {
      // Defer via timeout: runs outside the render/commit cascade.
      const id = setTimeout(() => setDismissed(false), 0);
      return () => clearTimeout(id);
    }
  }, [backendAlive, dismissed]);

  // Record the moment the backend first became unreachable.
  useEffect(() => {
    if (backendDown && startTime === null) {
      const t = Date.now();
      const id = setTimeout(() => setStartTime((prev) => prev ?? t), 0);
      return () => clearTimeout(id);
    }
    if (!backendDown && startTime !== null) {
      const id = setTimeout(() => setStartTime(null), 0);
      return () => clearTimeout(id);
    }
  }, [backendDown, startTime]);

  // Tick once per second while the banner is visible so elapsed/ETA stay
  // current without calling impure time functions during render.
  useEffect(() => {
    if (!showBanner) return;
    const tick = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(tick);
  }, [showBanner]);

  // Auto-hide after 60 seconds (give up)
  useEffect(() => {
    if (!showBanner) return;
    const timeout = setTimeout(() => setDismissed(true), WARMUP_TIMEOUT_MS);
    return () => clearTimeout(timeout);
  }, [showBanner]);

  if (!showBanner) return null;

  const elapsed = startTime && now ? Math.floor((now - startTime) / 1000) : 0;
  const eta = Math.max(0, ESTIMATED_COLD_START_S - elapsed);

  return (
    <div
      className={cn(
        "rounded-lg border border-blue-200 bg-blue-50 p-4",
        "dark:border-blue-800 dark:bg-blue-950/50",
        className
      )}
      role="alert"
      aria-live="polite"
    >
      <div className="flex items-start gap-3">
        <Loader2
          className="h-5 w-5 shrink-0 animate-spin text-blue-600 dark:text-blue-400"
          aria-hidden="true"
        />
        <div className="flex-1">
          <p className="text-sm font-medium text-blue-800 dark:text-blue-300">
            Backend is waking up
          </p>
          <p className="mt-1 text-xs text-blue-700 dark:text-blue-400">
            The analysis server is starting up from sleep. This usually takes
            30–45 seconds on the free tier.
          </p>
          <div className="mt-2 flex items-center gap-2 text-xs text-blue-600 dark:text-blue-400">
            <Clock className="h-3 w-3" aria-hidden="true" />
            <span>
              {elapsed > 0
                ? `Elapsed: ${elapsed}s · ETA: ~${eta}s`
                : "Estimated wait: ~30–45 seconds"}
            </span>
          </div>
          <p className="mt-1 text-xs text-blue-600/70 dark:text-blue-400/70">
            You can still use the app — the analysis will start automatically
            once the backend is ready.
          </p>
        </div>
        <button
          onClick={() => setDismissed(true)}
          className="shrink-0 rounded p-1 text-blue-600 hover:bg-blue-100 dark:text-blue-400 dark:hover:bg-blue-900"
          aria-label="Retry connection"
          title="Retry connection"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
