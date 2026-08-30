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

export function BackendWarmupBanner({ className }: BackendWarmupBannerProps) {
  const { data, isLoading, error, isColdStart } = useHealth(5_000); // Poll every 5s during warmup
  const [showBanner, setShowBanner] = useState(false);
  const [startTime, setStartTime] = useState<number | null>(null);

  useEffect(() => {
    // If we have an error (backend not responding), start showing the banner
    if (error && !isLoading) {
      if (!startTime) {
        setStartTime(Date.now());
      }
      setShowBanner(true);
    }
    // If backend is alive, hide the banner
    if (data?.status === "alive") {
      setShowBanner(false);
      setStartTime(null);
    }
  }, [error, isLoading, data, startTime]);

  // Auto-hide after 60 seconds (give up)
  useEffect(() => {
    if (!showBanner) return;
    const timeout = setTimeout(() => {
      setShowBanner(false);
    }, 60_000);
    return () => clearTimeout(timeout);
  }, [showBanner]);

  if (!showBanner) return null;

  const elapsed = startTime ? Math.floor((Date.now() - startTime) / 1000) : 0;
  const eta = Math.max(0, 45 - elapsed); // Render free tier cold start ~45s

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
          onClick={() => {
            setShowBanner(false);
            setStartTime(Date.now());
          }}
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