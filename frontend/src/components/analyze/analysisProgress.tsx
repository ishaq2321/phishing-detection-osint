"use client";

/**
 * AnalysisProgress — event-driven progress UI shown while analysis is running.
 *
 * Unlike synthetic timer-based progress, this component reflects real
 * request phases emitted by the analyse page.
 */

import { useEffect, useMemo, useState } from "react";
import {
  ClipboardCheck,
  UploadCloud,
  Server,
  Sparkles,
  Brain,
  CheckCircle2,
  Loader2,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/*  Step definitions                                                  */
/* ------------------------------------------------------------------ */

interface ProgressStep {
  phase: AnalysisPhase;
  label: string;
  icon: React.ElementType;
  description: string;
}

export type AnalysisPhase =
  | "idle"
  | "preparing"
  | "sending"
  | "waiting"
  | "processing"
  | "complete";

const STEPS: ProgressStep[] = [
  {
    phase: "preparing",
    label: "Preparing input",
    icon: ClipboardCheck,
    description: "Validating your submission and preparing the request.",
  },
  {
    phase: "sending",
    label: "Sending request",
    icon: UploadCloud,
    description: "Submitting analysis request to backend services.",
  },
  {
    phase: "waiting",
    label: "Awaiting backend response",
    icon: Server,
    description: "Running feature extraction, OSINT checks, and model inference.",
  },
  {
    phase: "processing",
    label: "Finalising report",
    icon: Sparkles,
    description: "Preparing final verdict and risk indicators.",
  },
  {
    phase: "complete",
    label: "Analysis complete",
    icon: CheckCircle2,
    description: "Result is ready. Redirecting to report.",
  },
];

const PHASE_PROGRESS: Record<AnalysisPhase, number> = {
  idle: 0,
  preparing: 15,
  sending: 30,
  waiting: 70,
  processing: 90,
  complete: 100,
};

/* ------------------------------------------------------------------ */
/*  Props                                                             */
/* ------------------------------------------------------------------ */

interface AnalysisProgressProps {
  /** Whether the real API call has finished. Jumps to 100% when true. */
  isComplete: boolean;
  /** Current real request phase from the analyse page. */
  phase: AnalysisPhase;
  /** Timestamp when submission started (epoch ms). */
  startedAt: number | null;
  /** Called after the final step finishes its mini-delay. */
  onFinished?: () => void;
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

export function AnalysisProgress({
  isComplete,
  phase,
  startedAt,
  onFinished,
}: AnalysisProgressProps) {
  const effectivePhase: AnalysisPhase = isComplete ? "complete" : phase;
  const activeStep = useMemo(() => {
    const idx = STEPS.findIndex((s) => s.phase === effectivePhase);
    return idx === -1 ? 0 : idx;
  }, [effectivePhase]);

  const progress = PHASE_PROGRESS[effectivePhase];
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    if (!startedAt || effectivePhase === "idle" || effectivePhase === "complete") {
      setElapsedMs(0);
      return;
    }

    const tick = () => setElapsedMs(Math.max(0, Date.now() - startedAt));
    tick();
    const id = setInterval(tick, 250);
    return () => clearInterval(id);
  }, [startedAt, effectivePhase]);

  useEffect(() => {
    if (!isComplete) return;
    const id = setTimeout(() => onFinished?.(), 450);
    return () => clearTimeout(id);
  }, [isComplete, onFinished]);

  const elapsedLabel = `${(elapsedMs / 1000).toFixed(1)}s`;

  return (
    <div className="space-y-6" role="status" aria-live="polite">
      {/* Progress bar */}
      <Progress
        value={progress}
        className="h-2"
        aria-label={`Analysis progress: ${progress}%`}
      />

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{STEPS[activeStep]?.description}</span>
        {effectivePhase !== "complete" && effectivePhase !== "idle" && (
          <span className="tabular-nums">Elapsed: {elapsedLabel}</span>
        )}
      </div>

      {/* Steps */}
      <div className="space-y-2">
        {STEPS.map((step, idx) => {
          const StepIcon = step.icon;
          const isDone = idx < activeStep || (idx === activeStep && effectivePhase === "complete");
          const isCurrent = idx === activeStep && !isComplete;

          return (
            <AnimatePresence key={step.label}>
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.05, duration: 0.25 }}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  isDone && "text-green-600 dark:text-green-400",
                  isCurrent && "bg-muted font-medium text-foreground",
                  !isDone && !isCurrent && "text-muted-foreground",
                )}
              >
                {isCurrent ? (
                  <Loader2
                    className="h-4 w-4 animate-spin"
                    aria-hidden="true"
                  />
                ) : isDone ? (
                  <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <StepIcon className="h-4 w-4" aria-hidden="true" />
                )}
                <span>{step.label}</span>
              </motion.div>
            </AnimatePresence>
          );
        })}
      </div>

      {/* sr-only live status */}
      <p className="sr-only">
        {effectivePhase === "complete"
          ? "Analysis complete"
          : `Step ${activeStep + 1} of ${STEPS.length}: ${STEPS[activeStep].label}`}
      </p>
    </div>
  );
}
