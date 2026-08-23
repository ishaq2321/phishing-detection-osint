"use client";

/**
 * VerdictFeedback — operator feedback loop wired to POST /api/feedback.
 *
 * Surfaces the backend's retrain-from-feedback bridge in the UI: users
 * label a verdict as correct / false positive / false negative, closing
 * the analyse → feedback → retrain loop.
 */

import { useState } from "react";
import { CheckCircle2, ThumbsDown, ThumbsUp, HelpCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { submitFeedback } from "@/lib/api/endpoints";
import type { FeedbackVerdict } from "@/types";
import { cn } from "@/lib/utils";

const OPTIONS: {
  value: FeedbackVerdict;
  label: string;
  icon: React.ElementType;
  activeClass: string;
}[] = [
  {
    value: "correct",
    label: "Correct",
    icon: CheckCircle2,
    activeClass: "border-emerald-400 bg-emerald-50 dark:bg-emerald-950",
  },
  {
    value: "false_positive",
    label: "False positive",
    icon: ThumbsDown,
    activeClass: "border-amber-400 bg-amber-50 dark:bg-amber-950",
  },
  {
    value: "false_negative",
    label: "Missed phishing",
    icon: ThumbsUp,
    activeClass: "border-red-400 bg-red-50 dark:bg-red-950",
  },
];

interface VerdictFeedbackProps {
  /** History entry ID — required by the backend contract. */
  historyId?: string;
}

type SubmitState = "idle" | "submitting" | "done" | "error";

export function VerdictFeedback({ historyId }: VerdictFeedbackProps) {
  const [state, setState] = useState<SubmitState>("idle");
  const [selected, setSelected] = useState<FeedbackVerdict | null>(null);

  if (!historyId) return null;

  async function handleSelect(verdict: FeedbackVerdict) {
    if (state === "submitting" || state === "done") return;
    setSelected(verdict);
    setState("submitting");
    try {
      const res = await submitFeedback({
        historyId: historyId as string,
        verdict,
      });
      setState(res.accepted ? "done" : "error");
    } catch {
      setState("error");
    }
  }

  return (
    <Card>
      <CardContent className="py-4">
        {state === "done" ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" aria-hidden="true" />
            Thanks — your label was recorded and will feed model retraining.
          </p>
        ) : (
          <>
            <p className="mb-3 flex items-center gap-2 text-sm font-medium">
              <HelpCircle className="h-4 w-4 text-primary" aria-hidden="true" />
              Is this verdict correct?
            </p>
            <div className="flex flex-wrap gap-2">
              {OPTIONS.map(({ value, label, icon: Icon, activeClass }) => (
                <Button
                  key={value}
                  variant="outline"
                  size="sm"
                  disabled={state === "submitting"}
                  onClick={() => handleSelect(value)}
                  aria-pressed={selected === value}
                  className={cn(
                    selected === value && state !== "error" && activeClass,
                  )}
                >
                  <Icon className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {label}
                </Button>
              ))}
            </div>
            {state === "error" && (
              <p className="mt-2 text-xs text-destructive" role="alert">
                Could not record feedback — check your connection and try again.
              </p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
