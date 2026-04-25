"use client";

/**
 * Analyse page — submit a URL, email, or free-text for phishing
 * detection.  Shows a step-by-step progress bar while the backend
 * processes the request, then redirects to the results page.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Globe,
  Mail,
  FileText,
  AlertTriangle,
  Send,
  X,
  Shield,
  Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AnalysisProgress, type AnalysisPhase } from "@/components/analyze";
import { LinkButton } from "@/components/ui/linkButton";
import { useResult } from "@/lib/resultsContext";
import { addEntry } from "@/lib/storage/historyStore";
import { showError } from "@/lib/toast";
import { PageTransition } from "@/components/ui/pageTransition";
import { FadeIn } from "@/components/ui/animations";
import { cn } from "@/lib/utils";
import type { ContentType, AnalysisResponse } from "@/types";
import { analyzeContent, analyzeUrl, analyzeEmail } from "@/lib/api/endpoints";

/* ------------------------------------------------------------------ */
/*  Input mode config                                                 */
/* ------------------------------------------------------------------ */

interface InputMode {
  value: ContentType;
  label: string;
  icon: React.ElementType;
  placeholder: string;
  description: string;
}

const INPUT_MODES: InputMode[] = [
  {
    value: "url",
    label: "URL",
    icon: Globe,
    placeholder: "https://example.com/login",
    description: "Paste a single URL to check for phishing indicators.",
  },
  {
    value: "email",
    label: "Email",
    icon: Mail,
    placeholder: "Paste the full email body here…",
    description: "Paste email content to detect social engineering tactics.",
  },
  {
    value: "text",
    label: "Text",
    icon: FileText,
    placeholder: "Paste any suspicious text content…",
    description: "Submit free-text to analyse for phishing language patterns.",
  },
];

/* ------------------------------------------------------------------ */
/*  Page component                                                    */
/* ------------------------------------------------------------------ */

export default function AnalyzePage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setResult } = useResult();
  const abortRef = useRef<AbortController | null>(null);

  /* ── State ─────────────────────────────────────────────────────── */
  const [mode, setMode] = useState<ContentType>("url");
  const [content, setContent] = useState("");
  const [emailSubject, setEmailSubject] = useState("");
  const [emailSender, setEmailSender] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiComplete, setApiComplete] = useState(false);
  const [responseRef, setResponseRef] = useState<AnalysisResponse | null>(null);
  const [analysisPhase, setAnalysisPhase] = useState<AnalysisPhase>("idle");
  const [startedAt, setStartedAt] = useState<number | null>(null);

  /* ── Pre-fill from query params (re-analyse action) ────────────── */
  useEffect(() => {
    const prefill = searchParams.get("content");
    const prefillType = searchParams.get("type") as ContentType | null;
    if (prefill) {
      const id = requestAnimationFrame(() => {
        setContent(prefill);
        if (prefillType && ["url", "email", "text"].includes(prefillType)) {
          setMode(prefillType);
        }
      });
      return () => cancelAnimationFrame(id);
    }
  }, [searchParams]);

  /* ── Submit analysis ───────────────────────────────────────────── */
  const handleSubmit = useCallback(async () => {
    const trimmed = content.trim();
    if (!trimmed) return;

    setIsSubmitting(true);
    setApiComplete(false);
    setResponseRef(null);
    setAnalysisPhase("preparing");
    setStartedAt(Date.now());

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      let response: AnalysisResponse;
      setAnalysisPhase("sending");

      if (mode === "url") {
        setAnalysisPhase("waiting");
        response = await analyzeUrl(
          { url: trimmed },
          { signal: controller.signal },
        );
      } else if (mode === "email") {
        setAnalysisPhase("waiting");
        response = await analyzeEmail(
          {
            content: trimmed,
            subject: emailSubject || undefined,
            sender: emailSender || undefined,
          },
          { signal: controller.signal },
        );
      } else {
        setAnalysisPhase("waiting");
        response = await analyzeContent(
          { content: trimmed, contentType: mode },
          { signal: controller.signal },
        );
      }

      setAnalysisPhase("processing");
      setResponseRef(response);
      setApiComplete(true);
      setAnalysisPhase("complete");
    } catch (error: unknown) {
      setIsSubmitting(false);
      setApiComplete(false);
      setAnalysisPhase("idle");
      setStartedAt(null);
      if (error instanceof DOMException && error.name === "AbortError") return;

      const message =
        error instanceof Error ? error.message : "Analysis failed";
      showError("Analysis failed", message);
    }
  }, [content, mode, emailSubject, emailSender]);

  /* ── Cancel ────────────────────────────────────────────────────── */
  const handleCancel = useCallback(() => {
    abortRef.current?.abort();
    setIsSubmitting(false);
    setApiComplete(false);
    setAnalysisPhase("idle");
    setStartedAt(null);
  }, []);

  /* ── Progress finished → navigate ──────────────────────────────── */
  const handleProgressFinished = useCallback(() => {
    if (!responseRef) return;

    /* Save to history */
    const historyEntry = addEntry(content.trim(), mode, responseRef);

    /* Set context for results page */
    setResult({
      response: responseRef,
      content: content.trim(),
      contentType: mode,
      historyId: historyEntry.id,
    });

    router.push("/results");
  }, [responseRef, content, mode, setResult, router]);

  /* ── Derived state ─────────────────────────────────────────────── */
  const currentMode = INPUT_MODES.find((m) => m.value === mode)!;
  const canSubmit = content.trim().length > 0 && !isSubmitting;

  /* ── Render ────────────────────────────────────────────────────── */
  return (
    <PageTransition>
      <div className="space-y-6">
        {/* Header */}
        <FadeIn>
          <div>
            <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
              Analyse Content
            </h1>
            <p className="text-sm text-muted-foreground sm:text-base">
              Submit a URL, email, or text to detect phishing threats.
            </p>
          </div>
        </FadeIn>

        {/* Analysis form */}
        <FadeIn delay={0.05}>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" aria-hidden="true" />
                <CardTitle>Phishing Detection</CardTitle>
              </div>
              <CardDescription>{currentMode.description}</CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
              {/* Mode selector */}
              <div className="space-y-2">
                <Label htmlFor="mode">Input Type</Label>
                <Select
                  value={mode}
                  onValueChange={(v) => setMode(v as ContentType)}
                  disabled={isSubmitting}
                >
                  <SelectTrigger id="mode" className="w-44">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {INPUT_MODES.map(({ value: v, label, icon: Icon }) => (
                      <SelectItem key={v} value={v}>
                        <span className="flex items-center gap-2">
                          <Icon className="h-4 w-4" aria-hidden="true" />
                          {label}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Content input */}
              <div className="space-y-2">
                <Label htmlFor="content">
                  {mode === "url" ? "URL" : "Content"}
                </Label>
                {mode === "url" ? (
                  <Input
                    id="content"
                    type="url"
                    placeholder={currentMode.placeholder}
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    disabled={isSubmitting}
                    aria-describedby="content-hint"
                  />
                ) : (
                  <Textarea
                    id="content"
                    placeholder={currentMode.placeholder}
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    disabled={isSubmitting}
                    rows={6}
                    className="min-h-[120px]"
                    aria-describedby="content-hint"
                  />
                )}
                <p id="content-hint" className="text-xs text-muted-foreground">
                  {mode === "url"
                    ? "Enter the full URL including the protocol (https://)."
                    : `Paste the ${mode} content you want to analyse.`}
                </p>
              </div>

              {/* Email-specific fields */}
              {mode === "email" && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="emailSubject">
                      Subject{" "}
                      <span className="text-muted-foreground">(optional)</span>
                    </Label>
                    <Input
                      id="emailSubject"
                      placeholder="Re: Urgent account verification"
                      value={emailSubject}
                      onChange={(e) => setEmailSubject(e.target.value)}
                      disabled={isSubmitting}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="emailSender">
                      Sender{" "}
                      <span className="text-muted-foreground">(optional)</span>
                    </Label>
                    <Input
                      id="emailSender"
                      placeholder="noreply@bank-support.com"
                      value={emailSender}
                      onChange={(e) => setEmailSender(e.target.value)}
                      disabled={isSubmitting}
                    />
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="flex items-center gap-3 pt-2">
                {isSubmitting ? (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={handleCancel}
                  >
                    <X className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    Cancel
                  </Button>
                ) : (
                  <Button
                    onClick={handleSubmit}
                    disabled={!canSubmit}
                    size="sm"
                  >
                    <Send className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    Analyse
                  </Button>
                )}

                {!isSubmitting && content.length > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setContent("");
                      setEmailSubject("");
                      setEmailSender("");
                    }}
                  >
                    Clear
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </FadeIn>

        {/* Progress bar — shown while submitting */}
        {isSubmitting && (
          <FadeIn>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Analysing…</CardTitle>
                <CardDescription>
                  Running the phishing detection pipeline.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <AnalysisProgress
                  isComplete={apiComplete}
                  phase={analysisPhase}
                  startedAt={startedAt}
                  onFinished={handleProgressFinished}
                />
              </CardContent>
            </Card>
          </FadeIn>
        )}

        {/* Tip card */}
        {!isSubmitting && (
          <>
            <FadeIn delay={0.1}>
              <Card
                className={cn(
                  "border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/50",
                )}
              >
                <CardContent className="flex items-start gap-3 pt-4">
                  <AlertTriangle
                    className="mt-0.5 h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400"
                    aria-hidden="true"
                  />
                  <div className="text-sm">
                    <p className="font-medium text-amber-800 dark:text-amber-300">
                      Tips for best results
                    </p>
                    <ul className="mt-1 list-inside list-disc text-amber-700 dark:text-amber-400/80">
                      <li>Include the full URL with protocol (https://)</li>
                      <li>For emails, paste the complete body text</li>
                      <li>
                        The system checks domain age, WHOIS, DNS, and blacklists
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            </FadeIn>

            {/* Batch link */}
            <FadeIn delay={0.2}>
              <Card className="border-dashed">
                <CardContent className="flex items-center justify-between py-4">
                  <div className="flex items-center gap-3">
                    <Layers className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
                    <div>
                      <p className="text-sm font-medium">Need to analyse multiple URLs?</p>
                      <p className="text-xs text-muted-foreground">
                        Process up to 50 URLs at once with parallel analysis.
                      </p>
                    </div>
                  </div>
                  <LinkButton href="/analyze/batch" variant="outline" size="sm">
                    Batch Mode
                  </LinkButton>
                </CardContent>
              </Card>
            </FadeIn>
          </>
        )}
      </div>
    </PageTransition>
  );
}
