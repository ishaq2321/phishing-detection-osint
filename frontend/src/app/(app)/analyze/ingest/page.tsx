"use client";

/**
 * EML Ingestion page — upload a raw .eml file (forwarded phishing
 * email) and get the parsed fields plus the full analysis verdict in
 * one round trip.
 *
 * The backend parses subject / sender / recipients / attachments from
 * the RFC 822 bytes and runs the same email pipeline as the JSON
 * endpoint; the response carries both the verdict and a `parsed`
 * summary so the investigator sees exactly what was read out of the
 * file.
 */

import { useRef, useState } from "react";
import { FileUp, Inbox, Loader2, Mail, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageTransition } from "@/components/ui/pageTransition";
import { FadeIn } from "@/components/ui/animations";
import { VerdictBanner } from "@/components/results/verdictBanner";
import { ReasonsList } from "@/components/results/reasonsList";
import { OsintCards } from "@/components/results/osintCards";
import { FeatureCards } from "@/components/results/featureCards";
import { ingestEmail } from "@/lib/api/endpoints";
import { addEntry } from "@/lib/storage/historyStore";
import { showInfo } from "@/lib/toast";
import type { EmailIngestResponse } from "@/types";
import { formatBytes } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/*  Page                                                              */
/* ------------------------------------------------------------------ */

export default function EmlIngestPage() {
  const [file, setFile] = useState<File | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<EmailIngestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  /* ---- File selection -------------------------------------------- */
  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0] ?? null;
    setFile(selected);
    setResult(null);
    setError(null);
  }

  /* ---- Submit ---------------------------------------------------- */
  async function handleSubmit() {
    if (!file || isRunning) return;

    setIsRunning(true);
    setError(null);
    setResult(null);

    try {
      const response = await ingestEmail(file);
      setResult(response);
      // Persist alongside single/batch analyses for consistent history.
      addEntry(response.parsed.subject || file.name, "email", response);
      showInfo("Result saved to history.");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to analyse the email file.",
      );
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <PageTransition>
      <div className="space-y-6">
        <FadeIn>
          <div className="flex items-center gap-3">
            <div className="rounded-full border bg-muted p-3">
              <Mail className="h-6 w-6 text-muted-foreground" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">
                EML Ingestion
              </h1>
              <p className="text-sm text-muted-foreground">
                Forward a suspicious email file (.eml) — the parser extracts
                subject, sender, body and attachments, then runs the full
                analysis pipeline.
              </p>
            </div>
          </div>
        </FadeIn>

        {/* Upload card */}
        <FadeIn delay={0.1}>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Upload an email file</CardTitle>
              <CardDescription>
                Raw RFC 822 / MIME format, as exported by Outlook, Thunderbird,
                or an email sandbox. Files up to 1 MB are accepted.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <input
                ref={fileRef}
                type="file"
                accept=".eml,message/rfc822,text/plain"
                className="hidden"
                onChange={handleFile}
                data-testid="eml-file-input"
              />

              {!file ? (
                <button
                  type="button"
                  onClick={() => fileRef.current?.click()}
                  className="flex w-full flex-col items-center gap-2 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors hover:border-primary/50 hover:bg-muted/50"
                >
                  <FileUp className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
                  <span className="text-sm font-medium">
                    Click to choose a .eml file
                  </span>
                  <span className="text-xs text-muted-foreground">
                    Only the extracted text is analysed — attachments are
                    detected but never executed or scored.
                  </span>
                </button>
              ) : (
                <div className="flex items-center justify-between rounded-lg border bg-muted/40 px-4 py-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{file.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatBytes(file.size)}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setFile(null);
                      setResult(null);
                      if (fileRef.current) fileRef.current.value = "";
                    }}
                  >
                    Remove
                  </Button>
                </div>
              )}

              <div className="flex items-center justify-end gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fileRef.current?.click()}
                >
                  {file ? "Choose different file" : "Browse…"}
                </Button>
                <Button onClick={handleSubmit} disabled={!file || isRunning}>
                  {isRunning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                      Analysing…
                    </>
                  ) : (
                    "Analyse email"
                  )}
                </Button>
              </div>

              {error && (
                <div
                  role="alert"
                  className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive"
                >
                  <ShieldAlert
                    className="mt-0.5 h-4 w-4 shrink-0"
                    aria-hidden="true"
                  />
                  <span>{error}</span>
                </div>
              )}
            </CardContent>
          </Card>
        </FadeIn>

        {/* Results */}
        {result && (
          <FadeIn delay={0.15}>
            <div className="space-y-6">
              {/* Parsed summary */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Inbox className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                    Parsed from the file
                  </CardTitle>
                  <CardDescription>
                    What the parser extracted — {formatBytes(result.parsed.sizeBytes)}{" "}
                    payload
                  </CardDescription>
                </CardHeader>
                <CardContent className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Subject
                    </p>
                    <p className="mt-1 text-sm">
                      {result.parsed.subject || "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Sender
                    </p>
                    <p className="mt-1 text-sm">
                      {result.parsed.senderName
                        ? `${result.parsed.senderName} <${result.parsed.senderAddress}>`
                        : result.parsed.senderAddress || "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Recipients
                    </p>
                    <p className="mt-1 text-sm">
                      {result.parsed.recipients.length > 0
                        ? result.parsed.recipients.join(", ")
                        : "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Attachments
                    </p>
                    <p className="mt-1 text-sm">
                      {result.parsed.hasAttachments
                        ? result.parsed.attachmentNames.join(", ")
                        : "None"}
                    </p>
                  </div>
                  <div className="sm:col-span-2">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Body preview
                    </p>
                    <p className="mt-1 line-clamp-3 whitespace-pre-wrap text-sm text-muted-foreground">
                      {result.parsed.bodyPreview || "—"}
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Verdict + detail */}
              <VerdictBanner verdict={result.verdict} />
              {result.verdict.reasons.length > 0 && (
                <ReasonsList reasons={result.verdict.reasons} />
              )}
              {result.osint && <OsintCards osint={result.osint} />}
              <FeatureCards features={result.features} />
            </div>
          </FadeIn>
        )}
      </div>
    </PageTransition>
  );
}
