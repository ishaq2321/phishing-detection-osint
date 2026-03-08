"use client";

/**
 * Results page — displays the full analysis output.
 *
 * Reads the latest result from `ResultsContext`.  If no result is
 * available (e.g. direct navigation), shows an empty state with a
 * link back to the Analyse page.
 */

import { ArrowLeft, Search } from "lucide-react";
import { LinkButton } from "@/components/ui/linkButton";
import { Separator } from "@/components/ui/separator";
import {
  VerdictBanner,
  ReasonsList,
  ContentPreview,
  ShareActions,
  OsintCards,
  FeatureCards,
} from "@/components/results";
import { useResult } from "@/lib/resultsContext";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function ResultsPage() {
  const { result } = useResult();

  /* ── Empty state ──────────────────────────────────────────────── */
  if (!result) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Analysis Results
          </h1>
          <p className="text-muted-foreground">
            No results to display — run an analysis first.
          </p>
        </div>

        <Card>
          <CardHeader className="items-center text-center">
            <div className="rounded-full border bg-muted p-4">
              <Search className="h-8 w-8 text-muted-foreground" />
            </div>
            <CardTitle>No Results Yet</CardTitle>
            <CardDescription>
              Submit a URL, email, or text on the Analyse page to see
              your results here.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <LinkButton href="/analyze">
              <Search className="mr-2 h-4 w-4" />
              Go to Analyse
            </LinkButton>
          </CardContent>
        </Card>
      </div>
    );
  }

  /* ── Results display ──────────────────────────────────────────── */
  const { response, content, contentType } = result;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Analysis Results
          </h1>
          <p className="text-muted-foreground">
            Detailed phishing detection report
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <ShareActions result={response} content={content} />
          <LinkButton href="/analyze" variant="outline" size="sm">
            <ArrowLeft className="mr-1.5 h-3.5 w-3.5" />
            New Analysis
          </LinkButton>
        </div>
      </div>

      {/* Verdict */}
      <VerdictBanner verdict={response.verdict} />

      <Separator />

      {/* Two-column grid: reasons + content */}
      <div className="grid gap-6 lg:grid-cols-2">
        <ReasonsList reasons={response.verdict.reasons} />
        <ContentPreview
          content={content}
          contentType={contentType}
          analyzedAt={response.analyzedAt}
          analysisTime={response.analysisTime}
        />
      </div>

      {/* OSINT intelligence cards */}
      <Separator />
      <div>
        <h2 className="mb-4 text-lg font-semibold tracking-tight">
          OSINT Intelligence
        </h2>
        <OsintCards osint={response.osint} />
      </div>

      {/* Feature extraction & detected tactics */}
      <Separator />
      <div>
        <h2 className="mb-4 text-lg font-semibold tracking-tight">
          Feature Extraction
        </h2>
        <FeatureCards features={response.features} />
      </div>
    </div>
  );
}
