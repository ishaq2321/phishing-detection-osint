"use client";

/**
 * Results page — displays the full analysis output.
 *
 * Reads the latest result from `ResultsContext`.  If no result is
 * available (e.g. direct navigation), shows an empty state with a
 * link back to the Analyse page.
 */

import dynamic from "next/dynamic";
import { ArrowLeft, Search } from "lucide-react";
import { LinkButton } from "@/components/ui/linkButton";
import { Separator } from "@/components/ui/separator";
import { PageTransition } from "@/components/ui/pageTransition";
import {
  FadeIn,
  SlideUp,
  ScaleIn,
  StaggerGroup,
  StaggerItem,
} from "@/components/ui/animations";
import {
  VerdictBanner,
  ReasonsList,
  ContentPreview,
  ShareActions,
  OsintCards,
  FeatureCards,
} from "@/components/results";
import { useResult } from "@/lib/resultsContext";
import { getSetting, type ResultsDetailLevel } from "@/lib/storage/settingsStore";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/* Dynamically import heavy chart components to reduce initial bundle */
const ScoreBreakdown = dynamic(
  () => import("@/components/charts/scoreBreakdown").then((m) => m.ScoreBreakdown),
  { ssr: false },
);
const ThreatGauge = dynamic(
  () => import("@/components/charts/threatGauge").then((m) => m.ThreatGauge),
  { ssr: false },
);
const ConfidenceBar = dynamic(
  () => import("@/components/charts/confidenceBar").then((m) => m.ConfidenceBar),
  { ssr: false },
);

export default function ResultsPage() {
  const { result } = useResult();
  const detailLevel: ResultsDetailLevel =
    typeof window !== "undefined" ? getSetting("resultsDetailLevel") : "detailed";

  const showReasons = detailLevel !== "simple";
  const showContent = detailLevel !== "simple";
  const showOsint = detailLevel !== "simple";
  const showFeatures = detailLevel === "expert";

  /* ── Empty state ──────────────────────────────────────────────── */
  if (!result) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
            Analysis Results
          </h1>
          <p className="text-sm text-muted-foreground sm:text-base">
            No results to display — run an analysis first.
          </p>
        </div>

        <Card>
          <CardHeader className="items-center text-center">
            <div className="rounded-full border bg-muted p-4">
              <Search className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
            </div>
            <CardTitle>No Results Yet</CardTitle>
            <CardDescription>
              Submit a URL, email, or text on the Analyse page to see
              your results here.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <LinkButton href="/analyze">
              <Search className="mr-2 h-4 w-4" aria-hidden="true" />
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
    <PageTransition>
      <div className="space-y-6" aria-live="polite" aria-atomic="false">
        {/* Page header */}
        <FadeIn>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
                Analysis Results
              </h1>
        <p className="text-sm text-muted-foreground sm:text-base">
          {detailLevel === "simple"
            ? "Phishing detection verdict"
            : detailLevel === "expert"
              ? "Comprehensive phishing detection report"
              : "Detailed phishing detection report"}
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
        </FadeIn>

        {/* Verdict — dramatic reveal */}
        <ScaleIn delay={0.15} duration={0.5}>
          <VerdictBanner verdict={response.verdict} />
        </ScaleIn>

        <Separator />

      {/* Two-column grid: reasons + content */}
      {(showReasons || showContent) && (
        <StaggerGroup className="grid gap-6 lg:grid-cols-2">
          {showReasons && (
            <StaggerItem>
              <ReasonsList reasons={response.verdict.reasons} />
            </StaggerItem>
          )}
          {showContent && (
            <StaggerItem>
              <ContentPreview
                content={content}
                contentType={contentType}
                analyzedAt={response.analyzedAt}
                analysisTime={response.analysisTime}
              />
            </StaggerItem>
          )}
        </StaggerGroup>
      )}

      {/* OSINT intelligence cards */}
      {showOsint && (
        <>
          <Separator />
          <SlideUp delay={0.1}>
            <div>
              <h2 className="mb-4 text-lg font-semibold tracking-tight">
                OSINT Intelligence
              </h2>
              <OsintCards osint={response.osint} />
            </div>
          </SlideUp>
        </>
      )}

      {/* Feature extraction & detected tactics */}
      {showFeatures && (
        <>
          <Separator />
          <SlideUp delay={0.15}>
            <div>
              <h2 className="mb-4 text-lg font-semibold tracking-tight">
                Feature Extraction
              </h2>
              <FeatureCards features={response.features} />
            </div>
          </SlideUp>
        </>
      )}

      {/* Score visualisation */}
      <Separator />
      <SlideUp delay={0.2}>
        <div>
          <h2 className="mb-4 text-lg font-semibold tracking-tight">
            Score Visualisation
          </h2>
          <StaggerGroup className="grid gap-4 lg:grid-cols-3">
            <StaggerItem>
              <ScoreBreakdown
                confidenceScore={response.verdict.confidenceScore}
              />
            </StaggerItem>
            <StaggerItem>
              <ThreatGauge score={response.verdict.confidenceScore} />
            </StaggerItem>
            <StaggerItem>
              <ConfidenceBar
                confidenceScore={response.verdict.confidenceScore}
                threatLevel={response.verdict.threatLevel}
              />
            </StaggerItem>
          </StaggerGroup>
        </div>
      </SlideUp>
      </div>
    </PageTransition>
  );
}
