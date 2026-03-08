import type { Metadata } from "next";
import { BookOpen, ArrowRight } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { SCORING_WEIGHTS, THREAT_LEVEL_MAP } from "@/lib/constants";

export const metadata: Metadata = {
  title: "How It Works",
};

/**
 * How It Works page — explains the phishing detection methodology.
 * Expanded content will come in Issue #37, but this provides a solid
 * foundation with real data from constants.
 */
export default function HowItWorksPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">How It Works</h1>
        <p className="text-muted-foreground">
          Understand the three-layer phishing detection pipeline powering
          PhishGuard.
        </p>
      </div>

      {/* Pipeline overview */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold">Detection Pipeline</h2>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge>Input</Badge>
          <ArrowRight className="h-4 w-4 text-muted-foreground" />
          <Badge variant="secondary">
            Text Analysis ({SCORING_WEIGHTS.text * 100}%)
          </Badge>
          <span className="text-muted-foreground">+</span>
          <Badge variant="secondary">
            URL Features ({SCORING_WEIGHTS.url * 100}%)
          </Badge>
          <span className="text-muted-foreground">+</span>
          <Badge variant="secondary">
            OSINT ({SCORING_WEIGHTS.osint * 100}%)
          </Badge>
          <ArrowRight className="h-4 w-4 text-muted-foreground" />
          <Badge>Verdict</Badge>
        </div>
      </section>

      <Separator />

      {/* Threat levels */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold">Threat Levels</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {(Object.entries(THREAT_LEVEL_MAP) as [string, typeof THREAT_LEVEL_MAP.safe][]).map(
            ([key, meta]) => (
              <Card key={key} className={meta.borderClass}>
                <CardHeader className="pb-2">
                  <CardTitle className={`text-base ${meta.colorClass}`}>
                    {meta.icon} {meta.label}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription>
                    {key === "safe" && "Score 0 – 0.39 · No action needed."}
                    {key === "suspicious" && "Score 0.4 – 0.59 · Exercise caution."}
                    {key === "dangerous" && "Score 0.6 – 0.79 · Likely phishing."}
                    {key === "critical" && "Score 0.8 – 1.0 · Confirmed threat."}
                  </CardDescription>
                </CardContent>
              </Card>
            ),
          )}
        </div>
      </section>

      <Separator />

      {/* Detailed methodology placeholder */}
      <section>
        <Card>
          <CardHeader className="items-center text-center">
            <div className="rounded-full border bg-muted p-4">
              <BookOpen className="h-8 w-8 text-muted-foreground" />
            </div>
            <CardTitle>Full Methodology</CardTitle>
            <CardDescription>
              Detailed NLP tactics, OSINT data sources, and scoring algorithm
              breakdown will be expanded in an upcoming issue.
            </CardDescription>
          </CardHeader>
        </Card>
      </section>
    </div>
  );
}
