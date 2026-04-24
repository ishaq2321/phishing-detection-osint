"use client";

/**
 * Dashboard — landing page showing key stats and quick-start actions.
 */

import { Shield, Search, Globe, ArrowRight, Zap } from "lucide-react";
import { Logo } from "@/components/brand";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/linkButton";
import { PageTransition } from "@/components/ui/pageTransition";
import { StaggerGroup, StaggerItem, FadeIn } from "@/components/ui/animations";
import { APP_NAME, APP_TAGLINE } from "@/lib/constants";

const highlights = [
  {
    icon: Search,
    title: "URL Analysis",
    description:
      "Deep inspection of URL structure, domain reputation, and deceptive patterns.",
  },
  {
    icon: Globe,
    title: "OSINT Enrichment",
    description:
      "Domain age, WHOIS data, DNS validation, and real-time blacklist checks.",
  },
  {
    icon: Shield,
    title: "NLP Detection",
    description:
      "Natural Language Processing identifies urgency, threats, and social engineering tactics.",
  },
] as const;

export default function DashboardPage() {
  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Hero / welcome section */}
        <FadeIn>
          <section className="flex flex-col items-center gap-4 text-center sm:items-start sm:text-left">
            <div className="flex items-center gap-3">
              <div className="rounded-full border bg-muted p-3">
                <Logo className="h-8 w-8" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
                  Welcome to {APP_NAME}
                </h1>
                <p className="text-muted-foreground">{APP_TAGLINE}</p>
              </div>
            </div>

            <div className="flex flex-wrap gap-3">
              <LinkButton href="/analyze" size="lg">
                <Zap className="mr-2 h-4 w-4" aria-hidden="true" />
                Analyse Now
              </LinkButton>
              <LinkButton href="/how-it-works" variant="outline" size="lg">
                How It Works
                <ArrowRight className="ml-2 h-4 w-4" aria-hidden="true" />
              </LinkButton>
            </div>
          </section>
        </FadeIn>

        {/* Quick-start cards */}
        <section>
          <h2 className="mb-4 text-lg font-semibold">Detection Capabilities</h2>
          <StaggerGroup className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {highlights.map(({ icon: Icon, title, description }) => (
              <StaggerItem key={title}>
                <Card>
                  <CardHeader className="flex flex-row items-center gap-3 space-y-0 pb-2">
                    <div className="rounded-lg bg-primary/10 p-2">
                      <Icon className="h-5 w-5 text-primary" aria-hidden="true" />
                    </div>
                    <CardTitle className="text-base">{title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{description}</CardDescription>
                  </CardContent>
                </Card>
              </StaggerItem>
            ))}
          </StaggerGroup>
        </section>

        {/* Status summary */}
        <FadeIn delay={0.3}>
          <section>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">System Overview</CardTitle>
                <CardDescription>
                  Real-time status of the phishing detection pipeline
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                <Badge variant="secondary">Scoring: text 55% · url 25% · osint 20%</Badge>
                <Badge variant="secondary">4 threat levels</Badge>
                <Badge variant="secondary">3 input modes</Badge>
              </CardContent>
            </Card>
          </section>
        </FadeIn>
      </div>
    </PageTransition>
  );
}
