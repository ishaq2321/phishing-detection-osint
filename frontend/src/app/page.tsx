import { Shield, Search, Globe, ArrowRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/linkButton";
import { ThemeToggle } from "@/components/layout/themeToggle";
import { APP_NAME, APP_TAGLINE, APP_VERSION } from "@/lib/constants";

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

export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col">
      {/* ── Top bar ──────────────────────────────────────────── */}
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur-sm">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-lg font-semibold">{APP_NAME}</span>
            <Badge variant="secondary" className="hidden sm:inline-flex">
              v{APP_VERSION}
            </Badge>
          </div>
          <ThemeToggle />
        </div>
      </header>

      {/* ── Hero ─────────────────────────────────────────────── */}
      <main id="main-content" className="flex flex-1 flex-col">
        <section className="mx-auto flex max-w-3xl flex-col items-center gap-6 px-4 pt-20 pb-12 text-center">
          <div className="rounded-full border bg-muted p-4">
            <Shield className="h-12 w-12 text-primary" />
          </div>

          <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
            {APP_NAME}
          </h1>

          <p className="max-w-lg text-lg text-muted-foreground">
            {APP_TAGLINE}. Analyse URLs, emails, and text to detect phishing
            attacks with real-time OSINT-powered threat scoring.
          </p>

          <div className="flex flex-wrap justify-center gap-3">
            <LinkButton href="/analyze" size="lg">
              Start Analysing
              <ArrowRight className="ml-2 h-4 w-4" />
            </LinkButton>
            <LinkButton href="/how-it-works" variant="outline" size="lg">
              How It Works
            </LinkButton>
          </div>
        </section>

        {/* ── Feature cards ──────────────────────────────────── */}
        <section className="mx-auto grid max-w-5xl gap-6 px-4 pb-20 sm:grid-cols-3">
          {highlights.map(({ icon: Icon, title, description }) => (
            <Card key={title} className="border bg-card/60 backdrop-blur-sm">
              <CardContent className="flex flex-col items-center gap-3 pt-6 text-center">
                <div className="rounded-lg bg-primary/10 p-3">
                  <Icon className="h-6 w-6 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">{title}</h2>
                <p className="text-sm text-muted-foreground">{description}</p>
              </CardContent>
            </Card>
          ))}
        </section>
      </main>

      {/* ── Footer ───────────────────────────────────────────── */}
      <footer className="border-t py-6 text-center text-sm text-muted-foreground">
        <p>
          {APP_NAME} &copy; {new Date().getFullYear()} &middot; Ishaq Muhammad
          (PXPRGK) &middot; ELTE Faculty of Informatics
        </p>
      </footer>
    </div>
  );
}
