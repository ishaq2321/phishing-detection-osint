import type { Metadata } from "next";
import {
  AlertTriangle,
  BookOpen,
  Brain,
  Calculator,
  FileText,
  Fingerprint,
  Globe,
  Heart,
  KeyRound,
  Link2,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Siren,
  Timer,
  UserX,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { SCORING_WEIGHTS, THREAT_LEVEL_MAP } from "@/lib/constants";
import { PipelineDiagram } from "@/components/methodology";
import { AnimatedSection } from "@/components/ui/animatedSection";

export const metadata: Metadata = {
  title: "How It Works",
};

/* ------------------------------------------------------------------ */
/*  Static data for accordion sections                                */
/* ------------------------------------------------------------------ */

const TEXT_ANALYSIS_ITEMS = [
  {
    icon: Timer,
    label: "Urgency Patterns",
    description:
      "Detects time-pressure language like \"act now\", \"expires in 24 hours\", or \"immediate action required\" that attackers use to bypass critical thinking.",
  },
  {
    icon: KeyRound,
    label: "Credential Harvesting",
    description:
      "Identifies requests for passwords, SSNs, credit card numbers, or login credentials — the primary objective of most phishing attacks.",
  },
  {
    icon: Fingerprint,
    label: "Brand Impersonation",
    description:
      "Recognises mentions of well-known brands (PayPal, Microsoft, Apple) combined with suspicious context to flag spoofed communications.",
  },
  {
    icon: Siren,
    label: "Fear & Threat Tactics",
    description:
      "Flags threatening language such as \"your account will be suspended\" or \"legal action\" designed to create panic.",
  },
  {
    icon: UserX,
    label: "Suspicious Formatting",
    description:
      "Analyses unusual formatting patterns: excessive capitalisation, emoji abuse, broken grammar, and mixed character sets.",
  },
  {
    icon: Heart,
    label: "Emotional Manipulation",
    description:
      "Detects appeals to emotion — lottery wins, charity scams, romance fraud cues — that exploit trust and sympathy.",
  },
];

const URL_ANALYSIS_ITEMS = [
  {
    label: "Suspicious TLDs",
    description:
      "Flags top-level domains frequently abused by attackers (.xyz, .top, .club, .work) that are statistically correlated with phishing.",
  },
  {
    label: "IP Addresses in URL",
    description:
      "Detects raw IP addresses used instead of domain names — a classic obfuscation technique to hide the true destination.",
  },
  {
    label: "Subdomain Depth",
    description:
      "Analyses excessive subdomain nesting (e.g. login.secure.paypal.attacker.com) used to mimic legitimate domains.",
  },
  {
    label: "Homograph Attacks",
    description:
      "Identifies Internationalized Domain Names (IDN) using lookalike Unicode characters — e.g. 'pаypal.com' with a Cyrillic 'а'.",
  },
  {
    label: "URL Shorteners",
    description:
      "Detects use of URL shortening services (bit.ly, tinyurl) that hide the true destination link from the user.",
  },
  {
    label: "Path & Query Anomalies",
    description:
      "Flags excessively long paths, encoded characters, and suspicious query parameters commonly used in redirect chains.",
  },
];

const OSINT_ITEMS = [
  {
    label: "WHOIS Domain Age",
    description:
      "Queries WHOIS records to determine when the domain was registered. Newly registered domains (< 30 days) are a strong phishing indicator.",
  },
  {
    label: "Registrar Reputation",
    description:
      "Checks the domain registrar against known abuse-friendly providers and privacy-masked registrations.",
  },
  {
    label: "DNS Record Validation",
    description:
      "Verifies that A, MX, and NS records exist and are configured properly — missing records indicate disposable infrastructure.",
  },
  {
    label: "VirusTotal Score",
    description:
      "Cross-references the domain with VirusTotal's 70+ security vendor database for known malicious detections.",
  },
  {
    label: "AbuseIPDB Reports",
    description:
      "Checks the hosting IP against AbuseIPDB's crowd-sourced abuse report database for previous malicious activity.",
  },
  {
    label: "Blacklist Membership",
    description:
      "Queries multiple threat intelligence blacklists (Spamhaus, SURBL, PhishTank) for the domain and IP addresses.",
  },
];

/* ------------------------------------------------------------------ */
/*  Threat level table data                                           */
/* ------------------------------------------------------------------ */

const THREAT_LEVEL_TABLE = [
  {
    level: "safe" as const,
    range: "0.00 – 0.39",
    action: "No action needed. The content appears legitimate.",
    iconComponent: ShieldCheck,
  },
  {
    level: "suspicious" as const,
    range: "0.40 – 0.59",
    action: "Exercise caution. Verify the sender and do not click unknown links.",
    iconComponent: ShieldAlert,
  },
  {
    level: "dangerous" as const,
    range: "0.60 – 0.79",
    action: "Likely phishing. Do not interact. Report to your IT department.",
    iconComponent: ShieldX,
  },
  {
    level: "critical" as const,
    range: "0.80 – 1.00",
    action: "Confirmed threat. Block the sender, report immediately, and change any exposed credentials.",
    iconComponent: AlertTriangle,
  },
];

/* ------------------------------------------------------------------ */
/*  Page component                                                    */
/* ------------------------------------------------------------------ */

/**
 * How It Works page — explains the phishing detection methodology.
 *
 * Sections:
 * 1. Architecture overview with interactive pipeline diagram
 * 2. Text Analysis accordion with NLP tactic details
 * 3. URL Feature Analysis accordion
 * 4. OSINT Enrichment accordion
 * 5. Scoring Algorithm with visual formula
 * 6. Threat Levels table with thresholds & recommended actions
 */
export default function HowItWorksPage() {
  return (
    <div className="space-y-10">
      {/* ── Page header ──────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">How It Works</h1>
        <p className="text-muted-foreground">
          Understand the three-layer phishing detection pipeline powering
          PhishGuard.
        </p>
      </div>

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  1. Architecture Overview                                 */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4">
        <div className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Architecture Overview</h2>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          Every submission passes through three independent analysis layers.
          Each layer produces a partial risk score, which is combined using
          a weighted formula to produce a final confidence score and threat
          level classification.
        </p>
        <PipelineDiagram />
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  2. Text Analysis                                         */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4">
        <div className="flex items-center gap-2">
          <FileText className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          <h2 className="text-lg font-semibold">Text Analysis</h2>
          <Badge variant="secondary" className="ml-auto tabular-nums">
            Weight: {SCORING_WEIGHTS.text * 100}%
          </Badge>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          Natural Language Processing with spaCy analyses the textual content
          for known phishing indicators. The model detects six categories of
          manipulative language commonly found in phishing emails and messages.
        </p>
        <Accordion>
          {TEXT_ANALYSIS_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <AccordionItem key={item.label} value={item.label}>
                <AccordionTrigger>
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                    {item.label}
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <p className="text-muted-foreground pl-6">
                    {item.description}
                  </p>
                </AccordionContent>
              </AccordionItem>
            );
          })}
        </Accordion>
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  3. URL Feature Analysis                                  */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4">
        <div className="flex items-center gap-2">
          <Link2 className="h-5 w-5 text-amber-600 dark:text-amber-400" />
          <h2 className="text-lg font-semibold">URL Feature Analysis</h2>
          <Badge variant="secondary" className="ml-auto tabular-nums">
            Weight: {SCORING_WEIGHTS.url * 100}%
          </Badge>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          URLs are decomposed into structural features and compared against
          known attack patterns. This layer catches obfuscation techniques
          that text analysis alone would miss.
        </p>
        <Accordion>
          {URL_ANALYSIS_ITEMS.map((item) => (
            <AccordionItem key={item.label} value={item.label}>
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Link2 className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                  {item.label}
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <p className="text-muted-foreground pl-6">
                  {item.description}
                </p>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  4. OSINT Enrichment                                      */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-green-600 dark:text-green-400" />
          <h2 className="text-lg font-semibold">OSINT Enrichment</h2>
          <Badge variant="secondary" className="ml-auto tabular-nums">
            Weight: {SCORING_WEIGHTS.osint * 100}%
          </Badge>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          Open Source Intelligence queries external threat-intelligence
          services to gather contextual data about the domain and hosting
          infrastructure. This layer is the most expensive but provides
          strong ground-truth signals.
        </p>
        <Accordion>
          {OSINT_ITEMS.map((item) => (
            <AccordionItem key={item.label} value={item.label}>
              <AccordionTrigger>
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-green-600 dark:text-green-400" />
                  {item.label}
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <p className="text-muted-foreground pl-6">
                  {item.description}
                </p>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  5. Scoring Algorithm                                     */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4">
        <div className="flex items-center gap-2">
          <Calculator className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Scoring Algorithm</h2>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          The three partial scores are combined using a weighted linear
          formula. Each weight was determined through empirical evaluation
          against a labelled phishing dataset.
        </p>

        {/* Formula card */}
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle className="text-base">Weighted Score Formula</CardTitle>
            <CardDescription>
              The final confidence score is a value between 0 and 1.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Visual formula */}
            <div className="rounded-lg border bg-muted/50 p-4 font-mono text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-foreground">
                  finalScore
                </span>
                <span className="text-muted-foreground">=</span>
                <span className="text-blue-600 dark:text-blue-400">
                  textScore × {SCORING_WEIGHTS.text}
                </span>
                <span className="text-muted-foreground">+</span>
                <span className="text-amber-600 dark:text-amber-400">
                  urlScore × {SCORING_WEIGHTS.url}
                </span>
                <span className="text-muted-foreground">+</span>
                <span className="text-green-600 dark:text-green-400">
                  osintScore × {SCORING_WEIGHTS.osint}
                </span>
              </div>
            </div>

            {/* Weight breakdown */}
            <div className="space-y-3">
              <p className="text-sm font-medium">Weight Distribution</p>
              <div className="flex h-6 overflow-hidden rounded-full">
                <div
                  className="flex items-center justify-center bg-blue-500 text-[10px] font-medium text-white"
                  style={{ width: `${SCORING_WEIGHTS.text * 100}%` }}
                >
                  {SCORING_WEIGHTS.text * 100}%
                </div>
                <div
                  className="flex items-center justify-center bg-amber-500 text-[10px] font-medium text-white"
                  style={{ width: `${SCORING_WEIGHTS.url * 100}%` }}
                >
                  {SCORING_WEIGHTS.url * 100}%
                </div>
                <div
                  className="flex items-center justify-center bg-green-500 text-[10px] font-medium text-white"
                  style={{ width: `${SCORING_WEIGHTS.osint * 100}%` }}
                >
                  {SCORING_WEIGHTS.osint * 100}%
                </div>
              </div>
              <div className="flex justify-between text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  Text Analysis
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-amber-500" />
                  URL Features
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-green-500" />
                  OSINT
                </span>
              </div>
            </div>

            {/* Why these weights */}
            <div className="rounded-lg border bg-primary/5 p-4 text-sm text-muted-foreground space-y-2">
              <p className="font-medium text-foreground flex items-center gap-2">
                <Brain className="h-4 w-4 text-primary" />
                Why these weights?
              </p>
              <p>
                <strong>Text analysis (40%)</strong> captures the widest range
                of social-engineering signals. <strong>OSINT (35%)</strong>
                provides objective, ground-truth data from external services.
                <strong> URL features (25%)</strong> supplement the other layers
                with structural indicators that are cheap to compute and hard
                for attackers to circumvent.
              </p>
            </div>
          </CardContent>
        </Card>
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  6. Threat Levels                                         */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Threat Levels</h2>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          The final score maps to one of four threat levels. Each level
          includes a recommended action for the user.
        </p>

        <div className="grid gap-4 sm:grid-cols-2">
          {THREAT_LEVEL_TABLE.map(({ level, range, action, iconComponent: Icon }) => {
            const meta = THREAT_LEVEL_MAP[level];
            return (
              <Card key={level} className={meta.borderClass}>
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-2">
                    <Icon className={`h-5 w-5 ${meta.colorClass}`} />
                    <CardTitle className={`text-base ${meta.colorClass}`}>
                      {meta.icon} {meta.label}
                    </CardTitle>
                    <Badge variant="outline" className="ml-auto tabular-nums text-xs">
                      {range}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm">
                    {action}
                  </CardDescription>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </AnimatedSection>

      {/* ── CTA ─────────────────────────────────────────────────── */}
      <Separator />
      <AnimatedSection className="text-center space-y-3 pb-4">
        <h2 className="text-lg font-semibold">Ready to Try It?</h2>
        <p className="text-sm text-muted-foreground">
          Submit a URL, email, or text sample and see the pipeline in action.
        </p>
        <a
          href="/analyze"
          className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
        >
          <Search className="h-4 w-4" />
          Start Analysing
        </a>
      </AnimatedSection>
    </div>
  );
}
