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
import { THREAT_LEVEL_MAP, URL_SCORING_WEIGHTS, MODEL_METRICS } from "@/lib/constants";
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
    range: "0.00 – 0.29",
    action: "No action needed. The content appears legitimate.",
    iconComponent: ShieldCheck,
  },
  {
    level: "suspicious" as const,
    range: "0.30 – 0.49",
    action: "Exercise caution. Verify the sender and do not click unknown links.",
    iconComponent: ShieldAlert,
  },
  {
    level: "dangerous" as const,
    range: "0.50 – 0.69",
    action: "Likely phishing. Do not interact. Report to your IT department.",
    iconComponent: ShieldX,
  },
  {
    level: "critical" as const,
    range: "0.70 – 1.00",
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
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">How It Works</h1>
        <p className="text-muted-foreground">
          Understand the three-layer phishing detection pipeline powering
          PhishGuard.
        </p>
      </div>

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  1. Architecture Overview                                 */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4 rounded-lg border-l-4 border-primary/60 bg-primary/[0.02] px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">1</span>
          <BookOpen className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Architecture Overview</h2>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          Every submission passes through three independent analysis layers,
          then a trained <strong>XGBoost</strong> machine-learning model
          combines URL structural features and OSINT signals to produce
          a phishing probability.  NLP text analysis supplements the ML
          score for email and free-text inputs.
        </p>
        <PipelineDiagram />
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  2. Text Analysis                                         */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4 rounded-lg border-l-4 border-blue-500/60 bg-blue-500/[0.02] px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-blue-500 text-xs font-bold text-white">2</span>
          <FileText className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          <h2 className="text-lg font-semibold">Text Analysis</h2>
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
      <AnimatedSection className="space-y-4 rounded-lg border-l-4 border-amber-500/60 bg-amber-500/[0.02] px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-amber-500 text-xs font-bold text-white">3</span>
          <Link2 className="h-5 w-5 text-amber-600 dark:text-amber-400" />
          <h2 className="text-lg font-semibold">URL Feature Analysis</h2>
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
      <AnimatedSection className="space-y-4 rounded-lg border-l-4 border-green-500/60 bg-green-500/[0.02] px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-green-500 text-xs font-bold text-white">4</span>
          <Globe className="h-5 w-5 text-green-600 dark:text-green-400" />
          <h2 className="text-lg font-semibold">OSINT Enrichment</h2>
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
      <AnimatedSection className="space-y-4 rounded-lg border-l-4 border-purple-500/60 bg-purple-500/[0.02] px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-purple-500 text-xs font-bold text-white">5</span>
          <Calculator className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Scoring Algorithm</h2>
        </div>
        <p className="max-w-prose text-sm text-muted-foreground">
          The system uses an XGBoost gradient-boosted decision tree as its
          primary classifier. The model was trained on {MODEL_METRICS.trainSamples.toLocaleString()} labelled
          samples and evaluated on a held-out test set of {MODEL_METRICS.testSamples.toLocaleString()} samples.
        </p>

        {/* ML Model card */}
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle className="text-base">XGBoost ML Model</CardTitle>
            <CardDescription>
              {MODEL_METRICS.featureCount} features extracted per URL — 17 structural + 4 OSINT.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Model metrics */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { label: "Accuracy", value: MODEL_METRICS.accuracy },
                { label: "F1 Score", value: MODEL_METRICS.f1 },
                { label: "AUC-ROC", value: MODEL_METRICS.auc },
                { label: "PR-AUC", value: MODEL_METRICS.prAuc },
              ].map(({ label, value }) => (
                <div
                  key={label}
                  className="rounded-lg border bg-muted/50 p-3 text-center"
                >
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="text-xl font-bold tabular-nums text-foreground">
                    {(value * 100).toFixed(1)}%
                  </p>
                </div>
              ))}
            </div>

            {/* Architecture diagram */}
            <div className="space-y-3">
              <p className="text-sm font-medium">URL Analysis Architecture</p>
              <div className="rounded-lg border bg-muted/50 p-4 font-mono text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-foreground">
                    finalScore
                  </span>
                  <span className="text-muted-foreground">=</span>
                  <span className="text-purple-600 dark:text-purple-400">
                    mlPrediction × {URL_SCORING_WEIGHTS.ml}
                  </span>
                  <span className="text-muted-foreground">+</span>
                  <span className="text-blue-600 dark:text-blue-400">
                    nlpScore × {URL_SCORING_WEIGHTS.text}
                  </span>
                </div>
              </div>

              {/* Weight bar */}
              <div className="flex h-6 overflow-hidden rounded-full">
                <div
                  className="flex items-center justify-center bg-purple-500 text-[10px] font-medium text-white"
                  style={{ width: `${URL_SCORING_WEIGHTS.ml * 100}%` }}
                >
                  {URL_SCORING_WEIGHTS.ml * 100}%
                </div>
                <div
                  className="flex items-center justify-center bg-blue-500 text-[10px] font-medium text-white"
                  style={{ width: `${URL_SCORING_WEIGHTS.text * 100}%` }}
                >
                  {URL_SCORING_WEIGHTS.text * 100}%
                </div>
              </div>
              <div className="flex justify-between text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-purple-500" />
                  ML Model (XGBoost)
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  NLP Text Analysis
                </span>
              </div>
            </div>

            {/* Why ML-primary */}
            <div className="rounded-lg border bg-primary/5 p-4 text-sm text-muted-foreground space-y-2">
              <p className="font-medium text-foreground flex items-center gap-2">
                <Brain className="h-4 w-4 text-primary" />
                Why ML-primary scoring?
              </p>
              <p>
                The <strong>XGBoost model (85%)</strong> captures complex
                non-linear patterns across 21 features — URL structure,
                encoding, entropy, and OSINT signals — that simple heuristics
                miss. <strong>NLP analysis (15%)</strong> supplements with
                social-engineering cues from surrounding text. For email/text
                inputs without a URL, the system falls back to a weighted
                combination of NLP, URL, and OSINT scores.
              </p>
            </div>
          </CardContent>
        </Card>
      </AnimatedSection>

      <Separator />

      {/* ══════════════════════════════════════════════════════════ */}
      {/*  6. Threat Levels                                         */}
      {/* ══════════════════════════════════════════════════════════ */}
      <AnimatedSection className="space-y-4 rounded-lg border-l-4 border-rose-500/60 bg-rose-500/[0.02] px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-rose-500 text-xs font-bold text-white">6</span>
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
                      {meta.label}
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
