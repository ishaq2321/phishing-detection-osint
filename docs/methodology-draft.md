# Methodology and Preliminary Results

## BSc Thesis — Phishing Detection Using OSINT-Enhanced Features

**Author:** Ishaq Muhammad (PXPRGK)
**Supervisor:** Md. Easin Arafat
**Institution:** Eötvös Loránd University (ELTE) — Faculty of Informatics

---

## 1. System Architecture

### 1.1 Overview

PhishGuard is a full-stack phishing detection system that employs a three-layer
analysis pipeline. Each layer operates independently, producing a partial risk
score that is combined using a weighted linear formula to generate a final
confidence score and threat-level classification.

```
┌──────────────────────────────────────────────────────────────┐
│                        User Interface                        │
│           Next.js 16 · React 19 · Tailwind CSS v4            │
└──────────────────────┬───────────────────────────────────────┘
                       │  REST API (JSON)
┌──────────────────────▼───────────────────────────────────────┐
│                      FastAPI Backend                          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Text/NLP    │  │  URL Feature │  │  OSINT           │   │
│  │  Analysis    │  │  Extraction  │  │  Enrichment      │   │
│  │  (spaCy)     │  │  (heuristic) │  │  (WHOIS/DNS/     │   │
│  │              │  │              │  │   VirusTotal/     │   │
│  │  Weight: 40% │  │  Weight: 25% │  │   AbuseIPDB)     │   │
│  │              │  │              │  │  Weight: 35%      │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────┘   │
│         │                 │                  │               │
│  ┌──────▼─────────────────▼──────────────────▼───────────┐   │
│  │                   Scoring Engine                       │   │
│  │  finalScore = text×0.40 + url×0.25 + osint×0.35       │   │
│  │  Threat Level: safe | suspicious | dangerous | critical│   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Data Flow

1. **Input Submission:** The user provides a URL, email body, or free-text via
   the frontend.
2. **Content-Type Detection:** The backend's `AnalysisOrchestrator`
   auto-detects the content type (URL, email, text) or uses the user-specified
   type.
3. **Parallel Analysis:** Three analysis layers run concurrently:
   - **NLP Analysis** (`TextAnalyzer`): spaCy NLP pipeline detects social
     engineering patterns.
   - **URL Feature Extraction** (`UrlAnalyzer` + `FeatureExtractor`): Parses
     URL structure and extracts heuristic features.
   - **OSINT Enrichment** (`WhoisLookup` + `DnsChecker` +
     `ReputationChecker`): Queries external intelligence sources.
4. **Score Calculation:** The `Scorer` combines partial scores with configured
   weights.
5. **Verdict Generation:** A threat level is assigned and the full result is
   returned to the frontend.
6. **Presentation:** The results page displays the verdict banner, confidence
   score, OSINT cards, feature summary, and interactive score visualisations.

---

## 2. Implementation Methodology

### 2.1 Technology Stack

| Layer       | Technology          | Version   | Justification                              |
|-------------|---------------------|-----------|--------------------------------------------|
| Frontend    | Next.js (App Router)| 16.1.6    | React 19, SSR support, file-based routing  |
| UI Library  | shadcn/ui + Base UI | v4        | Accessible, composable, theme-aware        |
| Styling     | Tailwind CSS        | v4        | Utility-first, responsive, dark mode       |
| Animation   | Motion (Framer)     | v12+      | Smooth transitions, layout animations      |
| Charts      | Recharts            | 3.8.0     | Declarative SVG charts for score display   |
| Data Tables | TanStack Table      | 8.21.3    | Headless, sortable, filterable tables      |
| Backend     | FastAPI             | 0.109.0   | Async Python API, auto-generated OpenAPI   |
| NLP         | spaCy               | 3.7.2     | Industrial-grade NLP, custom pipelines     |
| ML          | scikit-learn        | 1.4.0     | Feature extraction and scoring utilities   |
| OSINT       | python-whois        | 0.8.0     | WHOIS domain registration data             |
| DNS         | dnspython           | 2.5.0     | DNS record resolution and validation       |
| HTTP        | aiohttp             | 3.9.1     | Async HTTP for external API calls          |
| Config      | pydantic-settings   | 2.1.0     | Type-safe configuration from environment   |
| Logging     | structlog           | 24.1.0    | Structured JSON logging                    |

### 2.2 Design Patterns

1. **Protocol-Based Abstraction:** The `BaseAnalyzer` abstract class defines a
   common interface (`analyze`, `extractFeatures`, `calculateScore`) that all
   analysis modules implement, enabling polymorphic dispatch and easy extension.

2. **Dependency Injection:** The `AnalysisOrchestrator` receives its analysers
   and OSINT collectors as constructor parameters, enabling unit testing with
   mocks and allowing alternative implementations.

3. **Separation of Concerns:** The codebase is organised into four distinct
   modules (`api`, `ml`, `osint`, `analyzer`), each responsible for a single
   domain. Cross-module communication happens through well-defined Pydantic
   schemas.

4. **Client-Side State Management:** The frontend uses React Context
   (`ResultsContext`) for cross-page state and localStorage-backed stores for
   persistent settings and history.

5. **Dynamic Imports:** Heavy visualisation components (Recharts, TanStack
   Table) are lazily loaded via `next/dynamic` with `ssr: false` to minimise
   initial bundle size.

### 2.3 Development Workflow

- **Version Control:** Git with GitHub hosting, milestone-based issue tracking.
- **Issue Tracking:** 57 issues across 4 milestones, each linked to commits.
- **Code Quality:** Two custom MCP servers:
  - `thesis-project-manager.py` — milestone tracking, issue management,
    git commit linkage
  - `thesis-code-quality.py` — dead code detection, syntax checking,
    function search, automated test execution
- **Testing Pipeline:** pytest (backend, 593 tests), Jest (frontend unit,
  128 tests), Playwright (E2E, 28 tests)

---

## 3. NLP Feature Extraction

### 3.1 spaCy Pipeline

The `TextAnalyzer` class loads a spaCy English model (`en_core_web_sm`) and
applies a custom pipeline to detect six categories of phishing indicators:

| Category               | Indicators Detected                                  | Example Patterns                                    |
|------------------------|------------------------------------------------------|-----------------------------------------------------|
| **Urgency Patterns**   | Time-pressure language                               | "act now", "expires in 24 hours", "immediately"     |
| **Credential Requests**| Requests for sensitive information                   | "verify your password", "enter your SSN"            |
| **Brand Impersonation**| Mentions of well-known brands in suspicious context  | "PayPal", "Microsoft", "Apple" with action requests |
| **Fear/Threats**       | Threatening language to create panic                  | "account will be suspended", "legal action"         |
| **Suspicious Format**  | Unusual formatting and character use                 | Excessive caps, emoji abuse, mixed character sets    |
| **Emotional Appeals**  | Exploitative emotional language                      | "lottery winner", "charity donation", "inheritance"  |

### 3.2 Scoring

Each detected indicator contributes to the text risk score. The score is
normalised to the range [0, 1]. Multiple indicators of different categories
increase the score more than repeated indicators of the same type, modelling
the observation that diverse phishing signals are stronger evidence of
malicious intent.

---

## 4. OSINT Integration

### 4.1 Data Sources

| Source         | Module              | Data Retrieved                                       |
|----------------|---------------------|------------------------------------------------------|
| **WHOIS**      | `WhoisLookup`       | Domain age, registrar, registration/expiry dates, privacy status |
| **DNS**        | `DnsChecker`        | A, AAAA, MX, NS, TXT, CNAME records; CDN detection  |
| **VirusTotal** | `ReputationChecker` | Multi-vendor malicious detection count               |
| **AbuseIPDB**  | `ReputationChecker` | Abuse confidence score for hosting IP                |

### 4.2 Enrichment Process

1. Extract the domain from the submitted URL or email sender address.
2. Perform an async WHOIS lookup with retry logic and timeout handling.
3. Parse the raw WHOIS response to extract structured data (dates, contacts,
   privacy flags).
4. Resolve DNS records to validate the domain's infrastructure.
5. Query VirusTotal and AbuseIPDB for reputation scores.
6. Aggregate all OSINT data into an `OsintResult` Pydantic model.

### 4.3 Feature Derivation

From the raw OSINT data, the following features are derived:

- **Domain Age Score:** Domains < 30 days old receive maximum risk; score
  decays logarithmically to zero at ~2 years.
- **DNS Validity Score:** Missing A/MX records increase risk; CDN presence
  is a positive signal.
- **Blacklist Score:** Binary flag — any blacklist membership is a strong
  negative signal.
- **Privacy Score:** Private WHOIS registration adds moderate risk.
- **Reputation Score:** Normalised aggregate from VirusTotal and AbuseIPDB.

---

## 5. Scoring Algorithm

### 5.1 Mathematical Formulation

The final confidence score is computed as a weighted linear combination:

$$S_{final} = w_{text} \cdot S_{text} + w_{url} \cdot S_{url} + w_{osint} \cdot S_{osint}$$

Where:
- $S_{text} \in [0, 1]$ — NLP text analysis score
- $S_{url} \in [0, 1]$ — URL structural feature score
- $S_{osint} \in [0, 1]$ — OSINT enrichment score
- $w_{text} = 0.40$, $w_{url} = 0.25$, $w_{osint} = 0.35$

### 5.2 Weight Justification

| Weight   | Value | Rationale                                                   |
|----------|-------|-------------------------------------------------------------|
| Text     | 40%   | Captures the widest range of social engineering signals      |
| OSINT    | 35%   | Provides objective ground-truth from external sources        |
| URL      | 25%   | Structural indicators cheap to compute, hard to circumvent   |

### 5.3 Threat-Level Classification

| Threat Level  | Score Range  | Description                                          |
|---------------|--------------|------------------------------------------------------|
| **Safe**       | 0.00 – 0.39 | No significant phishing indicators detected          |
| **Suspicious** | 0.40 – 0.59 | Some indicators present; exercise caution             |
| **Dangerous**  | 0.60 – 0.79 | Strong phishing indicators; avoid interaction         |
| **Critical**   | 0.80 – 1.00 | Confirmed phishing threat; immediate action required  |

---

## 6. Frontend Architecture

### 6.1 Component Hierarchy

```
RootLayout
├── ThemeProvider (next-themes)
├── ResultsProvider (analysis context)
├── KeyboardShortcutsProvider
└── AppLayout
    ├── AppSidebar (navigation, branding)
    ├── AppHeader (health status, theme toggle)
    └── Main Content
        ├── DashboardPage (/)
        ├── AnalyzePage (/analyze)
        │   ├── InputModeSelector (URL/Email/Text)
        │   ├── ContentInput (adaptive form)
        │   └── AnalysisProgress (step animation)
        ├── BatchAnalyzePage (/analyze/batch)
        │   ├── BatchInput (multi-URL textarea + file upload)
        │   └── BatchResults (summary + table + export)
        ├── ResultsPage (/results)
        │   ├── VerdictBanner (animated score + threat level)
        │   ├── ReasonsList (indicator cards)
        │   ├── OsintCards (6 intelligence cards)
        │   ├── FeatureCards (extraction summary)
        │   ├── ScoreBreakdown (donut chart)
        │   ├── ThreatGauge (radial gauge)
        │   └── ConfidenceBar (horizontal bar)
        ├── HistoryPage (/history)
        │   └── HistoryTable (sortable, filterable, paginated)
        ├── HowItWorksPage (/how-it-works)
        │   ├── PipelineDiagram (interactive)
        │   └── Methodology Accordions
        └── SettingsPage (/settings)
            ├── API Configuration
            ├── Display Preferences
            └── History Management
```

### 6.2 State Management

| Store              | Mechanism       | Purpose                                      |
|--------------------|-----------------|----------------------------------------------|
| `ResultsContext`   | React Context   | Cross-page analysis result sharing            |
| `historyStore`     | localStorage    | Persistent analysis history (max 100 entries) |
| `settingsStore`    | localStorage    | User preferences (API URL, theme, detail)     |
| `useHealth`        | Polling hook    | Backend health status (30s interval)          |

### 6.3 Key Features

- **10 routes** with file-based App Router
- **Dark/light/system** theme support with persistence
- **Keyboard shortcuts** (/, Ctrl+Enter, Ctrl+H, ?, Escape, etc.)
- **Responsive design** with mobile bottom navigation
- **Batch analysis** for up to 50 URLs with parallel processing
- **Export** history to CSV/JSON
- **Accessibility** with ARIA labels, skip links, and focus management
- **Custom SVG branding** (logo, favicon, PWA icons)

---

## 7. Preliminary Results

### 7.1 Test Coverage

| Test Layer         | Framework     | Test Count | Status    |
|--------------------|---------------|------------|-----------|
| Backend Unit       | pytest        | 593        | ✅ Passing |
| Frontend Unit      | Jest + RTL    | 128        | ✅ Passing |
| Frontend E2E       | Playwright    | 28         | ✅ Passing |
| **Total**          |               | **749**    | ✅ All Pass|

### 7.2 Backend Test Breakdown

| Module           | Test Files | Test Functions | Coverage Areas                         |
|------------------|------------|----------------|----------------------------------------|
| API Router       | 2          | ~80            | All 9 endpoints, validation, errors    |
| Feature Extractor| 1          | ~50            | URL parsing, pattern detection         |
| Scorer           | 1          | ~45            | Weight calculation, risk levels        |
| URL Analyzer     | 1          | ~40            | Structural analysis, brand detection   |
| WHOIS Lookup     | 1          | ~60            | Domain queries, retry logic, parsing   |
| DNS Checker      | 1          | ~55            | Record resolution, CDN detection       |
| Reputation       | 1          | ~50            | VirusTotal, AbuseIPDB integration      |
| NLP Analyzer     | 1          | ~50            | spaCy pipeline, indicator detection    |
| Config           | 1          | ~30            | Settings, environment handling         |
| Schemas          | 3          | ~45            | Pydantic model validation              |
| History Store    | 1          | ~28            | CRUD, pagination, FIFO eviction        |
| Integration      | 5          | ~60            | Full pipeline, cross-module flows      |

### 7.3 Frontend Test Coverage

**Unit Tests (128 across 10 suites):**
- API client and endpoints (fetch mocking, error handling)
- Error classes (NetworkError, ValidationError, ApiError)
- History and settings localStorage stores
- Component rendering (VerdictBanner, OsintCards, FeatureCards)
- Constants validation
- Toast notification helpers

**E2E Tests (28 across 11 suites):**
- URL analysis flow (safe + dangerous verdicts)
- Email analysis flow (with/without optional fields)
- Navigation (sidebar links, dashboard CTAs)
- History (view, delete entries)
- Theme toggle (switching + persistence)
- Settings (about info, API connection, preferences, reset)
- Error handling (unreachable backend, validation)
- Responsive design (mobile viewport)
- Keyboard navigation (tab focus, form submission)
- Empty states (history, results)

### 7.4 Performance Metrics

| Metric                        | Value          | Notes                          |
|-------------------------------|----------------|--------------------------------|
| Backend test suite runtime    | ~150 seconds   | 593 tests, sequential          |
| Frontend unit test runtime    | ~5 seconds     | 128 tests, parallel            |
| Frontend E2E test runtime     | ~45 seconds    | 28 tests, 4 workers            |
| Frontend build time           | ~8 seconds     | 10 routes, static generation   |
| Frontend bundle (compressed)  | Optimised      | Dynamic imports for charts     |

### 7.5 Code Metrics

| Metric                   | Count  |
|--------------------------|--------|
| Backend source files     | 20     |
| Frontend source files    | ~50    |
| Backend modules          | 4 (api, ml, osint, analyzer) |
| Frontend routes          | 10     |
| API endpoints            | 9      |
| GitHub issues (closed)   | 54/57  |
| Git commits              | 50+    |

---

## 8. Evaluation Plan (Milestone 4)

### 8.1 Accuracy Evaluation

The system will be evaluated against a labelled dataset of known phishing and
legitimate URLs/emails:

1. **Dataset:** Curate 200+ samples (100 phishing, 100 legitimate) from:
   - PhishTank verified phishing URLs
   - Alexa Top 1000 for legitimate URLs
   - Public phishing email corpuses

2. **Metrics:**
   - Accuracy, Precision, Recall, F1-Score
   - False positive rate (legitimate content flagged as phishing)
   - False negative rate (phishing content missed)

3. **Ablation Study:** Evaluate the contribution of each layer independently:
   - Text-only scoring
   - URL-only scoring
   - OSINT-only scoring
   - Combined scoring (full pipeline)

### 8.2 Performance Evaluation

- Response time distribution for single URL analysis
- Throughput for batch analysis (50 URLs)
- Memory consumption under load
- External API latency impact (WHOIS, VirusTotal, AbuseIPDB)

### 8.3 Usability Evaluation

- Lighthouse accessibility score
- Keyboard navigability audit
- Mobile responsiveness on 3 viewport sizes
- User comprehension of threat levels and recommendations

---

*Draft prepared for Milestone 3 submission — March 2026*
