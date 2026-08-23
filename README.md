# PhishGuard — Phishing Detection Using OSINT-Enhanced Features

[![CI](https://github.com/ishaq2321/phishing-detection-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/ishaq2321/phishing-detection-osint/actions/workflows/ci.yml)

BSc Thesis Project — Faculty of Informatics, Eötvös Loránd University (ELTE)
**Defended June 24, 2026 — Grade: 5 (Excellent)**

## Live Demo

| Service   | URL                                          |
|-----------|----------------------------------------------|
| Frontend  | https://project-4soy4.vercel.app             |
| Backend   | https://phishguard-api-upl2.onrender.com     |
| API Docs  | https://phishguard-api-upl2.onrender.com/docs |

## Overview

PhishGuard is a full-stack phishing detection system that combines a
**trained XGBoost ML model**, **Natural Language Processing (NLP)**,
**URL structural analysis**, and **Open-Source Intelligence (OSINT)** to
detect phishing threats in URLs, emails, and free-text content.

The system uses an **ML-primary scoring architecture**: for URL analysis,
the XGBoost classifier (23,374 training samples, 21 features) contributes
85% of the final score; NLP text analysis contributes the remaining 15%.

### Key Results

| Metric            | Value                          |
|-------------------|--------------------------------|
| Accuracy          | 96.45%                         |
| F1 Score          | 96.39%                         |
| AUC-ROC           | 99.41%                         |
| PR-AUC            | 99.48%                         |
| Feature pipeline  | 17 URL structural + 4 OSINT    |
| NLP detectors     | 10 social-engineering tactics  |
| Automated tests   | **1,177** (1,001 pytest · 145 Jest · 31 Playwright) |

### Feature Highlights

- **Multiple input modes** — URL, email (subject/sender/body), free-text
- **Batch analysis** — `POST /api/analyze/batch` accepts up to 50 mixed URL/email items per request with concurrent execution and per-item partial failures
- **Raw `.eml` ingestion** — `POST /api/ingest/email` parses forwarded RFC 822/MIME files (1 MB cap, 413/422 guard rails)
- **OSINT enrichment** — WHOIS domain age, DNS validation, VirusTotal, AbuseIPDB (all optional; graceful degradation without keys)
- **Model drift monitoring** — per-feature PSI scores vs a rolling reference window, exposed via `GET /api/model/drift` and Prometheus gauges (zero external dependencies)
- **Deterministic explanations** — template-based "Why?" panel for URL verdicts: severity-ranked signals derived from feature values + OSINT, weighted by training-time SHAP importance (no LLM, fully auditable)
- **Explainable verdicts** — SHAP feature attributions plus human-readable reasons
- **Full-featured UI** — dark/light theme, keyboard shortcuts, responsive design, configurable detail levels (Simple / Detailed / Expert)
- **Production hardening** — OWASP security headers, rate limiting, optional `X-Api-Key` auth, structured JSON logs with `X-Request-ID`, deep `/api/health` probes, Prometheus `/metrics`

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Frontend (Next.js 16)                        │
│           8 routes · React 19 · Tailwind CSS v4              │
└──────────────────────┬───────────────────────────────────────┘
                       │ REST API (JSON)
┌──────────────────────▼───────────────────────────────────────┐
│                  Backend (FastAPI)                            │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Text/NLP    │  │  URL Feature │  │  OSINT           │   │
│  │  Analysis    │  │  Extraction  │  │  Enrichment      │   │
│  │  (spaCy)     │  │  (21 feats)  │  │  (WHOIS/DNS/    │   │
│  │  10 tactics  │  │  17 struct + │  │   VirusTotal/    │   │
│  │  15%         │  │  4 OSINT     │  │   AbuseIPDB)    │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────┘   │
│         │                 │                  │               │
│  ┌──────▼─────────────────▼──────────────────▼───────────┐   │
│  │            XGBoost ML Classifier (85%)                 │   │
│  │  Acc=96.45% · F1=96.39% · AUC=99.41% · PR-AUC=99.48% │   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer      | Technology                                             |
|------------|--------------------------------------------------------|
| Frontend   | Next.js 16.1, React 19, TypeScript, Tailwind CSS v4    |
| UI         | shadcn/ui, Recharts, TanStack Table, Motion            |
| Backend    | Python 3.10, FastAPI 0.109, Pydantic 2                 |
| NLP        | spaCy 3.7 (`en_core_web_sm`)                           |
| ML         | XGBoost 3.2, SHAP 0.49, Optuna 4.9, scikit-learn 1.4   |
| OSINT      | python-whois, dnspython, aiohttp/httpx                 |
| Testing    | pytest 9, Jest 30, Playwright 1.62                     |
| CI/CD      | GitHub Actions (pytest + Jest + Playwright on push/PR) |
| Deployment | Docker Compose (local), Vercel + Render (cloud)        |

## Quick Start

### Option A — Docker (recommended)

```bash
git clone https://github.com/ishaq2321/phishing-detection-osint.git
cd phishing-detection-osint
docker compose up --build
```

Then open:

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

Optional OSINT keys can be passed via environment:

```bash
VIRUSTOTAL_API_KEY=xxx ABUSEIPDB_API_KEY=yyy docker compose up --build
```

### Option B — Manual Setup

**Prerequisites:** Python ≥ 3.10, Node.js ≥ 20, npm ≥ 10.

1. **Backend**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # Linux/macOS (.venv\Scripts\activate on Windows)
   pip install -r backend/requirements.txt
   python -m spacy download en_core_web_sm

   cp backend/.env.example backend/.env   # optional: add VirusTotal/AbuseIPDB keys

   # Run from the repository root (the app uses absolute backend.* imports):
   uvicorn backend.main:app --reload --port 8000
   ```

2. **Frontend** (second terminal)

   ```bash
   cd frontend
   npm install
   cp .env.example .env.local       # optional: point at a non-local backend
   npm run dev
   ```

3. Open **http://localhost:3000**.

## API Endpoints

| Method   | Path                       | Description                                                        |
|----------|----------------------------|--------------------------------------------------------------------|
| `GET`    | `/api/health/live`         | Liveness probe (cheap)                                             |
| `GET`    | `/api/health/ready`        | Readiness probe (deep DNS + ML checks)                             |
| `GET`    | `/api/model/status`        | ML model status & feature info                                     |
| `GET`    | `/api/model/drift`         | Feature drift report (PSI per feature, stable/moderate/significant) |
| `POST`   | `/api/analyze`             | Analyse any content (auto-detect type)                             |
| `POST`   | `/api/analyze/url`         | URL-specific phishing analysis                                     |
| `POST`   | `/api/analyze/email`       | Email analysis (body + subject + sender)                           |
| `POST`   | `/api/analyze/batch`       | Batch analysis — up to 50 items, concurrent, partial failures OK   |
| `POST`   | `/api/ingest/email`        | Ingest a raw `.eml` file (413 over cap, 422 no readable body)      |
| `GET`    | `/api/history`             | List recent analyses (paginated)                                   |
| `GET`    | `/api/history/export.csv`  | Export full history as CSV attachment                              |
| `GET`    | `/api/history/export.json` | Export full history as JSON array                                  |
| `GET`    | `/api/history/{id}`        | Get one history entry by UUID                                      |
| `DELETE` | `/api/history/{id}`        | Delete a history entry                                             |
| `DELETE` | `/api/history`             | Clear all history                                                  |
| `POST`   | `/api/feedback`            | Operator feedback on past analyses (append-only JSONL)             |
| `GET`    | `/api/feedback`            | List recent feedback records                                       |
| `GET`    | `/metrics`                 | Prometheus metrics (text exposition format)                        |

### Example Request

```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://examp1e-login.tk/verify"}'
```

## Testing

Every commit runs the full suite via GitHub Actions (see the CI badge above).

| Layer    | Framework  | Count | Command                                    |
|----------|------------|-------|--------------------------------------------|
| Backend  | pytest     | 1,001 | `python -m pytest tests/ -q`               |
| Frontend | Jest       | 145   | `cd frontend && npx jest --ci`             |
| E2E      | Playwright | 31    | `cd frontend && npx playwright test`       |
| **Total**|            | **1177** |                                          |

Useful variations:

```bash
python -m pytest tests/unit/ -v                    # unit only
python -m pytest tests/integration/ -v             # integration only
python -m pytest tests/ --cov=backend              # coverage report
npx jest --ci --watch                              # Jest watch mode
```

## Threat Levels

| Level        | Score Range  | Action                                  |
|--------------|--------------|-----------------------------------------|
| ✅ Safe      | 0.00 – 0.29  | No action needed                        |
| ⚠️ Suspicious| 0.30 – 0.49  | Exercise caution, verify sender         |
| 🔴 Dangerous | 0.50 – 0.69  | Likely phishing, do not interact        |
| 🚨 Critical  | 0.70 – 1.00  | Confirmed threat, report immediately    |

## Project Structure

```
├── backend/                 # FastAPI server
│   ├── api/                 # REST endpoints, orchestrator, history store
│   ├── analyzer/            # NLP analyser (spaCy, 10 tactic categories)
│   ├── ml/                  # Feature extraction, scoring, trained models
│   ├── osint/               # WHOIS, DNS, reputation checking
│   ├── config.py            # Pydantic settings with .env support
│   └── main.py              # FastAPI app entry point
├── frontend/                # Next.js web application
│   ├── src/app/             # App Router pages (8 routes)
│   ├── src/components/      # UI components (charts, layout, results…)
│   ├── src/hooks/           # Custom hooks (analysis, health, shortcuts…)
│   ├── src/lib/             # API client, storage, utilities
│   ├── __tests__/           # Jest unit tests (145 tests)
│   ├── e2e/                 # Playwright browser tests (31 tests)
│   └── public/              # Static assets (logo, PWA icons)
├── tests/                   # Backend tests (1001 pytest tests)
│   ├── unit/
│   └── integration/
├── data/                    # Datasets (phishing + legitimate URLs)
├── docs/                    # Documentation & research
│   ├── latex_source/        # LaTeX thesis source (6 chapters)
│   ├── diagrams/            # Architecture diagrams (Mermaid)
│   ├── presentation/        # Defense slide deck
│   ├── PhishGuard_Thesis.pdf  # Compiled thesis PDF
│   ├── API.md               # Detailed endpoint documentation
│   ├── INSTALLATION.md      # Local setup guide
│   └── DEPLOYMENT_SETUP.md  # Vercel + Render configuration
├── .github/workflows/ci.yml # CI pipeline (pytest + Jest + Playwright)
├── Dockerfile               # Backend container image
├── docker-compose.yml       # Full local stack (api + web)
└── render.yaml              # Render.com deployment blueprint
```

## Deployment (Cloud)

### Backend — Render.com

Deploys automatically from `main` via the [`render.yaml`](render.yaml) blueprint.
Environment variables to configure: `CORS_ORIGINS` (your Vercel URL),
optionally `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `EML_MAX_BYTES`.
See [docs/DEPLOYMENT_SETUP.md](docs/DEPLOYMENT_SETUP.md).

### Frontend — Vercel

Import the repo with **Root Directory** = `frontend` and set
`NEXT_PUBLIC_API_URL` to your backend URL.

## Documentation

- [Thesis PDF](docs/PhishGuard_Thesis.pdf) — final submitted BSc thesis (6 chapters)
- [Thesis LaTeX source](docs/latex_source/)
- [API Documentation](docs/API.md)
- [Installation Guide](docs/INSTALLATION.md)
- [Deployment Guide](docs/DEPLOYMENT_SETUP.md)
- [User Journey](docs/USER_JOURNEY.md)
- [Privacy Policy](docs/PRIVACY.md)
- [Frontend README](frontend/README.md)

## Author

**Ishaq Muhammad** — Department of Data Science and Engineering,
ELTE Faculty of Informatics. Supervisor: Md. Easin Arafat.

## License

Academic BSc thesis project — not licensed for commercial use.
