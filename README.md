# PhishGuard — Phishing Detection Using OSINT-Enhanced Features

BSc Thesis Project — Faculty of Informatics, Eötvös Loránd University (ELTE)

## Live Demo

- **Frontend:** https://project-4soy4.vercel.app
- **Backend API:** https://phishguard-api-upl2.onrender.com
- **API Docs:** https://phishguard-api-upl2.onrender.com/docs

## 📋 Overview

PhishGuard is a full-stack phishing detection system that combines a
**trained XGBoost ML model**, **Natural Language Processing (NLP)**,
**URL structural analysis**, and **Open-Source Intelligence (OSINT)** to
detect phishing threats in URLs, emails, and free-text content.

The system uses an **ML-primary scoring architecture**: for URL analysis the
XGBoost classifier (trained on 23,374 samples, 21 features) provides 85% of
the final score, supplemented by NLP text analysis at 15%.

### Key Features

- **XGBoost ML classifier** — 96.45% accuracy, 96.39% F1, 99.41% AUC-ROC
- **21-feature pipeline** — 17 URL structural + 4 OSINT features
- **OSINT enrichment** — WHOIS, DNS, VirusTotal, AbuseIPDB
- **Explainable results** — SHAP explanations, detailed reasons & scores
- **Multiple input modes** — URL, email (with subject/sender), free-text
- **Batch analysis** — Process up to 50 URLs in parallel
- **Interactive visualisations** — Score charts, threat gauges, confidence bars
- **Full-featured UI** — Dark/light theme, keyboard shortcuts, responsive design
- **754 automated tests** — Backend (593), frontend unit (133), E2E (28)

## 🛠️ Tech Stack

| Layer       | Technology                                          |
|-------------|-----------------------------------------------------|
| Frontend    | Next.js 16, React 19, TypeScript, Tailwind CSS v4   |
| UI          | shadcn/ui v4, Recharts, TanStack Table, Motion       |
| Backend     | Python 3.10, FastAPI 0.109, Pydantic 2               |
| NLP         | spaCy 3.7 (en_core_web_sm)                           |
| ML          | XGBoost 3.2, SHAP 0.49, Optuna 4.7, scikit-learn 1.4 |
| OSINT       | python-whois, dnspython, aiohttp                     |
| Testing     | pytest 8, Jest 30, Playwright 1.58                   |
| Deployment  | Vercel (frontend), Render.com (backend)              |

## 📁 Project Structure

```
├── .github/              # GitHub config & Copilot instructions
├── .mcp/                 # MCP servers (project manager + code quality)
├── backend/              # FastAPI server
│   ├── api/              # REST endpoints, orchestrator, history store
│   ├── analyzer/         # NLP analyser (spaCy-based, 6 categories)
│   ├── ml/               # Feature extraction, URL analysis, scoring
│   ├── osint/            # WHOIS, DNS, reputation checking
│   ├── config.py         # Pydantic settings with .env support
│   └── main.py           # FastAPI app entry point
├── data/                 # Datasets (phishing + legitimate URLs)
├── docs/                 # Documentation & research
│   ├── milestones/       # M1–M4 progress tracking
│   ├── methodology-draft.md  # Thesis methodology draft
│   └── research.md       # Background research
├── frontend/             # Next.js 16 web application
│   ├── src/
│   │   ├── app/          # App Router pages (10 routes)
│   │   ├── components/   # UI components (brand, charts, layout, etc.)
│   │   ├── hooks/        # Custom hooks (health, keyboard, countUp)
│   │   ├── lib/          # API client, stores, utilities
│   │   └── types/        # TypeScript type definitions
│   ├── e2e/              # Playwright E2E tests (28 tests)
│   ├── __tests__/        # Jest unit tests (133 tests)
│   └── public/           # Static assets (logo, favicon, PWA icons)
├── tests/                # Backend tests (593 tests)
│   ├── unit/             # Unit tests for all modules
│   └── integration/      # Full pipeline integration tests
└── README.md
```

## 🚀 Quick Start

### Prerequisites

| Requirement | Version   | Check with          |
|-------------|-----------|---------------------|
| Python      | ≥ 3.10    | `python3 --version` |
| Node.js     | ≥ 20      | `node --version`    |
| npm         | ≥ 10      | `npm --version`     |
| Git         | ≥ 2.30    | `git --version`     |

### 1. Clone the Repository

```bash
git clone https://github.com/ishaq2321/phishing-detection-osint.git
cd phishing-detection-osint
```

### 2. Backend Setup

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate     # Linux/macOS
# .venv\Scripts\activate      # Windows

# Install Python dependencies
pip install -r backend/requirements.txt

# Download spaCy language model
python -m spacy download en_core_web_sm

# (Optional) Create .env from example
cp backend/.env.example backend/.env
# Edit backend/.env with your API keys for VirusTotal/AbuseIPDB
```

### 3. Frontend Setup

```bash
cd frontend

# Install Node.js dependencies
npm install

# (Optional) Create .env.local from example
cp .env.example .env.local
# Edit .env.local if backend runs on a non-default port
```

### 4. Run Both Servers

**Terminal 1 — Backend (port 8000):**

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend (port 3000):**

```bash
cd frontend
npm run dev
```

Open **http://localhost:3000** in your browser.

Backend API docs: **http://localhost:8000/docs**

## 📡 API Endpoints

| Method   | Path                  | Description                              |
|----------|-----------------------|------------------------------------------|
| `GET`    | `/api/health`         | Health status & service availability     |
| `GET`    | `/api/model/status`   | ML model status & feature info           |
| `POST`   | `/api/analyze`        | Analyse any content (auto-detect type)   |
| `POST`   | `/api/analyze/url`    | URL-specific phishing analysis           |
| `POST`   | `/api/analyze/email`  | Email analysis (body + subject + sender) |
| `GET`    | `/api/history`        | List recent analyses (paginated)         |
| `GET`    | `/api/history/{id}`   | Get a single history entry by UUID       |
| `DELETE` | `/api/history/{id}`   | Delete a history entry                   |
| `DELETE` | `/api/history`        | Clear all history                        |

### Example Request

```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://examp1e-login.tk/verify"}'
```

## 🧪 Running Tests

### Backend Tests (593 tests)

```bash
# Run all tests
source .venv/bin/activate
python -m pytest tests/ -v

# Run unit tests only
python -m pytest tests/unit/ -v

# Run integration tests only
python -m pytest tests/integration/ -v

# Run with coverage report
python -m pytest tests/ --cov=backend --cov-report=html
```

### Frontend Unit Tests (133 tests)

```bash
cd frontend
npm test            # Run all Jest tests
npm test -- --watch # Watch mode
```

### Frontend E2E Tests (28 tests)

```bash
cd frontend

# Install Playwright browsers (first time only)
npx playwright install chromium

# Run E2E tests (starts dev server automatically)
npm run test:e2e

# Run with UI mode (interactive debugging)
npm run test:e2e:ui
```

### All Tests Summary

| Layer        | Framework   | Tests | Command                          |
|--------------|-------------|-------|----------------------------------|
| Backend      | pytest      | 593   | `python -m pytest tests/`        |
| Frontend Unit| Jest        | 133   | `cd frontend && npm test`        |
| Frontend E2E | Playwright  | 28    | `cd frontend && npm run test:e2e`|
| **Total**    |             | **754** |                                |

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Frontend (Next.js 16)                        │
│           10 routes · React 19 · Tailwind CSS v4             │
└──────────────────────┬───────────────────────────────────────┘
                       │ REST API (JSON)
┌──────────────────────▼───────────────────────────────────────┐
│                  Backend (FastAPI)                            │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Text/NLP    │  │  URL Feature │  │  OSINT           │   │
│  │  Analysis    │  │  Extraction  │  │  Enrichment      │   │
│  │  (spaCy)     │  │  (21 feats)  │  │  (WHOIS/DNS/     │   │
│  │              │  │  17 struct + │  │   VirusTotal/     │   │
│  │  Supplement  │  │  4 OSINT     │  │   AbuseIPDB)     │   │
│  │  15%         │  │              │  │                   │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────┘   │
│         │                 │                  │               │
│  ┌──────▼─────────────────▼──────────────────▼───────────┐   │
│  │            XGBoost ML Classifier (85%)                 │   │
│  │  Acc=96.45% · F1=96.39% · AUC=99.41% · PR-AUC=99.48% │   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Threat Levels

| Level      | Score Range  | Action                                    |
|------------|--------------|-------------------------------------------|
| ✅ Safe     | 0.00 – 0.29 | No action needed                          |
| ⚠️ Suspicious | 0.30 – 0.49 | Exercise caution, verify sender        |
| 🔴 Dangerous | 0.50 – 0.69 | Likely phishing, do not interact       |
| 🚨 Critical | 0.70 – 1.00 | Confirmed threat, report immediately    |

## 🚀 Deployment

### Backend — Render.com

The backend deploys automatically from the `main` branch using the
[`render.yaml`](render.yaml) blueprint.

1. Go to [Render Dashboard](https://dashboard.render.com/) → **New** → **Blueprint**
2. Connect the GitHub repo `ishaq2321/phishing-detection-osint`
3. Render auto-detects `render.yaml` and creates the `phishguard-api` service
4. Set `CORS_ORIGINS` to your Vercel frontend URL (e.g. `https://phishguard.vercel.app`)
5. Optionally set `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` for enhanced OSINT

### Frontend — Vercel

1. Go to [Vercel](https://vercel.com/) → **New Project** → Import `ishaq2321/phishing-detection-osint`
2. Set **Root Directory** to `frontend`
3. Add environment variable: `NEXT_PUBLIC_API_URL` = your Render backend URL
   (e.g. `https://phishguard-api.onrender.com`)
4. Deploy — Vercel auto-detects Next.js and builds accordingly

## 🎯 Milestones

| Milestone        | Deadline          | Status        |
|------------------|-------------------|---------------|
| Milestone 1      | December 20, 2025 | ✅ Complete    |
| Milestone 2      | February 20, 2026 | ✅ Complete    |
| Milestone 3      | March 25, 2026    | ✅ Complete    |
| Milestone 4      | April 15, 2026    | ✅ Complete    |
| Final Submission | May 1, 2026       | 🟡 Draft In Progress |

## 📚 Documentation

- [User Guide](docs/user_guide.md) — How to use the PhishGuard application

- [Methodology Draft](docs/methodology-draft.md) — Thesis methodology and preliminary results
- [Milestone 1](docs/milestones/milestone-1.md) — Topic, design, initial prototype
- [Milestone 2](docs/milestones/milestone-2.md) — Core algorithm, backend, tests
- [Milestone 3](docs/milestones/milestone-3.md) — UI development, testing, documentation
- [Milestone 4](docs/milestones/milestone-4.md) — Final implementation, evaluation
- [Research Notes](docs/research.md) — Background research on phishing and OSINT
- [Frontend README](frontend/README.md) — Frontend-specific development guide

## 👤 Author

**Ishaq Muhammad** (PXPRGK)
Supervisor: Md. Easin Arafat
Department of Data Science and Engineering, ELTE — Faculty of Informatics

## 📄 License

This project is part of an academic BSc thesis and is not licensed for
commercial use.
