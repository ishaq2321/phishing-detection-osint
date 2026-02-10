# Phishing Detection Using OSINT-Enhanced Features

BSc Thesis Project - Faculty of Informatics, Eötvös Loránd University (ELTE)

## 📋 Project Overview

A web-based phishing detection system that uses Machine Learning (ML) and Natural Language Processing (NLP), enriched with Open-Source Intelligence (OSINT) features to detect suspicious emails and URLs.

### Features
- **ML/NLP Classification** - Analyze text patterns in phishing attempts using spaCy
- **OSINT Integration** - WHOIS data, domain age, DNS records, reputation checking
- **Explainable Results** - Transparent classification with weighted scoring and reasoning
- **REST API** - FastAPI-powered API with comprehensive endpoints
- **Comprehensive Testing** - 522 tests (473 unit + 49 integration) with 100% pass rate

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.10+, FastAPI 0.109.0 |
| ML/NLP | spaCy 3.7.2, scikit-learn |
| OSINT | python-whois, dnspython, VirusTotal API, AbuseIPDB |
| Schemas | Pydantic 2.5.3 |
| Testing | pytest 9.0.2, pytest-asyncio |
| Dataset | PhishTank (115 phishing URLs), Tranco Top Sites (225 legitimate URLs) |
| Frontend | TBD (Milestone 3) |

## 📁 Project Structure

```
├── .github/              # GitHub configurations & Copilot instructions
├── .mcp/                 # MCP servers for project management
├── backend/              # FastAPI server & ML model
│   ├── api/              # REST API endpoints & orchestrator
│   ├── analyzer/         # NLP analyzer (spaCy-based)
│   ├── ml/               # Feature extraction, URL analysis, scoring
│   ├── osint/            # WHOIS, DNS, Reputation checking
│   ├── config.py         # Application configuration
│   └── main.py           # FastAPI application entry point
├── data/                 # Datasets
│   ├── phishtank/        # Phishing URL dataset (115 URLs)
│   ├── legitimate/       # Legitimate URL dataset (225 URLs)
│   └── scripts/          # Data collection scripts
├── docs/                 # Documentation
│   ├── milestones/       # Milestone plans
│   └── research.md       # Research notes
├── frontend/             # Web UI (Milestone 3)
├── tests/                # Unit & integration tests (522 total)
│   ├── unit/             # 473 unit tests
│   ├── integration/      # 49 integration tests
│   └── conftest.py       # Shared test fixtures
└── README.md
```

## 🏗️ Architecture

```
┌──────────────────────────────────────────────┐
│                  FastAPI API                  │
│  /api/analyze  /api/health  /api/osint/{d}   │
└──────────────────┬───────────────────────────┘
                   │
          ┌────────▼────────┐
          │   Orchestrator  │
          │  (Coordinates)  │
          └──┬─────┬─────┬──┘
             │     │     │
    ┌────────▼┐ ┌──▼──┐ ┌▼────────┐
    │  OSINT  │ │ ML  │ │Analyzer │
    │ Module  │ │Mod. │ │ (NLP)   │
    ├─────────┤ ├─────┤ ├─────────┤
    │ WHOIS   │ │Feat.│ │ spaCy   │
    │ DNS     │ │Extr.│ │ Phrase  │
    │ Reput.  │ │URL  │ │ Entity  │
    │         │ │Score│ │ Brand   │
    └─────────┘ └─────┘ └─────────┘
```

## 🎯 Milestones

| Milestone | Deadline | Status |
|-----------|----------|--------|
| Milestone 1 | December 20, 2025 | ✅ Completed |
| Milestone 2 | February 20, 2026 | 🟡 In Progress |
| Milestone 3 | March 25, 2026 | ⚪ Not Started |
| Milestone 4 | April 15, 2026 | ⚪ Not Started |
| Final Submission | May 1, 2026 | ⚪ Not Started |

### Milestone 2 Progress
- ✅ OSINT Module (WHOIS, DNS, Reputation) — 3 modules, 2,205 LOC
- ✅ ML Module (Feature Extractor, URL Analyzer, Scorer) — 3 modules, 2,111 LOC
- ✅ NLP Analyzer (spaCy-based, 6 phishing categories) — 540 LOC
- ✅ API Layer (FastAPI endpoints + orchestrator) — 5 endpoints, 977 LOC
- ✅ Configuration Management (Pydantic Settings + .env) — 325 LOC
- ✅ Testing (522 tests, 100% pass rate)
- ✅ Dataset Collection (115 phishing + 225 legitimate URLs)

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd Thesis

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Download spaCy model
python -m spacy download en_core_web_sm

# Set up environment
cp backend/.env.example backend/.env
# Edit .env with your API keys (optional)
```

### Running the Server

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API documentation will be available at `http://localhost:8000/docs`

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run unit tests only
python -m pytest tests/unit/ -v

# Run integration tests only
python -m pytest tests/integration/ -v

# Run with coverage
python -m pytest tests/ --cov=backend --cov-report=html
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze URL or email (auto-detect) |
| POST | `/api/analyze/url` | Analyze URL specifically |
| POST | `/api/analyze/email` | Analyze email content |
| GET | `/api/health` | Health check |
| GET | `/api/osint/{domain}` | Get OSINT data for domain |

### Example Request

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "http://paypal-verify.tk/login", "contentType": "url"}'
```

## 📚 Documentation

- [Milestone 1 Plan](docs/milestones/milestone-1.md)
- [Milestone 2 Plan](docs/milestones/milestone-2.md)
- [Milestone 3 Plan](docs/milestones/milestone-3.md)
- [Milestone 4 Plan](docs/milestones/milestone-4.md)
- [Research Notes](docs/research.md)
- [Data Documentation](data/README.md)

## 👤 Author

**Ishaq Muhammad** (PXPRGK)  
Supervisor: Md. Easin Arafat, PhD Candidate  
Department of Data Science and Engineering, ELTE

## 📄 License

This project is part of an academic thesis and is not licensed for commercial use.
