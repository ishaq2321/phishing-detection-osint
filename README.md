# Phishing Detection Using OSINT-Enhanced Features

BSc Thesis Project - Faculty of Informatics, Eötvös Loránd University (ELTE)

## 📋 Project Overview

A web-based phishing detection system that uses Machine Learning (ML) and Natural Language Processing (NLP), enriched with Open-Source Intelligence (OSINT) features to detect suspicious emails and URLs.

### Features
- **ML/NLP Classification** - Analyze text patterns in phishing attempts
- **OSINT Integration** - WHOIS data, domain age, DNS records, reputation sources
- **Explainable Results** - Transparent classification with reasoning
- **Web Interface** - User-friendly submission and results display

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python, FastAPI |
| ML/NLP | scikit-learn, spaCy |
| OSINT | python-whois, dnspython, Google Safe Browsing API |
| Dataset | PhishTank |
| Frontend | TBD (React/Vue/HTML) |

## 📁 Project Structure

```
├── .github/              # GitHub configurations
├── backend/              # FastAPI server & ML model
├── frontend/             # Web UI
├── data/                 # Datasets
├── docs/                 # Documentation
│   └── milestones/       # Milestone plans
├── tests/                # Unit & integration tests
└── README.md
```

## 🎯 Milestones

| Milestone | Deadline | Status |
|-----------|----------|--------|
| Milestone 1 | December 20, 2025 | 🟡 In Progress |
| Milestone 2 | February 20, 2026 | ⚪ Not Started |
| Milestone 3 | March 25, 2026 | ⚪ Not Started |
| Milestone 4 | April 15, 2026 | ⚪ Not Started |
| Final Submission | May 1, 2026 | ⚪ Not Started |

## 🚀 Getting Started

```bash
# Clone the repository
git clone https://github.com/ishaq2321/phishing-detection-osint.git
cd phishing-detection-osint

# Set up Python environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Run the server
cd backend
uvicorn main:app --reload
```

## 📚 Documentation

- [Milestone 1 Plan](docs/milestones/milestone-1.md)
- [Architecture](docs/architecture.md) *(coming soon)*
- [Research Notes](docs/research.md) *(coming soon)*

## 👤 Author

**Ishaq Muhammad** (PXPRGK)  
Supervisor: Md. Easin Arafat, PhD Candidate  
Department of Data Science and Engineering, ELTE

## 📄 License

This project is part of an academic thesis and is not licensed for commercial use.
