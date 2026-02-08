# Milestone 2 Plan (Deadline: February 20, 2026)

## Project: Phishing Detection Using OSINT-Enhanced Features

**Start Date:** February 8, 2026  
**Deadline:** February 20, 2026  
**Duration:** 12 days  
**Status:** In Progress

---

## Executive Summary

Milestone 2 focuses on implementing the **core detection engine** with a modular architecture that supports both NLP (initial) and LLM (future) approaches. The key deliverables are:

1. OSINT data collection module (WHOIS, DNS, Reputation)
2. NLP-based text analysis engine (swappable with LLM later)
3. ML feature extraction and scoring
4. RESTful API endpoints with full Pydantic validation
5. Comprehensive test suite (unit, integration, API) with 80%+ coverage
6. Dataset collection and preprocessing (PhishTank + legitimate URLs)

---

## Key Design Principles

1. **Testability First** - All modules designed with dependency injection for easy mocking
2. **Modular Architecture** - Swappable components (NLP/LLM analyzer)
3. **Async by Default** - All I/O operations are async for performance
4. **Fail Gracefully** - External service failures don't crash the system
5. **Type Safety** - Full Pydantic models for all data structures

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PHISHING DETECTION SYSTEM                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────────────────────────────────────┐   │
│  │   Frontend   │    │                  Backend                      │   │
│  │   (HTML/JS)  │───►│  ┌────────────────────────────────────────┐  │   │
│  └──────────────┘    │  │              FastAPI App                │  │   │
│                      │  │  ┌──────────────────────────────────┐  │  │   │
│                      │  │  │         /api/analyze             │  │  │   │
│                      │  │  └──────────────┬───────────────────┘  │  │   │
│                      │  └─────────────────┼──────────────────────┘  │   │
│                      │                    │                          │   │
│                      │         ┌──────────▼──────────┐              │   │
│                      │         │  AnalysisOrchestrator │              │   │
│                      │         └──────────┬──────────┘              │   │
│                      │                    │                          │   │
│                      │    ┌───────────────┼───────────────┐         │   │
│                      │    ▼               ▼               ▼         │   │
│                      │ ┌──────┐     ┌──────────┐    ┌─────────┐    │   │
│                      │ │OSINT │     │ Analyzer │    │   ML    │    │   │
│                      │ │Module│     │(NLP/LLM) │    │Features │    │   │
│                      │ └──────┘     └──────────┘    └─────────┘    │   │
│                      │                                              │   │
│                      └──────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure (Target)

```
backend/
├── main.py                      # FastAPI app entry point
├── config.py                    # Configuration settings
├── requirements.txt             # Dependencies
│
├── api/
│   ├── __init__.py
│   ├── router.py                # API route definitions
│   └── schemas.py               # Pydantic request/response models
│
├── analyzer/
│   ├── __init__.py
│   ├── base.py                  # Abstract base analyzer interface
│   ├── nlpAnalyzer.py           # NLP implementation (Phase 1)
│   ├── llmAnalyzer.py           # LLM implementation (Future)
│   └── orchestrator.py          # Coordinates all analysis modules
│
├── osint/
│   ├── __init__.py
│   ├── whoisLookup.py           # WHOIS domain information
│   ├── dnsChecker.py            # DNS record validation
│   ├── reputationChecker.py     # Blacklist/reputation checks
│   └── schemas.py               # OSINT data models
│
├── ml/
│   ├── __init__.py
│   ├── featureExtractor.py      # URL and text feature extraction
│   ├── urlAnalyzer.py           # URL pattern analysis
│   └── scorer.py                # Risk scoring logic
│
└── utils/
    ├── __init__.py
    └── validators.py            # Input validation helpers

tests/
├── __init__.py
├── conftest.py                  # Pytest fixtures
│
├── unit/
│   ├── __init__.py
│   ├── test_whoisLookup.py
│   ├── test_dnsChecker.py
│   ├── test_featureExtractor.py
│   ├── test_urlAnalyzer.py
│   ├── test_nlpAnalyzer.py
│   └── test_scorer.py
│
├── integration/
│   ├── __init__.py
│   ├── test_osintModule.py
│   ├── test_analyzerPipeline.py
│   └── test_orchestrator.py
│
└── api/
    ├── __init__.py
    └── test_endpoints.py

data/
├── phishtank/                   # PhishTank dataset
│   ├── raw/
│   └── processed/
├── legitimate/                  # Legitimate URLs for training
└── samples/                     # Test samples
```

---

## Module Specifications

### 1. OSINT Module

#### 1.1 whoisLookup.py
**Purpose:** Retrieve domain registration information

**Functions:**
| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `getDomainAge(domain)` | str | int (days) | Days since registration |
| `getRegistrar(domain)` | str | str | Registrar name |
| `getWhoisData(domain)` | str | WhoisResult | Full WHOIS data |

**Data Model:**
```python
class WhoisResult(BaseModel):
    domain: str
    registrar: str | None
    creationDate: datetime | None
    expirationDate: datetime | None
    domainAgeDays: int | None
    registrantCountry: str | None
    isPrivate: bool
```

#### 1.2 dnsChecker.py
**Purpose:** Validate DNS records

**Functions:**
| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `getARecord(domain)` | str | list[str] | IP addresses |
| `getMxRecords(domain)` | str | list[str] | Mail servers |
| `getNsRecords(domain)` | str | list[str] | Name servers |
| `getDnsData(domain)` | str | DnsResult | Full DNS data |

**Data Model:**
```python
class DnsResult(BaseModel):
    domain: str
    aRecords: list[str]
    mxRecords: list[str]
    nsRecords: list[str]
    hasMx: bool
    hasValidNs: bool
```

#### 1.3 reputationChecker.py
**Purpose:** Check domain against blacklists

**Functions:**
| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `checkPhishTank(url)` | str | bool | Is in PhishTank DB |
| `checkGoogleSafeBrowsing(url)` | str | bool | Is flagged by Google |
| `getReputationScore(url)` | str | ReputationResult | Combined reputation |

**Data Model:**
```python
class ReputationResult(BaseModel):
    url: str
    inPhishTank: bool
    inGoogleSafeBrowsing: bool
    reputationScore: float  # 0.0 (bad) to 1.0 (good)
```

---

### 2. Analyzer Module (Swappable NLP/LLM)

#### 2.1 base.py - Abstract Interface
```python
from abc import ABC, abstractmethod
from pydantic import BaseModel

class AnalysisResult(BaseModel):
    isPhishing: bool
    confidenceScore: float  # 0.0 to 1.0
    threatLevel: str        # safe, suspicious, dangerous, critical
    reasons: list[str]
    detectedTactics: list[str]

class BaseAnalyzer(ABC):
    @abstractmethod
    async def analyze(self, content: str, contentType: str) -> AnalysisResult:
        """Analyze content for phishing indicators."""
        pass
```

#### 2.2 nlpAnalyzer.py - NLP Implementation (Phase 1)
**Approach:** spaCy EntityRuler + PhraseMatcher + scikit-learn

Based on latest spaCy documentation, we use:
- **EntityRuler** - Rule-based entity recognition for brand impersonation detection
- **PhraseMatcher** - Efficient matching for urgency/threat phrase detection
- **Token Matcher** - Pattern-based matching for suspicious request patterns

**Phishing Indicators to Detect:**

| Category | Examples | Detection Method |
|----------|----------|------------------|
| Urgency Keywords | "act now", "immediately", "within 24 hours" | PhraseMatcher |
| Threat Phrases | "account suspended", "unauthorized access" | PhraseMatcher |
| Authority Impersonation | "IT Department", "Security Team", "PayPal" | EntityRuler |
| Suspicious Requests | "verify password", "confirm SSN", "update payment" | Token Matcher |
| Credential Harvesting | "click here to login", "enter your details" | PhraseMatcher |
| Fear Tactics | "your account will be closed", "legal action" | PhraseMatcher |

**Implementation Pattern (from spaCy docs):**
```python
import spacy
from spacy.matcher import PhraseMatcher
from spacy.pipeline import EntityRuler

nlp = spacy.load("en_core_web_sm")

# Add EntityRuler for brand detection
ruler = nlp.add_pipe("entity_ruler", before="ner")
brand_patterns = [
    {"label": "BRAND", "pattern": "PayPal"},
    {"label": "BRAND", "pattern": "Microsoft"},
    {"label": "BRAND", "pattern": [{"LOWER": "apple"}, {"LOWER": "support"}]},
]
ruler.add_patterns(brand_patterns)

# PhraseMatcher for urgency detection
urgency_matcher = PhraseMatcher(nlp.vocab)
urgency_terms = ["act now", "immediately", "urgent action required"]
patterns = [nlp.make_doc(text) for text in urgency_terms]
urgency_matcher.add("URGENCY", patterns)
```

#### 2.3 llmAnalyzer.py - LLM Implementation (Future)
**Approach:** Ollama + Llama 3.1 with structured output

*To be implemented when infrastructure is available*

---

### 3. ML Module

#### 3.1 featureExtractor.py
**Purpose:** Extract numerical features for scoring

**URL Features:**
| Feature | Type | Description |
|---------|------|-------------|
| urlLength | int | Total URL length |
| domainLength | int | Domain name length |
| subdomainCount | int | Number of subdomains |
| hasIpAddress | bool | URL contains IP instead of domain |
| hasAtSymbol | bool | Contains @ (redirect trick) |
| hasDashInDomain | bool | Suspicious dashes |
| digitRatio | float | Ratio of digits to chars |
| specialCharCount | int | Count of special characters |
| isHttps | bool | Uses HTTPS |
| pathDepth | int | URL path depth |

**Text Features:**
| Feature | Type | Description |
|---------|------|-------------|
| urgencyScore | float | Urgency keyword density |
| threatScore | float | Threat phrase density |
| spellingErrorRate | float | Typo percentage |
| linkTextMismatch | bool | Display text != actual URL |

#### 3.2 scorer.py
**Purpose:** Combine all features into final risk score

**Logic:**
```
finalScore = (
    osintScore * 0.35 +
    urlFeatureScore * 0.25 +
    textAnalysisScore * 0.40
)
```

---

### 4. API Module

#### 4.1 Endpoints

| Method | Endpoint | Description | Request | Response |
|--------|----------|-------------|---------|----------|
| POST | /api/analyze | Analyze URL or email | AnalyzeRequest | AnalysisResponse |
| POST | /api/analyze/url | Analyze URL only | UrlRequest | AnalysisResponse |
| POST | /api/analyze/email | Analyze email content | EmailRequest | AnalysisResponse |
| GET | /api/health | Health check | - | HealthResponse |
| GET | /api/osint/{domain} | Get OSINT data only | - | OsintResponse |

#### 4.2 Request/Response Schemas

```python
class AnalyzeRequest(BaseModel):
    content: str
    contentType: str = "auto"  # auto, url, email

class AnalysisResponse(BaseModel):
    success: bool
    verdict: VerdictResult
    osint: OsintSummary | None
    features: FeatureSummary
    analysisTime: float

class VerdictResult(BaseModel):
    isPhishing: bool
    confidenceScore: float
    threatLevel: str
    reasons: list[str]
    recommendation: str
```

---

## Testing Strategy

### Test Pyramid

```
                    ┌─────────┐
                    │   E2E   │  (Manual for thesis demo)
                   ┌┴─────────┴┐
                   │    API    │  tests/api/
                  ┌┴───────────┴┐
                  │ Integration │  tests/integration/
                 ┌┴─────────────┴┐
                 │     Unit      │  tests/unit/
                 └───────────────┘
```

### Testing Best Practices (from pytest & FastAPI docs)

**1. Fixture-based Mocking Pattern:**
```python
# tests/conftest.py
import pytest
from unittest.mock import AsyncMock

@pytest.fixture
def mockWhoisResponse(monkeypatch):
    """Mock WHOIS lookup to avoid external calls."""
    async def mockLookup(domain: str):
        return WhoisResult(
            domain=domain,
            domainAgeDays=365,
            registrar="Mock Registrar",
            isPrivate=False
        )
    monkeypatch.setattr("backend.osint.whoisLookup.getWhoisData", mockLookup)
```

**2. Disable External Requests (conftest.py):**
```python
@pytest.fixture(autouse=True)
def noExternalRequests(monkeypatch):
    """Prevent any real HTTP requests during unit tests."""
    monkeypatch.delattr("requests.sessions.Session.request")
```

**3. FastAPI TestClient Pattern:**
```python
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_analyzeEndpoint():
    response = client.post(
        "/api/analyze",
        json={"content": "http://suspicious-site.com", "contentType": "url"}
    )
    assert response.status_code == 200
    assert "verdict" in response.json()
```

**4. Async Testing with pytest-asyncio:**
```python
import pytest
from httpx import ASGITransport, AsyncClient
from backend.main import app

@pytest.mark.asyncio
async def test_asyncAnalyze():
    async with AsyncClient(
        transport=ASGITransport(app=app), 
        base_url="http://test"
    ) as client:
        response = await client.post("/api/analyze", json={...})
        assert response.status_code == 200
```

**5. Dependency Override for Testing:**
```python
from backend.main import app
from backend.config import getSettings, Settings

def getTestSettings():
    return Settings(OSINT_CACHE_TTL=0, DEBUG=True)

app.dependency_overrides[getSettings] = getTestSettings
```

### Unit Tests (tests/unit/)

| Test File | Module | Test Cases |
|-----------|--------|------------|
| test_whoisLookup.py | osint/whoisLookup.py | Valid domain, invalid domain, timeout handling, private WHOIS |
| test_dnsChecker.py | osint/dnsChecker.py | A records, MX records, non-existent domain |
| test_featureExtractor.py | ml/featureExtractor.py | URL parsing, feature calculation, edge cases |
| test_urlAnalyzer.py | ml/urlAnalyzer.py | Pattern detection, homograph detection |
| test_nlpAnalyzer.py | analyzer/nlpAnalyzer.py | Keyword detection, urgency scoring, brand detection |
| test_scorer.py | ml/scorer.py | Score calculation, threshold logic |

### Integration Tests (tests/integration/)

| Test File | Purpose | Key Assertions |
|-----------|---------|----------------|
| test_osintModule.py | OSINT components work together | Full OSINT report returned |
| test_analyzerPipeline.py | Full analysis flow | End-to-end verdict generation |
| test_orchestrator.py | All modules coordinate correctly | Correct data flow between modules |

### API Tests (tests/api/)

| Test File | Purpose | Endpoints Covered |
|-----------|---------|-------------------|
| test_endpoints.py | All API endpoints work correctly | /api/analyze, /api/health, /api/osint |
| test_errorHandling.py | Error cases handled properly | 400, 404, 500 responses |
| test_validation.py | Input validation works | Invalid URLs, empty content |

### Test Data

**Fixtures (tests/conftest.py):**
- Known phishing URLs (from PhishTank)
- Known legitimate URLs (from Alexa Top 100)
- Sample phishing emails
- Sample legitimate emails
- Mock OSINT responses (for offline testing)

**Sample Test Data (tests/fixtures/):**
```
tests/fixtures/
├── phishingUrls.json          # Known phishing URLs for testing
├── legitimateUrls.json        # Known safe URLs for testing
├── phishingEmails.json        # Sample phishing email content
├── legitimateEmails.json      # Sample safe email content
├── mockWhoisResponses.json    # Mock WHOIS data
└── mockDnsResponses.json      # Mock DNS data
```

---

## Configuration Management

### config.py Structure
```python
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Phishing Detection API"
    DEBUG: bool = False
    API_VERSION: str = "0.2.0"
    
    # Analyzer Configuration
    ANALYZER_ENGINE: str = "nlp"  # "nlp" or "llm"
    
    # OSINT Configuration
    OSINT_CACHE_TTL: int = 3600  # 1 hour cache
    WHOIS_TIMEOUT: int = 10
    DNS_TIMEOUT: int = 5
    
    # API Keys (optional, for enhanced reputation checking)
    GOOGLE_SAFE_BROWSING_KEY: str | None = None
    VIRUSTOTAL_KEY: str | None = None
    
    # Scoring Thresholds
    THRESHOLD_SUSPICIOUS: float = 0.4
    THRESHOLD_DANGEROUS: float = 0.7
    THRESHOLD_CRITICAL: float = 0.9
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache
def getSettings() -> Settings:
    return Settings()
```

### Environment Files
```bash
# .env.example (committed to repo)
DEBUG=false
ANALYZER_ENGINE=nlp
OSINT_CACHE_TTL=3600
GOOGLE_SAFE_BROWSING_KEY=
VIRUSTOTAL_KEY=

# .env (local, not committed)
DEBUG=true
ANALYZER_ENGINE=nlp
```

---

## Development Workflow

### Git Strategy

**Branches:**
- `main` - Stable, tested code only
- `develop` - Integration branch
- `feature/*` - Feature branches (one per issue)
- `test/*` - Test implementation branches

**Workflow:**
1. Create GitHub issue
2. Create feature branch from `develop`
3. Implement with tests
4. Create pull request
5. Merge to `develop`
6. At milestone end, merge `develop` to `main`

### Tools

| Tool | Purpose | Recommendation |
|------|---------|----------------|
| Git | Version control | Use CLI for commits |
| GitHub Issues | Task tracking | Use GitHub MCP for bulk operations |
| pytest | Testing | Run locally before push |
| pytest-cov | Coverage | Target 80% coverage |

---

## GitHub Issues Plan

### Labels to Create
| Label | Color | Description |
|-------|-------|-------------|
| `osint` | #1D76DB | OSINT module related |
| `ml` | #0E8A16 | Machine learning module |
| `analyzer` | #5319E7 | Analyzer module |
| `api` | #F9D0C4 | API endpoints |
| `testing` | #BFD4F2 | Test implementation |
| `documentation` | #C2E0C6 | Documentation updates |
| `data` | #FBCA04 | Dataset related |
| `priority:high` | #B60205 | High priority |
| `priority:medium` | #FF9F1C | Medium priority |
| `milestone-2` | #6F42C1 | Milestone 2 |

### Epic Structure with Detailed Issues

```
EPIC: Milestone 2 - Core Detection Engine
│
├── OSINT Module (Priority: High)
│   │
│   ├── Issue #1: Implement whoisLookup module
│   │   Labels: osint, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] getDomainAge() returns days since registration
│   │   - [ ] getWhoisData() returns full WhoisResult model
│   │   - [ ] Handles timeout gracefully (returns None)
│   │   - [ ] Handles private WHOIS (isPrivate=True)
│   │   - [ ] Async implementation
│   │   - [ ] Unit tests pass (4+ test cases)
│   │
│   ├── Issue #2: Implement dnsChecker module
│   │   Labels: osint, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] getARecord() returns list of IP addresses
│   │   - [ ] getMxRecords() returns mail servers
│   │   - [ ] getDnsData() returns full DnsResult model
│   │   - [ ] Handles non-existent domains
│   │   - [ ] Async implementation
│   │   - [ ] Unit tests pass (4+ test cases)
│   │
│   ├── Issue #3: Implement reputationChecker module
│   │   Labels: osint, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] checkPhishTank() queries local PhishTank data
│   │   - [ ] getReputationScore() returns 0.0-1.0 score
│   │   - [ ] Graceful fallback if API unavailable
│   │   - [ ] Unit tests pass (3+ test cases)
│   │
│   └── Issue #4: Create OSINT schemas and integration
│       Labels: osint, testing, milestone-2
│       Acceptance Criteria:
│       - [ ] All Pydantic models defined in osint/schemas.py
│       - [ ] OsintOrchestrator combines all OSINT data
│       - [ ] Integration test verifies full OSINT flow
│
├── ML Module (Priority: High)
│   │
│   ├── Issue #5: Implement featureExtractor module
│   │   Labels: ml, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] extractUrlFeatures() returns 10+ features
│   │   - [ ] extractTextFeatures() returns 4+ features
│   │   - [ ] All features documented in UrlFeatures model
│   │   - [ ] Unit tests for edge cases (empty, malformed)
│   │
│   ├── Issue #6: Implement urlAnalyzer module
│   │   Labels: ml, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] Detects IP addresses in URLs
│   │   - [ ] Detects suspicious TLDs
│   │   - [ ] Detects homograph attacks (punycode)
│   │   - [ ] Detects URL shorteners
│   │   - [ ] Unit tests pass (6+ test cases)
│   │
│   ├── Issue #7: Implement scorer module
│   │   Labels: ml, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] Combines OSINT + URL + Text scores
│   │   - [ ] Returns threat level (safe/suspicious/dangerous/critical)
│   │   - [ ] Configurable thresholds via Settings
│   │   - [ ] Unit tests verify scoring logic
│   │
│   └── Issue #8: ML module unit tests
│       Labels: ml, testing, milestone-2
│       Acceptance Criteria:
│       - [ ] 80%+ coverage on ml/ module
│       - [ ] All edge cases tested
│       - [ ] Fixtures for test URLs created
│
├── Analyzer Module (Priority: High)
│   │
│   ├── Issue #9: Create base analyzer interface
│   │   Labels: analyzer, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] BaseAnalyzer ABC defined
│   │   - [ ] AnalysisResult Pydantic model defined
│   │   - [ ] Async analyze() method signature
│   │   - [ ] Documentation for implementing new analyzers
│   │
│   ├── Issue #10: Implement NLP analyzer with spaCy
│   │   Labels: analyzer, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] EntityRuler for brand detection
│   │   - [ ] PhraseMatcher for urgency/threat phrases
│   │   - [ ] Returns AnalysisResult with reasons
│   │   - [ ] Detects 6+ phishing indicator categories
│   │   - [ ] Unit tests pass (5+ test cases)
│   │
│   └── Issue #11: Analyzer module tests
│       Labels: analyzer, testing, milestone-2
│       Acceptance Criteria:
│       - [ ] Unit tests for NlpAnalyzer
│       - [ ] Tests with known phishing content
│       - [ ] Tests with legitimate content
│       - [ ] 80%+ coverage
│
├── API Module (Priority: High)
│   │
│   ├── Issue #12: Define API schemas with Pydantic
│   │   Labels: api, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] AnalyzeRequest model
│   │   - [ ] AnalysisResponse model
│   │   - [ ] All nested models defined
│   │   - [ ] Validation rules (min length, URL format)
│   │
│   ├── Issue #13: Implement /api/analyze endpoint
│   │   Labels: api, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] POST /api/analyze works
│   │   - [ ] Accepts URL and email content
│   │   - [ ] Returns full AnalysisResponse
│   │   - [ ] Handles errors gracefully
│   │   - [ ] Response time < 5 seconds
│   │
│   ├── Issue #14: Implement orchestrator
│   │   Labels: api, priority:high, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] Coordinates OSINT, ML, and Analyzer
│   │   - [ ] Parallel execution where possible
│   │   - [ ] Aggregates results into final verdict
│   │   - [ ] Handles partial failures gracefully
│   │
│   ├── Issue #15: API endpoint tests
│   │   Labels: api, testing, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] TestClient tests for all endpoints
│   │   - [ ] Tests for success cases
│   │   - [ ] Tests for error cases (400, 404)
│   │   - [ ] Tests for input validation
│   │
│   └── Issue #16: API error handling tests
│       Labels: api, testing, milestone-2
│       Acceptance Criteria:
│       - [ ] Test timeout handling
│       - [ ] Test malformed input
│       - [ ] Test rate limiting (if implemented)
│
├── Integration & E2E (Priority: Medium)
│   │
│   ├── Issue #17: Integration tests for full pipeline
│   │   Labels: testing, priority:medium, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] Test URL → OSINT → ML → Analyzer → Response
│   │   - [ ] Test with known phishing URLs
│   │   - [ ] Test with known safe URLs
│   │   - [ ] Verify correct classifications
│   │
│   └── Issue #18: End-to-end smoke tests
│       Labels: testing, milestone-2
│       Acceptance Criteria:
│       - [ ] Full system runs without errors
│       - [ ] Can analyze 10 sample URLs
│       - [ ] Results are reasonable
│
├── Data (Priority: Medium)
│   │
│   ├── Issue #19: Download and preprocess PhishTank dataset
│   │   Labels: data, priority:medium, milestone-2
│   │   Acceptance Criteria:
│   │   - [ ] PhishTank data downloaded
│   │   - [ ] Data cleaned and normalized
│   │   - [ ] Stored in data/phishtank/processed/
│   │   - [ ] 1000+ verified phishing URLs ready
│   │
│   └── Issue #20: Collect legitimate URL samples
│       Labels: data, milestone-2
│       Acceptance Criteria:
│       - [ ] 500+ legitimate URLs collected
│       - [ ] From Alexa Top Sites or similar
│       - [ ] Stored in data/legitimate/
│
├── Configuration & Setup (Priority: High)
│   │
│   └── Issue #21: Create config.py and settings management
│       Labels: priority:high, milestone-2
│       Acceptance Criteria:
│       - [ ] Pydantic Settings class
│       - [ ] Environment file support
│       - [ ] Dependency injection pattern
│       - [ ] .env.example created
│
└── Documentation (Priority: Low)
    │
    ├── Issue #22: Update research.md with NLP approach
    │   Labels: documentation, milestone-2
    │   Acceptance Criteria:
    │   - [ ] Document spaCy approach
    │   - [ ] Document feature extraction
    │   - [ ] Update comparison table
    │
    └── Issue #23: Create API documentation
        Labels: documentation, milestone-2
        Acceptance Criteria:
        - [ ] OpenAPI/Swagger docs work
        - [ ] All endpoints documented
        - [ ] Request/response examples
```

---

## Timeline

| Day | Date | Focus | Issues | Deliverables | Hours |
|-----|------|-------|--------|--------------|-------|
| 1 | Feb 8 (Sat) | Planning & Setup | #21 | Plan finalized, GitHub issues created, config.py | 4h |
| 2 | Feb 9 (Sun) | OSINT: WHOIS | #1 | whoisLookup.py + unit tests | 5h |
| 3 | Feb 10 (Mon) | OSINT: DNS | #2 | dnsChecker.py + unit tests | 5h |
| 4 | Feb 11 (Tue) | OSINT: Reputation | #3, #4 | reputationChecker.py + integration | 5h |
| 5 | Feb 12 (Wed) | ML: Features | #5, #6 | featureExtractor.py, urlAnalyzer.py + tests | 6h |
| 6 | Feb 13 (Thu) | ML: Scoring | #7, #8 | scorer.py + ML tests complete | 5h |
| 7 | Feb 14 (Fri) | Analyzer: Base + NLP | #9, #10 | NLP analyzer implementation | 6h |
| 8 | Feb 15 (Sat) | Analyzer: Testing | #11 | Analyzer tests complete | 4h |
| 9 | Feb 16 (Sun) | API: Implementation | #12, #13, #14 | Full API with orchestrator | 6h |
| 10 | Feb 17 (Mon) | API: Testing | #15, #16 | API tests complete | 5h |
| 11 | Feb 18 (Tue) | Integration | #17, #18 | Integration + E2E tests | 5h |
| 12 | Feb 19 (Wed) | Data + Docs | #19, #20, #22, #23 | Dataset ready, docs updated | 4h |
| 13 | Feb 20 (Thu) | Buffer + Polish | - | Final testing, code review, cleanup | 4h |

**Total Estimated Hours:** ~64 hours over 13 days (~5h/day average)

---

## Dependencies

### Python Packages

```txt
# Core Framework
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-dotenv==1.0.0

# HTTP & Async
httpx==0.26.0
aiohttp==3.9.0
requests==2.31.0

# OSINT
python-whois==0.8.0
dnspython==2.5.0

# NLP (Phase 1)
spacy==3.7.2

# ML
scikit-learn==1.4.0
numpy>=1.24.0

# Testing
pytest==8.0.0
pytest-asyncio==0.23.0
pytest-cov==4.1.0

# Code Quality
black==24.1.0
isort==5.13.0
mypy==1.8.0
ruff==0.1.14
```

### spaCy Model Download
```bash
python -m spacy download en_core_web_sm
```

### External APIs (Free Tier)

| API | Purpose | Free Limit | Required |
|-----|---------|------------|----------|
| PhishTank | Phishing database | Unlimited (download) | Yes (offline) |
| Google Safe Browsing | URL checking | 10,000/day | Optional |
| VirusTotal | File/URL scanning | 4/min, 500/day | Optional |

---

## Success Criteria

### Functional Requirements
- [ ] System accepts URL input and returns phishing verdict
- [ ] System accepts email content and returns phishing verdict
- [ ] OSINT data is collected for each domain (WHOIS + DNS)
- [ ] NLP analyzer detects 6+ phishing indicator categories
- [ ] Confidence score is calculated with human-readable reasoning
- [ ] API responds within 5 seconds for URL analysis
- [ ] System handles malformed input gracefully

### Quality Requirements
- [ ] Unit test coverage >= 80% (verified with pytest-cov)
- [ ] All tests pass (pytest exit code 0)
- [ ] No critical linting errors (ruff check passes)
- [ ] Type hints on all public functions (mypy passes)
- [ ] Code follows camelCase naming convention

### Documentation Requirements
- [ ] API documentation auto-generated (FastAPI /docs)
- [ ] All modules have docstrings
- [ ] README updated with Milestone 2 features
- [ ] research.md updated with NLP approach

### Deliverables Checklist
- [ ] 23 GitHub issues created and tracked
- [ ] All issues closed with commits
- [ ] Working demo video/screenshots for supervisor
- [ ] Progress report prepared for Arafat

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation Strategy |
|------|-------------|--------|---------------------|
| WHOIS rate limiting | Medium | Medium | Implement caching (1hr TTL), use mock data for testing |
| External API downtime | Low | Medium | Graceful degradation, return partial results with warning |
| spaCy model accuracy | Medium | Medium | Start with rule-based patterns, iterate on accuracy |
| Time overrun | Medium | High | Prioritize core features, defer nice-to-haves to M3 |
| Test flakiness | Low | Medium | Mock all external calls in unit tests |
| Dependency conflicts | Low | Low | Use requirements.txt with pinned versions |

### Contingency Plan
If behind schedule by Day 8:
1. Reduce test coverage target to 70%
2. Defer documentation to Milestone 3
3. Skip optional API endpoints (keep only /api/analyze)

---

## Future Considerations (Milestone 3+)

### LLM Integration Path
When ELTE HPC access is available:
1. Create `llmAnalyzer.py` implementing `BaseAnalyzer`
2. Add Ollama/vLLM integration with structured output
3. A/B test NLP vs LLM accuracy
4. Document comparison in thesis

### Frontend Integration (Milestone 3)
- Connect frontend to API
- Display structured results
- Show OSINT data visualization
- Real-time analysis feedback

---

## Notes

### Swapping NLP to LLM Later

The analyzer module is designed with a common interface (`BaseAnalyzer`). To switch from NLP to LLM:

1. Implement `llmAnalyzer.py` following the same interface
2. Change `ANALYZER_ENGINE=llm` in .env
3. No other code changes needed

### Testing Philosophy

- Write tests BEFORE or WITH implementation (TDD-lite)
- Mock external services in unit tests (using monkeypatch)
- Use real services only in integration tests (marked with @pytest.mark.integration)
- Keep tests fast (< 1 second per unit test)
- Use fixtures for reusable test data (conftest.py)

### Code Style Guide

```python
# File naming: camelCase.py
# Example: whoisLookup.py, featureExtractor.py

# Function naming: camelCase
def getDomainAge(domain: str) -> int:
    pass

# Class naming: PascalCase
class WhoisResult(BaseModel):
    pass

# Variable naming: camelCase
domainAge = 365
isPhishing = True

# Constants: UPPER_SNAKE_CASE
MAX_TIMEOUT = 10
DEFAULT_THRESHOLD = 0.5

# Database columns (future): snake_case
# user_id, created_at, domain_age
```

### Git Commit Convention

```
<type>(<scope>): <description>

Types:
- feat: New feature
- fix: Bug fix
- test: Adding tests
- docs: Documentation
- refactor: Code refactoring
- chore: Maintenance

Examples:
- feat(osint): implement whoisLookup module
- test(osint): add unit tests for dnsChecker
- fix(api): handle timeout in analyze endpoint
- docs(readme): update milestone 2 status
```

---

## Approval

- [ ] Plan reviewed with supervisor
- [ ] GitHub milestone created
- [ ] GitHub labels created
- [ ] GitHub issues created (23 total)
- [ ] Ready to begin implementation

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Feb 8, 2026 | Ishaq Muhammad | Initial plan created |
| 1.1 | Feb 8, 2026 | Ishaq Muhammad | Added detailed testing strategy, spaCy patterns, config management |
