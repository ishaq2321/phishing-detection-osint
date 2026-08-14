# PhishGuard API Documentation

PhishGuard is a high-performance, asynchronous phishing detection API powered by XGBoost, spaCy, and multi-source OSINT aggregation.

## Base URL
Production: `https://phishguard-api-upl2.onrender.com`
Local: `http://localhost:8000`

## Endpoints

### 1. Health Check
Checks the status of the API and its internal services.
**Endpoint:** `GET /api/health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-04-10T03:00:00Z",
  "services": {
    "osint": true,
    "ml": true,
    "analyzer": true
  }
}
```

### 2. Auto-Detect Analysis
Automatically detects the content type (URL or Email text) and performs a comprehensive analysis.
**Endpoint:** `POST /api/analyze`

**Request Body:**
```json
{
  "content": "https://suspicious-login.tk/verify",
  "contentType": "auto" 
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "verdict": {
    "isPhishing": true,
    "confidenceScore": 0.87,
    "threatLevel": "dangerous",
    "reasons": [
      "ML model confidence: 87.0%",
      "Domain registered recently (2 days ago)",
      "Uses suspicious top-level domain"
    ],
    "recommendation": "This content has multiple phishing indicators. Do not click links or provide information."
  },
  "osint": {
    "domain": "suspicious-login.tk",
    "domainAgeDays": 2,
    "registrar": "Freenom",
    "isPrivate": true,
    "hasValidDns": true,
    "reputationScore": 0.6,
    "inBlacklists": false
  },
  "features": {
    "urlFeatures": 4,
    "textFeatures": 0,
    "osintFeatures": 2,
    "totalRiskIndicators": 6,
    "detectedTactics": []
  },
  "analysisTime": 1240.5
}
```

### 3. URL-Specific Analysis
Forces the analyzer to treat the payload as a URL.
**Endpoint:** `POST /api/analyze/url`

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

### 4. Email/Text-Specific Analysis
Forces the analyzer to treat the payload as an email or raw text block, utilizing the spaCy NLP pipeline heavily.
**Endpoint:** `POST /api/analyze/email`

**Request Body:**
```json
{
  "content": "URGENT: Your account will be suspended in 24 hours. Click here to verify your identity.",
  "subject": "Account Suspension Notice",
  "sender": "security@paypal-verify-team.com"
}
```

### 5. Model Status
Returns whether the XGBoost model is loaded and which features it expects.
**Endpoint:** `GET /api/model/status`

**Response (200 OK):**
```json
{
  "loaded": true,
  "featureCount": 21,
  "featureNames": ["urlLength", "domainLength", "..."]
}
```

### 6. Batch Analysis
Analyses 1–50 items (URL / email / auto-detect) in a single round trip, running them concurrently server-side. Per-item failures do **not** reject the batch — the top-level HTTP status is always 200 and each item carries its own `status`.
**Endpoint:** `POST /api/analyze/batch`

**Request Body:**
```json
{
  "items": [
    { "type": "url", "url": "https://suspicious-paypal.com/verify" },
    { "type": "email", "content": "...", "subject": "Hi", "sender": "me@x" },
    { "type": "auto", "url": "https://example.com" }
  ]
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "analysisTime": 1250.0,
  "results": [
    { "index": 0, "status": "ok", "response": { "verdict": { "...": "..." } } },
    { "index": 1, "status": "error", "error": "type=url but url field is empty" },
    { "index": 2, "status": "ok", "response": { "verdict": { "...": "..." } } }
  ]
}
```

Notes:
- Empty payloads and >50 items are rejected with **422**.
- Successful items are persisted to the history store; failed items are not.
- The endpoint is rate-limited like the single-analysis routes (one batch counts as one request).

### 7. History
Persisted analyses (in-memory FIFO by default, SQLite-backed when `PHISHGUARD_PERSIST_HISTORY=1`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/history?limit=100&offset=0` | List analyses, newest first |
| `GET` | `/api/history/{id}` | Fetch one entry by UUID |
| `DELETE` | `/api/history/{id}` | Delete one entry |
| `DELETE` | `/api/history` | Clear all entries |

### 8. Feedback (Operator Loop)
Operators flag misclassifications against past analyses; records are appended to `./data/feedback.jsonl` (overridable via `PHISHGUARD_FEEDBACK_LOG`) and can be folded back into the training pipeline with `backend/ml/training/retrainFromFeedback.py`.

**Submit:** `POST /api/feedback`

**Request Body:**
```json
{
  "historyId": "a8bc7e95-1234-5678-90ab-cdef01234567",
  "verdict": "false_negative",
  "comment": "optional note",
  "reporter": "optional@operator"
}
```

`verdict` must be one of `false_negative`, `false_positive`, `correct` (else **422**).

**Response (200 OK):**
```json
{ "accepted": true, "feedbackId": "...", "historyId": "..." }
```

**List:** `GET /api/feedback?limit=100&offset=0` — returns the parsed record list, newest first, with a `total` count.
