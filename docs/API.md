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
  "explanation": {
    "summary": "Flagged primarily because the domain was registered only 2 days ago; fresh domains are a strong phishing indicator. 3 additional signal(s) were detected.",
    "items": [
      { "signal": "newlyRegisteredDomain", "severity": "critical", "detail": "The domain was registered only 2 days ago; fresh domains are a strong phishing indicator." },
      { "signal": "hasSuspiciousTld", "severity": "high", "detail": "The domain uses a TLD frequently abused in phishing campaigns (.tk, .ml, .xyz, etc.)." }
    ]
  },
  "analysisTime": 1240.5
}
```

**Explanation field (URL analyses only):** deterministic template-generated report — every item is derived from a concrete feature value or OSINT signal and ranked by severity, then by global SHAP importance of the underlying feature. Severities: `critical`, `high`, `medium`, `low`. Absent (`null`) for email/text analyses and when explanation generation fails.


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

### 5b. Model Drift Report
Per-feature Population Stability Index (PSI) of the live feature distribution against a snapshotted reference window. The monitor cold-starts: until `minSamples` (default 200) URL analyses have been logged it reports `cold_start`; afterwards the oldest window freezes as the baseline and every call compares the most recent `evaluationWindow` (default 100) vectors against it.

**Endpoint:** `GET /api/model/drift`

**Response (200 OK, ready):**
```json
{
  "status": "ok",
  "overall": "significant",
  "sampleCount": 312,
  "baselineAt": "2026-08-23T10:00:00+00:00",
  "features": [
    { "name": "digitRatio", "psi": 0.412, "status": "significant" },
    { "name": "hasSuspiciousTld", "psi": 0.081, "status": "stable" }
  ]
}
```

**Cold start:** `"status": "cold_start"`, empty `features`.

Bands per feature: `stable` < 0.1 ≤ `moderate` < 0.25 ≤ `significant`. `overall` mirrors the worst feature. Each evaluation also refreshes the `phishguard_drift_psi{feature}` and `phishguard_drift_max_psi` Prometheus gauges on `/metrics`.

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

### 9. History Export
Bulk-download the entire history store for offline triage or archive. Both endpoints return an attachment (`Content-Disposition`) and are bounded by the store's FIFO cap.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/history/export.csv` | Full history as CSV (`text/csv`) — one row per analysis, newest-first |
| `GET` | `/api/history/export.json` | Full history as a JSON array (`application/json`) — lossless dump, ISO-8601 timestamps |

**CSV columns (in order):**
```
id, createdAt, contentType, content, isPhishing, threatLevel,
confidenceScore, reasons, recommendation, osintDomain,
osintReputationScore, analysisTimeMs
```

Notes:
- `reasons` is a `; `-joined string; `content` is the full original payload (CSV-quoted).
- Rows are newest-first, matching `GET /api/history`.
- Empty store → header-only CSV / empty JSON array `[]`.
- The routes are registered before `/history/{entryId}` so `export.csv` is never mistaken for an entry ID.

### 10. Prometheus Metrics
Operational observability endpoint in the Prometheus text exposition format (version 0.0.4). Scraped by monitoring systems (e.g. every 15 s); deliberately **not** rate-limited hard and not behind the API-key middleware, same posture as `/api/health`.
**Endpoint:** `GET /metrics`

**Metrics exposed:**
```
phishguard_http_requests_total{method,path,status}      # request counter
phishguard_http_request_duration_seconds{method,path}   # latency histogram (5 ms..10 s buckets)
phishguard_analysis_total{content_type,threat_level}    # completed analyses
```

Notes:
- Zero-dependency implementation — no `prometheus-client` required; the exposition format is hand-rendered and pinned by golden tests.
- `/metrics` and `/api/health` are self-excluded from the request counters so scrapers don't pollute their own signal.
- The analysis counter is fed from the orchestrator, so single, batch, and `.eml` ingest analyses all count.
- Not listed in the OpenAPI schema (`include_in_schema=False`).

### 11. EML Ingestion
Parses a raw RFC 822 / MIME `.eml` file and runs it through the same email-analysis pipeline as `/api/analyze/email`. The response carries the full analysis result **plus** a `parsed` summary of the extracted fields, so an investigator forwarding a suspicious message sees exactly what was read out of the file.
**Endpoint:** `POST /api/ingest/email`

**Request:** raw bytes with `Content-Type: message/rfc822` (or `text/plain`):
```
POST /api/ingest/email
Content-Type: message/rfc822

From: security@paypa1-support.com
Subject: Your account is suspended

Urgent! Click here to verify your identity...
```

**Response (200 OK):**
```json
{
  "success": true,
  "verdict": { "isPhishing": true, "threatLevel": "dangerous", "...": "..." },
  "parsed": {
    "subject": "Your account is suspended",
    "senderName": "",
    "senderAddress": "security@paypa1-support.com",
    "recipients": ["victim@example.com"],
    "bodyPreview": "Urgent! Click here to verify your identity...",
    "hasAttachments": false,
    "attachmentNames": [],
    "sizeBytes": 742
  }
}
```

Notes:
- Payloads larger than the configured cap (default **1 MB**, env `EML_MAX_BYTES`) are rejected with **413**.
- Messages with no readable text body (empty, header-only, or binary) are rejected with **422**.
- The parser is deliberately lenient: HTML-only messages have tags stripped, RFC 2047 encoded-words are decoded, and malformed payloads degrade to partial fields instead of crashing.
- Attachments are detected but never analysed — only the extracted text is scored.
- Successful ingests are persisted to the history store; the endpoint is rate-limited like the other analysis routes and protected by API-key auth when configured.

**List:** `GET /api/feedback?limit=100&offset=0` — returns the parsed record list, newest first, with a `total` count.
