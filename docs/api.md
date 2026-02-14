# API Documentation

> **Phishing Detection API** — v1.0.0  
> Author: Ishaq Muhammad (PXPRGK)  
> BSc Thesis — ELTE Faculty of Informatics

---

## Overview

The Phishing Detection API provides RESTful endpoints for analysing URLs and email content for phishing indicators. It combines three detection layers:

| Layer | Purpose | Weight |
|-------|---------|--------|
| **NLP / Text Analysis** | Detect urgency, credential requests, impersonation | 40 % |
| **OSINT** | WHOIS age, DNS records, reputation blacklists | 35 % |
| **ML / URL Features** | Suspicious TLD, subdomain depth, special characters | 25 % |

**Base URL:** `http://localhost:8000`

**Interactive docs:**
- Swagger UI → `GET /docs`
- ReDoc → `GET /redoc`
- OpenAPI JSON → `GET /openapi.json`

---

## Authentication

No authentication is required for the current version.

---

## Endpoints

### 1. `POST /api/analyze`

Analyse any content (URL, email, or free text) for phishing indicators.

#### Request

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `content` | `string` | ✅ | — | URL, email body, or text to analyse |
| `contentType` | `string` | ❌ | `"auto"` | One of `auto`, `url`, `email`, `text` |

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "content": "http://paypal-verify.tk/login",
    "contentType": "url"
  }'
```

#### Response `200 OK`

```json
{
  "success": true,
  "verdict": {
    "isPhishing": true,
    "confidenceScore": 0.82,
    "threatLevel": "dangerous",
    "reasons": [
      "Uses urgency tactics",
      "Suspicious TLD (.tk)",
      "Domain registered recently (3 days ago)",
      "WHOIS privacy protection enabled"
    ],
    "recommendation": "This content has multiple phishing indicators. Do not click links or provide information."
  },
  "osint": {
    "domain": "paypal-verify.tk",
    "domainAgeDays": 3,
    "registrar": "Freenom",
    "isPrivate": true,
    "hasValidDns": true,
    "reputationScore": 0.15,
    "inBlacklists": false
  },
  "features": {
    "urlFeatures": 4,
    "textFeatures": 2,
    "osintFeatures": 3,
    "totalRiskIndicators": 9,
    "detectedTactics": ["brand_impersonation", "urgency"]
  },
  "analysisTime": 1250.5,
  "analyzedAt": "2026-02-14T12:00:00",
  "error": null
}
```

---

### 2. `POST /api/analyze/url`

Convenience endpoint specifically for URL analysis.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | `string` | ✅ | URL to analyse |

```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'
```

#### Response

Same schema as `POST /api/analyze` (see above).

---

### 3. `POST /api/analyze/email`

Convenience endpoint specifically for email content analysis.

#### Request

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `content` | `string` | ✅ | — | Email body text |
| `subject` | `string` | ❌ | `null` | Email subject line |
| `sender` | `string` | ❌ | `null` | Sender email address |

```bash
curl -X POST http://localhost:8000/api/analyze/email \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Your account has been suspended. Verify now at http://verify-now.tk",
    "subject": "URGENT: Account Suspended",
    "sender": "security@paypa1.com"
  }'
```

#### Response

Same schema as `POST /api/analyze`.

---

### 4. `GET /api/health`

Health check — returns service status and version.

```bash
curl http://localhost:8000/api/health
```

#### Response `200 OK`

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-02-14T12:00:00",
  "services": {
    "osint": true,
    "analyzer": true,
    "ml": true
  }
}
```

| `status` value | Meaning |
|----------------|---------|
| `healthy` | All services operational |
| `degraded` | One or more services unavailable |
| `unhealthy` | System cannot process requests |

---

### 5. `GET /api/`

API root — returns metadata and endpoint listing.

```bash
curl http://localhost:8000/api/
```

#### Response `200 OK`

```json
{
  "name": "Phishing Detection API",
  "version": "1.0.0",
  "docs": "/docs",
  "health": "/api/health",
  "endpoints": {
    "analyze": "/api/analyze",
    "analyzeUrl": "/api/analyze/url",
    "analyzeEmail": "/api/analyze/email"
  }
}
```

---

## Response Schemas

### `AnalysisResponse`

| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | Whether the analysis completed without errors |
| `verdict` | `VerdictResult` | Final phishing verdict |
| `osint` | `OsintSummary?` | OSINT data summary (null if not available) |
| `features` | `FeatureSummary` | Extracted feature counts |
| `analysisTime` | `float` | Processing time in milliseconds |
| `analyzedAt` | `datetime` | ISO 8601 timestamp |
| `error` | `string?` | Error message if `success` is `false` |

### `VerdictResult`

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `isPhishing` | `bool` | — | True if score ≥ 0.6 |
| `confidenceScore` | `float` | `0.0` – `1.0` | Combined weighted score |
| `threatLevel` | `string` | `safe` / `suspicious` / `dangerous` / `critical` | Severity classification |
| `reasons` | `list[str]` | — | Human-readable explanations (max 10) |
| `recommendation` | `string` | — | Suggested user action |

**Threat-level thresholds:**

| Score Range | Threat Level |
|-------------|-------------|
| 0.0 – 0.39 | `safe` |
| 0.4 – 0.59 | `suspicious` |
| 0.6 – 0.79 | `dangerous` |
| 0.8 – 1.0  | `critical` |

### `OsintSummary`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Analysed domain |
| `domainAgeDays` | `int?` | Domain age in days |
| `registrar` | `string?` | WHOIS registrar |
| `isPrivate` | `bool` | Privacy protection enabled |
| `hasValidDns` | `bool` | Has valid DNS records |
| `reputationScore` | `float` | `0.0`–`1.0` (higher = better reputation) |
| `inBlacklists` | `bool` | Found in any blacklist |

### `FeatureSummary`

| Field | Type | Description |
|-------|------|-------------|
| `urlFeatures` | `int` | URL-based suspicious features |
| `textFeatures` | `int` | NLP-detected text features |
| `osintFeatures` | `int` | OSINT risk indicators |
| `totalRiskIndicators` | `int` | Sum of all indicators |
| `detectedTactics` | `list[str]` | e.g. `["urgency", "brand_impersonation"]` |

---

## Error Handling

### Validation Error — `422 Unprocessable Entity`

Returned when the request body fails Pydantic validation.

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "", "contentType": "url"}'
```

```json
{
  "detail": [
    {
      "loc": ["body", "content"],
      "msg": "String should have at least 1 character",
      "type": "string_too_short"
    }
  ]
}
```

### Invalid Content Type — `422 Unprocessable Entity`

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "test", "contentType": "invalid"}'
```

```json
{
  "detail": [
    {
      "loc": ["body", "contentType"],
      "msg": "String should match pattern '^(auto|url|email|text)$'",
      "type": "string_pattern_mismatch"
    }
  ]
}
```

### Internal Server Error — `500 Internal Server Error`

Returned when analysis encounters an unexpected error.

```json
{
  "detail": "Analysis failed: <error message>"
}
```

In **debug mode**, the response includes the exception type:

```json
{
  "detail": "Unexpected error message",
  "type": "RuntimeError"
}
```

### Error Code Summary

| Code | Meaning | Common Cause |
|------|---------|--------------|
| `200` | Success | Analysis completed |
| `400` | Bad Request | Invalid input value |
| `422` | Validation Error | Missing / malformed fields |
| `500` | Internal Error | Unexpected server failure |

---

## Usage Examples

### Python (httpx)

```python
import httpx

response = httpx.post(
    "http://localhost:8000/api/analyze",
    json={
        "content": "http://paypal-verify.tk/login",
        "contentType": "url",
    },
)
result = response.json()

if result["verdict"]["isPhishing"]:
    print(f"⚠️  Phishing detected ({result['verdict']['threatLevel']})")
    for reason in result["verdict"]["reasons"]:
        print(f"   - {reason}")
else:
    print("✅ Content appears safe")
```

### JavaScript (fetch)

```javascript
const response = await fetch("http://localhost:8000/api/analyze", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    content: "http://paypal-verify.tk/login",
    contentType: "url",
  }),
});

const result = await response.json();
console.log(result.verdict.threatLevel);
```

### httpie

```bash
# Analyse a URL
http POST localhost:8000/api/analyze content="https://suspicious.tk/login" contentType=url

# Analyse an email
http POST localhost:8000/api/analyze/email \
  content="Your account is locked" \
  subject="Security Alert" \
  sender="no-reply@paypa1.com"

# Health check
http GET localhost:8000/api/health
```

---

## Running the Server

```bash
# Install dependencies
pip install -r backend/requirements.txt
python -m spacy download en_core_web_sm

# Start the server
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Access interactive docs
open http://localhost:8000/docs
```
