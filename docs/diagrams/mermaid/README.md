# PhishGuard Architecture Diagrams

This directory contains Mermaid.js (`.mmd`) source files for all architecture diagrams used in the PhishGuard thesis. These are the **authoritative sources** — the `.mmd` files are 1:1 mirrors of the actual codebase implementation.

## Available Diagrams

| Diagram | File | Description |
|---------|------|-------------|
| System Architecture | `system-architecture.mmd` | Next.js frontend, FastAPI backend, ML engine, OSINT APIs |
| User Journey | `user-journey.mmd` | User flow from input to SHAP-explained results |
| Sequence Diagram | `sequence-diagram.mmd` | Request/response lifecycle with parallel OSINT timeout |
| ML Pipeline | `ml-pipeline.mmd` | Raw data → 21-dim feature vector → XGBoost → 85/15 scoring |
| **Class Diagram** | `class-diagram.mmd` | All 17 Pydantic data models + 2 enums from codebase |

## Class Diagram Contents

The `class-diagram.mmd` includes **all** Pydantic models from `backend/api/schemas.py` and `backend/ml/schemas.py`:

**Request Schemas (<<Request>>):**
- `AnalyzeRequest`, `UrlRequest`, `EmailRequest`

**Response Schemas (<<Response>>):**
- `ModelStatusResponse`, `VerdictResult`, `OsintSummary`, `FeatureSummary`, `AnalysisResponse`, `HealthResponse`

**ML Schemas (<<ML>>):**
- `UrlFeatures`, `OsintFeatures`, `FeatureSet`, `ScoreComponent`, `RiskScore`, `SuspiciousPattern`, `UrlAnalysisResult`

**Enumerations:**
- `RiskLevel` (SAFE/SUSPICIOUS/DANGEROUS/CRITICAL)
- `FeatureCategory` (URL_STRUCTURE/DOMAIN_ANALYSIS/OSINT_DERIVED/REPUTATION)

All classes extend Pydantic's `BaseModel`. Relationships show composition (`*--`), references (`..>`), and inheritance (`<|--`).

## PNG Generation

To generate static PNG images from the `.mmd` source files:

```bash
# Install mermaid-cli globally (one-time)
npm install -g @mermaid-js/mermaid-cli

# Generate PNG for a specific diagram
mmdc -i class-diagram.mmd -o class-diagram.png -b transparent
```

Generated PNGs are stored alongside the `.mmd` files in this directory.

## Viewing

- **GitHub**: `.mmd` files render automatically in-browser
- **VS Code**: Install "Mermaid Preview" extension
- **LaTeX**: PNG images are linked in `chapter_03.tex` via `\includegraphics`