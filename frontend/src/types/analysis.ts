/**
 * TypeScript type definitions mirroring the backend Pydantic schemas.
 *
 * These types represent every response shape returned by the FastAPI
 * backend so that the frontend can consume them with full type safety.
 */

/* ------------------------------------------------------------------ */
/*  Verdict                                                           */
/* ------------------------------------------------------------------ */

/** Possible threat-level classifications. */
export type ThreatLevel = "safe" | "suspicious" | "dangerous" | "critical";

/** The core verdict produced by the scoring engine. */
export interface VerdictResult {
  isPhishing: boolean;
  confidenceScore: number;
  threatLevel: ThreatLevel;
  reasons: string[];
  recommendation: string;
}

/* ------------------------------------------------------------------ */
/*  OSINT                                                             */
/* ------------------------------------------------------------------ */

/** OSINT enrichment data collected for the analysed domain. */
export interface OsintSummary {
  domain: string;
  domainAgeDays: number | null;
  registrar: string | null;
  isPrivate: boolean;
  hasValidDns: boolean;
  reputationScore: number;
  inBlacklists: boolean;
}

/* ------------------------------------------------------------------ */
/*  Features                                                          */
/* ------------------------------------------------------------------ */

/** Aggregated feature summary returned alongside the verdict. */
export interface FeatureSummary {
  urlFeatures: number;
  textFeatures: number;
  osintFeatures: number;
  totalRiskIndicators: number;
  detectedTactics: string[];
}

/* ------------------------------------------------------------------ */
/*  Analysis response                                                 */
/* ------------------------------------------------------------------ */

/** Top-level response from `POST /api/analyze/*` endpoints. */
export interface AnalysisResponse {
  success: boolean;
  verdict: VerdictResult;
  osint: OsintSummary | null;
  features: FeatureSummary;
  analysisTime: number;
  analyzedAt: string;
  error: string | null;
}

/* ------------------------------------------------------------------ */
/*  Health                                                            */
/* ------------------------------------------------------------------ */

/** Health-status discriminator. */
export type HealthStatus = "healthy" | "degraded" | "unhealthy";

/** Response from `GET /api/health`. */
export interface HealthResponse {
  status: HealthStatus;
  version: string;
  timestamp: string;
  services: Record<string, boolean>;
}

/* ------------------------------------------------------------------ */
/*  Model status                                                      */
/* ------------------------------------------------------------------ */

/** Response from `GET /api/model/status`. */
export interface ModelStatusResponse {
  loaded: boolean;
  featureCount: number;
  featureNames: string[];
}

/* ------------------------------------------------------------------ */
/*  Request payloads                                                  */
/* ------------------------------------------------------------------ */

/** Content-type discriminator accepted by the generic analyse endpoint. */
export type ContentType = "auto" | "url" | "email" | "text";

/** Payload for `POST /api/analyze` (generic content). */
export interface AnalyzeRequest {
  content: string;
  contentType?: ContentType;
}

/** Payload for `POST /api/analyze/url`. */
export interface AnalyzeUrlRequest {
  url: string;
}

/** Payload for `POST /api/analyze/email`. */
export interface AnalyzeEmailRequest {
  content: string;
  subject?: string;
  sender?: string;
}

/* ------------------------------------------------------------------ */
/*  Batch analysis                                                    */
/* ------------------------------------------------------------------ */

/** Per-item discriminator accepted by `POST /api/analyze/batch`. */
export type BatchItemType = "auto" | "url" | "email";

/** A single item inside a batch payload (mirrors `BatchItemRequest`). */
export interface BatchItemRequest {
  type: BatchItemType;
  url?: string | null;
  content?: string | null;
  subject?: string | null;
  sender?: string | null;
}

/** Payload for `POST /api/analyze/batch` (1–50 items). */
export interface BatchAnalyzeRequest {
  items: BatchItemRequest[];
}

/** Per-item outcome: `ok` carries a response, `error` carries a message. */
export interface BatchItemResult {
  index: number;
  status: "ok" | "error";
  response?: AnalysisResponse | null;
  error?: string | null;
}

/** Response from `POST /api/analyze/batch` (always HTTP 200). */
export interface BatchAnalyzeResponse {
  success: boolean;
  total: number;
  succeeded: number;
  failed: number;
  analysisTime: number;
  results: BatchItemResult[];
}
