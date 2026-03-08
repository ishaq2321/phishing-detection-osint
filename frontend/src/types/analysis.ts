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
