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

/** Service status inside the health response. */
export interface ServiceStatus {
  status: string;
  details?: string;
}

/** Response from `GET /api/health`. */
export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
  services: Record<string, ServiceStatus>;
}

/* ------------------------------------------------------------------ */
/*  Request payloads                                                  */
/* ------------------------------------------------------------------ */

/** Payload for `POST /api/analyze` (raw text). */
export interface AnalyzeTextRequest {
  content: string;
  contentType?: string;
}

/** Payload for `POST /api/analyze/url`. */
export interface AnalyzeUrlRequest {
  url: string;
}

/** Payload for `POST /api/analyze/email`. */
export interface AnalyzeEmailRequest {
  subject: string;
  sender: string;
  body: string;
}
