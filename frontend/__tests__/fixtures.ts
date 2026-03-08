/**
 * Shared test fixtures — reusable mock data for all test files.
 */

import type {
  AnalysisResponse,
  VerdictResult,
  OsintSummary,
  FeatureSummary,
  HealthResponse,
} from "@/types";

/* ------------------------------------------------------------------ */
/*  Verdict fixtures                                                  */
/* ------------------------------------------------------------------ */

export const safeVerdict: VerdictResult = {
  isPhishing: false,
  confidenceScore: 0.15,
  threatLevel: "safe",
  reasons: ["No suspicious patterns detected"],
  recommendation: "This content appears to be safe.",
};

export const suspiciousVerdict: VerdictResult = {
  isPhishing: false,
  confidenceScore: 0.55,
  threatLevel: "suspicious",
  reasons: ["Unusual URL structure", "Recently registered domain"],
  recommendation: "Exercise caution with this content.",
};

export const dangerousVerdict: VerdictResult = {
  isPhishing: true,
  confidenceScore: 0.78,
  threatLevel: "dangerous",
  reasons: [
    "Credential harvesting keywords detected",
    "Domain impersonation attempt",
    "No valid DNS records",
  ],
  recommendation: "Do not interact with this content.",
};

export const criticalVerdict: VerdictResult = {
  isPhishing: true,
  confidenceScore: 0.95,
  threatLevel: "critical",
  reasons: [
    "Known malicious domain",
    "Active phishing campaign",
    "IP-based URL",
    "Blacklisted domain",
  ],
  recommendation: "This is a confirmed phishing attempt. Report immediately.",
};

/* ------------------------------------------------------------------ */
/*  OSINT fixtures                                                    */
/* ------------------------------------------------------------------ */

export const safeOsint: OsintSummary = {
  domain: "example.com",
  domainAgeDays: 9125,
  registrar: "MarkMonitor Inc.",
  isPrivate: false,
  hasValidDns: true,
  reputationScore: 0.02,
  inBlacklists: false,
};

export const suspiciousOsint: OsintSummary = {
  domain: "examp1e-login.tk",
  domainAgeDays: 12,
  registrar: "NameCheap, Inc.",
  isPrivate: true,
  hasValidDns: true,
  reputationScore: 0.65,
  inBlacklists: false,
};

/* ------------------------------------------------------------------ */
/*  Feature fixtures                                                  */
/* ------------------------------------------------------------------ */

export const safeFeatures: FeatureSummary = {
  urlFeatures: 0,
  textFeatures: 1,
  osintFeatures: 0,
  totalRiskIndicators: 1,
  detectedTactics: [],
};

export const dangerousFeatures: FeatureSummary = {
  urlFeatures: 5,
  textFeatures: 3,
  osintFeatures: 4,
  totalRiskIndicators: 12,
  detectedTactics: ["credential_request", "brand_impersonation", "urgency"],
};

/* ------------------------------------------------------------------ */
/*  Full response fixtures                                            */
/* ------------------------------------------------------------------ */

export const safeResponse: AnalysisResponse = {
  success: true,
  verdict: safeVerdict,
  osint: safeOsint,
  features: safeFeatures,
  analysisTime: 1.23,
  analyzedAt: "2026-03-08T12:00:00Z",
  error: null,
};

export const dangerousResponse: AnalysisResponse = {
  success: true,
  verdict: dangerousVerdict,
  osint: suspiciousOsint,
  features: dangerousFeatures,
  analysisTime: 2.45,
  analyzedAt: "2026-03-08T13:30:00Z",
  error: null,
};

/* ------------------------------------------------------------------ */
/*  Health fixtures                                                   */
/* ------------------------------------------------------------------ */

export const healthyResponse: HealthResponse = {
  status: "healthy",
  version: "1.0.0",
  timestamp: "2026-03-08T12:00:00Z",
  services: { nlp: true, osint: true, scorer: true },
};
