/**
 * Re-exports every shared type so consumers can import from `@/types`.
 */
export type {
  ThreatLevel,
  VerdictResult,
  OsintSummary,
  FeatureSummary,
  AnalysisResponse,
  HealthResponse,
  ServiceStatus,
  AnalyzeTextRequest,
  AnalyzeUrlRequest,
  AnalyzeEmailRequest,
} from "./analysis";
