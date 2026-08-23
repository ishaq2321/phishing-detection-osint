/**
 * Re-exports every shared type so consumers can import from `@/types`.
 */
export type {
  ThreatLevel,
  ContentType,
  HealthStatus,
  VerdictResult,
  OsintSummary,
  FeatureSummary,
  AnalysisResponse,
  ExplanationSeverity,
  ExplanationItem,
  ExplanationReport,
  HealthResponse,
  LiveHealthResponse,
  ModelStatusResponse,
  AnalyzeRequest,
  AnalyzeUrlRequest,
  AnalyzeEmailRequest,
  BatchItemType,
  BatchItemRequest,
  BatchAnalyzeRequest,
  BatchItemResult,
  BatchAnalyzeResponse,
  EmIngestSummary,
  EmailIngestResponse,
  FeedbackVerdict,
  FeedbackRequest,
  FeedbackResponse,
  DriftStatus,
  DriftFeature,
  DriftReport,
} from "./analysis";

export type { HistoryEntry } from "@/lib/storage/historyStore";
