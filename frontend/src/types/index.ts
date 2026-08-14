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
  HealthResponse,
  ModelStatusResponse,
  AnalyzeRequest,
  AnalyzeUrlRequest,
  AnalyzeEmailRequest,
  BatchItemType,
  BatchItemRequest,
  BatchAnalyzeRequest,
  BatchItemResult,
  BatchAnalyzeResponse,
} from "./analysis";

export type { HistoryEntry } from "@/lib/storage/historyStore";
