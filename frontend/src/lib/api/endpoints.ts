/**
 * Typed endpoint functions for the PhishGuard API.
 *
 * Each function maps one-to-one with a FastAPI route and returns a
 * fully-typed response.  All network / validation / API errors are
 * thrown as the custom error classes from `./errors.ts`.
 *
 * @module lib/api/endpoints
 */

import { apiClient, type RequestOptions } from "./client";
import { API_BASE_URL } from "@/lib/constants";
import { getSetting } from "@/lib/storage/settingsStore";

/**
 * Timeout for batch requests (ms).
 *
 * A single analysis can take several seconds (OSINT + ML + NLP); a
 * 50-item batch runs concurrently but can still legitimately exceed
 * the 30 s default, so batch calls get a longer budget.
 */
const BATCH_TIMEOUT_MS = 120_000;

import type {
  AnalyzeRequest,
  AnalyzeUrlRequest,
  AnalyzeEmailRequest,
  AnalysisResponse,
  BatchAnalyzeRequest,
  BatchAnalyzeResponse,
  DriftReport,
  EmailIngestResponse,
  FeedbackRequest,
  FeedbackResponse,
  HealthResponse,
  LiveHealthResponse,
  ModelStatusResponse,
} from "@/types";

/* ------------------------------------------------------------------ */
/*  Analysis endpoints                                                */
/* ------------------------------------------------------------------ */

/**
 * Analyse arbitrary content (auto-detection or explicit type).
 *
 * `POST /api/analyze`
 *
 * @param payload - Content string and optional contentType.
 * @param options - Timeout / AbortSignal overrides.
 */
export async function analyzeContent(
  payload: AnalyzeRequest,
  options?: RequestOptions,
): Promise<AnalysisResponse> {
  return apiClient<AnalysisResponse>(
    "/api/analyze",
    { method: "POST", body: JSON.stringify(payload) },
    options,
  );
}

/**
 * Analyse a single URL.
 *
 * `POST /api/analyze/url`
 *
 * @param payload - URL to analyse.
 * @param options - Timeout / AbortSignal overrides.
 */
export async function analyzeUrl(
  payload: AnalyzeUrlRequest,
  options?: RequestOptions,
): Promise<AnalysisResponse> {
  return apiClient<AnalysisResponse>(
    "/api/analyze/url",
    { method: "POST", body: JSON.stringify(payload) },
    options,
  );
}

/**
 * Analyse email content.
 *
 * `POST /api/analyze/email`
 *
 * @param payload - Email body with optional subject / sender.
 * @param options - Timeout / AbortSignal overrides.
 */
export async function analyzeEmail(
  payload: AnalyzeEmailRequest,
  options?: RequestOptions,
): Promise<AnalysisResponse> {
  return apiClient<AnalysisResponse>(
    "/api/analyze/email",
    { method: "POST", body: JSON.stringify(payload) },
    options,
  );
}

/* ------------------------------------------------------------------ */
/*  Batch analysis                                                    */
/* ------------------------------------------------------------------ */

/**
 * Analyse up to 50 items in a single round trip.
 *
 * `POST /api/analyze/batch`
 *
 * The server runs items concurrently and returns per-item results,
 * so a 50-URL batch is one HTTP request instead of 50.  A batch can
 * legitimately take much longer than a single analysis (50 items ×
 * OSINT lookups), so the default timeout is raised to 120 s.
 *
 * @param payload - List of items to analyse.
 * @param options - Timeout / AbortSignal overrides.
 */
export async function analyzeBatch(
  payload: BatchAnalyzeRequest,
  options?: RequestOptions,
): Promise<BatchAnalyzeResponse> {
  return apiClient<BatchAnalyzeResponse>(
    "/api/analyze/batch",
    { method: "POST", body: JSON.stringify(payload) },
    { timeoutMs: BATCH_TIMEOUT_MS, ...options },
  );
}

/* ------------------------------------------------------------------ */
/*  EML ingestion (Tier 4 E)                                          */
/* ------------------------------------------------------------------ */

/**
 * Upload a raw `.eml` file for parsing and analysis.
 *
 * `POST /api/ingest/email`
 *
 * The file bytes are sent as-is with `Content-Type: message/rfc822`;
 * the backend parses subject/sender/body/attachments and returns the
 * standard analysis plus a `parsed` summary.  A full email analysis
 * can take several seconds, so the timeout is raised like the batch
 * endpoint's.
 *
 * @param file - The `.eml` file to analyse.
 * @param options - Timeout / AbortSignal overrides.
 */
export async function ingestEmail(
  file: File,
  options?: RequestOptions,
): Promise<EmailIngestResponse> {
  return apiClient<EmailIngestResponse>(
    "/api/ingest/email",
    {
      method: "POST",
      body: file,
      /* Override the JSON content-type from the default headers: the
         raw RFC 822 bytes go out untouched. */
      headers: { "Content-Type": "message/rfc822" },
    },
    { timeoutMs: BATCH_TIMEOUT_MS, ...options },
  );
}

/* ------------------------------------------------------------------ */
/*  Health / meta endpoints                                           */
/* ------------------------------------------------------------------ */

/**
 * Cheap backend liveness check for UI indicators.
 *
 * `GET /api/health/live`
 *
 * Deliberately uses the *liveness* probe rather than the deep readiness
 * endpoint: the navbar polls every 30 s, and the deep probe performs real
 * DNS lookups and ML inference server-side on every call.
 */
export async function checkHealthLive(
  options?: RequestOptions,
): Promise<LiveHealthResponse> {
  return apiClient<LiveHealthResponse>(
    "/api/health/live",
    { method: "GET" },
    { timeoutMs: 5_000, ...options },
  );
}

/**
 * Resolve the base URL of the configured backend (user setting wins over
 * build-time env), for direct-download endpoints such as history exports.
 */
export function getBackendBaseUrl(): string {
  const userUrl = getSetting("apiUrl");
  if (userUrl && userUrl.trim() !== "") return userUrl.replace(/\/+$/, "");
  return API_BASE_URL;
}

/**
 * Direct download URLs for the backend's persistent history exports.
 * The frontend keeps its own localStorage history; these expose the
 * server-side record set (populated when PHISHGUARD_PERSIST_HISTORY=1).
 */
export function getServerHistoryExportUrls(): { csv: string; json: string } {
  const base = getBackendBaseUrl();
  return {
    csv: `${base}/api/history/export.csv`,
    json: `${base}/api/history/export.json`,
  };
}

/**
 * Ping the API root.
 *
 * `GET /api/`
 *
 * Returns the welcome message — useful as a lightweight connectivity check.
 */
export async function pingApi(
  options?: RequestOptions,
): Promise<{ message: string }> {
  return apiClient<{ message: string }>(
    "/api/",
    { method: "GET" },
    { timeoutMs: 5_000, ...options },
  );
}

/**
 * Retrieve the ML model's availability and metadata.
 *
 * `GET /api/model/status`
 */
export async function getModelStatus(
  options?: RequestOptions,
): Promise<ModelStatusResponse> {
  return apiClient<ModelStatusResponse>(
    "/api/model/status",
    { method: "GET" },
    { timeoutMs: 5_000, ...options },
  );
}

/**
 * Submit an operator verdict label for a past analysis.
 *
 * `POST /api/feedback`
 */
export async function submitFeedback(
  body: FeedbackRequest,
  options?: RequestOptions,
): Promise<FeedbackResponse> {
  return apiClient<FeedbackResponse>(
    "/api/feedback",
    { method: "POST", body: JSON.stringify(body) },
    { timeoutMs: 10_000, ...options },
  );
}

/**
 * Retrieve the model drift report.
 *
 * `GET /api/model/drift`
 */
export async function getModelDrift(
  options?: RequestOptions,
): Promise<DriftReport> {
  return apiClient<DriftReport>(
    "/api/model/drift",
    { method: "GET" },
    { timeoutMs: 15_000, ...options },
  );
}
