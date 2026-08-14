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
  EmailIngestResponse,
  HealthResponse,
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
 * Check the backend health status.
 *
 * `GET /api/health`
 *
 * Uses a short timeout (5 s) since this is typically polled.
 */
export async function checkHealth(
  options?: RequestOptions,
): Promise<HealthResponse> {
  return apiClient<HealthResponse>(
    "/api/health",
    { method: "GET" },
    { timeoutMs: 5_000, ...options },
  );
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
