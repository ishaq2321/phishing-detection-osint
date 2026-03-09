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
import type {
  AnalyzeRequest,
  AnalyzeUrlRequest,
  AnalyzeEmailRequest,
  AnalysisResponse,
  HealthResponse,
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
