/**
 * API Client — low-level fetch wrapper.
 *
 * Every outbound HTTP call goes through {@link apiClient} so that
 * base-URL resolution, timeouts, headers, and error mapping are
 * handled in exactly one place.
 *
 * @module lib/api/client
 */

import { API_BASE_URL } from "@/lib/constants";
import { getSetting } from "@/lib/storage/settingsStore";
import { ApiError, NetworkError, ValidationError } from "./errors";
import type { ValidationDetail } from "./errors";

/* ------------------------------------------------------------------ */
/* Configuration */
/* ------------------------------------------------------------------ */

/** Default timeout for all requests (ms). */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Headers sent with every request. */
const DEFAULT_HEADERS: HeadersInit = {
  "Content-Type": "application/json",
  Accept: "application/json",
};

/**
 * Resolve the effective API base URL.
 *
 * Priority:
 * 1. User-configured `apiUrl` in localStorage settings (via settingsStore)
 * 2. Build-time `NEXT_PUBLIC_API_URL` env var
 * 3. Hardcoded default `http://localhost:8000`
 */
function resolveBaseUrl(): string {
  const userUrl = getSetting("apiUrl");
  if (userUrl && userUrl.trim() !== "") return userUrl.replace(/\/+$/, "");
  return API_BASE_URL;
}

/* ------------------------------------------------------------------ */
/*  Request options                                                   */
/* ------------------------------------------------------------------ */

export interface RequestOptions {
  /** Override the default timeout (ms). */
  timeoutMs?: number;
  /** AbortSignal for external cancellation (e.g. user clicks Cancel). */
  signal?: AbortSignal;
}

/* ------------------------------------------------------------------ */
/*  Core client                                                       */
/* ------------------------------------------------------------------ */

/**
 * Low-level fetch wrapper.
 *
 * - Resolves `path` against the configured `API_BASE_URL`.
 * - Attaches JSON headers and an `AbortController`-based timeout.
 * - Maps failures to typed error classes: {@link NetworkError},
 *   {@link ValidationError}, {@link ApiError}.
 *
 * @typeParam T - Expected shape of the JSON response body.
 */
export async function apiClient<T>(
  path: string,
  init: RequestInit = {},
  options: RequestOptions = {},
): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, signal: externalSignal } = options;

  /* ---- AbortController (timeout + external signal) --------------- */
  const controller = new AbortController();

  const timeoutId = setTimeout(() => controller.abort("Request timed out"), timeoutMs);

  /* If the caller provided a signal, abort ours when theirs fires. */
  externalSignal?.addEventListener("abort", () => controller.abort(externalSignal.reason), {
    once: true,
  });

  /* ---- Build the Request ---------------------------------------- */
  const baseUrl = resolveBaseUrl();
  const url = `${baseUrl}${path}`;

  const fetchInit: RequestInit = {
    ...init,
    headers: { ...DEFAULT_HEADERS, ...init.headers },
    signal: controller.signal,
  };

  /* ---- Execute -------------------------------------------------- */
  let response: Response;

  try {
    response = await fetch(url, fetchInit);
  } catch (error: unknown) {
    clearTimeout(timeoutId);

    if (error instanceof DOMException && error.name === "AbortError") {
      throw new NetworkError("Request was cancelled or timed out.", error);
    }

    throw new NetworkError(
      "Cannot connect to the analysis server. Is the backend running?",
      error,
    );
  } finally {
    clearTimeout(timeoutId);
  }

  /* ---- Handle non-2xx ------------------------------------------- */
  if (!response.ok) {
    const body = await safeJson(response);

    /* FastAPI validation errors (422) */
    if (response.status === 422 && isValidationBody(body)) {
      throw new ValidationError(body.detail as ValidationDetail[]);
    }

    /* Generic API error */
    const message =
      typeof body?.detail === "string"
        ? body.detail
        : `Request failed with status ${response.status}`;

    throw new ApiError(message, response.status, body);
  }

  /* ---- Parse JSON ----------------------------------------------- */
  return (await response.json()) as T;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/**
 * Attempt to parse JSON from a response; return `undefined` on failure
 * so that callers never crash on an empty or non-JSON body.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function safeJson(res: Response): Promise<any> {
  try {
    return await res.json();
  } catch {
    return undefined;
  }
}

/**
 * Type-guard: does the parsed body look like a FastAPI 422 response?
 * Expected shape: `{ detail: [{ loc, msg, type }] }`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isValidationBody(body: any): body is { detail: ValidationDetail[] } {
  return (
    body != null &&
    Array.isArray(body.detail) &&
    body.detail.length > 0 &&
    typeof body.detail[0].msg === "string"
  );
}
