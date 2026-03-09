/**
 * Custom error classes for the API client.
 *
 * Three distinct failure modes are modelled so that callers can react
 * to each one appropriately (e.g. show a different toast message):
 *
 *  1. **NetworkError** — fetch itself failed (offline, DNS, CORS, timeout).
 *  2. **ApiError**     — backend returned a non-2xx HTTP status.
 *  3. **ValidationError** — backend rejected the request payload (422).
 */

/* ------------------------------------------------------------------ */
/*  NetworkError                                                      */
/* ------------------------------------------------------------------ */

/** Thrown when the HTTP request itself fails (network, timeout, CORS). */
export class NetworkError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "NetworkError";
  }
}

/* ------------------------------------------------------------------ */
/*  ApiError                                                          */
/* ------------------------------------------------------------------ */

/** Thrown when the backend returns a non-2xx status code. */
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly responseBody?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/* ------------------------------------------------------------------ */
/*  ValidationError                                                   */
/* ------------------------------------------------------------------ */

/** A single field-level validation issue returned by FastAPI (422). */
export interface ValidationDetail {
  loc: (string | number)[];
  msg: string;
  type: string;
}

/** Thrown when FastAPI returns a 422 Unprocessable Entity response. */
export class ValidationError extends ApiError {
  public readonly details: ValidationDetail[];

  constructor(details: ValidationDetail[]) {
    const summary =
      details.length > 0
        ? details.map((d) => d.msg).join("; ")
        : "Validation failed";

    super(summary, 422, details);
    this.name = "ValidationError";
    this.details = details;
  }
}

/* ------------------------------------------------------------------ */
/*  User-friendly message helper                                      */
/* ------------------------------------------------------------------ */

/**
 * Returns a concise, user-facing message for any error thrown by the
 * API client.  Safe to display in toast notifications.
 */
export function friendlyErrorMessage(error: unknown): string {
  if (error instanceof ValidationError) {
    return `Invalid input: ${error.message}`;
  }

  if (error instanceof ApiError) {
    if (error.statusCode >= 500) {
      return "The analysis server encountered an internal error. Please try again.";
    }
    return error.message;
  }

  if (error instanceof NetworkError) {
    return "Cannot connect to the analysis server. Is the backend running?";
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "An unexpected error occurred.";
}
