/**
 * Tests for lib/api/errors.ts — custom error classes and helpers.
 */

import {
  NetworkError,
  ApiError,
  ValidationError,
  friendlyErrorMessage,
} from "@/lib/api/errors";
import type { ValidationDetail } from "@/lib/api/errors";

/* ------------------------------------------------------------------ */
/*  NetworkError                                                      */
/* ------------------------------------------------------------------ */

describe("NetworkError", () => {
  it("sets the name to NetworkError", () => {
    const err = new NetworkError("offline");
    expect(err.name).toBe("NetworkError");
  });

  it("stores the message", () => {
    const err = new NetworkError("Cannot connect");
    expect(err.message).toBe("Cannot connect");
  });

  it("preserves the cause", () => {
    const original = new TypeError("fetch failed");
    const err = new NetworkError("offline", original);
    expect(err.cause).toBe(original);
  });

  it("is an instance of Error", () => {
    const err = new NetworkError("offline");
    expect(err).toBeInstanceOf(Error);
  });
});

/* ------------------------------------------------------------------ */
/*  ApiError                                                          */
/* ------------------------------------------------------------------ */

describe("ApiError", () => {
  it("sets the name to ApiError", () => {
    const err = new ApiError("Not found", 404);
    expect(err.name).toBe("ApiError");
  });

  it("stores the status code", () => {
    const err = new ApiError("Server error", 500);
    expect(err.statusCode).toBe(500);
  });

  it("stores the response body", () => {
    const body = { detail: "Bad request" };
    const err = new ApiError("Bad request", 400, body);
    expect(err.responseBody).toEqual(body);
  });

  it("is an instance of Error", () => {
    const err = new ApiError("error", 500);
    expect(err).toBeInstanceOf(Error);
  });
});

/* ------------------------------------------------------------------ */
/*  ValidationError                                                   */
/* ------------------------------------------------------------------ */

describe("ValidationError", () => {
  const details: ValidationDetail[] = [
    { loc: ["body", "url"], msg: "field required", type: "value_error" },
    { loc: ["body", "content"], msg: "too short", type: "value_error" },
  ];

  it("sets the name to ValidationError", () => {
    const err = new ValidationError(details);
    expect(err.name).toBe("ValidationError");
  });

  it("has status code 422", () => {
    const err = new ValidationError(details);
    expect(err.statusCode).toBe(422);
  });

  it("stores the validation details", () => {
    const err = new ValidationError(details);
    expect(err.details).toEqual(details);
  });

  it("builds a summary message from detail messages", () => {
    const err = new ValidationError(details);
    expect(err.message).toBe("field required; too short");
  });

  it("handles empty details array", () => {
    const err = new ValidationError([]);
    expect(err.message).toBe("Validation failed");
  });

  it("is an instance of ApiError", () => {
    const err = new ValidationError(details);
    expect(err).toBeInstanceOf(ApiError);
  });
});

/* ------------------------------------------------------------------ */
/*  friendlyErrorMessage                                              */
/* ------------------------------------------------------------------ */

describe("friendlyErrorMessage", () => {
  it("returns validation message for ValidationError", () => {
    const err = new ValidationError([
      { loc: ["body", "url"], msg: "field required", type: "value_error" },
    ]);
    expect(friendlyErrorMessage(err)).toBe("Invalid input: field required");
  });

  it("returns server error message for 5xx ApiError", () => {
    const err = new ApiError("Internal", 500);
    expect(friendlyErrorMessage(err)).toContain("internal error");
  });

  it("returns the error message for non-5xx ApiError", () => {
    const err = new ApiError("Not found", 404);
    expect(friendlyErrorMessage(err)).toBe("Not found");
  });

  it("returns network error message for NetworkError", () => {
    const err = new NetworkError("offline");
    expect(friendlyErrorMessage(err)).toContain("Cannot connect");
  });

  it("returns generic Error message", () => {
    const err = new Error("Something broke");
    expect(friendlyErrorMessage(err)).toBe("Something broke");
  });

  it("returns fallback for non-Error values", () => {
    expect(friendlyErrorMessage("oops")).toBe("An unexpected error occurred.");
    expect(friendlyErrorMessage(null)).toBe("An unexpected error occurred.");
    expect(friendlyErrorMessage(42)).toBe("An unexpected error occurred.");
  });
});
