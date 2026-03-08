/**
 * Tests for lib/api/client.ts — the low-level fetch wrapper.
 */

import { apiClient } from "@/lib/api/client";
import { NetworkError, ApiError, ValidationError } from "@/lib/api/errors";

/* ------------------------------------------------------------------ */
/*  Setup                                                             */
/* ------------------------------------------------------------------ */

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
});

function mockFetch(response: Partial<Response>) {
  const mockResponse = {
    ok: true,
    status: 200,
    json: jest.fn().mockResolvedValue({}),
    ...response,
  } as unknown as Response;

  global.fetch = jest.fn().mockResolvedValue(mockResponse);
  return global.fetch as jest.Mock;
}

/* ------------------------------------------------------------------ */
/*  Successful requests                                               */
/* ------------------------------------------------------------------ */

describe("apiClient — success", () => {
  it("resolves with parsed JSON on 200", async () => {
    const body = { success: true, data: "hello" };
    mockFetch({ ok: true, status: 200, json: jest.fn().mockResolvedValue(body) });

    const result = await apiClient<typeof body>("/api/test");
    expect(result).toEqual(body);
  });

  it("sends JSON content-type headers", async () => {
    const fetchMock = mockFetch({ ok: true, json: jest.fn().mockResolvedValue({}) });

    await apiClient("/api/test");

    const call = fetchMock.mock.calls[0];
    expect(call[1].headers).toMatchObject({
      "Content-Type": "application/json",
      Accept: "application/json",
    });
  });

  it("builds the full URL from API_BASE_URL + path", async () => {
    const fetchMock = mockFetch({ ok: true, json: jest.fn().mockResolvedValue({}) });

    await apiClient("/api/health");

    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("/api/health");
  });

  it("passes request init options", async () => {
    const fetchMock = mockFetch({ ok: true, json: jest.fn().mockResolvedValue({}) });

    await apiClient("/api/test", { method: "POST", body: '{"x":1}' });

    const init = fetchMock.mock.calls[0][1];
    expect(init.method).toBe("POST");
    expect(init.body).toBe('{"x":1}');
  });
});

/* ------------------------------------------------------------------ */
/*  Error handling                                                    */
/* ------------------------------------------------------------------ */

describe("apiClient — errors", () => {
  it("throws NetworkError when fetch throws", async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError("Failed to fetch"));

    await expect(apiClient("/api/test")).rejects.toThrow(NetworkError);
  });

  it("throws NetworkError with abort message on timeout", async () => {
    const abortError = new DOMException("Aborted", "AbortError");
    global.fetch = jest.fn().mockRejectedValue(abortError);

    await expect(apiClient("/api/test")).rejects.toThrow(NetworkError);
  });

  it("throws ApiError on non-2xx response", async () => {
    mockFetch({
      ok: false,
      status: 500,
      json: jest.fn().mockResolvedValue({ detail: "Internal server error" }),
    });

    await expect(apiClient("/api/test")).rejects.toThrow(ApiError);
  });

  it("throws ApiError with the status code", async () => {
    mockFetch({
      ok: false,
      status: 404,
      json: jest.fn().mockResolvedValue({ detail: "Not found" }),
    });

    try {
      await apiClient("/api/test");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).statusCode).toBe(404);
    }
  });

  it("throws ValidationError on 422 with detail array", async () => {
    const validationBody = {
      detail: [
        { loc: ["body", "url"], msg: "field required", type: "value_error" },
      ],
    };

    mockFetch({
      ok: false,
      status: 422,
      json: jest.fn().mockResolvedValue(validationBody),
    });

    await expect(apiClient("/api/test")).rejects.toThrow(ValidationError);
  });

  it("handles non-JSON error responses gracefully", async () => {
    mockFetch({
      ok: false,
      status: 500,
      json: jest.fn().mockRejectedValue(new Error("Not JSON")),
    });

    await expect(apiClient("/api/test")).rejects.toThrow(ApiError);
  });
});

/* ------------------------------------------------------------------ */
/*  Request options                                                   */
/* ------------------------------------------------------------------ */

describe("apiClient — options", () => {
  it("attaches an AbortController signal", async () => {
    const fetchMock = mockFetch({ ok: true, json: jest.fn().mockResolvedValue({}) });

    await apiClient("/api/test");

    const init = fetchMock.mock.calls[0][1];
    expect(init.signal).toBeDefined();
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });
});
