/**
 * Tests for lib/api/endpoints.ts — typed API endpoint functions.
 */

import { analyzeContent, analyzeUrl, analyzeEmail, checkHealth, pingApi } from "@/lib/api/endpoints";
import * as client from "@/lib/api/client";
import { safeResponse, healthyResponse } from "../fixtures";

/* ------------------------------------------------------------------ */
/*  Mock the underlying apiClient                                     */
/* ------------------------------------------------------------------ */

jest.mock("@/lib/api/client", () => ({
  apiClient: jest.fn(),
}));

const mockApiClient = client.apiClient as jest.Mock;

beforeEach(() => {
  mockApiClient.mockReset();
});

/* ------------------------------------------------------------------ */
/*  analyzeContent                                                    */
/* ------------------------------------------------------------------ */

describe("analyzeContent", () => {
  it("calls POST /api/analyze with the payload", async () => {
    mockApiClient.mockResolvedValue(safeResponse);

    const payload = { content: "Check this URL", contentType: "auto" as const };
    await analyzeContent(payload);

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/analyze",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      }),
      undefined,
    );
  });

  it("returns the AnalysisResponse", async () => {
    mockApiClient.mockResolvedValue(safeResponse);
    const result = await analyzeContent({ content: "test" });
    expect(result).toEqual(safeResponse);
  });
});

/* ------------------------------------------------------------------ */
/*  analyzeUrl                                                        */
/* ------------------------------------------------------------------ */

describe("analyzeUrl", () => {
  it("calls POST /api/analyze/url with the URL payload", async () => {
    mockApiClient.mockResolvedValue(safeResponse);

    await analyzeUrl({ url: "https://example.com" });

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/analyze/url",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ url: "https://example.com" }),
      }),
      undefined,
    );
  });
});

/* ------------------------------------------------------------------ */
/*  analyzeEmail                                                      */
/* ------------------------------------------------------------------ */

describe("analyzeEmail", () => {
  it("calls POST /api/analyze/email with the email payload", async () => {
    mockApiClient.mockResolvedValue(safeResponse);

    const payload = { content: "Hello...", subject: "Urgent!", sender: "a@b.com" };
    await analyzeEmail(payload);

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/analyze/email",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      }),
      undefined,
    );
  });

  it("works without optional subject and sender", async () => {
    mockApiClient.mockResolvedValue(safeResponse);

    await analyzeEmail({ content: "Email body" });

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/analyze/email",
      expect.objectContaining({
        body: JSON.stringify({ content: "Email body" }),
      }),
      undefined,
    );
  });
});

/* ------------------------------------------------------------------ */
/*  checkHealth                                                       */
/* ------------------------------------------------------------------ */

describe("checkHealth", () => {
  it("calls GET /api/health with a 5s timeout", async () => {
    mockApiClient.mockResolvedValue(healthyResponse);

    await checkHealth();

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/health",
      expect.objectContaining({ method: "GET" }),
      expect.objectContaining({ timeoutMs: 5_000 }),
    );
  });

  it("returns the HealthResponse", async () => {
    mockApiClient.mockResolvedValue(healthyResponse);
    const result = await checkHealth();
    expect(result).toEqual(healthyResponse);
  });
});

/* ------------------------------------------------------------------ */
/*  pingApi                                                           */
/* ------------------------------------------------------------------ */

describe("pingApi", () => {
  it("calls GET /api/ with a 5s timeout", async () => {
    mockApiClient.mockResolvedValue({ message: "PhishGuard API" });

    await pingApi();

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/",
      expect.objectContaining({ method: "GET" }),
      expect.objectContaining({ timeoutMs: 5_000 }),
    );
  });
});
