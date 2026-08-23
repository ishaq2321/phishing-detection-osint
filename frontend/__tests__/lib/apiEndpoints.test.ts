/**
 * Tests for lib/api/endpoints.ts — typed API endpoint functions.
 */

import {
  analyzeContent,
  analyzeUrl,
  analyzeEmail,
  analyzeBatch,
  ingestEmail,
  checkHealthLive,
  pingApi,
} from "@/lib/api/endpoints";
import type { BatchAnalyzeResponse } from "@/types";
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
/*  analyzeBatch                                                      */
/* ------------------------------------------------------------------ */

describe("analyzeBatch", () => {
  it("calls POST /api/analyze/batch with the batch payload", async () => {
    const batchResponse: BatchAnalyzeResponse = {
      success: true,
      total: 1,
      succeeded: 1,
      failed: 0,
      analysisTime: 12.5,
      results: [{ index: 0, status: "ok", response: safeResponse }],
    };
    mockApiClient.mockResolvedValue(batchResponse);

    const payload = { items: [{ type: "url" as const, url: "https://a.com" }] };
    await analyzeBatch(payload);

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/analyze/batch",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(payload),
      }),
      // Batch requests get the extended 120 s timeout.
      expect.objectContaining({ timeoutMs: 120_000 }),
    );
  });

  it("returns the BatchAnalyzeResponse", async () => {
    const batchResponse: BatchAnalyzeResponse = {
      success: true,
      total: 1,
      succeeded: 1,
      failed: 0,
      analysisTime: 12.5,
      results: [{ index: 0, status: "ok", response: safeResponse }],
    };
    mockApiClient.mockResolvedValue(batchResponse);

    const result = await analyzeBatch({ items: [] });
    expect(result).toEqual(batchResponse);
  });
});

/* ------------------------------------------------------------------ */
/*  checkHealth                                                       */
/* ------------------------------------------------------------------ */

describe("checkHealthLive", () => {
  it("calls GET /api/health/live with a 5s timeout", async () => {
    mockApiClient.mockResolvedValue(healthyResponse);

    await checkHealthLive();

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/health/live",
      expect.objectContaining({ method: "GET" }),
      expect.objectContaining({ timeoutMs: 5_000 }),
    );
  });

  it("returns the HealthResponse", async () => {
    mockApiClient.mockResolvedValue(healthyResponse);
    const result = await checkHealthLive();
    expect(result).toEqual(healthyResponse);
  });
});

/* ------------------------------------------------------------------ */
/*  ingestEmail                                                       */
/* ------------------------------------------------------------------ */

describe("ingestEmail", () => {
  it("sends the raw file bytes with message/rfc822 content type", async () => {
    mockApiClient.mockResolvedValue(safeResponse);
    const file = new File(["From: a@b.c\n\nBody"], "phish.eml", {
      type: "message/rfc822",
    });

    await ingestEmail(file);

    expect(mockApiClient).toHaveBeenCalledWith(
      "/api/ingest/email",
      expect.objectContaining({
        method: "POST",
        body: file, // raw File, not JSON.stringify'd
        headers: { "Content-Type": "message/rfc822" },
      }),
      expect.objectContaining({ timeoutMs: 120_000 }),
    );
  });

  it("returns the EmailIngestResponse", async () => {
    const ingestResponse = {
      ...safeResponse,
      parsed: {
        subject: "Security Alert",
        senderName: "",
        senderAddress: "security@paypa1-support.com",
        recipients: ["victim@example.com"],
        bodyPreview: "Urgent!",
        hasAttachments: false,
        attachmentNames: [],
        sizeBytes: 512,
      },
    };
    mockApiClient.mockResolvedValue(ingestResponse);

    const file = new File(["body"], "phish.eml");
    const result = await ingestEmail(file);
    expect(result).toEqual(ingestResponse);
    expect(result.parsed.senderAddress).toBe("security@paypa1-support.com");
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
