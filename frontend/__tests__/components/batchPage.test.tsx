/**
 * Tests for the Batch Analysis page (`app/(app)/analyze/batch/page.tsx`).
 *
 * Covers the three behaviours that matter:
 * 1. Primary path — one `POST /api/analyze/batch` round trip whose
 *    per-item results populate the table.
 * 2. Per-item errors — an errored entry renders its message without
 *    disturbing the successful rows.
 * 3. Fallback path — when the batch endpoint is unavailable (deploy
 *    skew / network failure), the page falls back to individual
 *    `analyzeUrl` calls so the feature still works.
 */

import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import BatchAnalysisPage from "@/app/(app)/analyze/batch/page";
import { analyzeBatch, analyzeUrl } from "@/lib/api/endpoints";
import { showInfo, showSuccess } from "@/lib/toast";
import { safeResponse, dangerousResponse } from "../fixtures";
import type { BatchAnalyzeResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Mocks                                                             */
/* ------------------------------------------------------------------ */

jest.mock("@/lib/api/endpoints", () => ({
  analyzeBatch: jest.fn(),
  analyzeUrl: jest.fn(),
}));

jest.mock("@/lib/toast", () => ({
  showError: jest.fn(),
  showInfo: jest.fn(),
  showSuccess: jest.fn(),
  showWarning: jest.fn(),
  showPromise: jest.fn(),
}));

const mockAnalyzeBatch = analyzeBatch as jest.Mock;
const mockAnalyzeUrl = analyzeUrl as jest.Mock;

beforeEach(() => {
  mockAnalyzeBatch.mockReset();
  mockAnalyzeUrl.mockReset();
});

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function typeUrlsAndClickAnalyse(urls: string) {
  render(<BatchAnalysisPage />);
  const textarea = screen.getByLabelText("URLs to analyse (one per line)");
  fireEvent.change(textarea, { target: { value: urls } });
  const count = urls.split("\n").filter((l) => l.trim().length > 0).length;
  fireEvent.click(
    screen.getByRole("button", { name: new RegExp(`Analyse ${count} URL`) }),
  );
}

function batchResponse(
  results: BatchAnalyzeResponse["results"],
): BatchAnalyzeResponse {
  return {
    success: true,
    total: results.length,
    succeeded: results.filter((r) => r.status === "ok").length,
    failed: results.filter((r) => r.status === "error").length,
    analysisTime: 42.5,
    results,
  };
}

/* ------------------------------------------------------------------ */
/*  Primary path — single batch round trip                            */
/* ------------------------------------------------------------------ */

describe("BatchAnalysisPage — batch endpoint path", () => {
  it("sends all URLs as one batch payload", async () => {
    mockAnalyzeBatch.mockResolvedValue(
      batchResponse([
        { index: 0, status: "ok", response: safeResponse },
        { index: 1, status: "ok", response: dangerousResponse },
      ]),
    );

    typeUrlsAndClickAnalyse("https://a.com\nhttps://b.com");

    await waitFor(() => expect(mockAnalyzeBatch).toHaveBeenCalledTimes(1));
    expect(mockAnalyzeBatch).toHaveBeenCalledWith(
      {
        items: [
          { type: "url", url: "https://a.com" },
          { type: "url", url: "https://b.com" },
        ],
      },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    // No per-URL calls in the primary path.
    expect(mockAnalyzeUrl).not.toHaveBeenCalled();
  });

  it("renders per-item results from the batch response", async () => {
    mockAnalyzeBatch.mockResolvedValue(
      batchResponse([
        { index: 0, status: "ok", response: safeResponse },
        { index: 1, status: "ok", response: dangerousResponse },
      ]),
    );

    typeUrlsAndClickAnalyse("https://a.com\nhttps://b.com");

    await waitFor(() => expect(screen.getAllByText("Done")).toHaveLength(2));
    // Threat badges from the returned verdicts.
    expect(screen.getByText("Safe")).toBeInTheDocument();
    expect(screen.getByText("Dangerous")).toBeInTheDocument();
    expect(showSuccess).toHaveBeenCalledWith(
      expect.stringContaining("2 URLs processed"),
    );
  });

  it("renders per-item errors without losing successful rows", async () => {
    mockAnalyzeBatch.mockResolvedValue(
      batchResponse([
        { index: 0, status: "ok", response: safeResponse },
        { index: 1, status: "error", error: "type=url but url field is empty" },
      ]),
    );

    typeUrlsAndClickAnalyse("https://a.com\nhttps://b.com");

    await waitFor(() => expect(screen.getAllByText("Done")).toHaveLength(1));
    expect(
      screen.getByText("type=url but url field is empty"),
    ).toBeInTheDocument();
    expect(screen.getByText("1 Failed")).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Fallback path — batch endpoint unavailable                        */
/* ------------------------------------------------------------------ */

describe("BatchAnalysisPage — chunked fallback", () => {
  it("falls back to individual analyzeUrl calls when the batch call fails", async () => {
    mockAnalyzeBatch.mockRejectedValue(new Error("404 — endpoint missing"));
    mockAnalyzeUrl.mockResolvedValue(safeResponse);

    typeUrlsAndClickAnalyse("https://a.com\nhttps://b.com");

    await waitFor(() => expect(mockAnalyzeUrl).toHaveBeenCalledTimes(2));
    expect(mockAnalyzeUrl).toHaveBeenCalledWith(
      { url: "https://a.com" },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(showInfo).toHaveBeenCalledWith(
      expect.stringContaining("falling back to individual analysis"),
    );
    await waitFor(() => expect(screen.getAllByText("Done")).toHaveLength(2));
  });
});
