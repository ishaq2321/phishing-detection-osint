/**
 * Shared mock API responses for E2E tests.
 *
 * Fixtures match the backend `AnalysisResponse` schema consumed by the
 * frontend:
 *   { success, verdict, osint, features, analysisTime, analyzedAt, error }
 */

import type { Page } from "@playwright/test";

/* ------------------------------------------------------------------ */
/*  Response payloads                                                 */
/* ------------------------------------------------------------------ */

export const safeAnalysisResponse = {
  success: true,
  verdict: {
    isPhishing: false,
    confidenceScore: 0.12,
    threatLevel: "safe",
    reasons: ["No suspicious features detected"],
    recommendation: "This content appears safe.",
  },
  osint: {
    domain: "example.com",
    domainAgeDays: 9125,
    registrar: "MarkMonitor Inc.",
    isPrivate: false,
    hasValidDns: true,
    inBlacklists: false,
    reputationScore: 0.95,
  },
  features: {
    urlFeatures: 0,
    textFeatures: 1,
    osintFeatures: 0,
    totalRiskIndicators: 1,
    detectedTactics: [],
  },
  analysisTime: 1.23,
  analyzedAt: new Date().toISOString(),
  error: null,
};

export const dangerousAnalysisResponse = {
  success: true,
  verdict: {
    isPhishing: true,
    confidenceScore: 0.87,
    threatLevel: "dangerous",
    reasons: [
      "Suspicious URL structure detected",
      "Domain registered recently",
      "Credential harvesting language detected",
    ],
    recommendation: "Do not interact with this content.",
  },
  osint: {
    domain: "examp1e-login.tk",
    domainAgeDays: 12,
    registrar: "NameCheap Inc.",
    isPrivate: true,
    hasValidDns: true,
    inBlacklists: true,
    reputationScore: 0.15,
  },
  features: {
    urlFeatures: 5,
    textFeatures: 3,
    osintFeatures: 4,
    totalRiskIndicators: 12,
    detectedTactics: ["credential_request", "brand_impersonation", "urgency"],
  },
  analysisTime: 2.45,
  analyzedAt: new Date().toISOString(),
  error: null,
};

export const liveHealthResponse = {
  status: "alive",
  uptimeSeconds: 42,
};

export const healthyResponse = {
  status: "healthy",
  version: "1.0.0",
  timestamp: new Date().toISOString(),
  services: {
    nlp: true,
    osint: true,
    scorer: true,
  },
};

/* ------------------------------------------------------------------ */
/*  Route interception helpers                                        */
/* ------------------------------------------------------------------ */

/**
 * Intercept all backend API calls and return deterministic responses.
 *
 * By default the analysis endpoints return `safeAnalysisResponse`.
 * Pass `"dangerous"` for phishing results.
 */
export async function mockApi(
  page: Page,
  variant: "safe" | "dangerous" = "safe",
) {
  const analysisResponse =
    variant === "dangerous" ? dangerousAnalysisResponse : safeAnalysisResponse;

  /* Health / ping */
  await page.route("**/api/health/live", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(liveHealthResponse) }),
  );
  // Deep readiness probe — kept mocked for direct navigations/tests.
  await page.route("**/api/health", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(healthyResponse) }),
  );
  await page.route("**/api/", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ message: "PhishGuard API" }) }),
  );

  /* Analysis endpoints */
  await page.route("**/api/analyze", (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(analysisResponse) });
    }
    return route.continue();
  });
  await page.route("**/api/analyze/url", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(analysisResponse) }),
  );
  await page.route("**/api/analyze/email", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(analysisResponse) }),
  );

  /* Batch endpoint — echo one per-item result per submitted item. */
  await page.route("**/api/analyze/batch", (route) => {
    if (route.request().method() !== "POST") {
      return route.continue();
    }
    const data = route.request().postDataJSON() as {
      items?: Array<{ type: string }>;
    };
    const results = (data.items ?? []).map((_item, index) => ({
      index,
      status: "ok" as const,
      response: analysisResponse,
    }));
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        success: true,
        total: results.length,
        succeeded: results.length,
        failed: 0,
        analysisTime: 42.5,
        results,
      }),
    });
  });

  /* EML ingest — echo the analysis response plus a parsed summary. */
  await page.route("**/api/ingest/email", (route) => {
    if (route.request().method() !== "POST") {
      return route.continue();
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...analysisResponse,
        parsed: {
          subject: "Security Alert",
          senderName: "",
          senderAddress: "security@paypa1-support.com",
          recipients: ["victim@example.com"],
          bodyPreview: "Urgent! Verify your account now.",
          hasAttachments: true,
          attachmentNames: ["invoice.pdf"],
          sizeBytes: 742,
        },
      }),
    });
  });
}

/**
 * Mock all API routes to return server errors.
 */
export async function mockApiDown(page: Page) {
  await page.route("**/api/**", (route) =>
    route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ detail: "Internal Server Error" }) }),
  );
}

/**
 * Clear localStorage to start fresh.
 */
export async function clearStorage(page: Page) {
  await page.evaluate(() => localStorage.clear());
}
