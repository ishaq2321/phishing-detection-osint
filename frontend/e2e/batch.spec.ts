/**
 * E2E — Batch Analysis Flow
 *
 * The batch page sends ONE `POST /api/analyze/batch` round trip and
 * renders per-row results; when the batch endpoint is unavailable it
 * transparently falls back to individual `/api/analyze/url` calls.
 */

import { test, expect } from "@playwright/test";
import { mockApi, clearStorage } from "./fixtures";

test.describe("Batch Analysis Flow", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, "safe");
    await page.goto("/analyze/batch");
    await clearStorage(page);
  });

  test("analyses multiple URLs in a single batch round trip", async ({
    page,
  }) => {
    let batchHits = 0;
    let singleUrlHits = 0;

    await page.route("**/api/analyze/batch", (route) => {
      batchHits += 1;
      return route.fallback(); // pass through to the fixture mock
    });
    await page.route("**/api/analyze/url", (route) => {
      singleUrlHits += 1;
      return route.fallback(); // pass through to the fixture mock
    });

    await page
      .locator("#batch-urls")
      .fill("https://example.com\nhttps://example.org");

    await page.getByRole("button", { name: "Analyse 2 URLs" }).click();

    /* Per-row results arrive from the single batch response. */
    await expect(page.getByText("Done")).toHaveCount(2);
    await expect(page.getByText("2 Safe")).toBeVisible();

    /* Exactly one batch request; zero individual URL calls. */
    expect(batchHits).toBe(1);
    expect(singleUrlHits).toBe(0);
  });

  test("falls back to individual analysis when the batch endpoint is down", async ({
    page,
  }) => {
    /* Break only the batch endpoint — the per-URL mock stays live. */
    await page.route("**/api/analyze/batch", (route) =>
      route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Not Found" }),
      }),
    );

    await page
      .locator("#batch-urls")
      .fill("https://example.com\nhttps://example.org");

    await page.getByRole("button", { name: "Analyse 2 URLs" }).click();

    /* The fallback notice fires, then rows complete via /api/analyze/url. */
    await expect(
      page.getByText("Batch endpoint unavailable — falling back to individual analysis."),
    ).toBeVisible();

    await expect(page.getByText("Done")).toHaveCount(2);
  });
});
