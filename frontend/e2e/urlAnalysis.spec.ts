/**
 * E2E — URL Analysis Flow
 *
 * Enter URL → Submit → See results → Check verdict.
 */

import { test, expect } from "@playwright/test";
import { mockApi, clearStorage } from "./fixtures";

test.describe("URL Analysis Flow", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, "dangerous");
    await page.goto("/");
    await clearStorage(page);
  });

  test("submits a URL and sees phishing results", async ({ page }) => {
    /* Navigate to analyse page */
    await page.goto("/analyze");

    /* The default mode should be URL — fill in the URL input */
    const urlInput = page.locator("#content");
    await urlInput.fill("https://examp1e-login.tk/verify");

    /* Submit */
    await page.getByRole("button", { name: "Analyse" }).click();

    /* Wait for results page */
    await page.waitForURL("**/results", { timeout: 15_000 });

    /* Verify verdict banner */
    await expect(page.getByLabel("Phishing detected")).toBeVisible();
    await expect(page.getByLabel(/confidence score: 87 percent/i)).toBeVisible();
    await expect(page.getByText("Dangerous")).toBeVisible();
  });

  test("submits a safe URL and sees safe results", async ({ page }) => {
    await mockApi(page, "safe");
    await page.goto("/analyze");

    const urlInput = page.locator("#content");
    await urlInput.fill("https://example.com");

    await page.getByRole("button", { name: "Analyse" }).click();
    await page.waitForURL("**/results", { timeout: 15_000 });

    await expect(page.getByLabel("Not phishing")).toBeVisible();
    await expect(page.getByLabel(/confidence score: 12 percent/i)).toBeVisible();
  });
});
