/**
 * E2E — History
 *
 * Analyse URL → Go to history → See entry → Click view → See results.
 */

import { test, expect } from "@playwright/test";
import { mockApi, clearStorage, safeAnalysisResponse } from "./fixtures";

test.describe("History", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, "safe");
    await page.goto("/");
    await clearStorage(page);
  });

  test("analysis appears in history and can be viewed", async ({ page }) => {
    /* Perform an analysis first */
    await page.goto("/analyze");
    await page.locator("#content").fill("https://example.com");
    await page.getByRole("button", { name: "Analyse" }).click();
    await page.waitForURL("**/results", { timeout: 15_000 });

    /* Navigate to history */
    await page.getByRole("link", { name: "History" }).first().click();
    await page.waitForURL("**/history");

    /* Entry should exist */
    await expect(page.getByText("example.com").first()).toBeVisible();
    await expect(page.getByText("Safe").first()).toBeVisible();

    /* Click view via row actions */
    await page.getByLabel("Row actions").first().click();
    await page.getByRole("menuitem", { name: "View Results" }).click();

    /* Should see results page */
    await page.waitForURL("**/results");
    await expect(page.getByLabel("Not phishing")).toBeVisible();
  });

  test("can delete a history entry", async ({ page }) => {
    /* Perform an analysis */
    await page.goto("/analyze");
    await page.locator("#content").fill("https://example.com");
    await page.getByRole("button", { name: "Analyse" }).click();
    await page.waitForURL("**/results", { timeout: 15_000 });

    /* Go to history */
    await page.getByRole("link", { name: "History" }).first().click();
    await page.waitForURL("**/history");

    /* Delete via row actions */
    await page.getByLabel("Row actions").first().click();
    await page.getByRole("menuitem", { name: "Delete" }).click();

    /* Entry should be gone — empty state should show */
    await expect(page.getByText("No Analyses Yet")).toBeVisible();
  });
});
