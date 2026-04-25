/**
 * E2E — Navigation
 *
 * Click all nav links → Verify pages load with correct headings.
 */

import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

test.describe("Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test("navigates to all pages via sidebar links", async ({ page }) => {
    await page.goto("/");

    /* Dashboard */
    await expect(page.getByRole("heading", { name: "PhishGuard" })).toBeVisible();

    /* Analyse */
    await page.getByRole("link", { name: "Analyse" }).first().click();
    await page.waitForURL("**/analyze");
    await expect(page.getByRole("heading", { name: "Analyse Content" })).toBeVisible();

    /* History */
    await page.getByRole("link", { name: "History" }).first().click();
    await page.waitForURL("**/history");
    await expect(page.getByRole("heading", { name: "Analysis History" })).toBeVisible();

    /* How It Works */
    await page.getByRole("link", { name: "How It Works" }).first().click();
    await page.waitForURL("**/how-it-works");
    await expect(page.getByRole("heading", { name: "How It Works" })).toBeVisible();

    /* Settings */
    await page.getByRole("link", { name: "Settings" }).first().click();
    await page.waitForURL("**/settings");
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  });

  test("dashboard CTA links work", async ({ page }) => {
    await page.goto("/");

    /* "Analyse Now" button → /analyze */
    await page.getByRole("link", { name: "Analyse Now" }).click();
    await page.waitForURL("**/analyze");
    await expect(page.getByRole("heading", { name: "Analyse Content" })).toBeVisible();

    /* Go back and try "How It Works" */
    await page.goto("/");
    await page.getByRole("link", { name: "How It Works" }).first().click();
    await page.waitForURL("**/how-it-works");
    await expect(page.getByRole("heading", { name: "How It Works" })).toBeVisible();
  });
});
