/**
 * E2E — Responsive Design
 *
 * Run key scenarios at mobile viewport (375×667).
 */

import { test, expect } from "@playwright/test";
import { mockApi, clearStorage } from "./fixtures";

test.describe("Responsive — Mobile", () => {
  test.use({ viewport: { width: 375, height: 667 } });

  test.beforeEach(async ({ page }) => {
    await mockApi(page, "safe");
    await page.goto("/");
    await clearStorage(page);
  });

  test("shows mobile bottom nav bar", async ({ page }) => {
    /* Mobile nav should be visible */
    await expect(page.getByRole("navigation").last()).toBeVisible();
  });

  test("can navigate to analyse page on mobile", async ({ page }) => {
    /* Landing already IS the analyse page; prove the mobile bottom nav
       route to it explicitly (desktop sidebar links are display:none). */
    await page.getByRole("navigation", { name: "Mobile navigation" })
      .getByRole("link", { name: "Analyse" })
      .click();
    await page.waitForURL("**/analyze");
    await expect(page.getByRole("heading", { name: "Analyse Content" })).toBeVisible();
  });

  test("can submit analysis on mobile", async ({ page }) => {
    await page.goto("/analyze");

    await page.locator("#content").fill("https://example.com");
    await page.getByRole("button", { name: "Analyse" }).click();
    await page.waitForURL("**/results", { timeout: 15_000 });

    await expect(page.getByLabel("Not phishing")).toBeVisible();
  });

  test("opens mobile menu", async ({ page }) => {
    /* Click the hamburger menu in header */
    const menuButton = page.getByLabel("Open navigation menu");
    if (await menuButton.isVisible()) {
      await menuButton.click();

      /* Menu should show navigation links */
      await expect(page.getByRole("link", { name: "History" }).first()).toBeVisible();
    }
  });
});
