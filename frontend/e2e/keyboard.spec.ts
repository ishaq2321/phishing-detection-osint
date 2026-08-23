/**
 * E2E — Keyboard Navigation
 *
 * Tab through entire app to verify focus management.
 */

import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

test.describe("Keyboard Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test("can tab through dashboard to analyse link", async ({ page }) => {
    await page.goto("/dashboard");

    /* Tab through — skip links and sidebar first, eventually hit "Analyse Now" */
    let found = false;
    for (let i = 0; i < 30; i++) {
      await page.keyboard.press("Tab");
      const focused = page.locator(":focus");
      const text = await focused.textContent().catch(() => "");
      if (text?.includes("Analyse Now")) {
        found = true;
        break;
      }
    }
    expect(found).toBe(true);

    /* Press Enter to navigate */
    await page.keyboard.press("Enter");
    await page.waitForURL("**/analyze");
  });

  test("can tab through analyse form and submit", async ({ page }) => {
    await page.goto("/analyze");

    /* Tab to content input and type */
    await page.locator("#content").focus();
    await page.locator("#content").fill("https://example.com");

    /* Tab to Analyse button */
    let foundButton = false;
    for (let i = 0; i < 15; i++) {
      await page.keyboard.press("Tab");
      const focused = page.locator(":focus");
      const text = await focused.textContent().catch(() => "");
      if (text?.includes("Analyse")) {
        foundButton = true;
        break;
      }
    }
    expect(foundButton).toBe(true);

    /* Submit via Enter key */
    await page.keyboard.press("Enter");
    await page.waitForURL("**/results", { timeout: 15_000 });
  });

  test("focus is visible on interactive elements", async ({ page }) => {
    await page.goto("/");

    /* Tab to first focusable element */
    await page.keyboard.press("Tab");
    const focused = page.locator(":focus");

    /* Check that the focused element exists and is visible */
    await expect(focused).toBeVisible();
  });
});
