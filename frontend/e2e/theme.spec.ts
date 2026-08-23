/**
 * E2E — Theme Toggle
 *
 * Switch dark / light → Verify persistence on reload.
 */

import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

test.describe("Theme Toggle", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test("toggles between light and dark mode", async ({ page }) => {
    await page.goto("/");

    /* Find the theme toggle dropdown button in the header */
    const themeButton = page.getByRole("button", { name: /toggle theme/i });
    await expect(themeButton).toBeVisible();

    /* Wait for hydration: clicking before React attaches handlers
       silently opens nothing, and the menu item is never found. */
    await page.waitForLoadState("networkidle");
    await expect(themeButton).toBeEnabled();

    /* Get initial theme */
    const initialClass = await page.locator("html").getAttribute("class");

    /* Open dropdown and click "Dark"; retry the click if hydration
       finished between visibility check and click. */
    await expect(async () => {
      await themeButton.click();
      await page.getByRole("menuitem", { name: "Dark" }).click();
    }).toPass({ timeout: 10_000 });

    /* Wait for theme change */
    await page.waitForTimeout(500);

    const newClass = await page.locator("html").getAttribute("class");
    expect(newClass).not.toBe(initialClass);
  });

  test("persists theme preference on reload", async ({ page }) => {
    await page.goto("/settings");

    /* Toggle dark mode via the Switch with aria-label */
    const darkModeSwitch = page.getByLabel("Toggle dark mode");
    await darkModeSwitch.click();
    await page.waitForTimeout(500);

    /* Capture current theme */
    const themeAfterToggle = await page.locator("html").getAttribute("class");

    /* Reload the page */
    await page.reload();
    await page.waitForTimeout(1000);

    /* Theme should persist */
    const themeAfterReload = await page.locator("html").getAttribute("class");
    expect(themeAfterReload).toContain(
      themeAfterToggle?.includes("dark") ? "dark" : "light",
    );
  });
});
