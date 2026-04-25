/**
 * E2E — Email Analysis Flow
 *
 * Switch to email mode → Enter content + subject + sender → Submit → See results.
 */

import { test, expect } from "@playwright/test";
import { mockApi, clearStorage } from "./fixtures";

test.describe("Email Analysis Flow", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, "dangerous");
    await page.goto("/analyze");
    await clearStorage(page);
  });

  test("analyses an email with subject and sender", async ({ page }) => {
    /* Switch to email mode via custom Select */
    await page.locator("#mode").click();
    await page.getByRole("option", { name: /email/i }).click();

    /* Fill email fields */
    await page.locator("#content").fill(
      "Dear customer, your account has been compromised. Click here immediately to verify your credentials.",
    );
    await page.locator("#emailSubject").fill("URGENT: Account Verification Required");
    await page.locator("#emailSender").fill("security@bank-supp0rt.com");

    /* Submit */
    await page.getByRole("button", { name: "Analyse" }).click();

    /* Wait for results */
    await page.waitForURL("**/results", { timeout: 15_000 });

    /* Verify results */
    await expect(page.getByLabel("Phishing detected")).toBeVisible();
    await expect(page.getByText("Dangerous")).toBeVisible();
  });

  test("analyses email without optional fields", async ({ page }) => {
    await mockApi(page, "safe");

    await page.locator("#mode").click();
    await page.getByRole("option", { name: /email/i }).click();

    await page.locator("#content").fill("Hello, here is our quarterly report.");

    await page.getByRole("button", { name: "Analyse" }).click();
    await page.waitForURL("**/results", { timeout: 15_000 });

    await expect(page.getByLabel("Not phishing")).toBeVisible();
  });
});
