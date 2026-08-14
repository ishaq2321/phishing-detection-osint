/**
 * E2E — EML Ingestion Flow
 *
 * Uploading a raw .eml file produces one `POST /api/ingest/email`
 * round trip; the page then renders the parsed summary (subject,
 * sender, recipients, attachments) plus the verdict banner.
 */

import { test, expect } from "@playwright/test";
import { mockApi, clearStorage } from "./fixtures";

test.describe("EML Ingestion Flow", () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, "safe");
    await page.goto("/analyze/ingest");
    await clearStorage(page);
  });

  test("uploads an .eml file and renders parsed fields plus verdict", async ({
    page,
  }) => {
    /* The Analyse button stays disabled until a file is chosen. */
    const analyse = page.getByRole("button", { name: "Analyse email" });
    await expect(analyse).toBeDisabled();

    await page.setInputFiles(
      'input[data-testid="eml-file-input"]',
      {
        name: "phishing-sample.eml",
        mimeType: "message/rfc822",
        buffer: Buffer.from("From: security@paypa1-support.com\nSubject: Security Alert\n\nUrgent!"),
      },
    );

    /* File name + size appear in the selection card. */
    await expect(page.getByText("phishing-sample.eml")).toBeVisible();

    await analyse.click();

    /* Parsed summary block. */
    await expect(page.getByText("Security Alert")).toBeVisible();
    await expect(
      page.getByText("security@paypa1-support.com"),
    ).toBeVisible();
    await expect(page.getByText("invoice.pdf")).toBeVisible();

    /* Verdict banner (safe fixture). */
    await expect(page.getByLabel("Not phishing")).toBeVisible();
  });
});
