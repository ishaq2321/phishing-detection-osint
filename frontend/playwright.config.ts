/**
 * Playwright E2E test configuration.
 *
 * Runs tests against the local Next.js dev server.  All tests use
 * Chromium only — sufficient for a thesis project.
 */

import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "html",
  timeout: 30_000,

  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: {
    /* E2E runs against a production build: dev-mode Turbopack aborts
       in-flight navigations during cold compiles (net::ERR_ABORTED),
       panics intermittently, and its dev overlay intercepts pointer
       events — none of which exist in what we actually ship. */
    command: "npm run build && npm run start",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
  },
});
