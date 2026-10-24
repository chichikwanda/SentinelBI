import { defineConfig } from "@playwright/test";

// Runs against the live stack (`make up`). Use 127.0.0.1, not "localhost": on Windows
// "localhost" resolves to ::1 first and published Docker ports only listen on IPv4.
//
// E2E_BROWSER_CHANNEL=chrome (or msedge) reuses an installed browser instead of downloading
// Playwright's Chromium (`npx playwright install chromium`).
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 90_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:3000",
    channel: process.env.E2E_BROWSER_CHANNEL || undefined,
    trace: "retain-on-failure",
  },
});
