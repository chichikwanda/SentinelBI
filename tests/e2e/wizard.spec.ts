import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://127.0.0.1:8000";
const PASSWORD = "correct-horse-battery";

function uniqueEmail() {
  return `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}

test("register, add a source in the wizard, see first flows and the alert", async ({
  page,
  request,
}) => {
  // 1. register a fresh organisation (hermetic: no shared state with other runs)
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill("E2E Org");
  await page.getByLabel("Email").fill(uniqueEmail());
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/dashboard/);
  await expect(page.getByTestId("no-alerts")).toBeVisible();

  // 2. onboarding wizard: describe the network, get an API key + setup instructions
  await page.getByRole("link", { name: "Add source", exact: true }).first().click();
  await page.getByTestId("source-name").fill("E2E office");
  await page.getByTestId("source-cidr").fill("10.20.0.0/24");
  await page.getByTestId("source-method").selectOption("http");
  await page.getByTestId("create-source").click();

  const apiKey = (await page.getByTestId("api-key").innerText()).trim();
  expect(apiKey).toMatch(/^sbi_/);
  await expect(page.getByTestId("snippet")).toContainText("/api/v1/ingest/flows");
  const status = page.getByTestId("first-flows-status");
  await expect(status).toHaveAttribute("data-state", "waiting");

  // 3. send traffic through the real ingest API (what a router/sensor/replay would do)
  const flows = Array.from({ length: 12 }, (_, i) => ({
    src_ip: "203.0.113.50",
    dst_ip: "10.20.0.10",
    src_port: 50000 + i,
    dst_port: 1 + i,
    protocol: 6,
    tcp_flags: 2,
    in_bytes: 44,
    out_bytes: 0,
    in_pkts: 1,
    out_pkts: 0,
    duration_ms: 0,
  }));
  const res = await request.post(`${API}/api/v1/ingest/flows`, {
    headers: { "X-API-Key": apiKey },
    data: { flows },
  });
  expect(res.status()).toBe(202);

  // 4. the wizard's live verification flips to "first flows received"
  await expect(status).toHaveAttribute("data-state", "received", { timeout: 30_000 });
  await expect(status).toContainText("First flows received");

  // 5. and the detection shows up in the live alerts table within seconds
  await page.getByRole("link", { name: "Dashboard", exact: true }).first().click();
  const row = page.getByTestId("alert-row").filter({ hasText: "Recon/Scan" });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(row).toContainText("203.0.113.50");
  await expect(row).toContainText("12");
});

test("signed-out visitors are sent to login, and bad credentials are rejected", async ({
  page,
}) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);

  await page.getByLabel("Email").fill("nobody@example.com");
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  // scope to the form: Next.js also renders its own role="alert" route announcer
  await expect(page.locator("form").getByRole("alert")).toHaveText("Invalid email or password");
  await expect(page).toHaveURL(/\/login/);
});
