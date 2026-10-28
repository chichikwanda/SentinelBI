import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://127.0.0.1:8000";
const PASSWORD = "correct-horse-battery";

test("an administrator can remove a source, and its API key stops working", async ({ page, request }) => {
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill("E2E Remove");
  await page.getByLabel("Email").fill(`e2e-rm-${Date.now()}@example.com`);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });

  // a source created through the wizard, with an API key that works
  await page.getByRole("link", { name: "Add source", exact: true }).first().click();
  await page.getByTestId("source-name").fill("Throwaway source");
  await page.getByTestId("source-cidr").fill("10.77.0.0/24");
  await page.getByTestId("source-method").selectOption("http");
  await page.getByTestId("create-source").click();
  const apiKey = (await page.getByTestId("api-key").innerText()).trim();
  const flow = { src_ip: "10.77.0.5", dst_ip: "198.51.100.9", protocol: 6, in_bytes: 100, out_bytes: 200 };
  const before = await request.post(`${API}/api/v1/ingest/flows`, { headers: { "X-API-Key": apiKey }, data: { flows: [flow] } });
  expect(before.status()).toBe(202);

  // remove it from the dashboard; the confirmation says what removal does
  await page.getByRole("link", { name: "Dashboard", exact: true }).first().click();
  const row = page.getByTestId("sources-body").getByRole("row", { name: /Throwaway source/ });
  await expect(row).toBeVisible({ timeout: 30_000 });
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("Throwaway source");
    expect(dialog.message()).toContain("API key stops working immediately");
    expect(dialog.message()).toContain("already stored are kept");
    await dialog.accept();
  });
  await row.getByTestId("remove-source").click();
  await expect(page.getByTestId("sources-body").getByRole("row", { name: /Throwaway source/ })).toHaveCount(0, { timeout: 30_000 });

  // the key is revoked at once
  const after = await request.post(`${API}/api/v1/ingest/flows`, { headers: { "X-API-Key": apiKey }, data: { flows: [flow] } });
  expect(after.status()).toBe(401);
});

test("declining the confirmation keeps the source", async ({ page }) => {
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill("E2E Keep");
  await page.getByLabel("Email").fill(`e2e-keep-${Date.now()}@example.com`);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
  await page.getByRole("link", { name: "Add source", exact: true }).first().click();
  await page.getByTestId("source-name").fill("Keep me");
  await page.getByTestId("source-cidr").fill("10.78.0.0/24");
  await page.getByTestId("source-method").selectOption("http");
  await page.getByTestId("create-source").click();
  await expect(page.getByTestId("api-key")).toBeVisible();
  await page.getByRole("link", { name: "Dashboard", exact: true }).first().click();
  const row = page.getByTestId("sources-body").getByRole("row", { name: /Keep me/ });
  await expect(row).toBeVisible({ timeout: 30_000 });
  page.once("dialog", (dialog) => dialog.dismiss());
  await row.getByTestId("remove-source").click();
  await page.waitForTimeout(1500);
  await expect(page.getByTestId("sources-body").getByRole("row", { name: /Keep me/ })).toHaveCount(1);
});
