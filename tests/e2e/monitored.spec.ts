import { expect, test } from "@playwright/test";
import { ingestTwoDaysAgo, registerWithSensor } from "./helpers";

const IP = "10.40.0.5";

test("registered IPs are on the dashboard even when quiet, and open into what they sent and received", async ({ page }) => {
  const key = await registerWithSensor(page, "E2E Monitored", IP);
  await ingestTwoDaysAgo(page, key, IP);
  // a second IP that has never reported anything
  const added = await page.request.post("/api/proxy/sources", {
    data: { name: "Branch PC", cidr: "10.40.0.77", method: "http" },
  });
  expect(added.status()).toBe(201);

  // 1. after logging in the registered IPs are listed, with no traffic in the last 24 hours
  await page.goto("/dashboard");
  const card = page.getByTestId("monitored-ips");
  await expect(card).toBeVisible();
  const mine = card.getByTestId("monitored-ip").filter({ hasText: IP });
  const branch = card.getByTestId("monitored-ip").filter({ hasText: "10.40.0.77" });
  await expect(mine).toContainText("none in 24 h", { timeout: 30_000 });
  await expect(branch).toContainText("Branch PC");
  await expect(card.getByTestId("quiet-sources")).toContainText("Branch PC has not reported yet");

  // 2. one click opens its traffic page; the empty day says when it was last active and offers a longer view
  await mine.getByRole("link", { name: `View traffic for ${IP}` }).click();
  await expect(page).toHaveURL(new RegExp(`/traffic\\?ip=${IP.replace(/\./g, "\\.")}`));
  const quiet = page.getByTestId("host-quiet");
  await expect(quiet).toContainText("No traffic for this address in the last 24 hours");
  await expect(quiet).toContainText("last active");
  await page.getByTestId("widen-window").click();
  await expect(quiet).toHaveCount(0, { timeout: 30_000 });

  // 3. totals: what the host sent and what it received, exactly
  await expect(page.getByTestId("host-sent")).toHaveText("2.7 kB");
  await expect(page.getByTestId("host-received")).toHaveText("118.2 kB");
  await expect(page.getByTestId("host-total")).toHaveText("121.0 kB");

  // 4. who it talked to: every peer says what was sent and what was received
  const peers = page.getByTestId("peers-table");
  await expect(peers).toContainText("Sent");
  await expect(peers).toContainText("Received");
  const rows = peers.getByTestId("split-row");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText("203.0.113.10");
  await expect(rows.nth(0)).toContainText("2.0 kB"); // sent
  await expect(rows.nth(0)).toContainText("100.0 kB"); // received
  await expect(rows.nth(0)).toContainText("102.0 kB"); // total
  await expect(rows.nth(1)).toContainText("198.51.100.7");
  await expect(rows.nth(1)).toContainText("600 B");
  await expect(rows.nth(1)).toContainText("18.0 kB");
  await expect(rows.nth(2)).toContainText("9.9.9.9");

  // 5. what it used, the same way
  const services = page.getByTestId("services-table").getByTestId("split-row");
  await expect(services).toHaveCount(3);
  await expect(services.nth(0)).toContainText("HTTPS (443)");
  await expect(services.nth(0)).toContainText("100.0 kB");
  await expect(page.getByTestId("services-table")).toContainText("DNS (53)");

  // 6. the quiet address still shows in the list of monitored IPs, and a report can start from here
  await expect(page.getByTestId("host-row").filter({ hasText: "10.40.0.77" })).toContainText("none in this window");
  await page.getByTestId("make-report").click();
  await expect(page).toHaveURL(/\/reports\?ip=10\.40\.0\.5&hours=168/);
  await expect(page.getByTestId("report-host").and(page.locator(`[data-ip="${IP}"]`))).toBeChecked({ timeout: 30_000 });
});

test("a source's name on the dashboard leads to its traffic", async ({ page }) => {
  await registerWithSensor(page, "E2E Source Link", "10.41.0.5");
  await page.goto("/dashboard");
  await page.getByRole("link", { name: /Monitor 10\.41\.0\.5/ }).first().click();
  await expect(page).toHaveURL(/\/traffic\?ip=10\.41\.0\.5/);
  await expect(page.getByTestId("host-detail")).toHaveAttribute("data-ip", "10.41.0.5");
});
