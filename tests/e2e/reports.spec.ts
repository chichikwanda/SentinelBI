import { expect, test } from "@playwright/test";
import { ingestTwoDaysAgo, registerWithSensor } from "./helpers";

const IP = "10.42.0.5";

test("the report builder: summary and detailed, choose what to include, download tables, print", async ({ page }) => {
  const key = await registerWithSensor(page, "E2E Reports", IP);
  await ingestTwoDaysAgo(page, key, IP);
  await page.goto(`/reports?ip=${IP}&hours=168`);

  // 1. summary: totals, the hosts table and the graph; who/what are left out until asked for
  const report = page.getByTestId("report");
  await expect(page.getByTestId("report-period")).toHaveValue("168");
  await expect(page.getByTestId("level-summary")).toHaveAttribute("aria-pressed", "true");
  await expect(report).toContainText("Last 7 days");
  const row = page.getByTestId("report-host-row");
  await expect(row).toHaveCount(1, { timeout: 30_000 });
  await expect(row).toContainText(IP);
  await expect(row).toContainText("2.7 kB"); // sent
  await expect(row).toContainText("118.2 kB"); // received
  await expect(row).toContainText("121.0 kB"); // total
  await expect(page.getByTestId("report-overview")).toContainText("121.0 kB");
  await expect(page.getByTestId("volume-chart")).toBeVisible();
  await expect(page.getByTestId("report-peers")).toHaveCount(0);
  await expect(page.getByTestId("report-services")).toHaveCount(0);

  // 2. detailed adds who the host talked to and what it used, each with sent and received
  await page.getByTestId("level-detailed").click();
  await expect(page.getByTestId("section-peers")).toBeChecked();
  const peers = page.getByTestId("report-peers");
  await expect(peers.getByTestId("split-row")).toHaveCount(3, { timeout: 30_000 });
  await expect(peers).toContainText("Sent");
  await expect(peers).toContainText("Received");
  await expect(peers.getByTestId("split-row").first()).toContainText("102.0 kB");
  await expect(page.getByTestId("report-services").getByTestId("split-row").first()).toContainText("HTTPS (443)");

  // 3. the reader chooses: switch sections off and on
  await page.getByTestId("section-charts").uncheck();
  await expect(page.getByTestId("volume-chart")).toHaveCount(0);
  await page.getByTestId("section-hosts").uncheck();
  await expect(page.getByTestId("report-hosts")).toHaveCount(0);
  await page.getByTestId("section-peers").uncheck();
  await expect(page.getByTestId("report-peers")).toHaveCount(0);
  await page.getByTestId("section-hosts").check();
  await expect(page.getByTestId("report-hosts")).toBeVisible();
  await page.getByTestId("report-host").and(page.locator(`[data-ip="${IP}"]`)).uncheck(); // no host selected
  await expect(page.getByTestId("report-empty")).toBeVisible();
  await page.getByTestId("report-host").and(page.locator(`[data-ip="${IP}"]`)).check();
  await page.getByTestId("level-summary").click();
  await expect(page.getByTestId("volume-chart")).toBeVisible();

  // 4. each table downloads as CSV with the same numbers
  await page.getByTestId("level-detailed").click();
  const download = page.waitForEvent("download");
  await page.getByTestId("report-peers").locator("xpath=ancestor::div[1]").getByRole("button", { name: "Download CSV" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe("sentinelbi-traffic-peers.csv");
  const csv = await page.request.get(`/api/proxy/reports/traffic.csv?hours=168&section=peers&ip=${IP}`);
  expect(csv.status()).toBe(200);
  const lines = (await csv.text()).trim().split("\n");
  expect(lines[0]).toBe("host,peer,sent_bytes,received_bytes,total_bytes,flows");
  expect(lines[1]).toBe(`${IP},203.0.113.10,2000,100000,102000,2`);
  const hosts = await page.request.get(`/api/proxy/reports/traffic.csv?hours=168&ip=${IP}`);
  expect((await hosts.text()).split("\n")[1]).toMatch(new RegExp(`^${IP.replace(/\./g, "\\.")},2720,118240,120960,6,`));
});

test("printing gives a clean white page with only the report, even from a dark-mode browser", async ({ page }) => {
  const key = await registerWithSensor(page, "E2E Print", "10.43.0.5");
  await ingestTwoDaysAgo(page, key, "10.43.0.5");
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/reports?ip=10.43.0.5&hours=168");
  await expect(page.getByTestId("report-host-row")).toHaveCount(1, { timeout: 30_000 });
  await expect(page.getByTestId("volume-chart")).toBeVisible();

  // on screen it is dark ...
  const screenText = await page.evaluate(() => getComputedStyle(document.body).color);
  expect(screenText).toBe("rgb(237, 237, 237)");

  // ... on paper it is dark text on white, the navigation and the controls are gone, the report stays
  await page.emulateMedia({ media: "print", colorScheme: "dark" });
  const printed = await page.evaluate(() => ({
    text: getComputedStyle(document.body).color,
    ink: getComputedStyle(document.querySelector(".viz-root") as Element).getPropertyValue("--viz-ink").trim(),
    grid: getComputedStyle(document.querySelector(".viz-root") as Element).getPropertyValue("--viz-grid").trim(),
  }));
  expect(printed.text).toBe("rgb(23, 23, 23)");
  expect(printed.ink).toBe("#0b0b0b"); // the chart's dark ink, not the dark theme's pale one
  expect(printed.grid).toBe("#e1e0d9");
  await expect(page.getByRole("navigation")).toBeHidden();
  await expect(page.getByTestId("report-print")).toBeHidden();
  await expect(page.getByRole("heading", { name: "Reports", exact: true })).toBeHidden();
  await expect(page.getByTestId("report")).toBeVisible();
  await expect(page.getByTestId("volume-chart")).toBeVisible();
  await expect(page.getByText("View as table")).toBeHidden(); // the collapsed table is not printed

  // and the printer's own rendering produces a real document
  const pdf = await page.pdf({ format: "A4" });
  expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  expect(pdf.length).toBeGreaterThan(5_000);
});
