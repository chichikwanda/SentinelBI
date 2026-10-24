import { expect, test } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

// Drives the whole MVP with REAL dataset rows: the demo sample is drawn from the model's
// held-out test split (`make sample`). It is derived from a licensed dataset, so it is not
// committed; without it this spec is skipped rather than faked.
const API = process.env.E2E_API_URL ?? "http://127.0.0.1:8000";
const SAMPLE = path.resolve(__dirname, "../../data/processed/demo_sample.csv");

test.skip(!fs.existsSync(SAMPLE), "run `make sample` first (needs the downloaded dataset)");

const COLUMNS: Record<string, string> = {
  IPV4_SRC_ADDR: "src_ip",
  L4_SRC_PORT: "src_port",
  IPV4_DST_ADDR: "dst_ip",
  L4_DST_PORT: "dst_port",
  PROTOCOL: "protocol",
  TCP_FLAGS: "tcp_flags",
  IN_BYTES: "in_bytes",
  OUT_BYTES: "out_bytes",
  IN_PKTS: "in_pkts",
  OUT_PKTS: "out_pkts",
  FLOW_DURATION_MILLISECONDS: "duration_ms",
};

function readFlows(): Record<string, string | number>[] {
  const [header, ...lines] = fs.readFileSync(SAMPLE, "utf-8").trim().split("\n");
  const cols = header.split(",");
  return lines.map((line) => {
    const cells = line.split(",");
    const flow: Record<string, string | number> = {};
    cols.forEach((c, i) => {
      const key = COLUMNS[c];
      if (!key) return; // Label/Attack ground truth never leaves the test
      flow[key] = key.endsWith("_ip") ? cells[i] : Math.round(Number(cells[i]));
    });
    return flow;
  });
}

test("real attack traffic produces alerts with ranked, referenced recommendations", async ({
  page,
  request,
}) => {
  const email = `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill("Detections Org");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct-horse-battery");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });

  // register a source through the UI, then send the sample through the real ingest API
  await page.getByRole("link", { name: "Add source", exact: true }).first().click();
  await page.getByTestId("source-name").fill("Replay");
  await page.getByTestId("source-cidr").fill("10.20.0.0/24");
  await page.getByTestId("source-method").selectOption("http");
  await page.getByTestId("create-source").click();
  const apiKey = (await page.getByTestId("api-key").innerText()).trim();

  const flows = readFlows();
  for (let i = 0; i < flows.length; i += 500) {
    const res = await request.post(`${API}/api/v1/ingest/flows`, {
      headers: { "X-API-Key": apiKey },
      data: { flows: flows.slice(i, i + 500) },
    });
    expect(res.status()).toBe(202);
  }

  // the dashboard shows detections, KPIs and the risk gauge
  await page.getByRole("link", { name: "Dashboard", exact: true }).first().click();
  const rows = page.getByTestId("alert-row");
  await expect(rows.first()).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("risk-gauge")).toBeVisible();
  await expect(page.getByTestId("open-alerts")).not.toHaveText("0");

  // alert detail: evidence, triage and recommendations
  await rows.first().getByRole("link").click();
  await expect(page.getByTestId("alert-title")).toBeVisible();
  const recs = page.getByTestId("recommendation");
  await expect(recs.first()).toBeVisible({ timeout: 30_000 });
  await expect(recs.first()).toContainText("Priority");
  await page.getByRole("button", { name: "Acknowledge" }).click();
  await expect(page.getByText("status: acknowledged")).toBeVisible();

  // marking a recommendation done moves it out of the to-do list
  await page.goto("/recommendations");
  const todo = page.getByTestId("recommendation");
  await expect(todo.first()).toBeVisible();
  const before = await todo.count();
  await todo.first().getByRole("button", { name: "Mark done" }).click();
  await expect(todo).toHaveCount(before - 1);

  // risk, models and reports pages render real data
  await page.goto("/risk");
  await expect(page.getByTestId("risk-score")).toBeVisible();
  await expect(page.getByTestId("asset-row").first()).toBeVisible();
  await page.goto("/models");
  await expect(page.getByTestId("model-row").first()).toBeVisible();
  await page.getByRole("button", { name: "Details" }).first().click();
  await expect(page.getByTestId("test-f1").or(page.getByTestId("no-metrics"))).toBeVisible();

  const pdf = await page.request.get("/api/proxy/reports/summary.pdf");
  expect(pdf.status()).toBe(200);
  expect(pdf.headers()["content-type"]).toBe("application/pdf");
  expect((await pdf.body()).subarray(0, 4).toString()).toBe("%PDF");
});
