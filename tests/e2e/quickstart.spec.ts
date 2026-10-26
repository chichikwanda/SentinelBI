import { execFileSync } from "node:child_process";
import path from "node:path";
import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://127.0.0.1:8000";
const PYTHON = process.env.E2E_PYTHON ?? "python";
const REPO = path.resolve(__dirname, "..", "..");
const PASSWORD = "correct-horse-battery";

test("enter an IP at registration, run the sensor, see how much data it moved", async ({ page }) => {
  // 1. register and name the IP to watch in the same form: no router setup involved
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill("E2E Quick Start");
  await page.getByLabel("Email").fill(`e2e-qs-${Date.now()}@example.com`);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByTestId("register-ip").fill("10.20.0.5");
  await page.getByRole("button", { name: "Create account" }).click();

  // 2. the wizard opens with the address filled in and the sensor chosen
  await expect(page).toHaveURL(/\/sources\/new\?ip=10\.20\.0\.5/, { timeout: 30_000 });
  await expect(page.getByTestId("source-cidr")).toHaveValue("10.20.0.5");
  await expect(page.getByTestId("source-method")).toHaveValue("sensor");
  await expect(page.getByTestId("method-help")).toContainText("never reads or sends the contents");
  await page.getByTestId("create-source").click();

  // 3. real commands with the key and address already in them
  await expect(page.getByTestId("sensor-notes")).toBeVisible();
  const apiKey = (await page.getByTestId("api-key").innerText()).trim();
  expect(apiKey).toMatch(/^sbi_/);
  const snippet = page.getByTestId("snippet");
  await expect(snippet).toContainText("--self-test");
  await expect(snippet).toContainText(apiKey);
  await expect(snippet).toContainText("--ip 10.20.0.5");
  await expect(page.getByTestId("first-flows-status")).toHaveAttribute("data-state", "waiting");

  // 4. the "no admin rights" tab replays the bundled demo capture through the real sensor script
  await page.getByRole("tab", { name: "Try it without admin rights" }).click();
  await expect(snippet).toContainText("sensor_demo.pcap");
  const out = execFileSync(
    PYTHON,
    [
      "sensor/sentinelbi_sensor.py",
      "--read-pcap", "data/samples/sensor_demo.pcap",
      "--shift-to-now",
      "--api-url", API,
      "--api-key", apiKey,
    ],
    { cwd: REPO, encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"] },
  );
  expect(out).toBe(""); // all progress goes to stderr; stdout stays clean

  // 5. the wizard sees the first flows
  const status = page.getByTestId("first-flows-status");
  await expect(status).toHaveAttribute("data-state", "received", { timeout: 60_000 });

  // 6. the data volume page: this host moved megabytes, and received far more than it sent
  await page.getByTestId("see-traffic").click();
  await expect(page).toHaveURL(/\/traffic\?ip=10\.20\.0\.5/);
  const detail = page.getByTestId("host-detail");
  await expect(detail).toHaveAttribute("data-ip", "10.20.0.5");
  await expect(page.getByTestId("host-received")).toContainText(/MB/, { timeout: 60_000 });
  await expect(page.getByTestId("host-sent")).toContainText(/MB/);
  await expect(page.getByTestId("traffic-total")).toContainText(/MB/);
  await expect(page.getByTestId("volume-chart")).toBeVisible();
  const rows = page.getByTestId("host-row");
  await expect(rows).toHaveCount(1); // only the registered address is a monitored host
  await expect(rows.first()).toContainText("10.20.0.5");

  // 7. the dashboard shows the same data, and the chart can switch from flows to data
  await page.getByRole("link", { name: "Dashboard", exact: true }).first().click();
  await expect(page.getByTestId("data-24h")).toContainText(/MB/, { timeout: 60_000 });
  await page.getByTestId("metric-bytes").click();
  await expect(page.getByTestId("metric-bytes")).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("top-hosts")).toContainText("10.20.0.5");
  await expect(page.getByTestId("quick-start")).toHaveCount(0); // a source exists now

  // 8. the report has the same host and the numbers add up
  const csv = await page.request.get("/api/proxy/reports/traffic.csv?hours=24");
  expect(csv.status()).toBe(200);
  const lines = (await csv.text()).trim().split("\n");
  expect(lines[0]).toBe("ip,sent_bytes,received_bytes,total_bytes,flows,last_seen");
  const [ip, sent, received, total] = lines[1].split(",");
  expect(ip).toBe("10.20.0.5");
  expect(Number(received)).toBeGreaterThan(Number(sent));
  expect(Number(total)).toBe(Number(sent) + Number(received));
  const pdf = await page.request.get("/api/proxy/reports/summary.pdf");
  expect(pdf.status()).toBe(200);

  // 9. the machine also has IPv6 addresses: the sensor tells the server (with the same API key),
  //    and they count as the same monitored machine
  const v6 = "2001:db8:aa::5";
  const told = await page.request.put(`${API}/api/v1/sensor/addresses`, {
    headers: { "X-API-Key": apiKey },
    data: { addresses: [v6] },
  });
  expect(told.status()).toBe(200);
  const ingested = await page.request.post(`${API}/api/v1/ingest/flows`, {
    headers: { "X-API-Key": apiKey },
    data: {
      flows: [
        {
          src_ip: v6, dst_ip: "2606:2800::1", protocol: 6, src_port: 51000, dst_port: 443,
          in_bytes: 2000, out_bytes: 90000, in_pkts: 10, out_pkts: 70, duration_ms: 400,
        },
      ],
    },
  });
  expect(ingested.status()).toBe(202);
  await page.goto("/dashboard");
  await expect(page.getByTestId("extra-addresses")).toContainText(/\+ 1 more address of this machine/);
  await page.goto("/traffic");
  await expect(page.getByTestId("host-row")).toHaveCount(2, { timeout: 60_000 });
  await expect(page.getByTestId("host-row").filter({ hasText: v6 })).toHaveCount(1);
});

test("a new organisation without a source is offered the quick start", async ({ page }) => {
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill("E2E Empty");
  await page.getByLabel("Email").fill(`e2e-empty-${Date.now()}@example.com`);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click(); // no IP given
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
  await expect(page.getByTestId("quick-start")).toBeVisible();
  await page.getByTestId("quick-start-ip").fill("192.168.1.20");
  await page.getByTestId("quick-start-go").click();
  await expect(page).toHaveURL(/\/sources\/new\?ip=192\.168\.1\.20/);
  await expect(page.getByTestId("source-cidr")).toHaveValue("192.168.1.20");
});
