import { expect, type Page } from "@playwright/test";

export const API = process.env.E2E_API_URL ?? "http://127.0.0.1:8000";
export const PASSWORD = "correct-horse-battery";

/** Register a new organisation with one sensor IP (the quick-start path) and return the source's API key. */
export async function registerWithSensor(page: Page, orgName: string, ip: string): Promise<string> {
  await page.goto("/register");
  await page.getByLabel("Organisation name").fill(orgName);
  await page.getByLabel("Email").fill(`e2e-${orgName.toLowerCase().replace(/\W+/g, "-")}-${Date.now()}@example.com`);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByTestId("register-ip").fill(ip);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/sources\/new\?ip=/, { timeout: 30_000 });
  await page.getByTestId("create-source").click();
  await expect(page.getByTestId("api-key")).toBeVisible();
  return (await page.getByTestId("api-key").innerText()).trim();
}

interface Peer {
  ip: string;
  port: number;
  protocol: number;
  sent: number;
  received: number;
}

/** What the seeded host did: the same three conversations twice, two days ago. */
export const PEERS: Peer[] = [
  { ip: "203.0.113.10", port: 443, protocol: 6, sent: 1000, received: 50_000 },
  { ip: "198.51.100.7", port: 80, protocol: 6, sent: 300, received: 9_000 },
  { ip: "9.9.9.9", port: 53, protocol: 17, sent: 60, received: 120 },
];
export const FLOWS_PER_PEER = 2;

/** Send flows from ``ip`` as they would have been two days ago, then wait until they are stored.
 *  Two days ago is outside the dashboard's 24-hour window and inside the 7-day one. */
export async function ingestTwoDaysAgo(page: Page, apiKey: string, ip: string): Promise<void> {
  const base = Date.now() - 2 * 24 * 3600 * 1000;
  const flows = PEERS.flatMap((p, i) =>
    Array.from({ length: FLOWS_PER_PEER }, (_, k) => ({
      ts: new Date(base + (i * 20 + k * 7) * 60_000).toISOString(),
      src_ip: ip,
      dst_ip: p.ip,
      src_port: 50_000 + i * 10 + k,
      dst_port: p.port,
      protocol: p.protocol,
      in_bytes: p.sent,
      out_bytes: p.received,
      in_pkts: 5,
      out_pkts: 9,
      duration_ms: 300,
    })),
  );
  const resp = await page.request.post(`${API}/api/v1/ingest/flows`, {
    headers: { "X-API-Key": apiKey },
    data: { flows },
  });
  expect(resp.status()).toBe(202);
  await expect
    .poll(
      async () => {
        const r = await page.request.get(`/api/proxy/traffic/hosts/${ip}?minutes=10080`);
        return (await r.json()).flows;
      },
      { timeout: 60_000 },
    )
    .toBe(flows.length);
}

export const SENT_TOTAL = PEERS.reduce((n, p) => n + p.sent * FLOWS_PER_PEER, 0); // 2 720 B
export const RECEIVED_TOTAL = PEERS.reduce((n, p) => n + p.received * FLOWS_PER_PEER, 0); // 118 240 B
