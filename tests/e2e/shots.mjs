// One-off: screenshots of the running app (used for the dissertation figures). Not part of the test suite.
//   node shots.mjs <output-dir>
import { chromium } from "@playwright/test";

const out = process.argv[2] ?? ".";
const browser = await chromium.launch({ channel: "chrome", headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
await page.goto("http://127.0.0.1:3000/login");
await page.getByLabel("Email").fill("admin@demo.sentinelbi.example");
await page.getByLabel("Password").fill("dev-only-demo-password");
await page.getByRole("button", { name: /sign in|log in/i }).click();
await page.waitForURL(/dashboard/, { timeout: 30000 });
await page.waitForTimeout(6000);
await page.screenshot({ path: `${out}/dashboard.png` });
for (const [path, name] of [["risk", "risk"], ["recommendations", "actions"], ["assessment", "assessment"], ["settings", "settings"], ["models", "models"]]) {
  await page.goto(`http://127.0.0.1:3000/${path}`);
  await page.waitForTimeout(4000);
  await page.screenshot({ path: `${out}/${name}.png` });
}
await browser.close();
console.log("done");
