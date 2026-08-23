// Smoke-check the DEPLOYED site: real origin, real https, so unlike the
// local gate this also exercises service-worker registration.
import { chromium } from "playwright-core";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
const glob = `${process.env.HOME}/.cache/ms-playwright`;
const dir = readdirSync(glob).filter(d => d.startsWith("chromium-")).sort().pop();
// Chrome for Testing unpacks as chrome-linux64/; older builds as chrome-linux/.
const exe = ["chrome-linux64", "chrome-linux"].map(s => join(glob, dir, s, "chrome")).find(existsSync);
const b = await chromium.launch({ executablePath: exe, args: ["--no-sandbox"] });
const p = await b.newPage();
const errs = [];
p.on("pageerror", e => errs.push(String(e)));
p.on("console", m => { if (m.type() === "error") errs.push(m.text()); });
await p.goto("https://lann.github.io/wosh/", { waitUntil: "load" });
await p.waitForSelector("#panel button", { timeout: 30000 });
await p.waitForSelector(".xterm-screen", { timeout: 30000 });
console.log("[1] deployed page loads: panel + xterm live");
const line = await p.evaluate(async () => {
  const { identity } = await import("./app.mjs");
  return await identity();
});
console.log(`[2] WebCrypto identity minted from the deployed site:\n    ${line}`);
const sw = await p.evaluate(async () => {
  const r = await navigator.serviceWorker.getRegistration();
  return r ? { scope: r.scope, active: !!r.active } : null;
});
console.log(`[3] service worker: ${sw ? `registered, scope ${sw.scope}` : "NOT registered"}`);
if (errs.length) console.log("console errors:\n  " + errs.join("\n  "));
console.log(errs.length ? "\nLIVE CHECK: errors above" : "\nLIVE CHECK PASS");
await b.close();
