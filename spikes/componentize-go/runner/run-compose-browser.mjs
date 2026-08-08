// Composition spike, browser leg: the wac-composed component inside
// headless Chromium, preview2-shim browser build via import map. Same
// assertions as the node leg (compose-assertions.mjs is served to the
// page).
import http from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright-core";
import { findChrome } from "./chrome.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM_BROWSER = join(
  HERE,
  "node_modules",
  "@bytecodealliance",
  "preview2-shim",
  "dist",
  "browser",
);

const IMPORT_MAP = JSON.stringify({
  imports: {
    "@bytecodealliance/preview2-shim/cli": "/shim/cli.js",
    "@bytecodealliance/preview2-shim/clocks": "/shim/clocks.js",
    "@bytecodealliance/preview2-shim/filesystem": "/shim/filesystem.js",
    "@bytecodealliance/preview2-shim/io": "/shim/io.js",
    "@bytecodealliance/preview2-shim/random": "/shim/random.js",
  },
});

const PAGE = `<!doctype html><meta charset=utf-8>
<script type="importmap">${IMPORT_MAP}</script>
<script type="module">
  window.__result = (async () => {
    const { driver } = await import("/generated/compose-probe.js");
    const { assertComposeProbe } = await import("/compose-assertions.mjs");
    return assertComposeProbe(driver);
  })();
</script>`;

const MIME = { ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm" };

const server = http.createServer(async (req, res) => {
  const pathname = decodeURIComponent(req.url.split("?")[0]);
  if (pathname === "/") {
    res.setHeader("content-type", "text/html");
    res.end(PAGE);
    return;
  }
  if (pathname === "/compose-assertions.mjs") {
    res.setHeader("content-type", "text/javascript");
    res.end(await readFile(join(HERE, "compose-assertions.mjs")));
    return;
  }
  const match = /^\/(generated|shim)\/([A-Za-z0-9._-]+)$/.exec(pathname);
  if (!match || pathname.includes("..")) {
    const ifc = /^\/generated\/interfaces\/([A-Za-z0-9._-]+)$/.exec(pathname);
    if (!ifc) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    try {
      const body = await readFile(join(HERE, "generated-compose", "interfaces", ifc[1]));
      res.setHeader("content-type", MIME[extname(ifc[1])] ?? "application/octet-stream");
      res.end(body);
    } catch {
      res.statusCode = 404;
      res.end("not found");
    }
    return;
  }
  const file =
    match[1] === "shim" ? join(SHIM_BROWSER, match[2]) : join(HERE, "generated-compose", match[2]);
  try {
    const body = await readFile(file);
    res.setHeader("content-type", MIME[extname(file)] ?? "application/octet-stream");
    res.end(body);
  } catch {
    res.statusCode = 404;
    res.end("not found");
  }
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const executablePath = await findChrome();
if (!executablePath) throw new Error("no Chromium found; set CHROME_PATH");
console.error(`chromium: ${executablePath}`);

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage();
  page.on("console", (m) => console.error(`[browser] ${m.text()}`));
  page.on("pageerror", (e) => console.error(`[browser error] ${e.message}`));
  await page.goto(`${base}/`);
  const result = await page.evaluate(() => window.__result);
  console.log(`compose spike browser leg: ${result}`);
  process.exitCode = String(result).startsWith("OK") ? 0 : 1;
} finally {
  await browser.close();
  server.close();
}
