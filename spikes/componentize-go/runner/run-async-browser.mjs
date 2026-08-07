// Async spike, browser leg: the jco-working subset (async-lifted export
// with internal goroutine concurrency) under real browser JSPI in
// headless Chromium. The [async-lower] import limitation is recorded by
// run-async-node.mjs; it is identical in the browser (same jco runtime).
import http from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright-core";
import { findChrome } from "./chrome.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const P2_SHIM = join(HERE, "node_modules", "@bytecodealliance", "preview2-shim", "dist", "browser");

const IMPORT_MAP = JSON.stringify({
  imports: {
    "@bytecodealliance/preview2-shim/cli": "/shim2/cli.js",
    "@bytecodealliance/preview2-shim/clocks": "/shim2/clocks.js",
    "@bytecodealliance/preview2-shim/filesystem": "/shim2/filesystem.js",
    "@bytecodealliance/preview2-shim/io": "/shim2/io.js",
    "@bytecodealliance/preview2-shim/random": "/shim2/random.js",
    "@bytecodealliance/preview3-shim/clocks": "/clocks-p3.js",
  },
});

const PAGE = `<!doctype html><meta charset=utf-8>
<script type="importmap">${IMPORT_MAP}</script>
<script type="module">
  window.__result = (async () => {
    const { asyncProbes } = await import("/generated/async-probe.js");
    if (asyncProbes.chanPipeline(4, 100) !== 5350n) throw new Error("chanPipeline");
    if ((await asyncProbes.spinPipeline(4, 100)) !== 5350n) throw new Error("spinPipeline");
    return "OK";
  })();
</script>`;

const MIME = { ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm" };

const roots = {
  shim2: P2_SHIM,
  generated: join(HERE, "generated-async"),
};

const server = http.createServer(async (req, res) => {
  const pathname = decodeURIComponent(req.url.split("?")[0]);
  if (pathname === "/") {
    res.setHeader("content-type", "text/html");
    res.end(PAGE);
    return;
  }
  if (pathname === "/clocks-p3.js") {
    res.setHeader("content-type", "text/javascript");
    res.end(await readFile(join(HERE, "browser-clocks-p3.js")));
    return;
  }
  const match = /^\/(shim2|generated)\/((?:interfaces\/)?[A-Za-z0-9._-]+)$/.exec(pathname);
  if (!match || pathname.includes("..")) {
    res.statusCode = 404;
    res.end("not found");
    return;
  }
  try {
    const file = join(roots[match[1]], match[2]);
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

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.error(`[browser error] ${e.message}`));
  await page.goto(`${base}/`);
  const result = await page.evaluate(() => window.__result);
  console.log(`async spike browser leg: ${result}`);
  process.exitCode = result === "OK" ? 0 : 1;
} finally {
  await browser.close();
  server.close();
}
