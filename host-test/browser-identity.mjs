// Browser gate: does the SSH client component actually load and run in
// a real browser under deltic?
//
// This is the leg no native test can cover. It drives the SAME artifact
// the native gates use -- deltic is a runtime linker, so there is no
// transpiled variant that could drift -- and asserts the two things
// that must hold before any session can work in a page:
//
//   1. deltic instantiates the composed component, with the iroh
//      endpoint's webcrypto/websocket/webrtc imports served by real
//      browser APIs.
//   2. `identity-openssh` returns a well-formed authorized_keys line
//      whose Ed25519 key lives behind the browser's Web Crypto. That
//      exercises the whole guest->WIT->host crypto path, and it is the
//      key SSH publickey auth will later sign with.
//   3. The identity PERSISTS: a page reload -- a fresh component
//      instance -- reports the same line, because the host serves it
//      from IndexedDB (`wosh:terminal/identity-store`). This is the
//      property no native gate can see: it lives in the browser's
//      storage, not in the component.
//
// Usage: node host-test/browser-identity.mjs [--keep]

import { chromium } from "playwright-core";
import { existsSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8098);

const MIME = {
  ".html": "text/html",
  ".mjs": "text/javascript",
  ".js": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
};

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  // Playwright-managed builds; newest wins.
  const glob = `${process.env.HOME}/.cache/ms-playwright`;
  const dirs = readdirSync(glob)
    .filter((d) => d.startsWith("chromium-"))
    .sort((a, b) => Number(a.split("-")[1]) - Number(b.split("-")[1]));
  for (const d of dirs.reverse()) {
    const p = join(glob, d, "chrome-linux", "chrome");
    if (existsSync(p)) return p;
  }
  throw new Error("no Chromium found; set CHROME_PATH");
}

const server = createServer(async (req, res) => {
  try {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const file = join(ROOT, path === "/" ? "index.html" : path);
    const body = await readFile(file);
    res.writeHead(200, {
      "content-type": MIME[extname(file)] ?? "application/octet-stream",
      // The component is large; keep it uncached so a rebuild is picked up.
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
});

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
};

await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
const browser = await chromium.launch({
  executablePath: findChrome(),
  args: ["--no-sandbox"],
});

try {
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "load" });

  // 1. the page itself came up
  await page.waitForSelector("#home button.scan", { timeout: 15_000 });
  await page.waitForSelector(".xterm-screen", { timeout: 15_000 });
  console.log("[1] page loaded: home screen and xterm are live");

  // 2. deltic really instantiates the component AND guest code runs.
  //    Proven by feeding a deliberately malformed connection string and
  //    requiring the error to come from OUR parser inside the guest --
  //    a host-side or loader failure could not produce this message.
  const parseErr = await page.evaluate(async () => {
    const { connect } = await import("./app.mjs");
    try {
      await connect({
        connstring: "not-a-valid-connstring",
        user: "nobody",
        ui: { confirmHostKey: () => false, getCredential: () => ({ kind: "password", password: "" }) },
      });
      return "<no error>";
    } catch (e) {
      // ComponentException.payload is the err string for result<_, string>.
      return String(typeof e?.payload === "string" ? e.payload : e?.message ?? e);
    }
  });
  console.log(`[2] guest-side parse of a bad connstring: ${parseErr}`);
  if (!/connection string/i.test(parseErr)) {
    fail(`expected a guest-side connection-string error, got: ${parseErr}`);
  } else {
    console.log("[2] the component instantiated and executed guest code in-page");
  }

  // 3. Publickey/WebCrypto identity, when this build has it.
  const caps = await page.evaluate(async () => {
    const { capabilities } = await import("./app.mjs");
    return await capabilities();
  });
  if (!caps.publickey) {
    console.log("[3] SKIP: this component build has no WebCrypto identity yet " +
                "(password-only); publickey auth is the unfinished leg");
  } else {
    // Through the identity SCREEN: this gate owns that UI.
    await page.click("#home .footer button:has-text('identity')");
    await page.click("#identity button:has-text(\"show this browser's public key\")");
    const line = (await page.locator("#identity .key code").first()
      .textContent({ timeout: 120_000 }) ?? "").trim();
    console.log(`[3] identity: ${line}`);
    if (!/^ssh-ed25519 AAAA[A-Za-z0-9+/]+=* wosh-browser$/.test(line)) {
      fail(`not a well-formed ed25519 authorized_keys line: ${line}`);
    }
    const again = await page.evaluate(async () => {
      const { identity } = await import("./app.mjs");
      return await identity();
    });
    if (again !== line) fail(`identity not stable across calls:\n  ${line}\n  ${again}`);
    else console.log("[4] identity is well-formed and stable across calls");

    // Persistence: a reload tears the component down; the identity must
    // come back identical from IndexedDB. This is THE property the
    // identity-store import exists for.
    await page.reload({ waitUntil: "load" });
    await page.waitForSelector("#home button.scan", { timeout: 15_000 });
    const reloaded = await page.evaluate(async () => {
      const { identity } = await import("./app.mjs");
      return await identity();
    });
    if (reloaded !== line) {
      fail(`identity did not survive a reload:\n  before ${line}\n  after  ${reloaded}`);
    } else {
      console.log("[5] identity persists across a page reload (IndexedDB)");
    }
  }

  // 6. the PWA shell. Registration itself is https-gated on purpose --
  //    local serving is http, so a stale worker can never confuse
  //    development or this gate -- so assert the shipped assets are
  //    coherent instead: a manifest the browser actually parsed, icons
  //    that resolve, and a service worker whose placeholders were
  //    substituted (an unreplaced one is a syntax error that would
  //    break every deployed visit).
  const manifest = await page.evaluate(async () => {
    const href = document.querySelector('link[rel=manifest]')?.href;
    if (!href) return { error: "no manifest link" };
    const m = await (await fetch(href)).json();
    const icons = await Promise.all(
      (m.icons ?? []).map(async (i) => ({
        src: i.src,
        ok: (await fetch(new URL(i.src, href))).ok,
      })),
    );
    return { name: m.name, display: m.display, start_url: m.start_url, icons };
  });
  if (manifest.error) {
    fail(`manifest: ${manifest.error}`);
  } else {
    const bad = manifest.icons.filter((i) => !i.ok).map((i) => i.src);
    if (bad.length) fail(`manifest icons do not resolve: ${bad.join(", ")}`);
    else {
      console.log(
        `[6] manifest ok: "${manifest.name}", display=${manifest.display}, ` +
          `${manifest.icons.length} icons resolve`,
      );
    }
  }

  const sw = await page.evaluate(async () => await (await fetch("./sw.js")).text());
  if (/__WOSH_(VERSION|PRECACHE)__/.test(sw)) {
    fail("sw.js shipped with unreplaced placeholders (would break every deployed visit)");
  } else {
    const version = sw.match(/const VERSION = "([^"]+)"/)?.[1];
    const precached = (sw.match(/const PRECACHE = \[([^\]]*)\]/)?.[1] ?? "")
      .split(",").filter(Boolean).length;
    const hasWasm = /dist\/wosh-ssh-client\.wasm/.test(sw);
    if (!version || !precached) fail(`sw.js looks malformed (version=${version}, ${precached} entries)`);
    else if (!hasWasm) fail("sw.js does not precache the client component");
    else console.log(`[7] service worker: version ${version}, ${precached} files precached (component included)`);
  }

  if (consoleErrors.length) {
    fail(`console errors:\n  ${consoleErrors.join("\n  ")}`);
  }

  if (!process.exitCode) {
    console.log("\nBROWSER GATE PASS: deltic runs the SSH client component in-page");
  }
} finally {
  if (!process.argv.includes("--keep")) await browser.close();
  server.close();
}
