// M5 gate for the unblocked browser-client parts: connection-string
// parsing and the storage schema in node (pure modules), then the
// IndexedDB CryptoKey persistence and the bootstrap panel in headless
// Chromium — including identity survival across a page reload, which
// is the property the whole module exists for. The in-browser iroh
// leg is NOT here: blocked on A3 (see jco-probe.mjs).
import assert from "node:assert/strict";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const WEB = join(HERE, "..", "web");

// --- phase 1: pure modules under node ----------------------------------------

const { parseConnstring, formatConnstring, connstringFromFragment } = await import(
  "../web/connstring.mjs"
);
const store = await import("../web/storage.mjs");

const ID = "a".repeat(64);
const CS = `1.${ID}.t0ken.http://127.0.0.1:3347`;

{
  const p = parseConnstring(CS);
  assert.deepEqual(p, {
    version: 1,
    endpointIdHex: ID,
    token: "t0ken",
    relayUrl: "http://127.0.0.1:3347",
  });
  assert.equal(formatConnstring(p), CS);

  // The relay URL keeps its dots (split is at-most-4).
  const q = parseConnstring(`1.${ID}.tok.https://relay.example.com:8443/path`);
  assert.equal(q.relayUrl, "https://relay.example.com:8443/path");

  // Hex normalizes down; version/id/token/url errors are legible.
  assert.equal(parseConnstring(`1.${"A".repeat(64)}.t.http://h`).endpointIdHex, ID);
  assert.throws(() => parseConnstring(`2.${ID}.t.http://h`), /version/);
  assert.throws(() => parseConnstring(`1.abc.t.http://h`), /32 bytes/);
  assert.throws(() => parseConnstring(`1.${ID}..http://h`), /token/);
  assert.throws(() => parseConnstring(`1.${ID}.t.not-a-url`), /relay URL/);
  assert.throws(() => parseConnstring(`1.${ID}.t.ftp://h`), /http/);
  assert.throws(() => parseConnstring("just-garbage"), /malformed/);

  // Fragment extraction: raw, hash-prefixed, full URL, percent-encoded.
  assert.equal(connstringFromFragment(CS), CS);
  assert.equal(connstringFromFragment(`#${CS}`), CS);
  assert.equal(connstringFromFragment(`https://site.example/#${CS}`), CS);
  assert.equal(connstringFromFragment(`#${encodeURIComponent(CS)}`), CS);
  assert.equal(connstringFromFragment("https://site.example/"), null);
  assert.equal(connstringFromFragment(""), null);
}

{
  // storage: fake localStorage, full life cycle.
  const fake = new Map();
  const storage = {
    getItem: (k) => fake.get(k) ?? null,
    setItem: (k, v) => fake.set(k, String(v)),
  };

  let state = store.load(storage);
  assert.deepEqual(state, store.emptyState());

  const { state: s1, proxy } = store.upsertProxy(state, {
    endpointIdHex: ID,
    relayUrl: "http://127.0.0.1:3347",
  });
  assert.equal(proxy.name, `proxy-${ID.slice(0, 8)}`);
  assert.equal(s1.proxies.length, 1);

  // Upsert dedupes on endpoint id and keeps addedAt.
  const { state: s2 } = store.upsertProxy(s1, {
    endpointIdHex: ID,
    relayUrl: "http://other:1",
    name: "named",
  });
  assert.equal(s2.proxies.length, 1);
  assert.equal(s2.proxies[0].relayUrl, "http://other:1");
  assert.equal(s2.proxies[0].name, "named");
  assert.equal(s2.proxies[0].addedAt, s1.proxies[0].addedAt);

  // Sessions: tagged key variant enforced; seq floor moves forward only.
  assert.throws(() => store.recordSession(s2, { proxyId: ID, key: { nope: {} } }), /exactly one/);
  assert.throws(
    () => store.recordSession(s2, { proxyId: ID, key: { plain: { key: "K" } } }),
    /seqFloor/,
  );
  let s3 = store.recordSession(s2, { proxyId: ID, key: { plain: { key: "K", seqFloor: 0 } } });
  s3 = store.bumpSeqFloor(s3, ID, 5_000_000);
  assert.equal(s3.sessions[0].key.plain.seqFloor, 5_000_000);
  assert.throws(() => store.bumpSeqFloor(s3, ID, 4), /forward/);

  // Save/load round-trip; removeProxy drops its sessions.
  store.save(storage, s3);
  const reloaded = store.load(storage);
  assert.deepEqual(reloaded, s3);
  const s4 = store.removeProxy(reloaded, ID);
  assert.equal(s4.proxies.length, 0);
  assert.equal(s4.sessions.length, 0);

  // Corrupt data → fresh state; future schema → refuses.
  storage.setItem(store.STORAGE_KEY, "{nope");
  assert.deepEqual(store.load(storage), store.emptyState());
  storage.setItem(store.STORAGE_KEY, JSON.stringify({ v: 2 }));
  assert.throws(() => store.load(storage), /v2/);
}

console.log("[web-tests] node phase OK (connstring, storage)");

// --- phase 2: IndexedDB keys + bootstrap panel in headless Chromium ----------

const PAGE = `<!doctype html><meta charset=utf-8>
<div id="panel"></div>
<script type="module">
  window.__result = (async () => {
    const phase = new URL(location.href).searchParams.get("phase");
    const { openKeyStore, ensureIdentity } = await import("/idb-keys.mjs");
    const store = await import("/storage.mjs");
    const { initBoot } = await import("/boot.mjs");

    if (phase === "1") {
      // Fresh origin state (the browser context is new, but be explicit).
      localStorage.clear();
      await new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase("experiment-mosh-keys");
        req.onsuccess = req.onblocked = () => resolve();
        req.onerror = () => reject(req.error);
      });

      const keys = await openKeyStore();
      const first = await ensureIdentity(keys);
      if (!first.created) return "FAIL: first ensureIdentity did not create";
      const again = await ensureIdentity(keys);
      if (again.created) return "FAIL: second ensureIdentity re-created";

      // The persisted handle signs; the key never leaves the browser.
      const kp = again.keyPair;
      if (kp.privateKey.extractable) return "FAIL: private key extractable";
      const msg = new TextEncoder().encode("m5-idb-keys");
      const sig = await crypto.subtle.sign("Ed25519", kp.privateKey, msg);
      const ok = await crypto.subtle.verify("Ed25519", kp.publicKey, sig, msg);
      if (!ok) return "FAIL: sign/verify with persisted key";

      // Bootstrap panel: fragment parsed, explicit save, honest A3
      // notice on connect, forget removes.
      const boot = await initBoot(document.getElementById("panel"));
      if (!boot.identityAvailable) return "FAIL: boot identity " + boot.identityError;
      if (!boot.pending) return "FAIL: fragment not parsed (" + boot.notice + ")";
      boot.saveOffer();
      if (boot.state.proxies.length !== 1) return "FAIL: save offer did not persist";
      document.querySelector(".connect-btn").click();
      if (!boot.notice.includes("polymorph-iroh#10")) {
        return "FAIL: connect did not surface the A3 block";
      }
      const bad = "1.zz." + "a".repeat(62) + ".t.http://h";
      boot.tryParse(bad);
      if (!boot.notice) return "FAIL: bad connstring produced no notice";
      return "OK phase1";
    }

    if (phase === "2") {
      // A fresh page load: identity and saved proxies both persist.
      const keys = await openKeyStore();
      const identity = await ensureIdentity(keys);
      if (identity.created) return "FAIL: identity did not persist across loads";
      const state = store.load(localStorage);
      if (state.proxies.length !== 1) return "FAIL: proxies did not persist";
      const boot = await initBoot(document.getElementById("panel"));
      if (document.querySelectorAll(".boot-proxy").length !== 1) {
        return "FAIL: saved proxy not rendered";
      }
      document.querySelector(".forget-btn").click();
      if (store.load(localStorage).proxies.length !== 0) return "FAIL: forget did not persist";
      return "OK phase2";
    }
    return "FAIL: unknown phase";
  })().catch((e) => "FAIL: " + (e.message ?? e));
</script>`;

const server = http.createServer(async (req, res) => {
  const pathname = decodeURIComponent(req.url.split("?")[0]);
  if (pathname === "/") {
    res.setHeader("content-type", "text/html");
    res.end(PAGE);
    return;
  }
  const m = /^\/(boot|connstring|storage|idb-keys)\.mjs$/.exec(pathname);
  if (!m || pathname.includes("..")) {
    res.statusCode = 404;
    res.end("not found");
    return;
  }
  res.setHeader("content-type", "text/javascript");
  res.end(await readFile(join(WEB, `${m[1]}.mjs`)));
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const { chromium } = await import("playwright-core");
const { findChrome } = await import("./chrome.mjs");
const executablePath = await findChrome();
if (!executablePath) throw new Error("no Chromium found; set CHROME_PATH");

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.error(`[page error] ${e.message}`));

  const ID2 = "b".repeat(64);
  await page.goto(`${base}/?phase=1#1.${ID2}.tok3n.http://127.0.0.1:3999`);
  const r1 = await page.evaluate(() => window.__result);
  console.log(`[web-tests] browser phase 1: ${r1}`);
  if (r1 !== "OK phase1") process.exit(1);

  await page.goto(`${base}/?phase=2`);
  const r2 = await page.evaluate(() => window.__result);
  console.log(`[web-tests] browser phase 2: ${r2}`);
  if (r2 !== "OK phase2") process.exit(1);

  console.log("web tests (M5 unblocked parts): OK");
} finally {
  await browser.close();
  server.close();
}
