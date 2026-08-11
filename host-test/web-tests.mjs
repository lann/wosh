// M5 gate for the browser-client modules: connection-string parsing
// and the storage schema in node (pure modules), then the IndexedDB
// CryptoKey persistence and the bootstrap panel in headless Chromium —
// including identity survival across a page reload, which is the
// property the whole module exists for. The in-browser iroh session
// itself is NOT here: it has its own gates (client-e2e-deno.mjs on the
// Deno lane, browser-e2e.mjs for the full in-page leg).
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

// --- phase 1.5: prf-wrap crypto under node (synthetic PRF output) -------------

const prf = await import("../web/prf-wrap.mjs");

{
  // Wrap/unwrap round-trip; the sealed floor is authoritative.
  const prfOut = crypto.getRandomValues(new Uint8Array(32));
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const escrow = await prf.wrapEscrow(prfOut, { key: "S3KR1T", seqFloor: 42 }, credId);
  assert.deepEqual(Object.keys(escrow), ["prf"]);
  assert.equal(escrow.prf.seqFloor, 42);
  const inner = await prf.unwrapEscrow(prfOut, escrow);
  assert.deepEqual(inner, { key: "S3KR1T", seqFloor: 42 });

  // A proxy-tampered outer floor does not reach the attach path.
  const tamperedOuter = { prf: { ...escrow.prf, seqFloor: 1 } };
  assert.deepEqual(await prf.unwrapEscrow(prfOut, tamperedOuter), {
    key: "S3KR1T",
    seqFloor: 42,
  });

  // Ciphertext tampering and wrong-credential PRF output both throw.
  const ct = prf.unb64u(escrow.prf.ct);
  ct[0] ^= 1;
  await assert.rejects(
    prf.unwrapEscrow(prfOut, { prf: { ...escrow.prf, ct: prf.b64u(ct) } }),
    /unwrap failed/,
  );
  await assert.rejects(
    prf.unwrapEscrow(crypto.getRandomValues(new Uint8Array(32)), escrow),
    /unwrap failed/,
  );

  // The blob is exactly the storage-schema session key (and therefore
  // the proto::Escrow JSON — parity-tested on the Rust side).
  const withSession = store.recordSession(store.emptyState(), {
    proxyId: ID,
    key: escrow,
  });
  assert.equal(withSession.sessions[0].key.prf.ct, escrow.prf.ct);

  // D4 sub-policy: no prf ⇒ no persistence.
  assert.throws(() => prf.assertPersistencePermitted(false), /refusing to persist/);
  assert.throws(() => prf.assertPersistencePermitted(undefined), /refusing to persist/);
  prf.assertPersistencePermitted(true);
}

console.log("[web-tests] node phase OK (prf-wrap crypto, D4 policy guard)");

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
        const req = indexedDB.deleteDatabase("wosh-keys");
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

      // Bootstrap panel: fragment parsed, explicit save, connect
      // policy (pairing tokens are deliberately not persisted, so a
      // saved-proxy connect without one asks for it), forget removes.
      const boot = await initBoot(document.getElementById("panel"));
      if (!boot.identityAvailable) return "FAIL: boot identity " + boot.identityError;
      if (!boot.pending) return "FAIL: fragment not parsed (" + boot.notice + ")";
      boot.saveOffer();
      if (boot.state.proxies.length !== 1) return "FAIL: save offer did not persist";
      document.querySelector(".connect-btn").click();
      if (!boot.notice.includes("pairing token required")) {
        return "FAIL: tokenless connect did not ask for a token (" + boot.notice + ")";
      }
      const bad = "1.zz." + "a".repeat(62) + ".t.http://h";
      boot.tryParse(bad);
      if (!boot.notice) return "FAIL: bad connstring produced no notice";

      // Reconnect routing (#12): the tab retains the last connect's
      // token in memory (tokens are never persisted); reconnect()
      // retries a fresh connect until a persistent session exists for
      // the proxy, then prefers the assertion-gated reattach.
      const IDC = "c".repeat(64);
      const div = document.createElement("div");
      document.body.append(div);
      const calls = [];
      const boot2 = await initBoot(div, localStorage, {
        onConnect: async (a) => calls.push(["connect", a]),
        onPersist: async () => ({
          sessionId: 9,
          escrow: { prf: { ct: "ct", iv: "iv", credId: "d", seqFloor: 1 } },
        }),
        onReattach: async (a) => {
          calls.push(["reattach", a]);
          return { escrow: { prf: { ct: "ct2", iv: "iv", credId: "d", seqFloor: 2 } } };
        },
      });
      if (await boot2.reconnect()) return "FAIL: reconnect before any connect succeeded";
      if (!boot2.notice.includes("no previous")) {
        return "FAIL: no-previous-connection notice: " + boot2.notice;
      }
      await boot2.connect({ relayUrl: "http://r", endpointIdHex: IDC, token: "tok" });
      if (calls.at(-1)?.[0] !== "connect") return "FAIL: connect stub not called";
      if (!(await boot2.reconnect())) return "FAIL: pre-persist reconnect failed";
      if (calls.at(-1)[0] !== "connect") {
        return "FAIL: pre-persist reconnect used " + calls.at(-1)[0];
      }
      if (calls.at(-1)[1].token !== "tok") return "FAIL: in-memory token not retained";
      await boot2.persist();
      if (!(await boot2.reconnect())) return "FAIL: post-persist reconnect failed";
      if (calls.at(-1)[0] !== "reattach") {
        return "FAIL: post-persist reconnect used " + calls.at(-1)[0];
      }
      if (calls.at(-1)[1].sessionId !== 9) {
        return "FAIL: reattach sessionId " + calls.at(-1)[1].sessionId;
      }
      // storage hygiene: phase 2 asserts exactly the ID2 proxy persisted
      store.save(localStorage, store.removeProxy(store.load(localStorage), IDC));

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
    if (phase === "3") {
      // WebAuthn prf ceremony against the CDP virtual authenticator
      // (wired by the node side before navigation). Prototype calls
      // per finding 6.
      const prf = await import("/prf-wrap.mjs");
      const protoCreate = CredentialsContainer.prototype.create;
      const protoGet = CredentialsContainer.prototype.get;
      const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

      const cred = await protoCreate.call(navigator.credentials, {
        publicKey: {
          rp: { name: "wosh web-tests" },
          user: { id: rand(16), name: "m6", displayName: "m6" },
          challenge: rand(32),
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
          },
          extensions: prf.prfExtensionForCreate(),
        },
      });
      const enabled = cred.getClientExtensionResults().prf?.enabled === true;
      if (!enabled) return "OK phase3 (prf NOT supported at create)";

      const assert1 = await protoGet.call(navigator.credentials, {
        publicKey: {
          challenge: rand(32),
          userVerification: "required",
          extensions: prf.prfExtensionForGet(),
        },
      });
      const out1 = assert1.getClientExtensionResults().prf?.results?.first;
      if (!out1 || out1.byteLength !== 32) {
        return "FAIL: prf enabled at create but eval returned " + out1?.byteLength;
      }

      // Wrap under the real PRF output; unwrap with a SECOND assertion's
      // output (deterministic per credential+salt — the reattach path).
      const escrow = await prf.wrapEscrow(
        out1,
        { key: "mosh-key-b64", seqFloor: 7 },
        new Uint8Array(cred.rawId),
      );
      const assert2 = await protoGet.call(navigator.credentials, {
        publicKey: {
          challenge: rand(32),
          userVerification: "required",
          extensions: prf.prfExtensionForGet(),
        },
      });
      const out2 = assert2.getClientExtensionResults().prf?.results?.first;
      const inner = await prf.unwrapEscrow(out2, escrow);
      if (inner.key !== "mosh-key-b64" || inner.seqFloor !== 7) {
        return "FAIL: unwrap after fresh assertion: " + JSON.stringify(inner);
      }
      return "OK phase3 (prf supported; wrap survives a fresh assertion)";
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
  const m = /^\/(boot|connstring|storage|idb-keys|prf-wrap)\.mjs$/.exec(pathname);
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
  args: [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    // Phase 3 needs a valid RP ID; "localhost" is one, "127.0.0.1" is
    // not. Pin the resolution so the page still hits our v4 listener.
    "--host-resolver-rules=MAP localhost 127.0.0.1",
  ],
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

  // Phase 3: real WebAuthn ceremonies against the CDP virtual
  // authenticator (the finding is the capability report either way;
  // the full browser↔proxy ceremony E2E stays A3-blocked).
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  let authenticatorAdded = false;
  try {
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
      },
    });
    authenticatorAdded = true;
  } catch (e) {
    console.log(
      `[web-tests] browser phase 3: SKIPPED (virtual authenticator with hasPrf unavailable: ${e.message})`,
    );
  }
  if (authenticatorAdded) {
    await page.goto(`http://localhost:${server.address().port}/?phase=3`);
    const r3 = await page.evaluate(() => window.__result);
    console.log(`[web-tests] browser phase 3: ${r3}`);
    if (!r3.startsWith("OK phase3")) process.exit(1);
  }

  console.log("web tests (M5 unblocked parts + M6 prf): OK");
} finally {
  await browser.close();
  server.close();
}
