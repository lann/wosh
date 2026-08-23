// Gate: the file-transfer panel end to end in a real browser -- the
// REAL page (site/transfer-ui.mjs + the real `wosh:terminal/transfer-io`
// host in site/transfer-io.ts, OPFS staging worker and all), driving the
// REAL composed component's SFTP engine, through a real listener and a
// real OpenSSH sshd.
//
// This file began life against a MOCK of the component's session
// exports, because the Rust SFTP engine had not landed when the panel
// was written. The mock is gone: `session.listDir/upload/download` and
// the `transfer` resource are now the component's own, and the
// verification that the mock did in an in-memory store is done by the
// TARGET -- `sha256sum` typed into the interactive pty, on the same
// live session the transfers ride. That is the point of this gate as
// distinct from `just e2e-transfer`: the native leg drives the
// component through typed Rust bindings, and so never exercises the
// page's reading of polyengine's JS conventions, its OPFS staging, its
// IndexedDB resume records, or a transfer sharing a session with a
// terminal a human is typing into.
//
// The five legs:
//   1. list      -- the panel descends into a seeded directory and
//                   shows what is really there, with real sizes.
//   2. upload    -- a multi-megabyte file picked through the real file
//                   chooser, verified by the target's own sha256sum.
//   3. download  -- the same bytes back out through OPFS staging,
//                   captured at the Blob and hashed here.
//   4. cancel    -- a download cancelled mid-flight leaves a PARTIAL
//                   staged file and says so (terminal.wit: what is
//                   already moved stays moved).
//   5. resume    -- ... which the next page life offers to resume, and
//                   the resumed download's bytes must match the file
//                   on the target exactly.
//
// Environment (the `just browser-transfer` recipe supplies it):
//   WOSH_CONNSTRING       the listener's connection string   (required)
//   WOSH_AUTHORIZED_KEYS  sshd's authorized_keys path        (required)
//   WOSH_USER             login user (default: $USER)
//   WOSH_HTTP_PORT        static server port (default: 8140)
//
// Usage: node host-test/browser-transfer.mjs

import { chromium } from "playwright-core";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";
import { tmpdir, homedir } from "node:os";
import { createHash } from "node:crypto";

const ROOT = new URL("../out/", import.meta.url).pathname;
const PORT = Number(process.env.WOSH_HTTP_PORT ?? 8140);
const CONNSTRING = process.env.WOSH_CONNSTRING;
const AUTH_KEYS = process.env.WOSH_AUTHORIZED_KEYS;
const USER = process.env.WOSH_USER ?? process.env.USER;
if (!CONNSTRING || !AUTH_KEYS || !USER) {
  console.error("need WOSH_CONNSTRING and WOSH_AUTHORIZED_KEYS; run via `just browser-transfer`");
  process.exit(2);
}

// The gate's sshd runs as this very user on 127.0.0.1, so "the target's
// filesystem" and this process's filesystem are the same one -- which
// is what lets the fixture be seeded and cleaned up from here (exactly
// as browser-e2e installs its authorized_keys line). Only the
// VERIFICATION goes through the target, because that is the half a
// shared filesystem would make meaningless.
const GATE_DIR_NAME = ".wosh-gate-transfer";
const GATE_DIR = join(homedir(), GATE_DIR_NAME);

const MIME = { ".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm" };
const server = createServer(async (req, res) => {
  try {
    const p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const f = join(ROOT, p === "/" ? "index.html" : p);
    const b = await readFile(f);
    res.writeHead(200, { "content-type": MIME[extname(f)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(b);
  } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const glob = `${process.env.HOME}/.cache/ms-playwright`;
  const dirs = readdirSync(glob)
    .filter((d) => d.startsWith("chromium-"))
    .sort((a, b) => Number(a.split("-")[1]) - Number(b.split("-")[1]));
  for (const d of dirs.reverse()) {
    // Chrome for Testing unpacks as chrome-linux64/; older Chromium
    // builds as chrome-linux/.
    for (const sub of ["chrome-linux64", "chrome-linux"]) {
      const p = join(glob, d, sub, "chrome");
      if (existsSync(p)) return p;
    }
  }
  throw new Error("no Chromium found; set CHROME_PATH");
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const gen = (len, salt) => {
  const b = Buffer.alloc(len);
  for (let i = 0; i < len; i++) b[i] = ((i * 2654435761) & 0xff) ^ salt;
  return b;
};

let failed = false;
const fail = (m) => { console.error(`FAIL: ${m}`); failed = true; };

// --- the fixture on the target -----------------------------------------
rmSync(GATE_DIR, { recursive: true, force: true });
mkdirSync(GATE_DIR, { recursive: true });
const GREETING = Buffer.from("hello from the real sftp engine\n");
writeFileSync(join(GATE_DIR, "greeting.txt"), GREETING);
// Big enough that a cancel can land mid-flight and leave a partial
// worth resuming, and deliberately not a round chunk multiple.
const BIG = gen(6 * 1024 * 1024 + 333, 0x00);
const BIG_HASH = sha256(BIG);
writeFileSync(join(GATE_DIR, "bigfile.bin"), BIG);
// What leg 2 uploads, staged where the browser's file chooser can
// reach it (NOT in the fixture directory -- it has to arrive there
// over SFTP for the leg to mean anything).
const tmpDir = mkdtempSync(join(tmpdir(), "wosh-transfer-"));
const UPLOAD = gen(3 * 1024 * 1024 + 777, 0x5a);
const UPLOAD_HASH = sha256(UPLOAD);
const uploadPath = join(tmpDir, "payload.bin");
writeFileSync(uploadPath, UPLOAD);

const browser = await chromium.launch({ executablePath: findChrome(), args: ["--no-sandbox"] });

let page;
try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  // The panel hands a finished download to the user as a Blob URL and
  // an `<a download>` click. Headless Chromium has no download UI to
  // drive, so capture the bytes where the Blob is made. Injected
  // before any page script so a reload keeps the hook.
  await context.addInitScript(() => {
    window.__capturedDownloads = [];
    const realCreate = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      if (blob instanceof Blob) {
        blob.arrayBuffer().then((buf) => window.__capturedDownloads.push(new Uint8Array(buf)));
      }
      return realCreate(blob);
    };
  });
  page = await context.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  if (process.env.WOSH_DEBUG) {
    page.on("console", (m) => console.log(`  [page ${m.type()}] ${m.text()}`));
    page.on("pageerror", (e) => console.log(`  [page error] ${e}`));
    page.on("response", (r) => { if (r.status() >= 400) console.log(`  [http ${r.status()}] ${r.url()}`); });
  }
  // Every download confirmation in this gate is a yes.
  page.on("dialog", (d) => d.accept());

  // Terminal text with xterm's own wrapping honoured: a 64-hex digest
  // on an 80-column pty wraps, and joining lines with "\n" regardless
  // would saw it in half.
  const screenText = () =>
    page.evaluate(() => {
      const buf = window.__wosh?.term?.buffer.active;
      if (!buf) return "";
      let out = "";
      for (let i = 0; i < buf.length; i++) {
        const line = buf.getLine(i);
        if (!line) continue;
        if (i > 0 && !line.isWrapped) out += "\n";
        out += line.translateToString(true);
      }
      return out;
    });

  const waitForScreen = async (re, timeout = 60_000) => {
    const deadline = Date.now() + timeout;
    for (;;) {
      const m = (await screenText()).match(re);
      if (m) return m;
      if (Date.now() > deadline) {
        throw new Error(`terminal never showed ${re}; screen was:\n${await screenText()}`);
      }
      await page.waitForTimeout(150);
    }
  };

  // Run a command on the REAL pty and read a marked answer back out.
  // This is the gate's only oracle for what is actually on the target.
  //
  // The marker is SPLIT at a quote seam -- typed as `"WOSH_""XFER1:"`,
  // which the shell concatenates back to `WOSH_XFER1:` before echo
  // ever runs. That seam is the whole trick, and it is not cosmetic.
  // A pty echoes what you type, so a marker written literally appears
  // on screen the instant the keystrokes land, BEFORE the command has
  // produced anything -- and a scrape that races the two matches the
  // echoed INPUT and reads the command text back as if it were the
  // answer. This gate did exactly that on a slow CI runner (captured
  // `$(sha256sum` as a file's digest) while winning the race locally
  // ten times over, which is the worst way for a gate to be wrong:
  // green everywhere its author can see. With the seam the joined
  // marker exists only in real OUTPUT, so `waitForScreen` waits for
  // the answer instead of sampling whichever text got there first.
  // (browser-e2e.mjs can use a plain marker at line ~311 because it
  // asserts a round-trip -- seeing the echo AND the output is the
  // point there, and it counts two occurrences.)
  let shellSeq = 0;
  const ask = async (command, valuePattern = "[^\\s]+") => {
    // The panel is a modal <dialog>: while it is open nothing can
    // reach the terminal underneath it, not even a synthetic click.
    // Step out of the way and step back, which is what a person would
    // do too -- and the sheet keeps its directory across a close.
    const wasOpen = await page.evaluate(() => !!document.getElementById("transfers-sheet")?.open);
    if (wasOpen) await page.evaluate(() => document.getElementById("transfers-sheet").close());
    // Sequence-numbered so a later question can never match an earlier
    // answer still sitting in the scrollback.
    const tail = `XFER${++shellSeq}:`;
    await page.click(".xterm-screen");
    await page.keyboard.type(`echo "WOSH_""${tail}$(${command})"\n`, { delay: 5 });
    // The value's SHAPE is pinned too, not just its marker: a digest
    // asks for 64 hex digits, so a truncated or error-laden line
    // keeps waiting rather than passing something merely non-blank.
    const m = await waitForScreen(new RegExp(`WOSH_${tail}(${valuePattern})`));
    if (wasOpen) {
      await page.click("#transfers-btn");
      await page.waitForSelector("#transfers-sheet .txbar", { timeout: 10_000 });
    }
    return m[1];
  };

  let identityInstalled = false;
  const connect = async () => {
    // NOT `goto` when the URL is already this one: navigating to an
    // identical URL (fragment included) is a SAME-DOCUMENT navigation
    // in Chromium, so the page keeps running and nothing reloads --
    // which silently turned leg 5's "next page life" into "the same
    // page life" and made its resume assertion vacuous.
    const target = `http://127.0.0.1:${PORT}/#${CONNSTRING}`;
    if (page.url() === target) await page.reload({ waitUntil: "load" });
    else await page.goto(target, { waitUntil: "load" });
    // Two legitimate outcomes, and which one happens is not this
    // gate's business: a FIRST load asks for the user and the host-key
    // verdict, while a later load of the same profile already has a
    // saved card (and a session to resume) and simply reconnects with
    // no dialog at all. Racing them keeps leg 5's reload from
    // depending on which.
    const connected = page
      .waitForFunction((u) => document.getElementById("status")?.textContent === `connected as ${u}`,
        USER, { timeout: 120_000 })
      .then(() => "connected");
    const asked = page
      .waitForSelector("#sheet[data-ask='connect'] input[placeholder='user']", { timeout: 20_000 })
      .then(() => "asked", () => "no-ask");
    const first = await Promise.race([connected, asked]);
    if (first === "asked") {
      if (!identityInstalled) {
        // The browser-minted WebCrypto key's authorized_keys line, put
        // where this run's sshd will look. Read from the LOADED page --
        // a fragment-only navigation would not have booted it.
        const line = (await page.evaluate(async () => {
          const { identity } = await import("./app.mjs");
          return await identity();
        })).trim();
        appendFileSync(AUTH_KEYS, line + "\n");
        identityInstalled = true;
      }
      await page.fill("#sheet input[placeholder='user']", USER);
      await page.click("#sheet button:text-is('connect')");
      await page.locator("#sheet .confirm code.fp").first().textContent({ timeout: 60_000 });
      await page.click("#sheet button:has-text('it matches')");
    }
    await connected;
  };

  await connect();
  console.log("[0] connected; the transfers ride this same live session");

  const openPanel = async () => {
    await page.waitForFunction(() => !document.getElementById("transfers-btn").hidden, null, { timeout: 20_000 });
    if (await page.evaluate(() => !!document.getElementById("transfers-sheet")?.open)) return;
    await page.click("#transfers-btn");
    await page.waitForSelector("#transfers-sheet .txbar", { timeout: 10_000 });
  };
  // Opening the panel always resets the breadcrumb to home (the real
  // button's own handler does), so descending is not a one-off: every
  // `ask` closes and reopens the sheet, and the gate has to walk back
  // in each time.
  const showGateDir = async () => {
    await openPanel();
    // `.crumb.here` tag-agnostically: the CURRENT directory renders as
    // a plain <span>, not a button, because it is not a navigation
    // target -- so this may only ever read it, never click it.
    const here = await page.$eval("#transfers-sheet .crumbs .crumb.here", (e) => e.textContent).catch(() => null);
    if (here === GATE_DIR_NAME) return;
    await page.waitForSelector(`#transfers-sheet .entry-row .namebtn:text-is('${GATE_DIR_NAME}')`, { timeout: 30_000 });
    await page.click(`#transfers-sheet .entry-row .namebtn:text-is('${GATE_DIR_NAME}')`);
    await page.waitForSelector(`#transfers-sheet .crumbs .crumb.here:text-is('${GATE_DIR_NAME}')`, { timeout: 20_000 });
  };

  // The transfers list lives in a dropdown now, closed by default and
  // behind a toggle that stays DISABLED until this page life has had a
  // transfer (or has loaded a resumable record). Idempotent, and
  // needed more than once: the panel resets `dropdownOpen` on every
  // open AND on every close, so each `ask` -- which steps out of the
  // modal to reach the terminal -- shuts it again.
  const openDropdown = async () => {
    await openPanel();
    await page.waitForSelector("#transfers-toggle:not([disabled])", { timeout: 30_000 });
    // Deliberately three-valued. `!el?.hidden` is TRUE for an element
    // that is missing entirely, which would read a renamed dropdown as
    // "already open" and skip straight past it -- the gate would then
    // pass having opened nothing. `null` falls through to the click,
    // whose own wait then fails loudly.
    const shown = await page.evaluate(() => {
      const d = document.querySelector("#transfers-sheet .tx-dropdown");
      return d ? !d.hidden : null;
    });
    if (shown === true) return;
    await page.click("#transfers-toggle");
    await page.waitForSelector("#transfers-sheet .tx-dropdown:not([hidden])", { timeout: 10_000 });
  };

  // Row names currently rendered in the LISTING pane (not the transfers
  // dropdown). textContent, not innerText: `.panes` is `.locked` while
  // the dropdown floats over it, and a hidden/clipped subtree reports
  // no innerText at all -- which would read as "the row is gone".
  const listedNames = () =>
    page.$$eval("#transfers-sheet .panes .entry-row .namebtn", (els) => els.map((e) => e.textContent));
  const crumbText = () =>
    page.$eval("#transfers-sheet .crumbs .crumb-list", (e) => e.textContent);

  // Light dismiss makes the dropdown's state everyone's business: a
  // pointerdown anywhere outside it is CONSUMED to close it, so any
  // leg that means to click the listing has to shut it first or watch
  // its click get swallowed. Closing via the toggle, which is
  // deliberately excluded from the outside-check.
  const closeDropdown = async () => {
    const shown = await page.evaluate(() => {
      const d = document.querySelector("#transfers-sheet .tx-dropdown");
      return d ? !d.hidden : null;
    });
    if (shown !== true) return;
    await page.click("#transfers-toggle");
    // `state: "attached"`, not the default "visible": waiting for a
    // [hidden] element to become VISIBLE is a contradiction that can
    // only ever time out.
    await page.waitForSelector("#transfers-sheet .tx-dropdown[hidden]", { state: "attached", timeout: 10_000 });
  };

  // --- leg 1: the listing is the target's real directory ------------------
  // Home first, for the one assertion that can only be made here: the
  // `..` row exists everywhere EXCEPT this panel's root. The panel's
  // root is home, not the filesystem root -- it tracks a crumb trail
  // rather than an absolute path, so there is nothing above home for
  // it to climb to.
  await openPanel();
  await page.waitForSelector(`#transfers-sheet .entry-row .namebtn:text-is('${GATE_DIR_NAME}')`, { timeout: 30_000 });
  if ((await listedNames()).includes("..")) fail("home shows a `..` row; the panel's root must not offer one");
  else console.log("PASS: leg1 no `..` row at the panel's root");

  await showGateDir();
  await page.waitForSelector("#transfers-sheet .entry-row .namebtn:text-is('greeting.txt')", { timeout: 20_000 });
  const greetingMeta = await page.$eval(
    "#transfers-sheet .entry-row:has(.namebtn:text-is('greeting.txt')) .meta",
    (e) => e.textContent,
  );
  if (!/\d/.test(greetingMeta ?? "")) fail(`greeting.txt has no size in the listing: ${greetingMeta}`);
  else console.log(`PASS: leg1 the panel listed the target's real directory (greeting.txt ${greetingMeta})`);

  // The transfers toggle is disabled, not hidden, until this page life
  // has had a transfer -- so a panel opened only to browse offers no
  // dropdown to open onto nothing. Cheap to check, and the sort of
  // thing that regresses silently into "always enabled".
  const toggleDisabledAtRest = await page.$eval("#transfers-toggle", (e) => e.disabled);
  if (!toggleDisabledAtRest) fail("#transfers-toggle is enabled before any transfer has started");
  else console.log("PASS: leg1 the transfers toggle starts disabled (nothing to drop down onto yet)");

  // --- leg 1b: `..` climbs, client-side ------------------------------------
  // The pop happens in the crumb trail, not on the wire: no literal
  // `..` is ever sent to the engine. So the check is that the CRUMB
  // came home, which is the state that would desync if a `..` were
  // shipped off to REALPATH instead.
  if (!(await listedNames()).includes("..")) fail("no `..` row inside the gate directory");
  await page.click("#transfers-sheet .panes .entry-row .namebtn:text-is('..')");
  await page.waitForSelector("#transfers-sheet .crumbs .crumb.here:text-is('~')", { timeout: 20_000 });
  await page.waitForSelector(`#transfers-sheet .entry-row .namebtn:text-is('${GATE_DIR_NAME}')`, { timeout: 30_000 });
  if ((await listedNames()).includes("..")) fail("`..` climbed to home but home still offers a `..` row");
  else console.log("PASS: leg1b the `..` row climbed back to the panel's root and vanished there");
  await showGateDir();

  // --- leg 1c: the refresh button re-reads the directory --------------------
  // The creation is SCHEDULED on the target and lands a few seconds
  // later, which is what makes this test real: `ask` steps out of the
  // modal to reach the terminal, and reopening the panel re-lists from
  // scratch, so a file that already existed by then would show up
  // without any refresh and the assertion would be vacuous. A delayed
  // creation leaves a genuinely stale listing to refresh -- and pins,
  // in passing, that the panel does NOT quietly poll the directory
  // behind the user's back.
  const REFRESH_PROBE = "refresh-probe.txt";
  await ask(
    `(sleep 6; printf 'refreshed\\n' > ~/${GATE_DIR_NAME}/${REFRESH_PROBE}) >/dev/null 2>&1 & echo scheduled`,
    "scheduled",
  );
  await showGateDir();
  if ((await listedNames()).includes(REFRESH_PROBE)) {
    fail(`${REFRESH_PROBE} already existed when the refresh leg started; the delayed creation raced it`);
  } else {
    // Wait for the file to really be there before asking the panel to
    // look again -- the gate's sshd is this user on localhost, so the
    // target's filesystem is readable from here, and waiting on it
    // beats sleeping and hoping.
    const probeOnDisk = join(GATE_DIR, REFRESH_PROBE);
    const deadline = Date.now() + 30_000;
    while (!existsSync(probeOnDisk) && Date.now() < deadline) await page.waitForTimeout(200);
    if (!existsSync(probeOnDisk)) fail(`the scheduled creation of ${REFRESH_PROBE} never happened on the target`);
    else {
      if ((await listedNames()).includes(REFRESH_PROBE)) {
        fail("the listing showed a file that appeared after it was read -- something is re-listing unasked");
      }
      await page.click("#transfers-sheet .crumbs #refresh-btn");
      await page.waitForSelector(`#transfers-sheet .panes .entry-row .namebtn:text-is('${REFRESH_PROBE}')`, { timeout: 20_000 });
      console.log("PASS: leg1c a stale listing stayed stale until #refresh-btn re-read it");
    }
  }

  // --- leg 2: upload, verified by the TARGET's own sha256sum --------------
  // Count refresh clicks from here on, so the auto-relist assertion
  // below can say the listing updated on its OWN and not because this
  // gate poked the button. A capture listener on the sheet, because
  // every render() replaces the button element itself.
  await page.evaluate(() => {
    window.__refreshClicks = 0;
    document.getElementById("transfers-sheet").addEventListener(
      "click",
      (e) => { if (e.target?.closest?.("#refresh-btn")) window.__refreshClicks++; },
      true,
    );
  });
  if ((await listedNames()).includes("payload.bin")) fail("payload.bin was already listed before the upload");

  // One upload affordance now, and it is inside the drop zone: "drop a
  // file here or [select a file] to upload".
  const [chooser] = await Promise.all([
    page.waitForEvent("filechooser"),
    page.click("#transfers-sheet .upload-drop #upload-picker-btn"),
  ]);
  await chooser.setFiles(uploadPath);
  // ...which enables the toggle. Open the dropdown and keep it open:
  // rows only poll at foreground cadence while it is showing.
  await openDropdown();
  console.log("PASS: leg2 starting a transfer enabled the toggle and opened the transfers dropdown");
  await page.waitForFunction(
    () => [...document.querySelectorAll("#transfers-sheet .tx-dropdown .transfer-row")]
      .some((r) => r.textContent.includes("done") || r.querySelector(".err-msg")),
    null,
    { timeout: 180_000 },
  );
  const uploadErr = await page.$eval(
    "#transfers-sheet .tx-dropdown .transfer-row",
    (r) => (r.classList.contains("err") ? r.querySelector(".err-msg")?.textContent : null),
  ).catch(() => null);
  if (uploadErr) fail(`upload failed in the page: ${uploadErr}`);
  else {
    // A finished upload into the directory on screen re-lists itself.
    // The click counter is what makes this a claim about the
    // MECHANISM rather than about whatever happened to be on screen:
    // nothing here asked for a refresh, and no navigation has
    // happened since the pre-upload check above.
    await page.waitForFunction(
      () => [...document.querySelectorAll("#transfers-sheet .panes .entry-row .namebtn")]
        .some((e) => e.textContent === "payload.bin"),
      null,
      { timeout: 30_000 },
    ).catch(() => {});
    const refreshClicks = await page.evaluate(() => window.__refreshClicks);
    if (!(await listedNames()).includes("payload.bin")) {
      fail("the completed upload did not appear in the listing on its own");
    } else if (refreshClicks !== 0) {
      fail(`the upload's row appeared, but ${refreshClicks} refresh click(s) happened -- the auto-relist is unproven`);
    } else {
      console.log("PASS: leg2 the completed upload re-listed the shown directory on its own (no refresh click)");
    }
    const remoteHash = await ask(
      `sha256sum ~/${GATE_DIR_NAME}/payload.bin | cut -d' ' -f1`,
      "[0-9a-f]{64}",
    );
    if (remoteHash !== UPLOAD_HASH) fail(`uploaded content mismatch: want ${UPLOAD_HASH} got ${remoteHash}`);
    else console.log("PASS: leg2 the target's own sha256sum matches the uploaded file");
  }

  // --- leg 3: download it back through OPFS staging -----------------------
  await showGateDir();
  await page.click("#transfers-sheet .entry-row .namebtn:text-is('payload.bin')");
  await page.waitForFunction(() => window.__capturedDownloads.length > 0, null, { timeout: 180_000 });
  const back = Buffer.from(await page.evaluate(() => Array.from(window.__capturedDownloads.at(-1))));
  if (sha256(back) !== UPLOAD_HASH) fail(`round-trip download mismatch: want ${UPLOAD_HASH} got ${sha256(back)}`);
  else console.log("PASS: leg3 round-trip download matches byte for byte");

  // --- leg 3b: the dropdown light-dismisses, and swallows the tap ----------
  // Its own leg rather than a rider on leg 4: leg 4 has to cancel a
  // transfer MID-flight, and spending that window opening and closing
  // a dropdown is how a timing-sensitive assertion turns into a flake.
  // Here nothing is racing.
  await showGateDir();
  await openDropdown();
  {
    // Tap the `..` row: the only row in this directory that would
    // NAVIGATE if the swallow failed, so "the crumbs did not move" is
    // a real claim and not a tautology. The dropdown is anchored under
    // the panel header and hangs over the top of the listing, so first
    // establish that this point actually belongs to the row -- a tap
    // that landed on the dropdown itself would prove nothing at all.
    const target = await page.evaluate(() => {
      const rows = [...document.querySelectorAll("#transfers-sheet .panes .entry-row .namebtn")];
      // The dropdown hangs over the TOP of the listing, so the `..`
      // row -- the one whose misfire would be loudest -- is usually
      // underneath it and unusable. Take the topmost row that is
      // genuinely reachable instead, preferring `..` when it is.
      const reachable = rows.filter((btn) => {
        const r = btn.getBoundingClientRect();
        const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return top === btn || btn.contains(top);
      });
      const btn = reachable.find((e) => e.textContent === "..") ?? reachable[0];
      if (!btn) return null;
      const r = btn.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2, name: btn.textContent };
    });
    if (!target) {
      fail("every listing row is covered by the dropdown; nothing to aim the light-dismiss tap at");
    } else {
      // Two ways this tap could leak through, one per row kind: a
      // directory descends (the crumbs move) and a file opens the
      // download confirm (a transfer row appears -- and this gate
      // auto-accepts every confirm, so a leak would really start one).
      // Watch both, so the assertion does not depend on which row
      // happened to be reachable.
      const crumbsBefore = await crumbText();
      const rowsBefore = await page.$$eval("#transfers-sheet .tx-dropdown .transfer-row", (r) => r.length);
      await page.mouse.move(target.x, target.y);
      await page.mouse.down();
      await page.mouse.up();
      await page.waitForSelector("#transfers-sheet .tx-dropdown[hidden]", { state: "attached", timeout: 10_000 })
        .catch(() => fail("a tap outside the dropdown did not close it"));
      // Give a leaked click time to become visible before denying it.
      await page.waitForTimeout(1000);
      const crumbsAfter = await crumbText();
      const rowsAfter = await page.$$eval("#transfers-sheet .tx-dropdown .transfer-row", (r) => r.length);
      if (crumbsAfter !== crumbsBefore) {
        fail(`the dismissing tap also navigated: crumbs went ${JSON.stringify(crumbsBefore)} -> ${JSON.stringify(crumbsAfter)}`);
      } else if (rowsAfter !== rowsBefore) {
        fail(`the dismissing tap also started a transfer (${rowsBefore} -> ${rowsAfter} rows)`);
      } else {
        console.log(`PASS: leg3b a tap outside closed the dropdown and was swallowed (${JSON.stringify(target.name)} under it never fired)`);
      }
    }
  }

  // --- leg 4: cancel mid-flight, keep the partial -------------------------
  await showGateDir();
  // Shut the dropdown FIRST: with it open, this click would be eaten
  // by light dismiss (closing the dropdown) instead of starting the
  // download -- exactly what leg 3b just proved it does.
  await closeDropdown();
  await page.click("#transfers-sheet .entry-row .namebtn:text-is('bigfile.bin')");
  // Dropdown AFTER the file click, not before: it is anchored under
  // the panel header and hangs over the listing, so opening it first
  // would put it between this gate and the row it means to click.
  // (`ask` in leg 2 shut it again -- stepping out of the modal to
  // reach the terminal resets it.)
  await openDropdown();
  await page.waitForSelector("#transfers-sheet .tx-dropdown .transfer-row .actions button:has-text('cancel')", { timeout: 30_000 });
  // Wait for STAGED BYTES rather than a clock: a sleep either cancels
  // before anything is staged (leaving leg5 nothing to resume) or
  // after the whole file has landed. The row reads "<done> / <total>",
  // so the test has to look at the left-hand side only -- matching any
  // digit anywhere finds the TOTAL and fires immediately, which is a
  // clock in disguise and the worse one.
  await page.waitForFunction(
    () => [...document.querySelectorAll("#transfers-sheet .tx-dropdown .transfer-row .bytes")]
      .some((b) => {
        const done = (b.textContent ?? "").split("/")[0];
        return /\d/.test(done) && !/^\s*0\s*B/.test(done);
      }),
    null,
    { timeout: 60_000 },
  );
  await page.click("#transfers-sheet .tx-dropdown .transfer-row .actions button:has-text('cancel')");
  // "cancelled", not "cancel": the row carries a `cancel` BUTTON the
  // whole time it is running, so the looser word would pass on a
  // cancel that never happened.
  await page.waitForFunction(
    () => [...document.querySelectorAll("#transfers-sheet .tx-dropdown .transfer-row")]
      .some((r) => /cancelled/i.test(r.textContent ?? "")),
    null,
    { timeout: 30_000 },
  );
  console.log("PASS: leg4 the cancelled download reported itself cancelled (its staged bytes are leg5's subject)");

  // --- leg 5: the next page life resumes it -------------------------------
  await connect(); // a reload plus a fresh session: the records are what survive
  await openPanel();
  // The toggle is enabled again on a fresh page life purely by the
  // resumable record loading -- there has been no transfer in THIS
  // page life yet -- and the dropdown starts closed, so it takes one
  // click to get at the resume affordance.
  await openDropdown();
  await page.waitForSelector("#transfers-sheet .tx-dropdown .transfer-row .actions button:has-text('resume')", { timeout: 30_000 });
  const staged = await page.$eval("#transfers-sheet .tx-dropdown .transfer-row .bytes", (e) => e.textContent);
  console.log(`  (staged bytes offered for resume: ${staged})`);
  const beforeResume = await page.evaluate(() => window.__capturedDownloads.length);
  await page.click("#transfers-sheet .tx-dropdown .transfer-row .actions button:has-text('resume')");
  await page.waitForFunction(
    (n) => window.__capturedDownloads.length > n,
    beforeResume,
    { timeout: 180_000 },
  );
  const resumed = Buffer.from(await page.evaluate(() => Array.from(window.__capturedDownloads.at(-1))));
  if (sha256(resumed) !== BIG_HASH) {
    fail(`resumed download mismatch: want ${BIG_HASH} got ${sha256(resumed)} (${resumed.length} bytes)`);
  } else {
    console.log("PASS: leg5 the resumed download completed and matches the file on the target");
  }

  if (pageErrors.length) fail(`page errors:\n  ${pageErrors.join("\n  ")}`);
} catch (e) {
  fail(String(e?.stack ?? e));
  // What the panel was showing when it went wrong: a transfer gate
  // that only says "timed out" costs its reader the whole diagnosis.
  try {
    const st = await page.evaluate(() => ({
      status: document.getElementById("status")?.textContent,
      sheetOpen: document.getElementById("sheet")?.open,
      sheetAsk: document.getElementById("sheet")?.dataset?.ask,
      sheet: document.getElementById("sheet")?.innerText,
    }));
    console.error(`--- page at failure ---\nstatus: ${st.status}\n#sheet open=${st.sheetOpen} ask=${st.sheetAsk}\n${st.sheet}\n---`);
    const sheet = await page.$eval("#transfers-sheet", (el) => el.innerText);
    const tx = await page.evaluate(() => {
      const t = document.getElementById("transfers-toggle");
      const d = document.querySelector("#transfers-sheet .tx-dropdown");
      // innerText is empty for a hidden subtree, so read textContent:
      // the rows stay queryable while the dropdown is visually closed.
      return { disabled: t?.disabled, open: d ? !d.hidden : null, rows: d?.textContent };
    });
    console.error(`--- transfers dropdown: toggle disabled=${tx.disabled} open=${tx.open} ---\n${tx.rows}\n---`);
    console.error(`--- #transfers-sheet at failure ---\n${sheet}\n---`);
  } catch { /* no page left to ask */ }
} finally {
  await browser.close();
  server.close();
  rmSync(GATE_DIR, { recursive: true, force: true });
  rmSync(tmpDir, { recursive: true, force: true });
}

if (failed) {
  console.error("browser-transfer: FAILED");
  process.exitCode = 1;
} else {
  console.log("\nBROWSER TRANSFER PASS: the real panel moved real bytes over a real SFTP session -- " +
    "listing, upload verified by the target itself, round-trip download, cancel-keeps-partial, reload-resume");
}
