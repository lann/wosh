// The file-transfer panel: a full-screen sheet over the terminal,
// reachable from the top bar's "files" button once a session is
// `ready`. Vanilla DOM, matching the site's other panels (index.html's
// #sheet/boot.mjs) -- no framework, no build-step beyond `just
// web-bundle`, which this module rides on only indirectly (it imports
// the ALREADY-bundled ./dist/polyengine.js for the transfer-io host
// pieces, the same way app.mjs loads the component itself).
//
// THE BYTES-VS-DISPLAY SPLIT (wit/terminal.wit dir-entry): every path
// this module sends back to the engine -- `list-dir`, `upload`,
// `download` -- is built from `entry.name` (raw bytes) or a File's
// name UTF-8-encoded, never from `entry.display`. `display` only ever
// reaches a text node. Current directory state is therefore kept as an
// array of Uint8Array SEGMENTS, not a string.
//
// PATH-JOINING (CONTRACT FRICTION): the WIT doc comment for `list-dir`
// says "pass the previous listing's entry bytes to descend" as if a
// bare entry name were a complete `path` argument. It cannot be, in
// general: `dir-entry.name` is documented as "the name" (a filename
// component), and nothing else remembers which directory the previous
// listing was OF. Read conservatively: this module accumulates
// segments client-side and joins them with `/` before every call
// (starting at `.`, per `list-dir`'s own doc comment on the first
// call), which is what "REALPATHs before reading, so relative input
// resolves against home" (wit/terminal.wit:702-711) implies is safe --
// realpath resolves a relative multi-segment path exactly like a
// single-segment one. Flagged here rather than guessed silently.
//
// RESUME-ON-RELOAD keying: one IndexedDB record per transfer, keyed by
// a random id minted when the transfer starts. A download record's
// `stagingId` names the OPFS file (transfer-io.ts); reopening a `Sink`
// over the SAME id resumes from its on-disk length, which the sink
// contract makes the resume anchor. An upload record keeps only
// `name`/`size`/`lastModified` from the `File` the user picked -- a
// `File` handle itself cannot survive a reload, so resuming an upload
// always asks the user to re-pick, and this module treats a re-pick
// whose (name, size, lastModified) all match as "the same file", never
// silently assuming a re-pick without checking.

/// <reference lib="dom" />

const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const c of children) node.append(c);
  return node;
};

// `result<_, string>` outcomes (transfer-progress.outcome) arrive in
// either of two shapes depending on where they came from: this
// module's own synthetic outcomes (a failed start-call) use the plain
// `{ok:...}`/`{err:...}` object; polyengine's real lift of a WIT
// `result` produces `{kind:"ok"}`/`{kind:"err", val}` instead -- the
// same `{tag}`-vs-`{kind}` variant-shape drift host-test/browser-e2e.mjs
// already documents for `status`. Read tolerantly rather than pick one
// and let the other silently stall (observed live: a finished transfer
// that never left the running row, because `"ok" in outcome` was false
// for the real shape).
const outcomeOk = (o) => !!o && ("ok" in o || o.kind === "ok");
const outcomeErrText = (o) => {
  if (!o) return null;
  if ("err" in o) return o.err;
  // polyengine spells the payload `value` (observed live: `val` here
  // rendered every failed transfer as permanently in-flight -- no error
  // text, no retry, staging never tidied). Keep `val` as a fallback for
  // the mock's shape.
  if (o.kind === "err") return o.value ?? o.val;
  return null;
};

const enc = new TextEncoder();
const decLossy = new TextDecoder("utf-8", { fatal: false });

/** Join byte-segments with `/`; `[]` means the starting `.`. */
function joinSegments(segments) {
  if (segments.length === 0) return enc.encode(".");
  const sep = 0x2f;
  const total = segments.reduce((a, s) => a + s.length, 0) + (segments.length - 1);
  const out = new Uint8Array(total);
  let o = 0;
  segments.forEach((s, i) => {
    out.set(s, o);
    o += s.length;
    if (i < segments.length - 1) out[o++] = sep;
  });
  return out;
}

const fmtBytes = (n) => {
  if (n == null) return "?";
  n = Number(n);
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let u = -1;
  do {
    n /= 1024;
    u++;
  } while (n >= 1024 && u < units.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[u]}`;
};

const fmtMtime = (secs) => {
  if (secs == null) return "";
  try {
    return new Date(Number(secs) * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch {
    return "";
  }
};

// --- IndexedDB: per-transfer resume records ---------------------------------

const DB_NAME = "wosh-transfers";
const STORE = "transfers";

const req = (r) =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

function openDb() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE, { keyPath: "id" });
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
    open.onblocked = () => reject(new Error("IndexedDB open blocked"));
  });
}

async function idbPut(record) {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(record);
    await new Promise((res, rej) => {
      tx.oncomplete = res;
      tx.onabort = tx.onerror = () => rej(tx.error);
    });
  } finally {
    db.close();
  }
}

async function idbDelete(id) {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(id);
    await new Promise((res, rej) => {
      tx.oncomplete = res;
      tx.onabort = tx.onerror = () => rej(tx.error);
    });
  } finally {
    db.close();
  }
}

async function idbAll() {
  const db = await openDb();
  try {
    const out = await req(db.transaction(STORE).objectStore(STORE).getAll());
    return out ?? [];
  } catch {
    return [];
  } finally {
    db.close();
  }
}

// --- panel ------------------------------------------------------------------

/**
 * Mount the panel: the top-bar button, the sheet, and the polling
 * machinery. `getSession` returns the live wrapped session
 * (app.mjs#activeSession) or `null`.
 */
export function initTransfers({ getSession } = {}) {
  const button = document.getElementById("transfers-btn");
  const sheet = document.getElementById("transfers-sheet");
  if (!button || !sheet) throw new Error("transfer-ui: #transfers-btn/#transfers-sheet missing");

  let session = getSession ? getSession() : null;

  // The worker path resolution note in transfer-io.ts: this module is
  // served unbundled from site/, so its own import.meta.url is the
  // right base for the worker's real file.
  let workerInjected = false;
  let polyengineMod; // cached dynamic import of the bundle
  async function poly() {
    polyengineMod ??= await import(new URL("./dist/polyengine.js", import.meta.url));
    if (!workerInjected) {
      polyengineMod.useTransferWorker(
        new Worker(new URL("./transfer-worker.mjs", import.meta.url), { type: "module" }),
      );
      workerInjected = true;
    }
    return polyengineMod;
  }

  // segments of the remote directory currently shown; [] == "."
  let segments = [];
  let labels = []; // display strings, parallel to segments, for the breadcrumb
  let listing = []; // last list-dir result

  // id -> { record, handle (the `transfer` resource), kind: 'active'|'resumable' }
  const transfers = new Map();
  let pollTimer = null;
  let visible = false; // "the dropdown is open" -- see toggleDropdown
  let dropdownOpen = false;
  let everHadTransfer = false; // sticky once true: the transfers button
  // stays enabled for the rest of the page's life once ANY transfer
  // has started, per the dispatch (disabled, not hidden, until then).

  // ---- rendering --------------------------------------------------------

  function toggleDropdown() {
    if (!everHadTransfer) return; // disabled button shouldn't fire, but belt-and-braces
    dropdownOpen = !dropdownOpen;
    // Polling cadence follows the dropdown, not the panel: browsing
    // files with the dropdown closed is background activity for any
    // transfer still running underneath.
    visible = dropdownOpen;
    if (dropdownOpen) startPolling();
    render();
  }

  function render() {
    const bar = el(
      "div",
      { className: "txbar" },
      el("button", { textContent: "\u00d7", title: "close", onclick: () => sheet.close() }),
      el("h1", { textContent: "Files" }),
      el("button", {
        id: "transfers-toggle",
        className: "tx-toggle",
        textContent: "transfers",
        disabled: !everHadTransfer,
        ariaExpanded: String(dropdownOpen), // el() assigns properties, not attributes; ariaExpanded is the reflected IDL property (ARIAMixin), "aria-expanded" as a key would silently no-op
        onclick: toggleDropdown,
      }),
    );

    // Each crumb is a real navigation target except the CURRENT
    // directory, which renders as a plain (non-button) span -- "keep
    // the current-directory crumb visually distinct as non-interactive"
    // means it must not look, or act, clickable.
    const crumbs = el("div", { className: "crumbs" });
    const atRoot = segments.length === 0;
    crumbs.append(
      atRoot
        ? el("span", { className: "crumb here", textContent: "~" })
        : el("button", { className: "crumb", textContent: "~", onclick: () => navigateTo(0) }),
    );
    labels.forEach((label, i) => {
      crumbs.append(document.createTextNode(" / "));
      const isHere = i === labels.length - 1;
      crumbs.append(
        isHere
          ? el("span", { className: "crumb here", textContent: label })
          : el("button", { className: "crumb", textContent: label, onclick: () => navigateTo(i + 1) }),
      );
    });

    const head = el("div", { className: "tx-head" }, bar, crumbs);

    // The transfers dropdown: anchored to `.tx-head` (position:
    // relative), so it drops directly below the header+crumbs block
    // regardless of their exact height -- no --bar-h-style JS
    // measurement needed. `hidden` rather than omitted from the DOM,
    // so its rows stay ordinarily queryable (site convention: [hidden]
    // always means hidden, see index.html's #sheet comment) even
    // while visually closed.
    const dropdown = el("div", { className: "tx-dropdown", hidden: !dropdownOpen });
    const resumable = [...transfers.values()].filter((t) => t.kind === "resumable");
    if (resumable.length) {
      dropdown.append(el("div", { className: "section-label", textContent: "interrupted downloads" }));
      for (const t of resumable) dropdown.append(renderResumableRow(t));
    }
    const active = [...transfers.values()].filter((t) => t.kind === "active");
    if (active.length) {
      dropdown.append(el("div", { className: "section-label", textContent: "transfers" }));
      for (const t of active) dropdown.append(renderTransferRow(t));
    }
    if (!resumable.length && !active.length) {
      dropdown.append(el("div", { className: "empty", textContent: "no transfers yet" }));
    }
    head.append(dropdown);

    const panes = el("div", { className: "panes" });

    // The drop zone is the ONE upload affordance now (dispatch #1): a
    // single sentence, picker inline, rather than a drop target plus a
    // separate header button offering the same action twice.
    const drop = el("div", { className: "upload-drop" });
    drop.append(document.createTextNode("drop a file here or "));
    drop.append(
      el("button", {
        id: "upload-picker-btn",
        className: "link-btn",
        type: "button",
        textContent: "select a file",
        onclick: () => pickUpload(),
      }),
    );
    drop.append(document.createTextNode(" to upload"));
    drop.addEventListener("dragover", (e) => {
      e.preventDefault();
      drop.classList.add("over");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("over");
      for (const f of e.dataTransfer?.files ?? []) startUpload(f);
    });
    panes.append(drop);

    if (!session) {
      panes.append(el("div", { className: "empty", textContent: "no active session" }));
    } else if (listing.length === 0) {
      panes.append(el("div", { className: "empty", textContent: "empty directory" }));
    } else {
      for (const entry of listing) panes.append(renderEntryRow(entry));
    }

    sheet.replaceChildren(head, panes);
  }

  function renderEntryRow(entry) {
    const icon = entry.isDir ? "\u{1F4C1}" : "\u{1F4C4}";
    const meta = entry.isDir
      ? ""
      : `${fmtBytes(entry.size)} ${fmtMtime(entry.mtime)}`.trim();
    const row = el(
      "div",
      { className: "entry-row" },
      el("span", { className: "icon", textContent: icon }),
      el("button", {
        className: "namebtn",
        textContent: entry.display,
        onclick: () => (entry.isDir ? descend(entry) : confirmDownload(entry)),
      }),
      el("span", { className: "meta", textContent: meta }),
    );
    return row;
  }

  function renderTransferRow(t) {
    const p = t.lastProgress ?? { done: 0n, total: null, outcome: null };
    const done = Number(p.done ?? 0n);
    const total = p.total != null ? Number(p.total) : null;
    const pct = total ? Math.min(100, Math.round((done / total) * 100)) : t.everSeenBytes ? 50 : 0;
    const err = outcomeErrText(p.outcome);
    const finishedOk = outcomeOk(p.outcome);

    const row = el("div", { className: `transfer-row${err ? " err" : ""}` });
    const label = `${t.record.direction === "upload" ? "\u2191" : "\u2193"} ${t.record.label}`;
    row.append(
      el(
        "div",
        { className: "t" },
        el("span", { className: "name", textContent: label }),
        el("span", { className: "bytes", textContent: `${fmtBytes(done)}${total ? ` / ${fmtBytes(total)}` : ""}` }),
      ),
      el("div", { className: "bar" }, el("span", { className: "fill", style: `width:${pct}%` })),
    );
    if (err) {
      row.append(el("div", { className: "err-msg", textContent: err }));
      const actions = el("div", { className: "actions" });
      actions.append(
        el("button", { textContent: "retry", onclick: () => retryTransfer(t, false) }),
        el("button", { textContent: "start over", onclick: () => retryTransfer(t, true) }),
      );
      row.append(actions);
    } else if (!finishedOk) {
      const actions = el("div", { className: "actions" });
      actions.append(el("button", { textContent: "cancel", onclick: () => cancelTransfer(t) }));
      row.append(actions);
    } else {
      row.append(el("div", { className: "err-msg", style: "color:var(--ok)", textContent: "done" }));
    }
    return row;
  }

  function renderResumableRow(t) {
    const row = el("div", { className: "transfer-row" });
    row.append(
      el(
        "div",
        { className: "t" },
        el("span", { className: "name", textContent: `\u2193 ${t.record.label}` }),
        el("span", { className: "bytes", textContent: fmtBytes(t.record.stagedBytes ?? 0) }),
      ),
    );
    const actions = el("div", { className: "actions" });
    actions.append(
      el("button", { textContent: "resume", onclick: () => resumeDownload(t), disabled: !session }),
      el("button", { textContent: "discard", onclick: () => discardResumable(t) }),
    );
    row.append(actions);
    return row;
  }

  // ---- navigation ---------------------------------------------------------

  async function refreshListing() {
    if (!session) {
      listing = [];
      render();
      return;
    }
    try {
      const path = joinSegments(segments);
      listing = await session.listDir(path);
    } catch (e) {
      listing = [];
      console.warn("wosh: list-dir failed:", e);
    }
    render();
  }

  function descend(entry) {
    segments = [...segments, entry.name];
    labels = [...labels, entry.display];
    refreshListing();
  }

  function navigateTo(depth) {
    segments = segments.slice(0, depth);
    labels = labels.slice(0, depth);
    refreshListing();
  }

  // ---- uploads --------------------------------------------------------------

  function pickUpload(opts = {}) {
    const input = el("input", { type: "file" });
    input.addEventListener("change", () => {
      for (const f of input.files ?? []) startUpload(f, opts);
    });
    input.click();
  }

  async function startUpload(file, { overwrite = false, expectMeta = null } = {}) {
    if (!session) return;
    // A re-pick (resume/retry) claims to be the SAME file continuing;
    // check what the File API can tell us (name/size/lastModified)
    // instead of silently trusting it. This is a fast, obviously-wrong
    // catch, not the real guard -- the engine's own tail verify is
    // what actually detects a changed file, but only after re-reading
    // the overlap window, so a byte-for-byte-wrong pick still costs a
    // round trip without this.
    if (expectMeta) {
      const same = file.name === expectMeta.name &&
        file.size === expectMeta.size &&
        file.lastModified === expectMeta.lastModified;
      if (!same) {
        const proceed = globalThis.confirm(
          `"${file.name}" doesn't look like the same file as "${expectMeta.name}" ` +
            `(size/modified time differ). Continue anyway?`,
        );
        if (!proceed) return;
      }
    }
    const { TransferSource } = await poly();
    const id = crypto.randomUUID();
    const remotePath = joinSegments([...segments, enc.encode(file.name)]);
    const record = {
      id,
      direction: "upload",
      label: file.name,
      remotePathSegments: [...segments, [...enc.encode(file.name)]],
      fileMeta: { name: file.name, size: file.size, lastModified: file.lastModified },
      overwrite,
    };
    const entry = { record, kind: "active", lastProgress: null, everSeenBytes: false };
    transfers.set(id, entry);
    everHadTransfer = true;
    render();
    try {
      const source = new TransferSource(file);
      const handle = await session.upload(source, remotePath, overwrite);
      entry.handle = handle;
      startPolling();
    } catch (e) {
      entry.lastProgress = { done: 0n, total: null, outcome: { err: String(e?.message ?? e) } };
      render();
    }
  }

  // ---- downloads ------------------------------------------------------------

  async function confirmDownload(entry) {
    const remotePath = joinSegments([...segments, entry.name]);
    const ok = globalThis.confirm(`Download "${entry.display}"${entry.size != null ? ` (${fmtBytes(entry.size)})` : ""}?`);
    if (!ok) return;
    await beginDownload({
      label: entry.display,
      remotePath,
      remotePathSegments: [...segments, [...entry.name]],
      total: entry.size != null ? Number(entry.size) : null,
    });
  }

  async function beginDownload({ label, remotePath, remotePathSegments, total, stagingId, overwrite }) {
    if (!session) return;
    const { TransferSink, newStagingId, removeStaged } = await poly();
    const id = crypto.randomUUID();
    const sid = stagingId ?? newStagingId();
    // `download`'s `overwrite` requires an EMPTY sink and refuses
    // otherwise -- a sink has no truncate by design, so discarding
    // staged bytes and handing over a fresh one is documented as the
    // HOST's move, not the engine's (wit/terminal.wit's `download`).
    // Reusing the same staging id (so a later resume still has a
    // stable anchor) means removing its old bytes first, here, before
    // the sink is opened.
    if (overwrite) await removeStaged(sid).catch(() => {});
    const record = {
      id,
      direction: "download",
      label,
      remotePathSegments,
      stagingId: sid,
      total,
      overwrite: !!overwrite,
    };
    await idbPut(record);
    const entry = { record, kind: "active", lastProgress: null, everSeenBytes: false };
    transfers.set(id, entry);
    everHadTransfer = true;
    render();
    try {
      const sink = new TransferSink(sid, true);
      const handle = await session.download(remotePath, sink, !!overwrite);
      entry.handle = handle;
      startPolling();
    } catch (e) {
      entry.lastProgress = { done: 0n, total: null, outcome: { err: String(e?.message ?? e) } };
      render();
    }
  }

  async function resumeDownload(t) {
    if (!session) return;
    const path = joinSegments(t.record.remotePathSegments.map((s) => new Uint8Array(s)));
    transfers.delete(t.record.id);
    await beginDownload({
      label: t.record.label,
      remotePath: path,
      remotePathSegments: t.record.remotePathSegments,
      total: t.record.total,
      stagingId: t.record.stagingId,
      overwrite: false,
    });
  }

  async function discardResumable(t) {
    transfers.delete(t.record.id);
    await idbDelete(t.record.id);
    const { removeStaged } = await poly();
    await removeStaged(t.record.stagingId).catch(() => {});
    render();
  }

  async function retryTransfer(t, overwrite) {
    transfers.delete(t.record.id);
    if (t.record.direction === "download") {
      const path = joinSegments(t.record.remotePathSegments.map((s) => new Uint8Array(s)));
      await beginDownload({
        label: t.record.label,
        remotePath: path,
        remotePathSegments: t.record.remotePathSegments,
        total: t.record.total,
        stagingId: t.record.stagingId,
        overwrite,
      });
    } else {
      // Uploads cannot resume without the File back in hand; retry
      // (and "start over") are therefore always a re-pick -- but the
      // re-pick must still carry the overwrite flag the button asked
      // for, or "start over" can never actually start over (the
      // engine's tail-mismatch refusal tells the user to retry with
      // overwrite; this IS that retry).
      const expectMeta = t.record.fileMeta;
      render();
      globalThis.alert(`Re-pick "${t.record.label}" to ${overwrite ? "start it over" : "retry"} the upload.`);
      pickUpload({ overwrite, expectMeta });
    }
  }

  async function cancelTransfer(t) {
    try {
      await t.handle?.cancel();
    } catch (e) {
      console.warn("wosh: cancel failed:", e);
    }
  }

  // ---- polling ----------------------------------------------------------

  function startPolling() {
    if (pollTimer) return;
    pollTimer = true; // synchronous guard: `tick`'s first run is async
    // and does not reach the real timer handle until its end, so a
    // second startPolling() call during that window must still see
    // "already running" rather than racing a duplicate loop -- which
    // is what let finishTransfer's OPFS cleanup double-fire below.
    const tick = async () => {
      let anyActive = false;
      for (const t of transfers.values()) {
        if (t.kind !== "active" || !t.handle) continue;
        let p;
        try {
          p = await t.handle.progress();
        } catch (e) {
          console.warn("wosh: transfer progress failed:", e);
          continue;
        }
        // `done` can dip across an interruption's resume (wit/terminal.wit
        // transfer-progress) -- never animate backwards, just re-anchor
        // on whatever the engine reports now.
        t.lastProgress = p;
        if (Number(p.done ?? 0n) > 0) t.everSeenBytes = true;
        if (p.outcome) {
          // `outcome` is NOT cleared by observation (wit/terminal.wit
          // transfer-progress), so every later poll of a finished
          // transfer sees it again -- `settled` makes the one-time
          // cleanup below (OPFS handoff, IDB bookkeeping) actually
          // one-time.
          if (!t.settled) {
            t.settled = true;
            await finishTransfer(t, p.outcome);
          }
        } else {
          anyActive = true;
        }
      }
      render();
      // Stop rather than reschedule once there is nothing left to
      // watch AND nobody is looking: an active transfer with the
      // panel closed still needs the slow background cadence (it
      // keeps moving unattended), but with both false this loop was
      // rescheduling itself forever, at 2s, for the rest of the page's
      // life. `startPolling()` is idempotent and gets called again by
      // the button's open handler and by every new upload/download.
      if (!anyActive && !visible) {
        pollTimer = null;
        return;
      }
      pollTimer = setTimeout(tick, visible ? 250 : 2000);
    };
    tick();
  }

  async function finishTransfer(t, outcome) {
    if (outcomeOk(outcome)) {
      if (t.record.direction === "download") {
        try {
          const { closeStaged, stagedBlob, removeStaged } = await poly();
          await closeStaged(t.record.stagingId);
          const blob = await stagedBlob(t.record.stagingId);
          const url = URL.createObjectURL(blob);
          const a = el("a", { href: url, download: t.record.label });
          document.body.append(a);
          a.click();
          a.remove();
          // The browser's own download manager reads the blob
          // asynchronously and unobservably from here -- there is no
          // "download started" signal to await. Removing the staged
          // file right after `click()` races that read (observed:
          // Chromium's OPFS getFile() snapshot throws NotFoundError
          // out from under an in-flight read once the directory entry
          // is gone). So the cleanup rides the SAME delay as
          // `revokeObjectURL`: comfortably longer than any real
          // download needs to start reading, on the assumption that a
          // held staged file a few seconds too long is a much cheaper
          // mistake than a corrupted handoff.
          setTimeout(async () => {
            URL.revokeObjectURL(url);
            await removeStaged(t.record.stagingId).catch(() => {});
            await idbDelete(t.record.id).catch(() => {});
          }, 30000);
        } catch (e) {
          console.warn("wosh: download handoff failed (staged file kept):", e);
          // Keep the staged file and the IDB record: the handoff
          // failed, not the transfer, and the next reload's resume
          // affordance still has a durable file to hand off from.
        }
      }
    }
    // On error: the record (for a download) stays in IDB so a reload
    // still offers resume; retry/start-over above re-derives it.
  }

  // ---- reload-resume ------------------------------------------------------

  async function loadResumable() {
    const records = await idbAll();
    for (const record of records) {
      if (record.direction !== "download") continue;
      if (transfers.has(record.id)) continue;
      let stagedBytes = 0;
      try {
        const { stagedBlob } = await poly();
        const blob = await stagedBlob(record.stagingId);
        stagedBytes = blob.size;
      } catch {
        // staged file already gone -- nothing to resume from; drop the record
        await idbDelete(record.id);
        continue;
      }
      // A record can outlive a SUCCESSFUL download: the completion
      // cleanup is deliberately delayed (see finishTransfer) so a
      // real download has time to read the blob before the staging
      // file disappears out from under it. If the staged length
      // already meets the known total, this is that window (or a
      // crash inside it), not a genuine partial -- self-heal by
      // removing it now rather than offering a pointless "resume".
      if (record.total != null && stagedBytes >= record.total) {
        const { removeStaged } = await poly();
        await removeStaged(record.stagingId).catch(() => {});
        await idbDelete(record.id);
        continue;
      }
      transfers.set(record.id, { record: { ...record, stagedBytes }, kind: "resumable" });
      // An interrupted download survived a reload -- "the first
      // transfer of the page's life" reads narrowly as THIS page's
      // life, but a resumable record that a human needs to see (and
      // that only the dropdown now shows) left disabled behind a
      // greyed-out button would be a worse default than enabling it.
      everHadTransfer = true;
    }
  }

  // ---- wiring -------------------------------------------------------------

  button.addEventListener("click", async () => {
    session = getSession ? getSession() : null;
    segments = [];
    labels = [];
    dropdownOpen = false; // reopen the panel to a clean, closed dropdown
    // `visible` now follows the DROPDOWN, not the panel (dispatch #4):
    // browsing files with the dropdown closed is background polling
    // for whatever transfer is still running underneath. Starting the
    // loop here is still worthwhile even at background cadence, so a
    // resumable record's staged-bytes readout is current if the user
    // opens the dropdown right away.
    startPolling();
    await loadResumable();
    await refreshListing();
    sheet.showModal();
  });
  sheet.addEventListener("close", () => {
    visible = false;
    dropdownOpen = false;
  });

  // The button's visibility tracks whether there is a `ready` session
  // to browse -- polled rather than pushed from app.mjs, so this
  // module stays a leaf the page wires in without threading a session
  // lifecycle callback through app.mjs's own connect/detach paths.
  setInterval(async () => {
    const s = getSession ? getSession() : null;
    if (!s) {
      button.hidden = true;
      return;
    }
    try {
      const st = await s.status();
      button.hidden = st?.kind !== "ready";
    } catch {
      button.hidden = true;
    }
  }, 1000);

  return {};
}
