// Scrollback persistence: the other half of session continuity.
//
// dtach and abduco keep no copy of what was on screen -- a reattach
// starts blank until the program running inside redraws, and a plain
// shell has nothing to redraw at all until the next prompt. tmux and
// screen keep only the VISIBLE screen, not the scrollback above it.
// None of them can hand the page back what it had. So the page keeps
// its own copy: an xterm.js serialize() dump (buffer contents, colors,
// cursor), saved periodically while a session with a persist key runs,
// and written back to the terminal before the session's first live
// byte arrives on the next load or reattach (see app.mjs's
// restoreScrollback).
//
// What this stores is plainly the terminal's CONTENT -- whatever was
// on screen, worth saying without euphemism: if the last session
// `cat`ed a secret, that secret rides along in the dump like any other
// character cell. The privacy posture is the same boundary the host-key
// pins and the SSH identity already stand behind -- IndexedDB is
// origin-scoped, nothing here is sent anywhere, and it never rides in
// the connection string or any request. The session fold's "keep
// scrollback on this device" toggle is the honest opt-out: unticking
// it calls wipe() and stops future saves.
//
// Keyed by `${endpointId} ${user}` (boot.mjs), not by command: the
// same account on the same target is one scrollback regardless of
// what is run there. Capped to the 8 most recently touched keys so an
// old, abandoned host doesn't sit in IndexedDB forever growing the
// store for nothing anyone will read again.
//
// IndexedDB unavailable (private mode, a locked-down profile) degrades
// to no-ops with one console.warn -- never a thrown error to the
// caller: a missing scrollback is a worse first paint, not a reason to
// break connecting.

const DB_NAME = "wosh-scrollback";
const STORE = "buffers";
const CAP = 8;

const req = (r) =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

function openDb() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error("no IndexedDB in this context"));
      return;
    }
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
    open.onblocked = () => reject(new Error("IndexedDB open blocked"));
  });
}

let warned = false;
const degrade = (e) => {
  if (!warned) {
    warned = true; // one warning is plenty; every miss after this is expected
    console.warn("wosh: IndexedDB unavailable; scrollback will not survive a reload", e);
  }
};

/** `{ buf, at }` for `key`, or `null` when absent or storage is unavailable. */
export async function get(key) {
  let db;
  try {
    db = await openDb();
  } catch (e) {
    degrade(e);
    return null;
  }
  try {
    const v = await req(db.transaction(STORE).objectStore(STORE).get(key));
    return v && typeof v.buf === "string" ? v : null;
  } catch (e) {
    degrade(e);
    return null;
  } finally {
    db.close();
  }
}

/**
 * Save `buf` under `key`, stamped with the current time, then prune
 * down to the CAP most recently touched keys. Never throws: a failed
 * save just means this dump did not land, same as a dropped frame.
 */
export async function put(key, buf) {
  let db;
  try {
    db = await openDb();
  } catch (e) {
    degrade(e);
    return;
  }
  try {
    const at = Date.now();
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    store.put({ buf, at }, key);
    await new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
    await prune(db);
  } catch (e) {
    degrade(e);
  } finally {
    db.close();
  }
}

/** Keep only the CAP most recently touched keys; drop the rest. */
async function prune(db) {
  const entries = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE);
    const store = tx.objectStore(STORE);
    const out = [];
    const cursorReq = store.openCursor();
    cursorReq.onsuccess = () => {
      const cursor = cursorReq.result;
      if (cursor) {
        out.push({ key: cursor.primaryKey, at: cursor.value?.at ?? 0 });
        cursor.continue();
      } else {
        resolve(out);
      }
    };
    cursorReq.onerror = () => reject(cursorReq.error);
  });
  if (entries.length <= CAP) return;
  entries.sort((a, b) => b.at - a.at);
  const stale = entries.slice(CAP);
  const tx = db.transaction(STORE, "readwrite");
  const store = tx.objectStore(STORE);
  for (const { key } of stale) store.delete(key);
  await new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(tx.error);
  });
}

/** Delete everything -- the toggle-off path. */
export async function wipe() {
  let db;
  try {
    db = await openDb();
  } catch (e) {
    degrade(e);
    return;
  }
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    await new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    degrade(e);
  } finally {
    db.close();
  }
}
