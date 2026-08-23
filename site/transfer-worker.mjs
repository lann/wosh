// Dedicated worker owning OPFS FileSystemSyncAccessHandles for staged
// download files. See transfer-io.ts's file comment for why sync access
// handles rather than `createWritable`: only a sync handle's `flush()`
// gives us a mid-transfer durability checkpoint, which the sink
// contract's `committed()` (wit/terminal.wit transfer-io.sink) needs.
// Sync access handles are OPFS-only *and* worker-only across engines
// (Safari included), hence this file.
//
// Protocol: `{ reqId, op, id, ... }` in, `{ reqId, ok, result|error }`
// out. One handle per staging id, opened once and held until `close`.

let rootDirPromise;
async function transfersDir() {
  rootDirPromise ??= (async () => {
    const root = await navigator.storage.getDirectory();
    return await root.getDirectoryHandle("transfers", { create: true });
  })();
  return rootDirPromise;
}

// id -> { handle: FileSystemSyncAccessHandle, offset: number (written,
// maybe not yet flushed), flushed: number (durable -- the resume anchor) }
const open = new Map();

async function doOpen(id, create) {
  if (open.has(id)) return open.get(id).flushed;
  const dir = await transfersDir();
  const fh = await dir.getFileHandle(id, { create: !!create });
  const handle = await fh.createSyncAccessHandle();
  const size = handle.getSize();
  open.set(id, { handle, offset: size, flushed: size });
  return size;
}

function doWrite(id, bytes) {
  const st = open.get(id);
  if (!st) throw new Error(`transfer sink ${id}: not open`);
  st.handle.write(bytes, { at: st.offset });
  st.offset += bytes.byteLength;
}

function doFlush(id) {
  const st = open.get(id);
  if (!st) throw new Error(`transfer sink ${id}: not open`);
  st.handle.flush();
  st.flushed = st.offset;
  return st.flushed;
}

function doCommitted(id) {
  const st = open.get(id);
  if (!st) throw new Error(`transfer sink ${id}: not open`);
  return st.flushed;
}

function doClose(id) {
  const st = open.get(id);
  if (!st) return;
  st.handle.close();
  open.delete(id);
}

async function doRemove(id) {
  doClose(id);
  const dir = await transfersDir();
  await dir.removeEntry(id).catch(() => {});
}

self.onmessage = async (ev) => {
  const { reqId, op, id } = ev.data;
  try {
    let result;
    switch (op) {
      case "open":
        result = await doOpen(id, ev.data.create);
        break;
      case "write":
        doWrite(id, ev.data.bytes);
        break;
      case "flush":
        result = doFlush(id);
        break;
      case "committed":
        result = doCommitted(id);
        break;
      case "close":
        doClose(id);
        break;
      case "remove":
        await doRemove(id);
        break;
      default:
        throw new Error(`transfer worker: unknown op ${op}`);
    }
    self.postMessage({ reqId, ok: true, result });
  } catch (e) {
    self.postMessage({ reqId, ok: false, error: String(e?.message ?? e) });
  }
};
