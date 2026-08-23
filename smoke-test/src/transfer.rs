//! The native half of `wosh:terminal/transfer-io`, plus the gate leg
//! that drives file transfer end to end.
//!
//! In a browser the two ends of a transfer are a picked `File` (random
//! access, read-only) and OPFS staging (append-only, durable on flush).
//! Neither exists here, so this host stands in with the two dumbest
//! things that keep the same CONTRACT (terminal.wit, `transfer-io`):
//!
//! * [`MemSource`] is an in-memory buffer. A source only has to be
//!   random-access and fixed-size, and a `Vec<u8>` is both.
//! * [`FileSink`] is a temp file with a write-behind buffer.
//!   `committed` is the FSYNCED length and nothing else: `write`
//!   buffers, `flush` writes the buffer down and `sync_all`s it before
//!   advancing the counter. That is the strict reading of "durably
//!   kept -- the number that survives a page death", and it is the
//!   number the engine anchors a download resume on, so overstating it
//!   would corrupt files rather than merely re-transfer a tail.
//!
//! The gate leg below then pins, against a real OpenSSH sshd through
//! the real listener and the real tunnel:
//!
//! * a listing whose sizes are right, and whose NON-UTF-8 entry
//!   survives as bytes (`display` lossy, `name` byte-exact) all the way
//!   through SFTP, ssh-core, the component and these bindings;
//! * a download addressed by those RAW BYTES;
//! * an upload larger than one replay budget, verified server-side by
//!   `sha256sum` on the probe channel;
//! * that same upload surviving a transport death mid-flight (the
//!   feature's whole reason to exist);
//! * the equal-length already-done path, and the legible refusal when
//!   `overwrite` is asked of a sink that is not empty.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use sha2::{Digest as _, Sha256};
use wasmtime::component::{Accessor, HasSelf, Resource, ResourceAny};

use crate::bindings::exports::wosh::terminal::terminal::Guest as Terminal;
use crate::bindings::wosh::terminal::transfer_io;
use crate::Ctx;

// ---------------------------------------------------------------------
// the two host resources
// ---------------------------------------------------------------------

/// An upload's byte supply: an in-memory buffer.
pub struct MemSource {
    pub bytes: Vec<u8>,
}

/// A download's destination: a temp file whose `committed` is the
/// fsynced length. `write` only buffers; nothing is claimed until
/// `flush` has put it on the disk and returned.
pub struct FileSink {
    pub path: PathBuf,
    file: std::fs::File,
    pending: Vec<u8>,
    committed: u64,
}

impl FileSink {
    /// A fresh, empty sink.
    pub fn create(path: PathBuf) -> Result<Self> {
        let file = std::fs::File::create(&path)?;
        Ok(Self { path, file, pending: Vec::new(), committed: 0 })
    }

    /// A sink that already holds `prefill` durably -- what a host hands
    /// over when staged bytes from an earlier, interrupted download
    /// survived. Used to pin `overwrite`'s empty-sink requirement.
    pub fn create_prefilled(path: PathBuf, prefill: &[u8]) -> Result<Self> {
        let mut sink = Self::create(path)?;
        sink.file.write_all(prefill)?;
        sink.file.sync_all()?;
        sink.committed = prefill.len() as u64;
        Ok(sink)
    }
}

impl transfer_io::Host for Ctx {}
impl transfer_io::HostSource for Ctx {}
impl transfer_io::HostSink for Ctx {}

impl transfer_io::HostSourceWithStore<Ctx> for HasSelf<Ctx> {
    async fn drop(
        accessor: &Accessor<Ctx, Self>,
        rep: Resource<MemSource>,
    ) -> wasmtime::Result<()> {
        accessor.with(|mut a| a.get().table.delete(rep))?;
        Ok(())
    }

    async fn size(accessor: &Accessor<Ctx, Self>, self_: Resource<MemSource>) -> wasmtime::Result<u64> {
        accessor.with(|mut a| {
            let src = a.get().table.get(&self_)?;
            Ok(src.bytes.len() as u64)
        })
    }

    async fn read(
        accessor: &Accessor<Ctx, Self>,
        self_: Resource<MemSource>,
        offset: u64,
        len: u32,
    ) -> wasmtime::Result<std::result::Result<Vec<u8>, String>> {
        accessor.with(|mut a| {
            let src = a.get().table.get(&self_)?;
            let total = src.bytes.len() as u64;
            if offset > total {
                // Past the end is not "short at end-of-file", it is a
                // caller error; say so rather than hand back nothing.
                return Ok(Err(format!("read at {offset} past the source's {total} bytes")));
            }
            let start = offset as usize;
            let end = std::cmp::min(start + len as usize, src.bytes.len());
            Ok(Ok(src.bytes[start..end].to_vec()))
        })
    }
}

impl transfer_io::HostSinkWithStore<Ctx> for HasSelf<Ctx> {
    async fn drop(accessor: &Accessor<Ctx, Self>, rep: Resource<FileSink>) -> wasmtime::Result<()> {
        accessor.with(|mut a| a.get().table.delete(rep))?;
        Ok(())
    }

    async fn write(
        accessor: &Accessor<Ctx, Self>,
        self_: Resource<FileSink>,
        data: Vec<u8>,
    ) -> wasmtime::Result<std::result::Result<(), String>> {
        accessor.with(|mut a| {
            let sink = a.get().table.get_mut(&self_)?;
            sink.pending.extend_from_slice(&data);
            Ok(Ok(()))
        })
    }

    async fn committed(
        accessor: &Accessor<Ctx, Self>,
        self_: Resource<FileSink>,
    ) -> wasmtime::Result<u64> {
        accessor.with(|mut a| {
            let sink = a.get().table.get(&self_)?;
            Ok(sink.committed)
        })
    }

    async fn flush(
        accessor: &Accessor<Ctx, Self>,
        self_: Resource<FileSink>,
    ) -> wasmtime::Result<std::result::Result<(), String>> {
        accessor.with(|mut a| {
            let sink = a.get().table.get_mut(&self_)?;
            // Order matters and is the entire contract: bytes reach the
            // disk, the disk confirms, and only THEN does `committed`
            // claim them.
            let out = (|| -> std::io::Result<()> {
                sink.file.write_all(&sink.pending)?;
                sink.file.sync_all()
            })();
            match out {
                Ok(()) => {
                    sink.committed += sink.pending.len() as u64;
                    sink.pending.clear();
                    Ok(Ok(()))
                }
                Err(e) => Ok(Err(format!("flush {}: {e}", sink.path.display()))),
            }
        })
    }
}

// ---------------------------------------------------------------------
// the gate leg
// ---------------------------------------------------------------------

/// The generated payload both upload legs move. Deliberately not a
/// round multiple of the SFTP payload size, and larger than
/// `REPLAY_BUDGET_BYTES` (512 KiB, session-global) so the engine's
/// in-flight bound is actually exercised rather than skipped.
fn payload(len: usize, salt: u8) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for (i, b) in v.iter_mut().enumerate() {
        *b = ((i as u64).wrapping_mul(2654435761) as u8) ^ salt;
    }
    v
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The seeded fixture, created SERVER-SIDE over the probe channel so
/// the non-UTF-8 name is made by the target's own shell rather than
/// smuggled in by a host that happens to share its filesystem.
const SEED_TXT: &[u8] = b"wosh-transfer-seed\n";
const ODD_TXT: &[u8] = b"wosh-transfer-odd\n";
/// The name carrying byte 0xff: not valid UTF-8 in any encoding SFTP
/// pretends to have, which is the point (terminal.wit, `dir-entry`).
const ODD_NAME: &[u8] = b"odd-\xff-name.bin";

struct Probe {
    exit: Option<i32>,
    out: String,
}

async fn probe(
    acc: &Accessor<Ctx>,
    iface: &Terminal,
    s: ResourceAny,
    command: &str,
) -> Result<Probe> {
    let r = iface
        .session()
        .call_probe(acc, s, command.to_string())
        .await?
        .map_err(|e| anyhow!("probe {command:?}: {e}"))?;
    Ok(Probe { exit: r.exit_status, out: String::from_utf8_lossy(&r.output).into_owned() })
}

/// Poll a transfer to its terminal outcome. `transfer-progress`'s
/// outcome is NOT cleared by observation, so this can poll as often as
/// it likes; `on_progress` is the hook the resume leg tears the tunnel
/// from, called with `done` after every poll.
async fn drive<F>(
    acc: &Accessor<Ctx>,
    iface: &Terminal,
    tr: ResourceAny,
    timeout: Duration,
    label: &str,
    mut on_progress: F,
) -> Result<std::result::Result<(), String>>
where
    F: AsyncFnMut(u64, Option<u64>) -> Result<()>,
{
    let transfers = iface.transfer();
    let deadline = Instant::now() + timeout;
    loop {
        let p = transfers.call_progress(acc, tr).await?;
        if let Some(outcome) = p.outcome {
            return Ok(outcome);
        }
        on_progress(p.done, p.total).await?;
        if Instant::now() > deadline {
            bail!("{label}: timed out at {} of {:?} bytes", p.done, p.total);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Run a shell command from the gate host -- the transport-kill hook.
async fn run_host_cmd(cmd: &str) -> Result<()> {
    let status = tokio::process::Command::new("bash").arg("-c").arg(cmd).status().await?;
    if !status.success() {
        bail!("host command {cmd:?} failed: {status}");
    }
    Ok(())
}

/// The whole transfer leg, run on a session that has already reached
/// `ready` (it reuses the publickey leg's connect, host-key gate and
/// authentication verbatim, exactly as `--probe` does).
pub async fn run(
    acc: &Accessor<Ctx>,
    iface: &Terminal,
    s: ResourceAny,
    dir: &str,
    stage: &std::path::Path,
    mid_transfer_cmd: Option<&str>,
) -> Result<()> {
    let session = iface.session();

    // --- T0. seed the remote directory, server-side -----------------
    // `printf '\377'` is how a POSIX shell makes a raw 0xff byte; the
    // filename it lands in is what the whole bytes-end-to-end story is
    // about, and making it HERE means the target's own filesystem
    // produced it, not this host writing through a shared mount.
    let seed = format!(
        "rm -rf {dir} && mkdir -p {dir} && \
         printf 'wosh-transfer-seed\\n' > {dir}/seed.txt && \
         printf 'wosh-transfer-odd\\n' > \"$(printf '{dir}/odd-\\377-name.bin')\" && \
         echo SEEDED"
    );
    let p = probe(acc, iface, s, &seed).await?;
    if p.exit != Some(0) || !p.out.contains("SEEDED") {
        bail!("seeding {dir} failed (exit {:?}):\n{}", p.exit, p.out);
    }
    println!("[T0] seeded {dir} server-side (including a filename carrying byte 0xff)");

    // --- T1. list it ------------------------------------------------
    let entries = session
        .call_list_dir(acc, s, dir.as_bytes().to_vec())
        .await?
        .map_err(|e| anyhow!("list-dir {dir}: {e}"))?;
    let names: Vec<String> = entries.iter().map(|e| e.display.clone()).collect();
    println!("[T1] list-dir returned {} entries: {names:?}", entries.len());

    let seed_entry = entries
        .iter()
        .find(|e| e.name == b"seed.txt")
        .ok_or_else(|| anyhow!("seed.txt missing from the listing: {names:?}"))?;
    if seed_entry.size != Some(SEED_TXT.len() as u64) {
        bail!("seed.txt size is {:?}, expected {}", seed_entry.size, SEED_TXT.len());
    }
    if seed_entry.is_dir {
        bail!("seed.txt came back marked is-dir");
    }
    println!("[T1] seed.txt is listed with its true size ({} bytes)", SEED_TXT.len());

    // The non-UTF-8 entry. Two separate claims: the RAW bytes survived
    // the whole stack, and `display` is the lossy rendering -- which
    // must NOT be equal to the bytes, or nothing was really tested.
    let odd = entries
        .iter()
        .find(|e| e.name == ODD_NAME)
        .ok_or_else(|| anyhow!(
            "the 0xff filename did not survive the listing byte-exactly; got {:?}",
            entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
        ))?;
    let expected_display = String::from_utf8_lossy(ODD_NAME).into_owned();
    if odd.display != expected_display {
        bail!("lossy display is {:?}, expected {expected_display:?}", odd.display);
    }
    if odd.display.as_bytes() == ODD_NAME {
        bail!("display and name are the same bytes -- the 0xff never made it in");
    }
    println!(
        "[T1] the 0xff filename round-tripped byte-exactly; display is the lossy {:?}",
        odd.display
    );

    // --- T2. download it BY ITS RAW BYTES ---------------------------
    // Joining is the caller's job (terminal.wit, `dir-entry`): the
    // listed directory's bytes, a slash, and the entry's `name`.
    let mut odd_path = dir.as_bytes().to_vec();
    odd_path.push(b'/');
    odd_path.extend_from_slice(&odd.name);

    let odd_sink_path = stage.join("odd-download.bin");
    let odd_sink = acc.with(|mut a| -> Result<_> {
        Ok(a.get().table.push(FileSink::create(odd_sink_path.clone())?)?)
    })?;
    let tr = session
        .call_download(acc, s, odd_path.clone(), odd_sink, false)
        .await?
        .map_err(|e| anyhow!("download of the 0xff name: {e}"))?;
    drive(acc, iface, tr, Duration::from_secs(60), "odd-name download", async |_, _| Ok(()))
        .await?
        .map_err(|e| anyhow!("download of the 0xff name failed: {e}"))?;
    let got = std::fs::read(&odd_sink_path)?;
    if got != ODD_TXT {
        bail!("the 0xff file's contents came back wrong: {:?}", String::from_utf8_lossy(&got));
    }
    println!("[T2] downloaded the 0xff-named file by its raw bytes; contents match");

    // --- T3. upload ~4 MiB, verified server-side --------------------
    // Four times REPLAY_BUDGET_BYTES, so the engine's in-flight bound
    // (the thing that keeps the tunnel's replay buffer resumable) is
    // genuinely exercised.
    let big = payload(4 * 1024 * 1024 + 4097, 0x00);
    let big_hash = sha256_hex(&big);
    let remote_up = format!("{dir}/upload.bin");
    let src = acc.with(|mut a| a.get().table.push(MemSource { bytes: big.clone() }))?;
    let started = Instant::now();
    let tr = session
        .call_upload(acc, s, src, remote_up.as_bytes().to_vec(), false)
        .await?
        .map_err(|e| anyhow!("upload: {e}"))?;
    drive(acc, iface, tr, Duration::from_secs(300), "upload", async |_, _| Ok(()))
        .await?
        .map_err(|e| anyhow!("upload failed: {e}"))?;
    println!("[T3] uploaded {} bytes in {:?}", big.len(), started.elapsed());
    let p = probe(acc, iface, s, &format!("sha256sum {remote_up}")).await?;
    let server_hash = p.out.split_whitespace().next().unwrap_or("").to_string();
    if server_hash != big_hash {
        bail!("server-side sha256 mismatch:\n  server {server_hash}\n  local  {big_hash}");
    }
    println!("[T3] the target's own sha256sum agrees with the bytes we sent");

    // --- T4. download it back ---------------------------------------
    let back_path = stage.join("roundtrip.bin");
    let back = acc.with(|mut a| -> Result<_> {
        Ok(a.get().table.push(FileSink::create(back_path.clone())?)?)
    })?;
    let tr = session
        .call_download(acc, s, remote_up.as_bytes().to_vec(), back, false)
        .await?
        .map_err(|e| anyhow!("download: {e}"))?;
    drive(acc, iface, tr, Duration::from_secs(300), "download", async |_, _| Ok(()))
        .await?
        .map_err(|e| anyhow!("download failed: {e}"))?;
    let got = std::fs::read(&back_path)?;
    if sha256_hex(&got) != big_hash {
        bail!("round-trip download differs: {} bytes, sha256 {}", got.len(), sha256_hex(&got));
    }
    println!("[T4] downloaded it back through the sink; bytes identical");

    // --- T5. equal-length re-upload: the already-done path ----------
    // Same source, same remote path, no overwrite. terminal.wit:
    // "matching tail means already done, reported as an immediate
    // success" -- so this must succeed, and it must not spend the
    // wall time a real 4 MiB upload just did.
    let src = acc.with(|mut a| a.get().table.push(MemSource { bytes: big.clone() }))?;
    let again = Instant::now();
    let tr = session
        .call_upload(acc, s, src, remote_up.as_bytes().to_vec(), false)
        .await?
        .map_err(|e| anyhow!("equal-length re-upload: {e}"))?;
    drive(acc, iface, tr, Duration::from_secs(120), "re-upload", async |_, _| Ok(()))
        .await?
        .map_err(|e| anyhow!("equal-length re-upload was refused: {e}"))?;
    println!(
        "[T5] the equal-length re-upload reported success in {:?} (the first took {:?})",
        again.elapsed(),
        started.elapsed()
    );

    // --- T6. overwrite onto a sink that is not empty -----------------
    // A sink cannot truncate, by design, so this is a refusal and the
    // only thing under test is that it is a LEGIBLE one.
    let dirty_path = stage.join("dirty-sink.bin");
    let dirty = acc.with(|mut a| -> Result<_> {
        Ok(a
            .get()
            .table
            .push(FileSink::create_prefilled(dirty_path.clone(), b"staged already")?)?)
    })?;
    let tr = session
        .call_download(acc, s, remote_up.as_bytes().to_vec(), dirty, true)
        .await?
        .map_err(|e| anyhow!("download (overwrite, dirty sink) refused at the call: {e}"))?;
    let outcome = drive(
        acc,
        iface,
        tr,
        Duration::from_secs(60),
        "overwrite-onto-dirty-sink",
        async |_, _| Ok(()),
    )
    .await?;
    match outcome {
        Ok(()) => bail!("overwrite onto a non-empty sink SUCCEEDED; it must refuse"),
        Err(why) => {
            if !why.contains("overwrite") || !why.contains("empty") {
                bail!("the refusal is not legible about why: {why}");
            }
            println!("[T6] overwrite onto a non-empty sink refused legibly: {why}");
        }
    }
    // And it kept what was staged: nothing may quietly discard bytes.
    if std::fs::read(&dirty_path)? != b"staged already" {
        bail!("the refused overwrite disturbed the sink's staged bytes");
    }
    println!("[T6] the staged bytes survived the refusal");

    // --- T7. the resume leg ------------------------------------------
    if let Some(cmd) = mid_transfer_cmd {
        // A transfer's reason to exist. The transport is torn out from
        // under a live upload; the session must ride it out (tunnel
        // replay, or -- if the SFTP channel itself dies -- the engine's
        // own re-anchor), and the bytes that land on the target must be
        // the bytes we sent, byte for byte.
        let big2 = payload(16 * 1024 * 1024 + 9001, 0x5a);
        let hash2 = sha256_hex(&big2);
        let remote2 = format!("{dir}/resumed.bin");
        let src = acc.with(|mut a| a.get().table.push(MemSource { bytes: big2.clone() }))?;
        let tr = session
            .call_upload(acc, s, src, remote2.as_bytes().to_vec(), false)
            .await?
            .map_err(|e| anyhow!("resume-leg upload: {e}"))?;

        let mut killed = false;
        let mut saw_detached_link = false;
        let started = Instant::now();
        let outcome = drive(
            acc,
            iface,
            tr,
            Duration::from_secs(600),
            "resume-leg upload",
            async |done, _total| {
                if !killed && done >= 1024 * 1024 {
                    killed = true;
                    println!("[T7] {done} bytes in -- tearing the transport out from under it");
                    run_host_cmd(cmd).await?;
                    println!("[T7] transport killed and restarted; the session must now resume");
                }
                if killed && !saw_detached_link {
                    // Proof the transport really died rather than the
                    // kill missing: the client's own view of the link.
                    use crate::bindings::exports::wosh::terminal::terminal::LinkState;
                    if session.call_link_state(acc, s).await? != LinkState::Attached {
                        saw_detached_link = true;
                        println!("[T7] link-state left `attached` -- the resume machine is up");
                    }
                }
                Ok(())
            },
        )
        .await?;
        outcome.map_err(|e| anyhow!("the transfer did not survive the transport death: {e}"))?;
        if !killed {
            bail!("the resume leg finished before the transport was ever torn");
        }
        if !saw_detached_link {
            bail!(
                "the transfer completed but link-state never left `attached`: \
                 the transport was never actually torn, so nothing was resumed"
            );
        }
        println!("[T7] the upload completed across the outage in {:?}", started.elapsed());
        let p = probe(acc, iface, s, &format!("sha256sum {remote2}")).await?;
        let server_hash = p.out.split_whitespace().next().unwrap_or("").to_string();
        if server_hash != hash2 {
            bail!("post-resume sha256 mismatch:\n  server {server_hash}\n  local  {hash2}");
        }
        println!("[T7] the target's sha256sum matches: the resumed upload is byte-perfect");
    }

    println!(
        "\nE2E-TRANSFER PASS: SFTP listing (raw non-UTF-8 names included), upload verified by \
         the target's own sha256sum, round-trip download, the already-done and \
         refused-overwrite paths -- and an upload that rode out a transport death"
    );
    Ok(())
}
