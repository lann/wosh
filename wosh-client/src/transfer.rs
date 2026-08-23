//! The SFTP transfer engine: the thing that actually moves file bytes
//! between the browser's storage and the far end, sitting on ssh-core's
//! bulk channel plane and speaking the `wosh-sftp` codec.
//!
//! Three planes meet here and none of them knows about the others, which
//! is why this module is where all the awkwardness lives:
//!
//! * **`wosh:ssh-core`'s bulk channel** is synchronous and tick-driven.
//!   Nothing moves unless somebody calls `feed` or `pump` on the session,
//!   and at most one SSH packet (~32 KiB) crosses per tick. `write`
//!   reports bytes ACCEPTED (a short write is the entire backpressure
//!   signal) and `drain(max)` lets this side set the pace.
//! * **`wosh:terminal/transfer-io`** is asynchronous and host-owned: a
//!   `source` reads at an offset, a `sink` appends and reports what it has
//!   DURABLY kept. Neither can be cancelled mid-call (see lib.rs's
//!   no-cancel discipline), so every await here runs to completion.
//! * **SFTP v3 itself** is a pipelined request/response protocol whose
//!   throughput comes entirely from having many requests in flight.
//!
//! # Pump cadence: why there is no fixed poll interval
//!
//! core.wit says it outright: "a loop that drains until empty and pumps
//! whenever the wire has bytes will saturate; a fixed poll interval will
//! not. (At one 32 KiB SSH packet per tick, a 100 ms cadence caps a
//! transfer near 320 KB/s no matter how fast the tunnel is.)" The probe
//! export in lib.rs ticks at a fixed 100 ms because a probe is one
//! question; a transfer cannot afford that.
//!
//! So [`pump_round`] is the unit of work, not a timer: it writes until
//! the channel refuses, drains until the channel is empty, decodes every
//! complete packet, and ticks the core once so those bytes actually reach
//! the wire. The engine loop calls it back to back, [`yield_now`]ing
//! between rounds so the reader and writer tasks (and every other export)
//! keep running. Only a round that achieved NOTHING -- no bytes accepted,
//! none drained, no packet decoded, no reply harvested -- sleeps, and only
//! [`IDLE_TICK_MS`], which is the round-trip-bound case where the engine
//! is genuinely waiting on the far end. The reader task's own `feed`
//! calls are wire-driven ticks that advance the core in parallel; the
//! rounds here add the pump ticks the core needs when the wire is quiet.
//!
//! (An idle round sleeps rather than parking on `State::status_signal`.
//! That `Signal` is single-consumer by construction -- `wait` overwrites
//! the stored waker -- so a transfer parking on it would steal wakeups
//! from anything else that ever parks there, and racing it against the
//! sleep would mean a `select!` over a host import, which this codebase
//! does not do.)
//!
//! # Replay-budget bounding: the invariant nothing else makes visible
//!
//! The tunnel underneath keeps every unacknowledged outbound payload in a
//! replay buffer capped at [`wosh_tunnel::REPLAY_CAP`] (4 MiB). That cap
//! is what a resume can bridge; overflowing it makes the session
//! UNRESUMABLE by design, and lib.rs's `resume_loop` then declares the
//! session dead rather than reconnect into a corrupt SSH stream.
//!
//! A transfer is the only thing in this client capable of producing
//! megabytes of outbound SSH traffic faster than the peer acknowledges
//! it, so a transfer is the only thing that can push the replay buffer
//! over. Nothing in SFTP knows this, and nothing in ssh-core knows it
//! either: the channel's own backpressure bounds the CORE's buffer, not
//! the tunnel's. Hence [`REPLAY_BUDGET_BYTES`] -- a wosh-level invariant
//! enforced here, well under the cap, applied to outstanding SFTP WRITE
//! payload (upload) and outstanding READ request sizes (download, where
//! the reply is what will be flowing back and the requests are what keep
//! it coming).
//!
//! The budget is SESSION-GLOBAL, and that is the whole of it: one
//! [`Budget`] pool on the session, which every transfer draws
//! [`Permits`] from and returns them to as the server acknowledges
//! work. Per-transfer budgets would be an invariant in name only -- the
//! replay buffer is one buffer for the whole session, the page starts
//! one upload per dropped file, and nothing caps how many files get
//! dropped, so seven concurrent transfers at 512 KiB each would sail
//! past a 4 MiB cap while every transfer individually believed itself
//! well-behaved. Transfers therefore contend for a fixed depth rather
//! than multiplying it, which also means several at once are each
//! slower: the shared wire did not get wider because more files were
//! dropped on it.
//!
//! # Resume anchors
//!
//! Resume is the default, not a mode, and the two directions anchor
//! differently because the host's two ends are deliberately asymmetric
//! (transfer-io's doc: read-at-offset versus append-only).
//!
//! * **Upload** re-STATs the remote path. Absent or empty: fresh. Shorter
//!   than the source: read the last min(64 KiB, remote length) from the
//!   REMOTE and compare byte for byte against the same range of the
//!   source -- rsync's append-verify, sized to catch a torn tail. Equal:
//!   continue at the remote length. Unequal, or a remote longer than the
//!   source: fail legibly rather than guess.
//! * **Download** anchors on `sink.committed()`, because an append-only
//!   sink cannot hand its tail back for comparison. What substitutes is
//!   the remote's identity -- FSTAT size and mtime captured at first
//!   start, carried in the transfer's own state and re-checked on every
//!   re-anchor. A remote that changed since is refused, not spliced.
//!
//! # Cancellation and session loss
//!
//! Cancel sets a flag. The engine stops ISSUING at the next round
//! boundary, lets the requests it already put on the wire answer (nothing
//! is dropped mid-flight -- the no-cancel discipline is about host
//! imports, and every one of those here is awaited to completion), CLOSEs
//! the remote handle, flushes the sink, and reports `cancelled`. What
//! moved stays moved, which is exactly what a later resume continues
//! from.
//!
//! A tunnel-level blip is invisible here: the SSH stream is replayed
//! beneath notice and the channel never notices. A dead SFTP CHANNEL (the
//! server closed the subsystem, or the SSH session itself went and came
//! back) parks the transfer, re-opens the channel lazily, and re-anchors
//! exactly as a fresh resume would -- which is the one case where
//! `progress.done` may dip, as terminal.wit's `transfer-progress`
//! permits.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::bindings::exports::wosh::terminal::terminal::{
    DirEntry, GuestTransfer, Transfer, TransferDirection, TransferProgress,
};
use crate::bindings::wosh::ssh_core::core::{Channel, ChannelState};
use crate::bindings::wosh::terminal::transfer_io::{Sink, Source};
use crate::{sleep_ms, State};

use wosh_sftp as sftp;

// ---------------------------------------------------------------------
// Sizing constants
// ---------------------------------------------------------------------

/// The ceiling on unacknowledged in-flight transfer data, in bytes,
/// across the WHOLE SESSION -- not per transfer.
///
/// Session-global is the only shape that works, and the reasoning is
/// arithmetic rather than taste: the thing being protected (the tunnel's
/// replay buffer) is one buffer per session, shared by every channel on
/// it. A per-transfer budget of this size holds for one transfer and
/// fails for seven, and seven is not a hypothetical -- the page starts
/// one upload per dropped file, and nothing anywhere caps how many that
/// is. So the budget is a POOL, hung off the session
/// (`State::transfer_budget`), that every transfer draws permits from
/// and returns them to; the sum of all transfers' unacknowledged bytes
/// is what stays under this number.
///
/// This exists solely because of [`wosh_tunnel::REPLAY_CAP`] (4 MiB,
/// `tunnel/src/lib.rs`): outbound payloads sit in the tunnel's replay
/// buffer until the peer ACKs them, and a buffer that overflows makes the
/// session unresumable -- `resume_loop` kills such a session on purpose
/// rather than reconnect into a stream with a hole in it. A transfer is
/// the only producer in this client fast enough to get there, so a
/// transfer is where the bound belongs.
///
/// The second bound this number has to respect is the tunnel's per-frame
/// ceiling, `wosh_tunnel::MAX_FRAME`, also 1 MiB. That one is enforced
/// where bytes become frames (`MAX_WIRE_CHUNK` in lib.rs) rather than
/// here -- it has to be, since the resume tail never passes through this
/// engine -- but the budget must not sit AT a ceiling it is measured in
/// different units from: this counts SFTP payload, and the wire adds SSH
/// packet, channel and frame overhead on top of every byte of it.
///
/// 512 KiB is therefore half the frame ceiling and an eighth of the
/// replay cap, with room for the interactive channel, keepalive traffic
/// and the ACK lag beside it -- and still deep enough for dozens of SFTP
/// requests in flight at browser latencies, which is where SFTP's
/// throughput comes from (see the codec's module docs on pipelining).
///
/// Concurrent transfers therefore share this depth rather than each
/// getting one, which means several at once are individually slower --
/// correctly so: the wire they share did not get wider. Contention is
/// first-come-first-served per round, with no fairness beyond that, so a
/// transfer can in principle be starved by busier siblings. Accepted at
/// this scale: permits are returned every time the server acknowledges
/// anything, a starved transfer is idle rather than broken, and it
/// cannot be failed for being starved (see [`Futility`], which charges
/// nothing while a transfer is merely waiting).
pub(crate) const REPLAY_BUDGET_BYTES: u64 = 512 * 1024;

/// Payload size for READ/WRITE when the server does not advertise
/// `limits@openssh.com`. 32000 bytes is the conventional SFTP v3 figure
/// (it keeps the whole packet under the 34000-byte buffer every OpenSSH
/// sftp-server has used since the draft).
const DEFAULT_PAYLOAD: u32 = 32_000;

/// Upper bound on a payload even when the server advertises more, so a
/// single packet stays well under the codec's [`sftp::MAX_PACKET_LEN`].
const MAX_PAYLOAD: u32 = 128 * 1024;

/// How much of the tail both ends re-read to agree on an upload resume
/// point. Sized to catch a torn final write, not to re-verify the file.
const TAIL_VERIFY_BYTES: u64 = 64 * 1024;

/// Flush the sink (and therefore advance `committed`) at least this
/// often during a download.
const FLUSH_EVERY_BYTES: u64 = 4 * 1024 * 1024;

/// Chunk size for `channel.drain`. The channel hands over at most this
/// much per call and the loop drains until empty, so this only sets the
/// granularity, not the pace.
const DRAIN_MAX: u32 = 256 * 1024;

/// How long a round that achieved nothing sleeps before trying again.
/// Only reached when the engine is waiting on the far end, where the
/// round trip dwarfs this; a round that moved anything never sleeps.
const IDLE_TICK_MS: u64 = 5;

/// Pause before re-opening the SFTP channel and re-anchoring after the
/// channel died under a live session.
const REANCHOR_DELAY_MS: u64 = 500;

/// How many CONSECUTIVE FUTILE re-anchors end a transfer -- futile
/// meaning the session was `ready` throughout and not one further byte
/// moved.
///
/// Two budgets, and keeping them apart is the whole point. The SESSION
/// owns transport retry: `resume_loop` in lib.rs redials with its own
/// backoff for up to ten minutes, and the README states the principle
/// this file inherits -- the resume budget is spent in time spent
/// TRYING, not in time elapsed. The TRANSFER owns protocol retry only:
/// the SFTP channel dying the moment it opens, a tail verification that
/// will not settle, a server refusing the subsystem it just granted.
///
/// A counter that fails to make that split charges one outage many
/// times over. This one did: a plain relay restart (two seconds down,
/// plus bind time) produced re-anchor after re-anchor against a
/// transport that was never going to answer until the SESSION brought
/// it back, and five `Connection refused`es later the transfer gave up
/// on a session that resumed perfectly well moments afterwards. So a
/// re-anchor is only charged here when the session was `ready` and the
/// attempt achieved nothing (see [`Futility`]); while the session is
/// down, this supervisor waits on the resume machine and spends
/// nothing.
const MAX_FUTILE_REANCHORS: u32 = 5;

/// Refuse to build a listing larger than this. A directory listing is
/// materialised whole in a `list<dir-entry>`, so an unbounded readdir
/// loop is an unbounded allocation.
const MAX_DIR_ENTRIES: usize = 200_000;

// SSH_FXF_* open flags (draft-ietf-secsh-filexfer-02 sec 6.3). Spelled
// out here because `wosh-sftp` re-exports only the types it hand-decodes
// -- `encode_open` takes a bare `u32` bitmask -- and these four values
// are wire constants, fixed by the draft.
const SSH_FXF_READ: u32 = 0x0000_0001;
const SSH_FXF_WRITE: u32 = 0x0000_0002;
const SSH_FXF_CREAT: u32 = 0x0000_0008;
const SSH_FXF_TRUNC: u32 = 0x0000_0010;

/// The `exec` fallbacks tried, in order, when a server has no
/// `Subsystem sftp` line. OpenSSH's `sftp-server` speaks its protocol on
/// stdin/stdout however it was started (core.wit, `open-exec-channel`);
/// these are where the distributions put it.
const SFTP_SERVER_CANDIDATES: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
];

// ---------------------------------------------------------------------
// Pure decision logic
//
// Everything in this section is sans-I/O on purpose: the resume
// decisions are the part of this engine where a plausible-but-wrong
// answer silently corrupts a file, so they are ordinary functions over
// numbers and byte slices, unit-tested natively at the bottom of this
// module.
// ---------------------------------------------------------------------

/// What an upload should do once the remote path has been STATed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UploadPlan {
    /// Nothing usable is there (or `overwrite` was asked for): open with
    /// CREAT|TRUNC and write from zero.
    Fresh,
    /// A shorter-or-equal remote file exists: re-read `tail` bytes ending
    /// at `remote_len` from both ends and compare before continuing.
    Verify { remote_len: u64, tail: u64 },
    /// Refuse, with a reason a human can act on.
    Refuse(String),
}

/// Decide an upload's opening move from the remote size (`None` when the
/// path does not exist) and the source's size.
pub(crate) fn plan_upload(remote: Option<u64>, local: u64, overwrite: bool) -> UploadPlan {
    if overwrite {
        return UploadPlan::Fresh;
    }
    match remote {
        None | Some(0) => UploadPlan::Fresh,
        Some(r) if r > local => UploadPlan::Refuse(format!(
            "the remote file is longer than the source ({r} bytes against {local}): \
             refusing to guess -- retry with overwrite to replace it"
        )),
        Some(r) => UploadPlan::Verify {
            remote_len: r,
            tail: r.min(TAIL_VERIFY_BYTES),
        },
    }
}

/// Where an upload starts once the two tails have been compared.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UploadStart {
    /// Nothing left to send: the remote already holds the whole file and
    /// its tail matches.
    Complete,
    /// Continue at this offset.
    Append(u64),
}

/// Turn a tail comparison into a resume point.
///
/// Equal-length is not a special case: terminal.wit's `upload` calls it
/// "the same dance with nothing left to append", so a matching tail
/// means already done and is reported as an immediate success, while a
/// mismatching one is the ordinary tails-disagree refusal. The other two
/// refusals the contract names -- disagreeing tails, a remote longer
/// than the source -- are here and in [`plan_upload`] respectively.
pub(crate) fn resume_after_verify(
    remote_len: u64,
    local: u64,
    tails_equal: bool,
) -> Result<UploadStart, String> {
    if !tails_equal {
        return Err(format!(
            "the remote file's last bytes do not match the source at offset {remote_len}: \
             it is a different file, or a previous upload tore -- retry with overwrite \
             to replace it"
        ));
    }
    if remote_len == local {
        Ok(UploadStart::Complete)
    } else {
        Ok(UploadStart::Append(remote_len))
    }
}

/// The remote file's identity as captured at a download's first start:
/// what substitutes for re-reading an append-only sink's tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteId {
    pub size: u64,
    /// `None` when the server's ATTRS carried no modification time.
    pub mtime: Option<u64>,
}

/// Compare the remote's identity now against the one captured when this
/// transfer first started.
///
/// The rule is terminal.wit's `download`, verbatim in effect: an mtime
/// that was present and then changed OR vanished is a refusal, and only
/// a server that never reported one gets the weaker size-only check. A
/// file that changed is refused rather than spliced.
pub(crate) fn check_identity(first: &RemoteId, now: &RemoteId) -> Result<(), String> {
    if first.size != now.size {
        return Err(format!(
            "the remote file changed while the transfer was interrupted \
             (it was {} bytes, it is now {}): refusing to splice two different files \
             -- start the download again",
            first.size, now.size
        ));
    }
    match (first.mtime, now.mtime) {
        (Some(a), Some(b)) if a != b => Err(
            "the remote file was modified while the transfer was interrupted: \
             refusing to splice two different files -- start the download again"
                .to_string(),
        ),
        (Some(_), None) => Err(
            "the remote file no longer reports a modification time, so the bytes \
             already downloaded cannot be shown to belong to it -- start the \
             download again"
                .to_string(),
        ),
        _ => Ok(()),
    }
}

/// What a download should do once the sink's anchor and the remote's size
/// are both known.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DownloadPlan {
    /// Everything is already in the sink.
    Complete,
    /// Read from this offset onward.
    Start(u64),
}

/// Decide a download's opening move.
///
/// `overwrite` requires an EMPTY sink (`committed` = 0) and fails
/// legibly otherwise, per terminal.wit's `download`: a sink has no
/// truncate by design, so discarding staged bytes and handing over a
/// fresh sink is the host's move, not this engine's.
pub(crate) fn plan_download(
    committed: u64,
    remote_len: u64,
    overwrite: bool,
) -> Result<DownloadPlan, String> {
    if overwrite {
        if committed > 0 {
            return Err(format!(
                "overwrite needs an empty destination, but it already holds {committed} \
                 bytes: this component's sink is append-only (see transfer-io) and \
                 cannot truncate it -- hand over a fresh destination"
            ));
        }
        return Ok(DownloadPlan::Start(0));
    }
    if committed > remote_len {
        return Err(format!(
            "the destination already holds more bytes than the remote file has \
             ({committed} against {remote_len}): it is not a prefix of this file \
             -- start the download again into a fresh destination"
        ));
    }
    if committed == remote_len {
        Ok(DownloadPlan::Complete)
    } else {
        Ok(DownloadPlan::Start(committed))
    }
}

/// The session-wide pool of in-flight permits that keeps every transfer,
/// TOGETHER, under [`REPLAY_BUDGET_BYTES`]. One of these lives on the
/// session (`State::transfer_budget`); see the module header for why the
/// bound exists at all and the constant for why it is shared.
#[derive(Debug)]
pub(crate) struct Budget {
    limit: u64,
    outstanding: u64,
}

impl Budget {
    pub(crate) fn new(limit: u64) -> Self {
        Budget {
            limit,
            outstanding: 0,
        }
    }

    /// May `n` more bytes go in flight anywhere on this session?
    ///
    /// The `outstanding == 0` escape keeps a pathological combination (a
    /// server advertising a chunk larger than the whole pool) from
    /// deadlocking everything: when nothing at all is outstanding, one
    /// request always fits. It is deliberately about the POOL being
    /// empty, not the asking transfer holding nothing -- otherwise every
    /// transfer would be entitled to one oversized request each, which
    /// is the aggregate overrun this pool exists to prevent.
    pub(crate) fn admits(&self, n: u64) -> bool {
        self.outstanding == 0 || self.outstanding + n <= self.limit
    }

    pub(crate) fn charge(&mut self, n: u64) {
        self.outstanding += n;
    }

    pub(crate) fn release(&mut self, n: u64) {
        self.outstanding = self.outstanding.saturating_sub(n);
    }

    /// How much of the pool is spoken for right now, across every
    /// transfer on the session. Read only by the tests that pin the
    /// aggregate property; the engines go through [`Permits`], which is
    /// what keeps the accounting leak-proof.
    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> u64 {
        self.outstanding
    }
}

/// One transfer's claim on the shared pool.
///
/// The `Drop` impl is the point. An attempt can leave by a dozen routes
/// -- the channel dies, the session goes, the source shrinks, the page
/// cancels -- and permits it still holds must go back to the pool on
/// every one of them. Returning them by hand at each exit is the kind of
/// bookkeeping that is correct until someone adds the thirteenth route;
/// leaked permits would then shrink the session's pool for good, and the
/// symptom (transfers getting slower and eventually stalling, session
/// after session) would point nowhere near the cause.
pub(crate) struct Permits {
    pool: Rc<RefCell<Budget>>,
    held: u64,
}

impl Permits {
    pub(crate) fn new(pool: Rc<RefCell<Budget>>) -> Self {
        Permits { pool, held: 0 }
    }

    /// Take `n` bytes' worth if the pool can spare them, all or nothing.
    pub(crate) fn try_charge(&mut self, n: u64) -> bool {
        let mut pool = self.pool.borrow_mut();
        if !pool.admits(n) {
            return false;
        }
        pool.charge(n);
        self.held += n;
        true
    }

    /// Hand `n` back, as the server acknowledges each request.
    pub(crate) fn release(&mut self, n: u64) {
        let n = n.min(self.held);
        self.held -= n;
        self.pool.borrow_mut().release(n);
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> u64 {
        self.held
    }
}

impl Drop for Permits {
    fn drop(&mut self) {
        self.pool.borrow_mut().release(self.held);
    }
}

/// The consecutive-futility counter behind [`MAX_FUTILE_REANCHORS`].
///
/// Sans-I/O on purpose, like every other decision in this section: the
/// question "has this transfer stopped getting anywhere, or is it merely
/// waiting out an outage?" is one a test should be able to ask directly.
#[derive(Debug)]
pub(crate) struct Futility {
    limit: u32,
    strikes: u32,
    /// The `done` count as of the last time progress was observed. The
    /// same number the page polls -- server-acked bytes for an upload,
    /// durably committed bytes for a download.
    mark: u64,
}

impl Futility {
    pub(crate) fn new(limit: u32, done: u64) -> Self {
        Futility {
            limit,
            strikes: 0,
            mark: done,
        }
    }

    /// Charge one re-anchor and say whether the transfer should give up.
    ///
    /// Three rules, in order:
    ///
    /// 1. Progress forgives everything. If `done` has advanced since the
    ///    last mark, this transfer is working -- slowly, across
    ///    interruptions, but working -- and the count starts over. A
    ///    transfer that keeps moving can never exhaust this budget, which
    ///    is the property that matters on a bad network.
    /// 2. An interruption the session is already handling is not charged.
    ///    `session_was_ready` is false exactly when the transport is
    ///    down, resuming, or stalled; that is the session's budget to
    ///    spend, not this one's.
    /// 3. Otherwise it is a genuine SFTP-level failure on a live session:
    ///    strike, and give up at the limit.
    pub(crate) fn charge(&mut self, session_was_ready: bool, done: u64) -> bool {
        if done > self.mark {
            self.mark = done;
            self.strikes = 0;
            return false;
        }
        if !session_was_ready {
            return false;
        }
        self.strikes += 1;
        self.strikes >= self.limit
    }

    #[cfg(test)]
    pub(crate) fn strikes(&self) -> u32 {
        self.strikes
    }
}

/// Payload size for one READ/WRITE, from the server's advertised limits
/// when it gave any.
pub(crate) fn payload_size(advertised: Option<u64>) -> u32 {
    match advertised {
        Some(n) if n > 0 => n.min(MAX_PAYLOAD as u64) as u32,
        _ => DEFAULT_PAYLOAD,
    }
}

/// Directories first, then bytewise by name.
///
/// Bytewise, not locale- or case-aware, because these names are raw bytes
/// with no declared encoding (see `dir-entry` in terminal.wit): any
/// collation would first have to invent a decoding, and would then order
/// two byte-identical listings differently on two machines. Directories
/// first is the convention every file browser uses and the one thing
/// users notice the absence of.
pub(crate) fn sort_entries(entries: &mut [DirEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.as_slice().cmp(b.name.as_slice()))
    });
}

/// Whether a listing entry is a directory: the ATTRS mode word when the
/// server sent one, the long name's leading character when it did not.
///
/// The mode is the authority. Draft sec 7 only RECOMMENDS that
/// `longname` look like `ls -l` output, so a server that is not OpenSSH
/// may legally put anything there, whereas
/// `SSH_FILEXFER_ATTR_PERMISSIONS` means one thing everywhere. The codec
/// hands over the RAW permissions word and classifies it by masking
/// `S_IFMT` itself ([`sftp::file_kind_from_raw`], infallible for any
/// `u32`) -- which is what makes the mode usable here at all: the typed
/// accessor underneath resolves `S_IFMT` through an `unwrap` that a mode
/// its enum does not name would panic on, and a panic in a wasm
/// component traps the whole instance. A directory listing is exactly
/// where unusual file types turn up, so that distinction is not
/// academic.
///
/// The longname reading survives only as the fallback for ATTRS with no
/// PERMISSIONS flag -- rare, but legal.
pub(crate) fn is_dir(raw_permissions: Option<u32>, longname: &[u8]) -> bool {
    match raw_permissions {
        Some(mode) => sftp::file_kind_from_raw(mode) == sftp::FileKind::Directory,
        None => longname.first() == Some(&b'd'),
    }
}

// ---------------------------------------------------------------------
// The SFTP connection: one channel, shared by every operation
// ---------------------------------------------------------------------

/// Where one outstanding request's answer will land.
enum SlotState {
    Pending,
    Ready(sftp::Response),
    Failed(String),
}

type Slot = Rc<RefCell<SlotState>>;

/// The session's single SFTP connection: one bulk channel, the framer
/// that reassembles packets off it, and the correlator that hands each
/// response back to whoever asked.
///
/// One connection serves everything -- both directions of every transfer
/// and every directory listing -- because SFTP request ids already
/// multiplex, and a second channel would buy nothing but a second server
/// process. Ownership lives in `State::sftp`; every operation borrows it
/// briefly and synchronously, never across an await.
pub(crate) struct Sftp {
    ch: Channel,
    framer: sftp::Framer,
    corr: sftp::Correlator<Slot>,
    /// The ids `corr` currently holds, in submission order.
    ///
    /// Redundant with the correlator's own map, and kept only because
    /// [`sftp::Correlator`]'s surface is `submit`/`take`/`pending_len`
    /// with no way to ENUMERATE what is outstanding -- which is exactly
    /// what a dying channel needs, to fail every waiter at once instead
    /// of leaving them parked on answers that will never come.
    live: Vec<u32>,
    /// Bytes encoded but not yet ACCEPTED by the channel. `write` returns
    /// how much it took, so the remainder waits here for the next round.
    out: Vec<u8>,
    /// The server's `limits@openssh.com` answer, when it advertised the
    /// extension and answered.
    limits: Option<sftp::Limits>,
    /// The VERSION packet's extension set, once it has arrived. It
    /// carries no request id, so it cannot be correlated: the opener
    /// takes it from here.
    version_seen: Option<sftp::Extensions>,
    /// Set once the channel or the stream is unusable. Every pending slot
    /// is failed at the same moment, so nothing waits on a dead channel.
    dead: Option<String>,
}

impl Sftp {
    /// Queue a request built around a freshly allocated id, and return
    /// the slot its answer will land in.
    fn submit(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> Slot {
        let slot: Slot = Rc::new(RefCell::new(SlotState::Pending));
        let id = self.corr.submit(slot.clone());
        self.live.push(id);
        self.out.extend_from_slice(&build(id));
        slot
    }

    /// Mark the connection unusable and fail everything still waiting on
    /// it. Idempotent: the first reason is the one kept, because it is
    /// the one that explains the rest.
    fn die(&mut self, reason: String) {
        if self.dead.is_none() {
            self.dead = Some(reason);
        }
        let reason = self.dead.clone().unwrap_or_default();
        for id in std::mem::take(&mut self.live) {
            if let Ok(slot) = self.corr.take(id) {
                *slot.borrow_mut() = SlotState::Failed(reason.clone());
            }
        }
    }

    /// Route one decoded packet to the request that asked for it.
    fn deliver(&mut self, body: &[u8]) {
        match sftp::decode_response(body) {
            // VERSION carries no request id (draft sec 3) and is answered
            // once, at handshake; the opener watches for it here.
            Ok(sftp::Response::Version(sv)) => self.version_seen = Some(sv.extensions),
            Ok(resp) => {
                let Some(id) = response_id(&resp) else { return };
                self.live.retain(|live| *live != id);
                // A response for an id nobody is waiting on -- the late
                // answer to a request whose owner gave up (a cancelled
                // transfer's last READs) -- is dropped, which is correct:
                // the stream stays framed either way.
                if let Ok(slot) = self.corr.take(id) {
                    *slot.borrow_mut() = SlotState::Ready(resp);
                }
            }
            Err(e) => self.die(format!("sftp: {e}")),
        }
    }
}

/// The request id a decoded response answers, or `None` for the one
/// response type that has none.
fn response_id(resp: &sftp::Response) -> Option<u32> {
    match resp {
        sftp::Response::Version(_) => None,
        sftp::Response::Status { id, .. }
        | sftp::Response::Handle { id, .. }
        | sftp::Response::Data { id, .. }
        | sftp::Response::Name { id, .. }
        | sftp::Response::Attrs { id, .. }
        | sftp::Response::ExtendedReply { id, .. } => Some(*id),
    }
}

/// One round of moving bytes, and the only place this module touches the
/// channel or the core. Entirely synchronous: no borrow here can span an
/// await because there is no await.
///
/// Returns whether anything at all happened; a round that returns `false`
/// is the engine's signal that it may sleep (module header).
fn pump_round(state: &Rc<State>) -> bool {
    let mut progress = false;
    {
        let mut held = state.sftp.borrow_mut();
        let Some(s) = held.as_mut() else { return false };

        // Outbound: write until the channel refuses. A short write --
        // including zero -- is the whole backpressure signal (core.wit),
        // so the remainder simply stays queued for the next round.
        while !s.out.is_empty() && s.dead.is_none() {
            match s.ch.write(&s.out) {
                Ok(0) => break,
                Ok(n) => {
                    s.out.drain(..(n as usize).min(s.out.len()));
                    progress = true;
                }
                Err(e) => s.die(format!("sftp channel write: {e}")),
            }
        }

        // Inbound: drain until EMPTY. core.wit's ordering trap -- an
        // empty drain means "nothing right now", not end of stream, and
        // `eof` must not be honoured until the buffer is dry.
        loop {
            let bytes = s.ch.drain(DRAIN_MAX);
            if bytes.is_empty() {
                break;
            }
            s.framer.feed(&bytes);
            progress = true;
        }

        loop {
            match s.framer.take_packet() {
                Ok(Some(body)) => {
                    s.deliver(&body);
                    progress = true;
                }
                Ok(None) => break,
                Err(e) => {
                    s.die(format!("sftp framing: {e}"));
                    break;
                }
            }
        }

        // Only now -- with the buffer drained above -- is the channel's
        // own state the truth about the far end.
        if s.dead.is_none() {
            match s.ch.state() {
                ChannelState::Open => {}
                ChannelState::Eof => s.die("sftp channel: the server closed its end".to_string()),
                ChannelState::Closed(reason) => s.die(format!("sftp channel closed: {reason}")),
            }
        }
    }

    // The core only moves bytes on a tick, and this is the tick a quiet
    // wire would not otherwise provide. Drain whatever it produced to the
    // outbox and wake the writer, exactly as `drive` does.
    {
        let mut inner = state.inner.borrow_mut();
        inner.core.pump();
        if inner.take_core_output() {
            progress = true;
        }
    }
    state.writer_signal.notify();
    progress
}

/// Hand control back to the executor without sleeping.
///
/// Self-waking during `poll` is exactly how wit-bindgen's task loop spells
/// "yield": the wake flips the task's sleep state to WOKEN, and the
/// scheduler answers a `Pending` in that state with `CallbackCode::Yield`
/// rather than parking on a waitable (wit-bindgen 0.59
/// `rt/async_support.rs`). So this costs one scheduler turn, not a timer.
async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await
}

/// Why an engine round cannot continue.
enum Halt {
    /// The SSH session is over; nothing will bring this transfer back.
    Fatal(String),
    /// The SFTP channel died under a session that is still alive, or the
    /// tunnel is mid-resume: park and re-anchor.
    Reanchor(String),
}

/// The session's health, as of right now. Called once per engine round,
/// synchronously.
fn session_health(state: &Rc<State>) -> Result<(), Halt> {
    let inner = state.inner.borrow();
    if inner.detached {
        return Err(Halt::Fatal("the session was detached".to_string()));
    }
    if let crate::CoreStatus::Closed(reason) = inner.core.status() {
        return Err(Halt::Fatal(format!("the session closed: {reason}")));
    }
    if inner.link_down {
        return Err(Halt::Fatal(
            "the connection was lost and could not be resumed".to_string(),
        ));
    }
    if inner.resuming {
        // The SSH session is alive and merely not receiving bytes
        // (terminal.wit's `link-state`). Park; the channel survives a
        // tunnel resume, and if it did not, the check below catches it.
        return Err(Halt::Reanchor("the transport is reconnecting".to_string()));
    }
    drop(inner);
    if let Some(reason) = state
        .sftp
        .borrow()
        .as_ref()
        .and_then(|s| s.dead.as_ref().cloned())
    {
        return Err(Halt::Reanchor(reason));
    }
    Ok(())
}

/// One engine round: pump, check the session, and report whether anything
/// moved. Every loop in this module is built out of this.
fn round(state: &Rc<State>) -> Result<bool, Halt> {
    let progress = pump_round(state);
    session_health(state)?;
    Ok(progress)
}

/// Pump until `slot` holds an answer. The simple request/response shape,
/// used by everything that is not a bulk data loop.
async fn await_reply(state: &Rc<State>, slot: &Slot) -> Result<sftp::Response, Halt> {
    loop {
        {
            let mut held = slot.borrow_mut();
            match std::mem::replace(&mut *held, SlotState::Pending) {
                SlotState::Ready(resp) => return Ok(resp),
                SlotState::Failed(e) => {
                    *held = SlotState::Failed(e.clone());
                    return Err(Halt::Reanchor(e));
                }
                SlotState::Pending => {}
            }
        }
        let progress = round(state)?;
        if progress {
            yield_now().await;
        } else {
            sleep_ms(IDLE_TICK_MS).await;
        }
    }
}

// --- typed request helpers -------------------------------------------

/// Turn a STATUS response into a plain result, keeping SFTP's EOF
/// distinguishable from a real failure (the codec splits them for exactly
/// this reason).
fn expect_status(resp: sftp::Response, what: &str) -> Result<sftp::StatusOutcome, Halt> {
    match resp {
        sftp::Response::Status { result, .. } => match result {
            Ok(outcome) => Ok(outcome),
            Err(e) => Err(Halt::Fatal(format!("{what}: {e}"))),
        },
        other => Err(Halt::Fatal(format!(
            "{what}: the server answered with {} instead of a status",
            describe(&other)
        ))),
    }
}

fn describe(resp: &sftp::Response) -> &'static str {
    match resp {
        sftp::Response::Version(_) => "a version",
        sftp::Response::Status { .. } => "a status",
        sftp::Response::Handle { .. } => "a handle",
        sftp::Response::Data { .. } => "data",
        sftp::Response::Name { .. } => "a name list",
        sftp::Response::Attrs { .. } => "attributes",
        sftp::Response::ExtendedReply { .. } => "an extended reply",
    }
}

/// Queue a request; fails only when the connection is already dead.
fn submit(state: &Rc<State>, build: impl FnOnce(u32) -> Vec<u8>) -> Result<Slot, Halt> {
    let mut held = state.sftp.borrow_mut();
    let Some(s) = held.as_mut() else {
        return Err(Halt::Reanchor("the sftp channel is not open".to_string()));
    };
    if let Some(reason) = &s.dead {
        return Err(Halt::Reanchor(reason.clone()));
    }
    Ok(s.submit(build))
}

async fn request(
    state: &Rc<State>,
    build: impl FnOnce(u32) -> Vec<u8>,
) -> Result<sftp::Response, Halt> {
    let slot = submit(state, build)?;
    await_reply(state, &slot).await
}

/// STAT a path: `Ok(None)` when it simply is not there, which is a
/// perfectly ordinary answer for an upload's anchor probe.
async fn stat_optional(
    state: &Rc<State>,
    path: &[u8],
) -> Result<Option<sftp::FileAttrs>, Halt> {
    let path = path.to_vec();
    match request(state, |id| sftp::encode_stat(id, &path)).await? {
        sftp::Response::Attrs { attrs, .. } => Ok(Some(attrs)),
        sftp::Response::Status { result, .. } => match result {
            Err(e) if matches!(e.code, sftp::ErrorCode::NoSuchFile) => Ok(None),
            Err(e) => Err(Halt::Fatal(format!("stat the remote path: {e}"))),
            // A bare OK for a STAT is a protocol oddity; treat it as "no
            // attributes" rather than inventing a size.
            Ok(_) => Ok(None),
        },
        other => Err(Halt::Fatal(format!(
            "stat the remote path: the server answered with {}",
            describe(&other)
        ))),
    }
}

async fn open_handle(
    state: &Rc<State>,
    path: &[u8],
    flags: u32,
) -> Result<Vec<u8>, Halt> {
    let path = path.to_vec();
    match request(state, |id| {
        sftp::encode_open(id, &path, flags, sftp::FileAttrs::new())
    })
    .await?
    {
        sftp::Response::Handle { handle, .. } => Ok(handle),
        sftp::Response::Status { result, .. } => Err(Halt::Fatal(match result {
            Err(e) => format!("open the remote file: {e}"),
            Ok(_) => "open the remote file: the server answered ok without a handle".to_string(),
        })),
        other => Err(Halt::Fatal(format!(
            "open the remote file: the server answered with {}",
            describe(&other)
        ))),
    }
}

async fn fstat(state: &Rc<State>, handle: &[u8]) -> Result<sftp::FileAttrs, Halt> {
    let handle = handle.to_vec();
    match request(state, |id| sftp::encode_fstat(id, &handle)).await? {
        sftp::Response::Attrs { attrs, .. } => Ok(attrs),
        sftp::Response::Status { result, .. } => Err(Halt::Fatal(match result {
            Err(e) => format!("stat the open remote file: {e}"),
            Ok(_) => "stat the open remote file: no attributes returned".to_string(),
        })),
        other => Err(Halt::Fatal(format!(
            "stat the open remote file: the server answered with {}",
            describe(&other)
        ))),
    }
}

/// Queue a CLOSE and walk away without waiting for the answer.
///
/// For the paths that abandon an attempt mid-flight -- the transport
/// went, the channel died -- where awaiting the reply would mean
/// awaiting a wire that is, by hypothesis, not answering. If the channel
/// is merely quiet (a tunnel resume underneath), the packet goes out
/// when it returns and the server reclaims the handle; if the channel is
/// gone, the server reclaimed everything already. Without this a
/// transfer that re-anchors repeatedly leaks one open handle per
/// attempt, against the server's `open_handles` limit.
fn close_handle_eventually(state: &Rc<State>, handle: &[u8]) {
    let handle = handle.to_vec();
    let _ = submit(state, move |id| sftp::encode_close(id, &handle));
}

/// CLOSE a handle, best effort. A failure here cannot change what already
/// moved, and reporting it over the real outcome would bury the news.
async fn close_handle(state: &Rc<State>, handle: &[u8]) {
    let handle = handle.to_vec();
    let _ = request(state, |id| sftp::encode_close(id, &handle)).await;
}

/// Read exactly `len` bytes at `offset`, following short reads. Used only
/// by the tail verification, where a short read is not the end of the
/// file and the comparison needs the whole range.
async fn read_exact_remote(
    state: &Rc<State>,
    handle: &[u8],
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, Halt> {
    let mut got: Vec<u8> = Vec::with_capacity(len as usize);
    while (got.len() as u64) < len {
        let at = offset + got.len() as u64;
        let want = (len - got.len() as u64).min(MAX_PAYLOAD as u64) as u32;
        let handle = handle.to_vec();
        match request(state, |id| sftp::encode_read(id, &handle, at, want)).await? {
            sftp::Response::Data { data, .. } => {
                if data.is_empty() {
                    break;
                }
                got.extend_from_slice(&data);
            }
            sftp::Response::Status { result, .. } => match result {
                // EOF inside a range the server just told us exists: the
                // file shrank under us. The caller's comparison fails on
                // the short buffer, which is the right outcome.
                Ok(_) => break,
                Err(e) => return Err(Halt::Fatal(format!("read the remote tail: {e}"))),
            },
            other => {
                return Err(Halt::Fatal(format!(
                    "read the remote tail: the server answered with {}",
                    describe(&other)
                )))
            }
        }
    }
    Ok(got)
}

// ---------------------------------------------------------------------
// Lazy channel opening
// ---------------------------------------------------------------------

/// Ensure the session has a live SFTP connection, opening one if it does
/// not (or if the previous one died).
///
/// Both open paths are tried in the order core.wit prescribes: the
/// `sftp` subsystem first, then `exec` of an `sftp-server` binary for an
/// sshd with no `Subsystem` line. The verdict is protocol-shaped rather
/// than transport-shaped, because it has to be: a channel is born `open`
/// before the server has granted anything, and a refusal only arrives
/// later as `closed(reason)`. So each candidate writes INIT and waits for
/// VERSION-or-`closed`, and that race IS the answer.
async fn ensure_open(state: &Rc<State>) -> Result<(), String> {
    loop {
        // A dead connection is discarded here rather than where it died,
        // so that whoever notices does not have to own the re-open.
        {
            let mut held = state.sftp.borrow_mut();
            if held.as_ref().is_some_and(|s| s.dead.is_some()) {
                *held = None;
            }
            if held.is_some() {
                return Ok(());
            }
        }
        // Exactly one task opens; the others wait for the outcome and
        // then re-check above.
        if state.sftp_opening.get() {
            sleep_ms(IDLE_TICK_MS).await;
            continue;
        }
        state.sftp_opening.set(true);
        let result = open_channel(state).await;
        state.sftp_opening.set(false);
        return result;
    }
}

async fn open_channel(state: &Rc<State>) -> Result<(), String> {
    let mut refusals: Vec<String> = Vec::new();

    // The subsystem, then each exec candidate.
    let mut attempts: Vec<(String, bool)> = vec![("sftp".to_string(), false)];
    for candidate in SFTP_SERVER_CANDIDATES {
        attempts.push((candidate.to_string(), true));
    }

    for (name, is_exec) in attempts {
        let opened = {
            let inner = state.inner.borrow();
            if is_exec {
                inner.core.open_exec_channel(&name)
            } else {
                inner.core.open_subsystem(&name)
            }
        };
        let ch = match opened {
            Ok(ch) => ch,
            Err(e) => {
                // Decidable without the wire: not `ready`, or the
                // connection is already gone. Every candidate would fail
                // the same way, so stop here.
                return Err(format!("open an sftp channel: {e}"));
            }
        };

        {
            let mut held = state.sftp.borrow_mut();
            let mut s = Sftp {
                ch,
                framer: sftp::Framer::new(),
                corr: sftp::Correlator::new(),
                live: Vec::new(),
                out: Vec::new(),
                limits: None,
                version_seen: None,
                dead: None,
            };
            s.out.extend_from_slice(&sftp::encode_init());
            *held = Some(s);
        }

        match await_version(state).await {
            Ok(extensions) => {
                if extensions.contains(sftp::Extensions::LIMITS) {
                    fetch_limits(state).await;
                }
                return Ok(());
            }
            Err(reason) => {
                {
                    let mut held = state.sftp.borrow_mut();
                    if let Some(s) = held.as_mut() {
                        s.ch.close();
                    }
                    *held = None;
                }
                refusals.push(format!("{name}: {reason}"));
            }
        }
    }

    Err(format!(
        "no sftp server on the target -- the `sftp` subsystem and every known \
         sftp-server path were refused ({})",
        refusals.join("; ")
    ))
}

/// Pump until the server's VERSION arrives, the channel dies, or the
/// session does. This is the reply-or-`closed` race core.wit describes.
async fn await_version(state: &Rc<State>) -> Result<sftp::Extensions, String> {
    loop {
        let progress = pump_round(state);

        // The VERSION packet is the one response with no request id, so
        // `deliver` cannot route it; look for it directly.
        let verdict = {
            let mut held = state.sftp.borrow_mut();
            match held.as_mut() {
                None => Some(Err("the sftp channel vanished".to_string())),
                Some(s) => {
                    if let Some(reason) = &s.dead {
                        Some(Err(reason.clone()))
                    } else {
                        s.version_seen.take().map(Ok)
                    }
                }
            }
        };
        if let Some(v) = verdict {
            return v;
        }

        {
            let inner = state.inner.borrow();
            if inner.detached || inner.link_down {
                return Err("the session ended".to_string());
            }
            if let crate::CoreStatus::Closed(reason) = inner.core.status() {
                return Err(format!("the session closed: {reason}"));
            }
        }

        if progress {
            yield_now().await;
        } else {
            sleep_ms(IDLE_TICK_MS).await;
        }
    }
}

/// Ask for `limits@openssh.com` and size chunks from the answer. Purely
/// an optimisation: a server that refuses simply keeps the draft's
/// default payload size.
async fn fetch_limits(state: &Rc<State>) {
    let Ok(resp) = request(state, sftp::encode_limits).await else {
        return;
    };
    if let sftp::Response::ExtendedReply { payload, .. } = resp {
        if let Ok(limits) = sftp::parse_limits(&payload) {
            if let Some(s) = state.sftp.borrow_mut().as_mut() {
                s.limits = Some(limits);
            }
        }
    }
}

fn read_payload(state: &Rc<State>) -> u32 {
    payload_size(state.sftp.borrow().as_ref().and_then(|s| s.limits.map(|l| l.read_len)))
}

fn write_payload(state: &Rc<State>) -> u32 {
    payload_size(
        state
            .sftp
            .borrow()
            .as_ref()
            .and_then(|s| s.limits.map(|l| l.write_len)),
    )
}

// ---------------------------------------------------------------------
// list-dir
// ---------------------------------------------------------------------

/// REALPATH the caller's bytes, then OPENDIR/READDIR to EOF.
///
/// Runs inline in the export (terminal.wit permits it: a listing is
/// bounded, unlike a transfer) but still on the engine's round loop, so
/// it neither blocks the core nor polls it at a fixed interval.
pub(crate) async fn list_dir(state: &Rc<State>, path: Vec<u8>) -> Result<Vec<DirEntry>, String> {
    ensure_open(state).await?;
    match list_dir_inner(state, &path).await {
        Ok(entries) => Ok(entries),
        Err(Halt::Fatal(e)) | Err(Halt::Reanchor(e)) => Err(e),
    }
}

async fn list_dir_inner(state: &Rc<State>, path: &[u8]) -> Result<Vec<DirEntry>, Halt> {
    // REALPATH first, so relative input ("." or a name from a previous
    // listing) resolves against the SSH user's home, as terminal.wit
    // promises.
    let canonical = {
        let p = path.to_vec();
        match request(state, |id| sftp::encode_realpath(id, &p)).await? {
            sftp::Response::Name { entries, .. } => entries
                .into_iter()
                .next()
                .map(|e| e.filename)
                .unwrap_or_else(|| path.to_vec()),
            sftp::Response::Status { result, .. } => {
                return Err(Halt::Fatal(match result {
                    Err(e) => format!("resolve the remote path: {e}"),
                    Ok(_) => "resolve the remote path: no name returned".to_string(),
                }))
            }
            other => {
                return Err(Halt::Fatal(format!(
                    "resolve the remote path: the server answered with {}",
                    describe(&other)
                )))
            }
        }
    };

    let handle = {
        let p = canonical.clone();
        match request(state, |id| sftp::encode_opendir(id, &p)).await? {
            sftp::Response::Handle { handle, .. } => handle,
            sftp::Response::Status { result, .. } => {
                return Err(Halt::Fatal(match result {
                    Err(e) => format!("open the remote directory: {e}"),
                    Ok(_) => "open the remote directory: no handle returned".to_string(),
                }))
            }
            other => {
                return Err(Halt::Fatal(format!(
                    "open the remote directory: the server answered with {}",
                    describe(&other)
                )))
            }
        }
    };

    let mut out: Vec<DirEntry> = Vec::new();
    let mut overflow = false;
    loop {
        let h = handle.clone();
        let resp = match request(state, |id| sftp::encode_readdir(id, &h)).await {
            Ok(resp) => resp,
            Err(e) => {
                close_handle(state, &handle).await;
                return Err(e);
            }
        };
        match resp {
            sftp::Response::Name { entries, .. } => {
                for entry in entries {
                    // "." and ".." are the server's business, not the
                    // browser's: a page navigates with the path it
                    // already has.
                    if entry.filename == b"." || entry.filename == b".." {
                        continue;
                    }
                    if out.len() >= MAX_DIR_ENTRIES {
                        overflow = true;
                        break;
                    }
                    out.push(to_dir_entry(entry));
                }
                if overflow {
                    break;
                }
            }
            // SSH_FX_EOF ends the listing and is NOT an error -- the
            // codec splits it out precisely so this cannot be confused.
            sftp::Response::Status { result, .. } => match result {
                Ok(sftp::StatusOutcome::Eof) | Ok(sftp::StatusOutcome::Ok) => break,
                Err(e) => {
                    close_handle(state, &handle).await;
                    return Err(Halt::Fatal(format!("read the remote directory: {e}")));
                }
            },
            other => {
                close_handle(state, &handle).await;
                return Err(Halt::Fatal(format!(
                    "read the remote directory: the server answered with {}",
                    describe(&other)
                )));
            }
        }
    }
    close_handle(state, &handle).await;

    if overflow {
        return Err(Halt::Fatal(format!(
            "the remote directory holds more than {MAX_DIR_ENTRIES} entries: refusing \
             to build a listing that large"
        )));
    }

    sort_entries(&mut out);
    Ok(out)
}

fn to_dir_entry(entry: sftp::NameEntry) -> DirEntry {
    DirEntry {
        display: String::from_utf8_lossy(&entry.filename).into_owned(),
        is_dir: is_dir(entry.raw_permissions, &entry.longname),
        size: entry.attrs.get_size(),
        mtime: entry.attrs.get_time().map(|(_, m)| m.into_raw() as u64),
        name: entry.filename,
    }
}

// ---------------------------------------------------------------------
// The transfer resource
// ---------------------------------------------------------------------

/// Everything the engine task and the resource facade share. The facade
/// only ever reads (and sets two flags); the engine only ever writes.
pub(crate) struct Shared {
    direction: TransferDirection,
    done: u64,
    total: Option<u64>,
    outcome: Option<Result<(), String>>,
    /// The page called `cancel`.
    cancelled: bool,
    /// The page dropped the handle. terminal.wit is explicit that there
    /// is no orphaned background transfer: a page that wants one to
    /// continue holds its resource.
    dropped: bool,
}

impl Shared {
    fn new(direction: TransferDirection) -> Self {
        Shared {
            direction,
            done: 0,
            total: None,
            outcome: None,
            cancelled: false,
            dropped: false,
        }
    }

    /// The terminal outcome, recorded once. A later cancel or failure
    /// cannot overwrite a completed transfer's verdict.
    fn finish(&mut self, outcome: Result<(), String>) {
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
        }
    }
}

/// The page's handle on one transfer: a window onto engine state, and the
/// thing that cancels it.
pub struct TransferHandle {
    shared: Rc<RefCell<Shared>>,
}

impl Drop for TransferHandle {
    fn drop(&mut self) {
        self.shared.borrow_mut().dropped = true;
    }
}

impl GuestTransfer for TransferHandle {
    /// Cheap, current, and free of side effects -- in particular the
    /// outcome is NOT cleared by observation (terminal.wit contrasts this
    /// with the probe's park-and-poll): a finished transfer stays
    /// observable until this resource drops.
    async fn progress(&self) -> TransferProgress {
        let shared = self.shared.borrow();
        TransferProgress {
            direction: shared.direction,
            done: shared.done,
            total: shared.total,
            outcome: shared.outcome.clone(),
        }
    }

    /// Idempotent, and deliberately inert: it raises a flag and does
    /// nothing else.
    ///
    /// Every import call a cancellation implies -- CLOSE of the remote
    /// handle, the sink's final flush, the pumping that lets already-
    /// issued requests answer -- happens in the engine task, never here.
    /// Two rules force that. Tearing down from this export would mean
    /// dropping awaits that must not be dropped (the no-cancel
    /// discipline in lib.rs's header). And an export is a poor place to
    /// leave the component instance from: the canonical ABI forbids it
    /// outright in some windows, and this codebase has already been
    /// bitten by a boundary crossing from the wrong context.
    ///
    /// It does not even WAKE the engine, which is a choice rather than
    /// an oversight: a wake across tasks is itself a boundary crossing,
    /// and the engine's own idle tick notices the flag within
    /// [`IDLE_TICK_MS`]. Nothing here is worth 5 ms of latency.
    async fn cancel(&self) {
        request_cancel(&self.shared);
    }
}

/// Why the engine stopped issuing new work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Stop {
    Cancelled,
    Dropped,
}

fn stop_requested(shared: &Rc<RefCell<Shared>>) -> Option<Stop> {
    let s = shared.borrow();
    if s.cancelled {
        Some(Stop::Cancelled)
    } else if s.dropped {
        Some(Stop::Dropped)
    } else {
        None
    }
}

fn stop_message(stop: Stop) -> String {
    match stop {
        Stop::Cancelled => "cancelled".to_string(),
        Stop::Dropped => "the transfer handle was dropped".to_string(),
    }
}

/// The whole of what `cancel` does. Factored out so the property that
/// matters -- that cancelling touches shared state and NOTHING else, no
/// import, no await, no teardown -- is a thing a native test can hold on
/// to rather than a thing a reader has to re-derive from the export.
pub(crate) fn request_cancel(shared: &Rc<RefCell<Shared>>) {
    shared.borrow_mut().cancelled = true;
}

/// Whether a transfer loop may stop at this round boundary, and with
/// what verdict. `None` means keep pumping.
///
/// The first clause is the no-cancel discipline in numeric form: while
/// anything is still in flight the answer is always "keep pumping",
/// because those requests are already on the wire and abandoning them
/// would leave the SFTP stream talking to nobody. Cancel stops the
/// engine ISSUING; it never drops what was issued.
///
/// Completion outranks cancellation on purpose. A cancel that lands in
/// the same round as the last acknowledgement describes a transfer that
/// did, in fact, finish -- and reporting `cancelled` for a file that is
/// wholly transferred would have the page show a failure for a success.
pub(crate) fn quiesce_step(
    stop: Option<Stop>,
    inflight_empty: bool,
    all_issued: bool,
) -> Option<Result<(), String>> {
    if !inflight_empty {
        return None;
    }
    if all_issued {
        return Some(Ok(()));
    }
    stop.map(|s| Err(stop_message(s)))
}

/// What one attempt at a transfer concluded.
enum Attempt {
    Done,
    Failed(String),
    Retry(String),
}

impl From<Halt> for Attempt {
    fn from(h: Halt) -> Attempt {
        match h {
            Halt::Fatal(e) => Attempt::Failed(e),
            Halt::Reanchor(e) => Attempt::Retry(e),
        }
    }
}

/// The outer loop both directions share: run an attempt, and on a
/// re-anchorable interruption park briefly and run it again from scratch.
/// A re-anchor re-derives the resume point from the two ends, which is
/// the only moment `progress.done` may dip (terminal.wit).
///
/// `attempt` hands back a fresh, fully-owned future each time it is
/// called (every engine clones its `Rc`s into the future rather than
/// borrowing them from the closure): a closure that LENT its captures to
/// the future it returns cannot be expressed as `FnMut() -> Fut`.
async fn supervise<F, Fut>(state: Rc<State>, shared: Rc<RefCell<Shared>>, mut attempt: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Attempt>,
{
    let mut futility = Futility::new(MAX_FUTILE_REANCHORS, shared.borrow().done);
    loop {
        match attempt().await {
            Attempt::Done => {
                shared.borrow_mut().finish(Ok(()));
                return;
            }
            Attempt::Failed(e) => {
                shared.borrow_mut().finish(Err(e));
                return;
            }
            Attempt::Retry(reason) => {
                if let Some(stop) = stop_requested(&shared) {
                    shared.borrow_mut().finish(Err(stop_message(stop)));
                    return;
                }
                // Wait for a session that can carry SFTP at all before
                // deciding anything. A transport that is down or mid
                // resume is the SESSION's problem and it is already on
                // it; re-opening a channel against it would fail on
                // `Connection refused` at this supervisor's expense,
                // which is precisely the accounting mistake this split
                // exists to prevent.
                let waited = match await_session_ready(&state, &shared).await {
                    SessionWait::AlreadyReady => false,
                    SessionWait::Recovered => true,
                    SessionWait::Stopped(stop) => {
                        shared.borrow_mut().finish(Err(stop_message(stop)));
                        return;
                    }
                    SessionWait::Gone(why) => {
                        shared.borrow_mut().finish(Err(why));
                        return;
                    }
                };

                let done = shared.borrow().done;
                if futility.charge(!waited, done) {
                    shared.borrow_mut().finish(Err(format!(
                        "{reason} -- and {MAX_FUTILE_REANCHORS} further attempts on a                          live session moved nothing, so this is not going to settle"
                    )));
                    return;
                }
                eprintln!("transfer: {reason}; re-anchoring");
                sleep_ms(REANCHOR_DELAY_MS).await;
            }
        }
    }
}

/// How a wait for a usable session ended.
enum SessionWait {
    /// The session was `ready` the moment we looked -- so whatever went
    /// wrong was SFTP-level, and it counts against the transfer.
    AlreadyReady,
    /// The transport was down or resuming and has since come back. The
    /// session's resume machine did the work and its budget paid for it.
    Recovered,
    /// The page cancelled or dropped the transfer while we waited.
    Stopped(Stop),
    /// The session ended for good; no re-anchor can help.
    Gone(String),
}

/// Park until the session can carry SFTP again, however long its own
/// resume machine takes.
///
/// There is deliberately no deadline here. The session already has one
/// -- `RESUME_WINDOW_MS`, ten minutes of TRYING -- and when it expires
/// the session declares itself dead, which this loop observes as
/// [`SessionWait::Gone`]. A second, shorter deadline layered on top
/// would do nothing but abandon transfers the session was still about to
/// rescue.
async fn await_session_ready(state: &Rc<State>, shared: &Rc<RefCell<Shared>>) -> SessionWait {
    let mut waited = false;
    loop {
        let verdict = {
            let inner = state.inner.borrow();
            if inner.detached {
                Err(SessionWait::Gone("the session was detached".to_string()))
            } else if let crate::CoreStatus::Closed(reason) = inner.core.status() {
                Err(SessionWait::Gone(format!("the session closed: {reason}")))
            } else if inner.link_down {
                Err(SessionWait::Gone(
                    "the connection was lost and could not be resumed".to_string(),
                ))
            } else if inner.resuming || inner.stalled {
                // Reconnecting, or parked waiting for `wake`. Either way
                // the session owns what happens next.
                Ok(false)
            } else {
                Ok(matches!(inner.core.status(), crate::CoreStatus::Ready))
            }
        };
        match verdict {
            Err(gone) => return gone,
            Ok(true) => {
                return if waited {
                    SessionWait::Recovered
                } else {
                    SessionWait::AlreadyReady
                }
            }
            Ok(false) => {}
        }
        if let Some(stop) = stop_requested(shared) {
            return SessionWait::Stopped(stop);
        }
        waited = true;
        sleep_ms(REANCHOR_DELAY_MS).await;
    }
}

// ---------------------------------------------------------------------
// upload
// ---------------------------------------------------------------------

/// Start an upload and return once it is UNDERWAY, per terminal.wit:
/// everything after this point is reported through the resource.
pub(crate) async fn start_upload(
    state: &Rc<State>,
    source: Source,
    remote_path: Vec<u8>,
    overwrite: bool,
) -> Result<Transfer, String> {
    require_ready(state)?;
    let shared = Rc::new(RefCell::new(Shared::new(TransferDirection::Upload)));
    let handle = Transfer::new(TransferHandle {
        shared: shared.clone(),
    });
    let state = state.clone();
    let engine_shared = shared.clone();
    wit_bindgen::spawn_local(async move {
        let source = Rc::new(source);
        let path = Rc::new(remote_path);
        let total = source.size().await;
        engine_shared.borrow_mut().total = Some(total);
        let supervised = engine_shared.clone();
        supervise(state.clone(), supervised, move || {
            upload_attempt(
                state.clone(),
                source.clone(),
                path.clone(),
                overwrite,
                engine_shared.clone(),
                total,
            )
        })
        .await;
    });
    Ok(handle)
}

async fn upload_attempt(
    state: Rc<State>,
    source: Rc<Source>,
    path: Rc<Vec<u8>>,
    overwrite: bool,
    shared: Rc<RefCell<Shared>>,
    total: u64,
) -> Attempt {
    let state = &state;
    let shared = &shared;
    let path: &[u8] = &path;
    if let Some(stop) = stop_requested(shared) {
        return Attempt::Failed(stop_message(stop));
    }
    if let Err(e) = ensure_open(state).await {
        return Attempt::Failed(e);
    }

    // --- anchor -------------------------------------------------------
    let remote_len = if overwrite {
        None
    } else {
        match stat_optional(state, path).await {
            Ok(attrs) => attrs.and_then(|a| a.get_size()),
            Err(h) => return h.into(),
        }
    };

    let plan = plan_upload(remote_len, total, overwrite);
    let (flags, mut next) = match &plan {
        UploadPlan::Refuse(e) => return Attempt::Failed(e.clone()),
        UploadPlan::Fresh => (SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC, 0u64),
        // Read as well as write: the tail comparison reads back from the
        // very handle it will then append through, so there is no window
        // in which another OPEN could see a different file.
        UploadPlan::Verify { .. } => (SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_CREAT, 0u64),
    };

    let handle = match open_handle(state, path, flags).await {
        Ok(h) => h,
        Err(h) => return h.into(),
    };

    if let UploadPlan::Verify { remote_len, tail } = plan {
        let from = remote_len - tail;
        let remote_tail = match read_exact_remote(state, &handle, from, tail).await {
            Ok(bytes) => bytes,
            Err(h) => {
                close_handle(state, &handle).await;
                return h.into();
            }
        };
        let local_tail = match source.read(from, tail as u32).await {
            Ok(bytes) => bytes,
            Err(e) => {
                close_handle(state, &handle).await;
                return Attempt::Failed(format!("read the source's tail: {e}"));
            }
        };
        let equal = remote_tail.len() as u64 == tail && remote_tail == local_tail;
        match resume_after_verify(remote_len, total, equal) {
            Ok(UploadStart::Complete) => {
                close_handle(state, &handle).await;
                shared.borrow_mut().done = total;
                return Attempt::Done;
            }
            Ok(UploadStart::Append(at)) => next = at,
            Err(e) => {
                close_handle(state, &handle).await;
                return Attempt::Failed(e);
            }
        }
    }

    shared.borrow_mut().done = next;

    // --- the write loop -----------------------------------------------
    let chunk = write_payload(state);
    // Permits come from the SESSION's pool, not from a fresh budget of
    // this transfer's own: the replay buffer they protect is shared by
    // every transfer on the session.
    let mut permits = Permits::new(state.transfer_budget.clone());
    // (offset, length, slot) per WRITE on the wire.
    let mut inflight: Vec<(u64, u64, Slot)> = Vec::new();
    let mut acked = next;
    let mut stopping: Option<Stop> = None;
    let mut failure: Option<Attempt> = None;

    loop {
        if stopping.is_none() {
            stopping = stop_requested(shared);
        }

        // Harvest what the server has answered.
        let mut harvested = false;
        let mut i = 0;
        while i < inflight.len() {
            let ready = {
                let mut held = inflight[i].2.borrow_mut();
                match std::mem::replace(&mut *held, SlotState::Pending) {
                    SlotState::Pending => None,
                    other => Some(other),
                }
            };
            match ready {
                None => i += 1,
                Some(slot_state) => {
                    let (_, len, _) = inflight.remove(i);
                    permits.release(len);
                    harvested = true;
                    match slot_state {
                        SlotState::Ready(resp) => match expect_status(resp, "write to the remote file") {
                            Ok(_) => {
                                acked += len;
                                shared.borrow_mut().done = acked;
                            }
                            Err(h) => failure = Some(h.into()),
                        },
                        SlotState::Failed(e) => failure = Some(Attempt::Retry(e)),
                        SlotState::Pending => unreachable!("filtered above"),
                    }
                }
            }
        }

        if let Some(f) = failure {
            close_handle(state, &handle).await;
            return f;
        }

        // Done, or quiesced: either way, only once nothing is in flight.
        if let Some(verdict) = quiesce_step(stopping, inflight.is_empty(), next >= total) {
            close_handle(state, &handle).await;
            return match verdict {
                Err(e) => Attempt::Failed(e),
                Ok(()) => {
                    shared.borrow_mut().done = acked;
                    Attempt::Done
                }
            };
        }

        // Issue more, up to the replay budget (module header).
        let mut issued = false;
        while stopping.is_none() && next < total {
            let want = ((total - next).min(chunk as u64)) as u32;
            // Take the permit BEFORE reading the source: a read whose
            // bytes then have nowhere to go would have to be thrown away
            // and re-read, and the source is the host's storage.
            if !permits.try_charge(want as u64) {
                break;
            }
            let data = match source.read(next, want).await {
                Ok(data) => data,
                Err(e) => {
                    close_handle(state, &handle).await;
                    return Attempt::Failed(format!("read the source: {e}"));
                }
            };
            // transfer-io's source is short "only at end-of-file", and
            // `want` was clipped to what is left, so a short read here
            // means the file changed under the transfer. That is the
            // user's own race, and the honest answer is to say so rather
            // than upload a file with a hole in it.
            if (data.len() as u64) < want as u64 {
                close_handle(state, &handle).await;
                return Attempt::Failed(format!(
                    "the source ran out at {} bytes but reported a size of {total}: \
                     it changed while the upload was running",
                    next + data.len() as u64
                ));
            }
            let len = data.len() as u64;
            let at = next;
            let h = handle.clone();
            let slot = match submit(state, move |id| sftp::encode_write(id, &h, at, &data)) {
                Ok(slot) => slot,
                Err(halt) => {
                    close_handle(state, &handle).await;
                    return halt.into();
                }
            };
            inflight.push((at, len, slot));
            next += len;
            issued = true;
        }

        let progress = match round(state) {
            Ok(p) => p,
            Err(halt) => {
                // The channel or the session went. Whatever was acked is
                // on the remote file and a re-anchor will find it.
                close_handle_eventually(state, &handle);
                return halt.into();
            }
        };
        if progress || harvested || issued {
            yield_now().await;
        } else {
            sleep_ms(IDLE_TICK_MS).await;
        }
    }
}

// ---------------------------------------------------------------------
// download
// ---------------------------------------------------------------------

pub(crate) async fn start_download(
    state: &Rc<State>,
    remote_path: Vec<u8>,
    sink: Sink,
    overwrite: bool,
) -> Result<Transfer, String> {
    require_ready(state)?;
    let shared = Rc::new(RefCell::new(Shared::new(TransferDirection::Download)));
    let handle = Transfer::new(TransferHandle {
        shared: shared.clone(),
    });
    let state = state.clone();
    let engine_shared = shared.clone();
    wit_bindgen::spawn_local(async move {
        let sink = Rc::new(sink);
        let path = Rc::new(remote_path);
        // The remote's identity, captured at FIRST start and compared on
        // every re-anchor thereafter. It lives here, in the transfer's
        // own state, because that is the only place that outlives an
        // interruption (terminal.wit's `download`).
        let identity: Rc<RefCell<Option<RemoteId>>> = Rc::new(RefCell::new(None));
        let supervised = engine_shared.clone();
        supervise(state.clone(), supervised, move || {
            download_attempt(
                state.clone(),
                sink.clone(),
                path.clone(),
                overwrite,
                engine_shared.clone(),
                identity.clone(),
            )
        })
        .await;
    });
    Ok(handle)
}

async fn download_attempt(
    state: Rc<State>,
    sink: Rc<Sink>,
    path: Rc<Vec<u8>>,
    overwrite: bool,
    shared: Rc<RefCell<Shared>>,
    identity: Rc<RefCell<Option<RemoteId>>>,
) -> Attempt {
    let state = &state;
    let sink = &sink;
    let shared = &shared;
    let identity = &identity;
    let path: &[u8] = &path;
    if let Some(stop) = stop_requested(shared) {
        return Attempt::Failed(stop_message(stop));
    }
    if let Err(e) = ensure_open(state).await {
        return Attempt::Failed(e);
    }

    let handle = match open_handle(state, path, SSH_FXF_READ).await {
        Ok(h) => h,
        Err(h) => return h.into(),
    };
    let attrs = match fstat(state, &handle).await {
        Ok(attrs) => attrs,
        Err(h) => {
            close_handle(state, &handle).await;
            return h.into();
        }
    };
    let Some(remote_len) = attrs.get_size() else {
        close_handle(state, &handle).await;
        return Attempt::Failed(
            "the server would not report the remote file's size, so there is no way to \
             know when the download is complete"
                .to_string(),
        );
    };
    let now_id = RemoteId {
        size: remote_len,
        mtime: attrs.get_time().map(|(_, m)| m.into_raw() as u64),
    };

    // First start captures; every later attempt compares. The verdict
    // is reached under the borrow and acted on after it, because the
    // action awaits (module header of lib.rs: a RefCell borrow never
    // spans an `.await`).
    let identity_verdict = {
        let mut held = identity.borrow_mut();
        match held.as_ref() {
            None => {
                *held = Some(now_id);
                Ok(())
            }
            Some(first) => check_identity(first, &now_id),
        }
    };
    if let Err(e) = identity_verdict {
        close_handle(state, &handle).await;
        return Attempt::Failed(e);
    }
    shared.borrow_mut().total = Some(remote_len);

    let committed = sink.committed().await;
    let mut next = match plan_download(committed, remote_len, overwrite) {
        Ok(DownloadPlan::Complete) => {
            close_handle(state, &handle).await;
            if let Err(e) = sink.flush().await {
                return Attempt::Failed(format!("flush the destination: {e}"));
            }
            shared.borrow_mut().done = sink.committed().await;
            return Attempt::Done;
        }
        Ok(DownloadPlan::Start(at)) => at,
        Err(e) => {
            close_handle(state, &handle).await;
            return Attempt::Failed(e);
        }
    };

    // `written` is what has reached the sink in order; `next` is the
    // offset the next READ asks for. They differ by whatever is in
    // flight or waiting to be re-ordered.
    let mut written = next;
    shared.borrow_mut().done = committed;

    let chunk = read_payload(state);
    // Permits come from the SESSION's pool -- see the upload engine.
    let mut permits = Permits::new(state.transfer_budget.clone());
    let mut inflight: Vec<(u64, u64, Slot)> = Vec::new();
    // Out-of-order arrivals, keyed by offset. Bounded by the pool: a
    // reply can only exist because a request held permits for it.
    let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    // Gaps left by short DATA replies, carried ACROSS rounds. They must
    // outlive the round that discovered them: with a contended pool a
    // refill can fail to get permits, and a gap dropped on the floor
    // stalls the in-order writer for good.
    let mut refills: Vec<(u64, u64)> = Vec::new();
    let mut since_flush = 0u64;
    let mut eof_at: Option<u64> = None;
    let mut stopping: Option<Stop> = None;

    loop {
        if stopping.is_none() {
            stopping = stop_requested(shared);
        }

        // Harvest.
        let mut harvested = false;
        let mut failure: Option<Attempt> = None;
        let mut i = 0;
        while i < inflight.len() {
            let ready = {
                let mut held = inflight[i].2.borrow_mut();
                match std::mem::replace(&mut *held, SlotState::Pending) {
                    SlotState::Pending => None,
                    other => Some(other),
                }
            };
            match ready {
                None => i += 1,
                Some(slot_state) => {
                    let (at, want, _) = inflight.remove(i);
                    permits.release(want);
                    harvested = true;
                    match slot_state {
                        SlotState::Ready(sftp::Response::Data { data, .. }) => {
                            let got = data.len() as u64;
                            if got == 0 {
                                eof_at = Some(eof_at.map_or(at, |e| e.min(at)));
                            } else {
                                if got < want {
                                    // A short DATA is ordinary (draft sec
                                    // 6.5): re-ask for the remainder
                                    // rather than leave a hole the
                                    // in-order writer would stall on.
                                    refills.push((at + got, want - got));
                                }
                                pending.insert(at, data);
                            }
                        }
                        SlotState::Ready(sftp::Response::Status { result, .. }) => match result {
                            // EOF on a READ is not an error -- the codec
                            // splits it out so this cannot be mistaken.
                            Ok(_) => eof_at = Some(eof_at.map_or(at, |e| e.min(at))),
                            Err(e) => {
                                failure =
                                    Some(Attempt::Failed(format!("read the remote file: {e}")))
                            }
                        },
                        SlotState::Ready(other) => {
                            failure = Some(Attempt::Failed(format!(
                                "read the remote file: the server answered with {}",
                                describe(&other)
                            )))
                        }
                        SlotState::Failed(e) => failure = Some(Attempt::Retry(e)),
                        SlotState::Pending => unreachable!("filtered above"),
                    }
                }
            }
        }
        if let Some(f) = failure {
            close_handle(state, &handle).await;
            let _ = sink.flush().await;
            return f;
        }

        // Write everything that is now contiguous. The sink is
        // append-only, so order is not a preference here.
        let mut wrote = false;
        while let Some(data) = pending.remove(&written) {
            let len = data.len() as u64;
            if let Err(e) = sink.write(data).await {
                close_handle(state, &handle).await;
                return Attempt::Failed(format!("write to the destination: {e}"));
            }
            written += len;
            since_flush += len;
            wrote = true;
            // `done` counts DURABLY committed bytes (terminal.wit), which
            // is the sink's number, not ours.
            let committed = sink.committed().await;
            shared.borrow_mut().done = committed;
        }
        if since_flush >= FLUSH_EVERY_BYTES {
            if let Err(e) = sink.flush().await {
                close_handle(state, &handle).await;
                return Attempt::Failed(format!("flush the destination: {e}"));
            }
            since_flush = 0;
            let committed = sink.committed().await;
            shared.borrow_mut().done = committed;
        }

        // Finished, cancelled, or the file ended early.
        //
        // The second clause is a stall guard, not an optimisation: with
        // nothing outstanding, nothing buffered out of order, nothing to
        // refill and nothing left to ask for, no future round can move
        // this transfer -- and without saying so the loop would idle on
        // its sleep forever rather than report what happened.
        let nothing_left = inflight.is_empty()
            && pending.is_empty()
            && refills.is_empty()
            && (eof_at.is_some() || next >= remote_len);
        let ended = written >= remote_len || nothing_left;
        if let Some(verdict) = quiesce_step(stopping, inflight.is_empty(), ended) {
            close_handle(state, &handle).await;
            // Whatever the verdict, what reached the sink stays there and
            // is made durable: a cancelled download's bytes are exactly
            // what a later resume continues from (terminal.wit).
            if let Err(e) = sink.flush().await {
                return Attempt::Failed(format!("flush the destination: {e}"));
            }
            let committed = sink.committed().await;
            shared.borrow_mut().done = committed;
            if let Err(e) = verdict {
                return Attempt::Failed(e);
            }
            if written < remote_len {
                // terminal.wit's `download`: a remote that ends short of
                // its stated size is a FAILURE that keeps the sink's
                // bytes -- nothing ever claims a file is whole that is
                // not.
                return Attempt::Failed(format!(
                    "the remote file ended at {written} bytes but was reported as \
                     {remote_len}: it was truncated while the download was running"
                ));
            }
            return Attempt::Done;
        }

        // Issue more reads, and any refills first: a hole stalls the
        // in-order writer, so it is the most valuable request to make.
        let mut issued = false;
        if stopping.is_none() {
            // Refills first: a gap stalls the in-order writer, so it is
            // the most valuable request to make. One that cannot get
            // permits this round stays in the list for the next.
            let mut deferred: Vec<(u64, u64)> = Vec::new();
            for (at, len) in refills.drain(..) {
                let want = len.min(chunk as u64);
                if !permits.try_charge(want) {
                    deferred.push((at, len));
                    continue;
                }
                match issue_read(state, &handle, at, want as u32) {
                    Ok(slot) => {
                        inflight.push((at, want, slot));
                        issued = true;
                    }
                    Err(halt) => return halt.into(),
                }
                // A refill clipped to `chunk` leaves the rest of the gap
                // behind; it is asked for on a later round.
                if want < len {
                    deferred.push((at + want, len - want));
                }
            }
            refills = deferred;

            while next < remote_len && eof_at.is_none() {
                let want = ((remote_len - next).min(chunk as u64)) as u32;
                if !permits.try_charge(want as u64) {
                    break;
                }
                match issue_read(state, &handle, next, want) {
                    Ok(slot) => {
                        inflight.push((next, want as u64, slot));
                        next += want as u64;
                        issued = true;
                    }
                    Err(halt) => return halt.into(),
                }
            }
        }

        let progress = match round(state) {
            Ok(p) => p,
            Err(halt) => {
                // Park. What reached the sink is durable up to its own
                // `committed`, which is exactly where the re-anchor picks
                // up -- so `done` may dip here, as terminal.wit allows.
                close_handle_eventually(state, &handle);
                let _ = sink.flush().await;
                return halt.into();
            }
        };
        if progress || harvested || issued || wrote {
            yield_now().await;
        } else {
            sleep_ms(IDLE_TICK_MS).await;
        }
    }
}

fn issue_read(state: &Rc<State>, handle: &[u8], at: u64, want: u32) -> Result<Slot, Halt> {
    let h = handle.to_vec();
    submit(state, move |id| sftp::encode_read(id, &h, at, want))
}

/// Every SFTP operation needs an authenticated, running session: the bulk
/// plane refuses to open a channel otherwise (core.wit), and saying so
/// here is more legible than a refusal three layers down.
fn require_ready(state: &Rc<State>) -> Result<(), String> {
    let inner = state.inner.borrow();
    match inner.core.status() {
        crate::CoreStatus::Ready => Ok(()),
        crate::CoreStatus::Closed(reason) => Err(format!("the session is closed: {reason}")),
        _ => Err("the session is not ready yet".to_string()),
    }
}

// ---------------------------------------------------------------------
// Tests for the decision logic
//
// These are plain Rust over numbers and bytes -- no WIT, no channel, no
// host, no await -- which is the whole reason the resume decisions were
// factored out of the engine loops in the first place: they are where a
// plausible-but-wrong answer silently corrupts a file. They run on the
// host toolchain, no wasm runner needed:
//
//     cargo test -p wosh-client
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_upload_when_nothing_is_there() {
        assert_eq!(plan_upload(None, 1000, false), UploadPlan::Fresh);
        assert_eq!(plan_upload(Some(0), 1000, false), UploadPlan::Fresh);
    }

    #[test]
    fn overwrite_ignores_whatever_is_there() {
        assert_eq!(plan_upload(Some(500), 1000, true), UploadPlan::Fresh);
        // Even a longer remote, which without overwrite is a refusal.
        assert_eq!(plan_upload(Some(5000), 1000, true), UploadPlan::Fresh);
    }

    #[test]
    fn a_longer_remote_is_refused_not_guessed() {
        match plan_upload(Some(2000), 1000, false) {
            UploadPlan::Refuse(msg) => assert!(msg.contains("longer")),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_shorter_remote_verifies_a_bounded_tail() {
        // Bigger than the verify window: clipped to it.
        assert_eq!(
            plan_upload(Some(10 * 1024 * 1024), 20 * 1024 * 1024, false),
            UploadPlan::Verify {
                remote_len: 10 * 1024 * 1024,
                tail: TAIL_VERIFY_BYTES,
            }
        );
        // Smaller than the window: the whole remote file is the tail.
        assert_eq!(
            plan_upload(Some(100), 1000, false),
            UploadPlan::Verify {
                remote_len: 100,
                tail: 100,
            }
        );
    }

    #[test]
    fn matching_tails_append_and_mismatching_ones_refuse() {
        assert_eq!(
            resume_after_verify(400, 1000, true),
            Ok(UploadStart::Append(400))
        );
        let refused = resume_after_verify(400, 1000, false).unwrap_err();
        assert!(refused.contains("do not match"));
        assert!(refused.contains("overwrite"));
    }

    #[test]
    fn an_equal_length_remote_with_a_matching_tail_is_already_done() {
        assert_eq!(
            resume_after_verify(1000, 1000, true),
            Ok(UploadStart::Complete)
        );
        // ... and one whose tail differs is the "tails disagree" refusal,
        // not a silent no-op.
        assert!(resume_after_verify(1000, 1000, false).is_err());
    }

    #[test]
    fn identity_holds_when_size_and_mtime_are_unchanged() {
        let id = RemoteId {
            size: 4096,
            mtime: Some(1_700_000_000),
        };
        assert!(check_identity(&id, &id).is_ok());
    }

    #[test]
    fn a_changed_size_or_mtime_refuses_the_resume() {
        let first = RemoteId {
            size: 4096,
            mtime: Some(1_700_000_000),
        };
        let resized = RemoteId {
            size: 8192,
            mtime: Some(1_700_000_000),
        };
        let touched = RemoteId {
            size: 4096,
            mtime: Some(1_700_000_001),
        };
        let untimed = RemoteId {
            size: 4096,
            mtime: None,
        };
        assert!(check_identity(&first, &resized).is_err());
        assert!(check_identity(&first, &touched).is_err());
        // An mtime that WAS reported and now is not cannot show the
        // bytes belong to this file either.
        assert!(check_identity(&first, &untimed).is_err());
    }

    #[test]
    fn a_server_that_never_reported_an_mtime_is_checked_on_size_alone() {
        let first = RemoteId {
            size: 4096,
            mtime: None,
        };
        assert!(check_identity(
            &first,
            &RemoteId {
                size: 4096,
                mtime: None
            }
        )
        .is_ok());
        // Size still decides.
        assert!(check_identity(
            &first,
            &RemoteId {
                size: 4097,
                mtime: None
            }
        )
        .is_err());
    }

    #[test]
    fn download_resumes_from_the_sinks_committed_anchor() {
        assert_eq!(
            plan_download(1024, 4096, false),
            Ok(DownloadPlan::Start(1024))
        );
        assert_eq!(plan_download(0, 4096, false), Ok(DownloadPlan::Start(0)));
        assert_eq!(plan_download(4096, 4096, false), Ok(DownloadPlan::Complete));
    }

    #[test]
    fn a_sink_holding_more_than_the_remote_is_refused() {
        let err = plan_download(8192, 4096, false).unwrap_err();
        assert!(err.contains("more bytes"));
    }

    #[test]
    fn overwrite_needs_an_empty_sink_because_a_sink_cannot_truncate() {
        assert_eq!(plan_download(0, 4096, true), Ok(DownloadPlan::Start(0)));
        let err = plan_download(10, 4096, true).unwrap_err();
        assert!(err.contains("append-only"));
    }

    #[test]
    fn the_budget_bounds_what_is_in_flight() {
        let mut b = Budget::new(1024);
        assert!(b.admits(512));
        b.charge(512);
        assert_eq!(b.outstanding(), 512);
        assert!(b.admits(512));
        b.charge(512);
        assert_eq!(b.outstanding(), 1024);
        // Full: nothing more goes on the wire until something is acked.
        assert!(!b.admits(1));
        b.release(512);
        assert!(b.admits(512));
        assert!(!b.admits(513));
    }

    #[test]
    fn the_budget_never_deadlocks_on_an_oversized_chunk() {
        let b = Budget::new(1024);
        // A single request larger than the whole budget still goes, so a
        // server advertising a huge chunk cannot wedge the transfer.
        assert!(b.admits(1 << 20));
        let mut b = Budget::new(1024);
        b.charge(1);
        assert!(!b.admits(1 << 20));
    }

    #[test]
    fn releases_never_underflow() {
        let mut b = Budget::new(1024);
        b.charge(10);
        b.release(100);
        assert_eq!(b.outstanding(), 0);
        assert!(b.admits(1024));
    }

    // --- the pool is per SESSION, not per transfer --------------------

    fn a_pool(limit: u64) -> Rc<RefCell<Budget>> {
        Rc::new(RefCell::new(Budget::new(limit)))
    }

    /// The property the module header claims and the per-transfer budget
    /// did not have: two transfers drawing on one session cannot exceed
    /// it BETWEEN them, however they interleave.
    #[test]
    fn two_transfers_cannot_jointly_exceed_the_pool() {
        let pool = a_pool(1024);
        let mut a = Permits::new(pool.clone());
        let mut b = Permits::new(pool.clone());

        assert!(a.try_charge(512));
        assert!(b.try_charge(512));
        // The pool is spent. Neither may take another byte, even though
        // each holds only half of it.
        assert!(!a.try_charge(1));
        assert!(!b.try_charge(1));
        assert_eq!(pool.borrow().outstanding(), 1024);

        // One acknowledgement frees exactly what it freed, for whoever
        // asks first.
        a.release(256);
        assert_eq!(pool.borrow().outstanding(), 768);
        assert!(b.try_charge(256));
        assert!(!a.try_charge(1));
    }

    /// The regression in its original arithmetic: seven concurrent
    /// transfers, each of which would have believed itself within
    /// budget, must not sum past the tunnel's replay cap.
    #[test]
    fn many_concurrent_transfers_stay_under_the_replay_cap() {
        let pool = a_pool(REPLAY_BUDGET_BYTES);
        let mut transfers: Vec<Permits> = (0..7).map(|_| Permits::new(pool.clone())).collect();
        // Every transfer pushes as hard as it can, round-robin.
        for _ in 0..64 {
            for t in transfers.iter_mut() {
                let _ = t.try_charge(64 * 1024);
            }
        }
        let outstanding = pool.borrow().outstanding();
        assert!(outstanding <= REPLAY_BUDGET_BYTES);
        assert!(
            outstanding < wosh_tunnel::REPLAY_CAP as u64,
            "seven transfers put {outstanding} bytes in flight, past the replay cap"
        );
    }

    /// Permits are returned by the pool even when an attempt leaves
    /// without tidying up -- which is the normal way an attempt ends
    /// when the channel dies under it.
    #[test]
    fn an_abandoned_attempt_returns_its_permits() {
        let pool = a_pool(1024);
        {
            let mut doomed = Permits::new(pool.clone());
            assert!(doomed.try_charge(1024));
            assert_eq!(doomed.held(), 1024);
            assert_eq!(pool.borrow().outstanding(), 1024);
            // ... and the attempt is abandoned here, holding everything.
        }
        assert_eq!(pool.borrow().outstanding(), 0);
        let mut next = Permits::new(pool.clone());
        assert!(next.try_charge(1024));
    }

    #[test]
    fn a_transfer_cannot_release_more_than_it_holds() {
        let pool = a_pool(1024);
        let mut a = Permits::new(pool.clone());
        let mut b = Permits::new(pool.clone());
        assert!(a.try_charge(256));
        assert!(b.try_charge(256));
        // A stray over-release must not hand away another transfer's
        // permits and let the pool overrun.
        a.release(4096);
        assert_eq!(a.held(), 0);
        assert_eq!(pool.borrow().outstanding(), 256);
    }

    #[test]
    fn the_replay_budget_stays_well_under_the_tunnels_cap() {
        // The whole reason REPLAY_BUDGET_BYTES exists: overflowing the
        // tunnel's replay buffer makes the session unresumable.
        assert!(REPLAY_BUDGET_BYTES < wosh_tunnel::REPLAY_CAP as u64 / 4);
    }

    /// The budget counts SFTP PAYLOAD; the wire adds SSH packet, channel
    /// and tunnel-frame overhead to every byte of it. A budget at the
    /// frame ceiling is therefore a budget over it -- which is how a
    /// 1,050,004-byte frame reached a listener that rejects anything
    /// above 1 MiB, and then got replayed unchanged forever.
    #[test]
    fn the_replay_budget_leaves_room_for_framing_overhead() {
        assert!(REPLAY_BUDGET_BYTES < wosh_tunnel::MAX_FRAME as u64);
        assert!(REPLAY_BUDGET_BYTES <= wosh_tunnel::MAX_FRAME as u64 / 2);
    }

    /// And regardless of the budget, no single frame may reach the
    /// ceiling: the resume tail is bounded by the replay cap, not by
    /// anything here, so the split in `write_data` is what keeps that
    /// path legal.
    #[test]
    fn the_wire_chunk_stays_under_the_frame_ceiling() {
        assert!(crate::MAX_WIRE_CHUNK < wosh_tunnel::MAX_FRAME);
        assert!(crate::MAX_WIRE_CHUNK * 4 <= wosh_tunnel::MAX_FRAME);
    }

    #[test]
    fn payload_size_falls_back_and_clamps() {
        assert_eq!(payload_size(None), DEFAULT_PAYLOAD);
        assert_eq!(payload_size(Some(0)), DEFAULT_PAYLOAD);
        assert_eq!(payload_size(Some(64 * 1024)), 64 * 1024);
        // Clamped so one packet stays well under the codec's cap.
        assert_eq!(payload_size(Some(1 << 30)), MAX_PAYLOAD);
        assert!((MAX_PAYLOAD as u64) < wosh_sftp::MAX_PACKET_LEN as u64);
    }

    // --- the two-budget split -----------------------------------------

    #[test]
    fn a_transfer_that_keeps_moving_never_exhausts_its_budget() {
        let mut f = Futility::new(MAX_FUTILE_REANCHORS, 0);
        // Every re-anchor happens on a live session -- the worst case for
        // this counter -- but each one is preceded by real progress.
        let mut done = 0u64;
        for _ in 0..1000 {
            done += 4096;
            assert!(!f.charge(true, done));
        }
        assert_eq!(f.strikes(), 0);
    }

    #[test]
    fn consecutive_futile_attempts_on_a_live_session_do_exhaust_it() {
        let mut f = Futility::new(MAX_FUTILE_REANCHORS, 0);
        for i in 1..MAX_FUTILE_REANCHORS {
            assert!(!f.charge(true, 0), "attempt {i} should not be terminal");
        }
        // The last one is: nothing moved, five times over, on a session
        // that was up throughout.
        assert!(f.charge(true, 0));
    }

    /// The T7 regression, in the form the counter sees it: one relay
    /// restart used to arrive here as five separate strikes.
    #[test]
    fn an_outage_the_session_is_handling_costs_the_transfer_nothing() {
        let mut f = Futility::new(MAX_FUTILE_REANCHORS, 0);
        for _ in 0..50 {
            assert!(!f.charge(false, 0));
        }
        assert_eq!(f.strikes(), 0);
        // And the budget is still whole afterwards, for failures that
        // really are the transfer's own.
        for _ in 1..MAX_FUTILE_REANCHORS {
            assert!(!f.charge(true, 0));
        }
        assert!(f.charge(true, 0));
    }

    #[test]
    fn progress_part_way_through_a_bad_patch_starts_the_count_over() {
        let mut f = Futility::new(MAX_FUTILE_REANCHORS, 0);
        assert!(!f.charge(true, 0));
        assert!(!f.charge(true, 0));
        assert_eq!(f.strikes(), 2);
        // One acknowledged chunk is enough: this transfer is moving.
        assert!(!f.charge(true, 32_000));
        assert_eq!(f.strikes(), 0);
        for _ in 1..MAX_FUTILE_REANCHORS {
            assert!(!f.charge(true, 32_000));
        }
        assert!(f.charge(true, 32_000));
    }

    /// `done` may legitimately DIP across a re-anchor (terminal.wit: a
    /// resume replays a verified tail). A dip is not progress, and must
    /// not be mistaken for it -- nor may it wedge the counter.
    #[test]
    fn a_done_count_that_dips_across_a_re_anchor_is_not_progress() {
        let mut f = Futility::new(MAX_FUTILE_REANCHORS, 1_000_000);
        assert!(!f.charge(true, 900_000));
        assert_eq!(f.strikes(), 1);
        // Climbing back to where it was is still not past the mark.
        assert!(!f.charge(true, 1_000_000));
        assert_eq!(f.strikes(), 2);
        // Genuinely past it, and the count resets.
        assert!(!f.charge(true, 1_000_001));
        assert_eq!(f.strikes(), 0);
    }

    // --- the cancel path ---------------------------------------------
    //
    // What these DO cover: that cancelling is a state mutation and
    // nothing more, that it never abandons requests already on the wire,
    // that it is idempotent, and that it cannot overwrite a verdict
    // already reached. That is the structure the browser trap was blamed
    // on, and it is testable here because `cancel` was deliberately
    // built out of nothing but shared state.
    //
    // What they do NOT cover, and cannot from a native test: the
    // component-model boundary itself. No native harness lifts this
    // module's exports through the canonical ABI, so "the export calls
    // no import" is enforced by construction and by review here, not by
    // assertion. The runtime-level proof is `just browser-transfer`
    // leg 4.

    fn a_running_transfer() -> Rc<RefCell<Shared>> {
        Rc::new(RefCell::new(Shared::new(TransferDirection::Download)))
    }

    #[test]
    fn cancel_only_raises_a_flag() {
        let shared = a_running_transfer();
        request_cancel(&shared);
        let s = shared.borrow();
        assert!(s.cancelled);
        // Nothing else moved: no outcome invented, no progress rewritten.
        assert!(s.outcome.is_none());
        assert_eq!(s.done, 0);
        assert!(!s.dropped);
    }

    #[test]
    fn cancel_is_idempotent() {
        let shared = a_running_transfer();
        request_cancel(&shared);
        request_cancel(&shared);
        assert_eq!(stop_requested(&shared), Some(Stop::Cancelled));
    }

    #[test]
    fn a_finished_transfer_keeps_its_verdict_when_cancelled_afterwards() {
        let shared = a_running_transfer();
        shared.borrow_mut().finish(Ok(()));
        request_cancel(&shared);
        // The flag is set, but the outcome recorded first stands: a
        // transfer that completed did not become a cancelled one.
        shared.borrow_mut().finish(Err("cancelled".to_string()));
        assert_eq!(shared.borrow().outcome, Some(Ok(())));
    }

    #[test]
    fn a_dropped_handle_stops_the_engine_too() {
        let shared = a_running_transfer();
        shared.borrow_mut().dropped = true;
        assert_eq!(stop_requested(&shared), Some(Stop::Dropped));
    }

    /// The no-cancel discipline, in the only form a test can hold: while
    /// requests are on the wire, cancellation cannot end the loop.
    #[test]
    fn cancel_never_abandons_requests_already_in_flight() {
        assert_eq!(
            quiesce_step(Some(Stop::Cancelled), false, false),
            None,
            "a cancelled transfer with requests in flight must keep pumping"
        );
        assert_eq!(quiesce_step(Some(Stop::Dropped), false, false), None);
        // Even a COMPLETE transfer waits for its acknowledgements.
        assert_eq!(quiesce_step(None, false, true), None);
    }

    #[test]
    fn cancel_reports_cancelled_once_the_wire_is_quiet() {
        assert_eq!(
            quiesce_step(Some(Stop::Cancelled), true, false),
            Some(Err("cancelled".to_string()))
        );
    }

    #[test]
    fn completion_outranks_a_cancel_that_lands_in_the_same_round() {
        // The transfer genuinely finished; calling that a cancellation
        // would show the page a failure for a file that fully moved.
        assert_eq!(
            quiesce_step(Some(Stop::Cancelled), true, true),
            Some(Ok(()))
        );
    }

    #[test]
    fn an_untouched_transfer_keeps_going() {
        assert_eq!(quiesce_step(None, true, false), None);
        assert_eq!(quiesce_step(None, false, false), None);
    }

    #[test]
    fn is_dir_reads_the_mode_word_when_there_is_one() {
        assert!(is_dir(Some(0o040755), b""));
        assert!(!is_dir(Some(0o100644), b""));
        assert!(!is_dir(Some(0o120777), b""));
        // An S_IFMT pattern POSIX does not define is not a directory,
        // and above all does not panic.
        assert!(!is_dir(Some(0o150000), b""));
    }

    /// The mode is authoritative; `longname` is only RECOMMENDED to look
    /// like `ls -l` (draft sec 7), so a server that disagrees with itself
    /// is believed on the mode.
    #[test]
    fn the_mode_word_outranks_the_long_name() {
        assert!(is_dir(
            Some(0o040755),
            b"-rw-r--r-- 1 u g 10 Jan 1 00:00 not-a-dir-apparently"
        ));
        assert!(!is_dir(
            Some(0o100644),
            b"drwxr-xr-x 2 u g 4096 Jan 1 00:00 claims-to-be-a-dir"
        ));
    }

    /// ATTRS without the PERMISSIONS flag: rare, legal, and all the
    /// long name is for.
    #[test]
    fn without_a_mode_the_long_name_is_the_fallback() {
        assert!(is_dir(None, b"drwxr-xr-x 2 u g 4096 Jan 1 00:00 sub"));
        assert!(!is_dir(None, b"-rw-r--r-- 1 u g 10 Jan 1 00:00 f"));
        assert!(!is_dir(None, b"lrwxrwxrwx 1 u g 3 Jan 1 00:00 l"));
    }

    #[test]
    fn neither_a_mode_nor_a_usable_long_name_is_not_a_directory() {
        assert!(!is_dir(None, b""));
        assert!(!is_dir(None, b"total 4"));
    }
}
