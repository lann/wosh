//! SFTP v3 wire codec and request/response correlation, for wosh-client's
//! in-browser file browser talking to OpenSSH's `sftp-server` subsystem.
//!
//! Authority: [draft-ietf-secsh-filexfer-02] ("SFTP version 3" -- the
//! version every OpenSSH server still speaks over the `sftp` subsystem;
//! versions 4+ were never adopted by OpenSSH and are out of scope here).
//! Section references in comments below (e.g. "sec 3", "sec 6.9") refer to
//! that draft.
//!
//! [draft-ietf-secsh-filexfer-02]: https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
//!
//! # Why sans-I/O
//!
//! `wosh-client` is a wasm32-wasip2 component: no tokio, no `std::net`, no
//! async runtime. The actual transport -- a synchronous
//! `subsystem-write`/`subsystem-drain` pair over a WIT boundary -- lives
//! above this crate. This crate only turns typed requests into bytes and
//! bytes into typed responses; it never touches a socket. That is also why
//! [`openssh-sftp-protocol`](openssh_sftp_protocol) is the right dependency
//! to build on: it is a verified sans-I/O codec (its dependency tree pulls
//! in none of tokio/mio/libc/getrandom/ring/bytes -- see `cargo tree -p
//! wosh-sftp --target wasm32-wasip2` in this crate's CI gate), so we are not
//! choosing a library that later turns out to assume a socket exists.
//!
//! # Why `SSH_FXP_NAME` is hand-decoded
//!
//! `openssh-sftp-protocol` decodes `READDIR`/`REALPATH` filenames as
//! `Box<Path>`. `Path`'s `Deserialize` impl is serde's blanket impl, which
//! routes through `str` -- it rejects any byte sequence that is not valid
//! UTF-8. SFTP v3 filenames are **raw bytes with no defined encoding** (the
//! draft never says otherwise), so a single non-UTF-8 entry in a directory
//! -- a stray `0xff` from a legacy encoding, a half-written rename, deliberate
//! mischief -- is a real, unremarkable thing to find on a Unix filesystem.
//! Worse: `response.rs`'s `SSH_FXP_NAME` decode loop uses `?` inside a `for`
//! loop over all entries in the packet, so ONE bad filename anywhere in a
//! directory listing aborts decoding of the ENTIRE listing, including every
//! well-formed entry before and after it. For a file browser that is a
//! correctness bug, not a cosmetic one: the directory becomes unbrowsable.
//!
//! The fix here is narrow on purpose: [`decode_response`] peeks the packet
//! type byte and hand-parses ONLY `SSH_FXP_NAME` (type 104) and its
//! filename/longname fields as `Vec<u8>`, never converting to `str` or
//! `Path` inside this crate (that conversion, if wanted at all, is the UI
//! layer's job, on data it can choose to render lossily). Every other
//! packet type is handed to the verified library unchanged. Do not
//! "simplify" this back to a blanket `Response::deserialize` call -- that
//! is exactly the bug this crate exists to avoid reintroducing.
//!
//! `SSH_FXP_DATA` (103) and `SSH_FXP_EXTENDED_REPLY` (201) are ALSO
//! hand-decoded, for a different reason: they are not variants of
//! `openssh_sftp_protocol::response::ResponseInner` at all (see that
//! crate's `Response::is_data`/`Response::is_extended_reply` helpers, which
//! exist precisely so callers intercept them upstream of the generic
//! decoder). `SSH_FXP_VERSION` (2) is likewise special-cased because it
//! carries no request id and is answered only once, at handshake.
//!
//! # Why request encoding is split between the library and hand-rolled code
//!
//! The rule this crate follows, uniformly, in both directions: **never let
//! `openssh-sftp-protocol`'s serde impls touch a path, a filename, or a
//! handle.** Paths and filenames are `&[u8]`/`Vec<u8>` end to end, because
//! SFTP v3 defines them as raw bytes with no encoding (sec 3's `string`
//! type is a length-prefixed byte string, full stop) -- not because this
//! crate is agnostic about it, but because treating them as anything else
//! is a correctness bug waiting to surface on a real filesystem (see the
//! `SSH_FXP_NAME` rationale above, which was the first place this bit us).
//! A lossy rendering for display, if ever wanted, is the UI layer's job on
//! data it can choose to render however it likes; this crate never performs
//! that conversion itself, in either direction.
//!
//! Concretely, that means:
//!
//! - Every path-bearing request (`OPEN`, `STAT`, `LSTAT`, `REALPATH`,
//!   `OPENDIR`, `posix-rename@openssh.com`) is hand-encoded, matching the
//!   wire format in sec 6.x byte for byte -- cross-checked against the
//!   independent hand-rolled reference encoder noted in the crate's test
//!   module, AND against a round-trip test that takes a non-UTF-8 filename
//!   straight out of a decoded `SSH_FXP_NAME` response and re-encodes it
//!   into these requests, asserting the bytes on the wire are identical to
//!   the bytes that came off the wire. That test is the actual point of
//!   this crate; do not delete it.
//! - `openssh_sftp_protocol::Handle`/`HandleOwned` -- the type
//!   `RequestInner::{Close,Read,Write,Fstat,Readdir,Fsync}` would require a
//!   reference to -- additionally wrap their byte buffer in a private
//!   (`pub(crate)`) field with no public constructor (the only way to
//!   obtain one is to decode it out of a `SSH_FXP_HANDLE` response, which
//!   this crate does not do, for the same reason as above), so every
//!   handle-bearing request is hand-encoded too.
//! - `INIT` and `limits@openssh.com` carry no path or handle at all (just a
//!   version number / a fixed extension name), so they are hand-encoded as
//!   well, for consistency and to avoid depending on
//!   `openssh_sftp_protocol::request` at all.
//! - `FileAttrs` (the `ATTRS` structure embedded in `OPEN`) has no path/
//!   filename hazard -- it is plain numeric fields -- so it stays the
//!   library's public, safe-to-use type, serialized in isolation via
//!   `ssh_format::Serializer` (no length-prefix header, since it is spliced
//!   into a hand-built packet body) and spliced into the hand-rolled `OPEN`
//!   body.
//!
//! # Framing and correlation
//!
//! [`Framer`] reassembles the `u32-length-prefixed | type | body` wire
//! packets (sec 3) out of arbitrarily-chopped transport chunks -- the WIT
//! boundary above hands us whatever `subsystem-drain` happened to return,
//! with no alignment guarantee to packet boundaries. It enforces
//! [`MAX_PACKET_LEN`] against the length prefix BEFORE buffering the body,
//! so a hostile or corrupt prefix (`u32::MAX`) is a typed error, not an
//! attempt to allocate 4 GiB.
//!
//! [`IdAllocator`] and [`Correlator`] exist because SFTP is designed to be
//! pipelined (sec 3: "there is no ... requirement... that requests be
//! processed... in the order they were sent" -- responses may and do arrive
//! out of order) and pipelining is where SFTP's throughput actually comes
//! from: one request in flight at a time makes bulk transfer round-trip
//! bound. `Correlator<T>` lets a caller tag each outstanding request with
//! whatever context it needs (a read offset, a UI row, ...) and look it
//! back up by request id when the matching response arrives, in any order.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub use openssh_sftp_protocol::file_attrs::FileAttrs;
pub use openssh_sftp_protocol::response::{Extensions, ServerVersion};
pub use openssh_sftp_protocol::ErrorCode;

use openssh_sftp_protocol::constants;
use openssh_sftp_protocol::file_attrs::{Permissions, UnixTimeStamp};
use openssh_sftp_protocol::response::{
    Response as LibResponse, ResponseInner as LibResponseInner, StatusCode as LibStatusCode,
};
use serde::Serialize as _;

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Everything that can go wrong encoding a request or decoding a response.
#[derive(Debug)]
pub enum Error {
    /// A response packet's body ran out of bytes before the fields it was
    /// supposed to contain were fully read. Distinct from [`Error::PacketTooLarge`]:
    /// this is "the framer handed us a complete-length packet whose insides
    /// don't parse", not "the length prefix itself was hostile".
    Truncated,
    /// A response packet parsed the wrong shape for its declared type
    /// (bad enum discriminant, non-UTF-8 status message, etc).
    Malformed(String),
    /// The framer's length prefix claimed more than [`MAX_PACKET_LEN`]
    /// bytes. Rejected before any allocation proportional to the claimed
    /// length -- see module docs.
    PacketTooLarge(u32),
    /// A response referenced a request id [`Correlator`] has no pending
    /// entry for (already answered, never sent, or the framer desynced).
    UnknownRequestId(u32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "sftp packet truncated"),
            Error::Malformed(m) => write!(f, "sftp packet malformed: {m}"),
            Error::PacketTooLarge(n) => write!(f, "sftp packet too large: {n} bytes"),
            Error::UnknownRequestId(id) => write!(f, "sftp response for unknown request id {id}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

// Note: there is deliberately no `Error::Encode` (or any request-encoding
// error at all): paths, filenames, and handles are hand-encoded raw bytes
// (see module docs) with no UTF-8 or other validity requirement, so
// encoding a well-formed request cannot fail. If a future request type
// needs a fallible encode (e.g. a field whose length cannot fit `u32`),
// add a narrowly-scoped error at that point rather than reintroducing a
// blanket `Encode` variant.

// ---------------------------------------------------------------------
// Low-level byte reader/writer used by the hand-rolled parts (NAME, DATA,
// EXTENDED_REPLY, handle-bearing requests). Bounds-checked, never panics.
// ---------------------------------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.b.len() {
            return Err(Error::Truncated);
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }

    /// SFTP v3 "string" (sec 3): a `uint32` length prefix followed by that
    /// many raw bytes, no encoding implied.
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn rest(&self) -> &'a [u8] {
        &self.b[self.p..]
    }

    fn advance(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Bytes consumed so far -- how far into the original slice we are.
    fn pos(&self) -> usize {
        self.p
    }
}

fn put_u32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_be_bytes());
}

fn put_str(o: &mut Vec<u8>, s: &[u8]) {
    put_u32(o, s.len() as u32);
    o.extend_from_slice(s);
}

/// Wrap a body (packet-type byte + payload) in the `uint32` big-endian
/// length prefix (sec 3: "All packets... prefixed with a uint32 length").
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(5 + payload.len());
    put_u32(&mut o, 1 + payload.len() as u32);
    o.push(kind);
    o.extend_from_slice(payload);
    o
}

/// Serialize `FileAttrs` in isolation (no length-prefix header -- unlike
/// `ssh_format::to_bytes`, which always adds one for a whole packet) so its
/// bytes can be spliced into a hand-built request body. `FileAttrs` has no
/// path/filename hazard (plain numeric fields), so the library's public
/// `Serialize` impl is used as-is; see module docs for why paths and
/// handles do not get the same treatment.
fn serialize_attrs(attrs: &FileAttrs) -> Vec<u8> {
    let mut ser = ssh_format::Serializer::new(Vec::new());
    attrs
        .serialize(&mut ser)
        .expect("FileAttrs has no unbounded fields and cannot fail to serialize");
    ser.output
}

// ---------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------

/// `SSH_FXP_INIT` (sec 3): the only packet with no request id. The
/// client always sends version 3 -- this crate targets v3 exclusively
/// (see module docs).
pub fn encode_init() -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, constants::SSH2_FILEXFER_VERSION);
    frame(constants::SSH_FXP_INIT, &p)
}

/// `SSH_FXP_OPEN` (sec 6.3). `path` is a raw byte path (see module docs);
/// `flags` is an `SSH_FXF_*` bitmask (see [`openssh_sftp_protocol::constants`]).
pub fn encode_open(id: u32, path: &[u8], flags: u32, attrs: FileAttrs) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, path);
    put_u32(&mut p, flags);
    p.extend_from_slice(&serialize_attrs(&attrs));
    frame(constants::SSH_FXP_OPEN, &p)
}

fn encode_path_request(kind: u8, id: u32, path: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, path);
    frame(kind, &p)
}

/// `SSH_FXP_STAT` (sec 6.8): follows symlinks.
pub fn encode_stat(id: u32, path: &[u8]) -> Vec<u8> {
    encode_path_request(constants::SSH_FXP_STAT, id, path)
}

/// `SSH_FXP_LSTAT` (sec 6.8): does not follow symlinks.
pub fn encode_lstat(id: u32, path: &[u8]) -> Vec<u8> {
    encode_path_request(constants::SSH_FXP_LSTAT, id, path)
}

/// `SSH_FXP_REALPATH` (sec 6.9): canonicalize a path server-side.
pub fn encode_realpath(id: u32, path: &[u8]) -> Vec<u8> {
    encode_path_request(constants::SSH_FXP_REALPATH, id, path)
}

/// `SSH_FXP_OPENDIR` (sec 6.6).
pub fn encode_opendir(id: u32, path: &[u8]) -> Vec<u8> {
    encode_path_request(constants::SSH_FXP_OPENDIR, id, path)
}

/// `limits@openssh.com` (OpenSSH extension, no wire arguments): asks the
/// server for its preferred packet/read/write sizes and max open handles.
/// Needed to size `READ`/`WRITE` requests correctly instead of guessing.
pub fn encode_limits(id: u32) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, b"limits@openssh.com");
    frame(constants::SSH_FXP_EXTENDED, &p)
}

/// `posix-rename@openssh.com` (OpenSSH extension): POSIX rename semantics
/// (atomically replaces `newpath` if it exists), unlike plain `SSH_FXP_RENAME`.
pub fn encode_posix_rename(id: u32, oldpath: &[u8], newpath: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, b"posix-rename@openssh.com");
    put_str(&mut p, oldpath);
    put_str(&mut p, newpath);
    frame(constants::SSH_FXP_EXTENDED, &p)
}

// -- Handle-bearing requests: hand-rolled. See module docs for why. --

/// `SSH_FXP_CLOSE` (sec 6.4).
pub fn encode_close(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, handle);
    frame(constants::SSH_FXP_CLOSE, &p)
}

/// `SSH_FXP_READ` (sec 6.5).
pub fn encode_read(id: u32, handle: &[u8], offset: u64, len: u32) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, handle);
    put_u64(&mut p, offset);
    put_u32(&mut p, len);
    frame(constants::SSH_FXP_READ, &p)
}

/// `SSH_FXP_WRITE` (sec 6.5).
pub fn encode_write(id: u32, handle: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, handle);
    put_u64(&mut p, offset);
    put_str(&mut p, data);
    frame(constants::SSH_FXP_WRITE, &p)
}

/// `SSH_FXP_FSTAT` (sec 6.8): stat by open handle rather than path.
pub fn encode_fstat(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, handle);
    frame(constants::SSH_FXP_FSTAT, &p)
}

/// `SSH_FXP_READDIR` (sec 6.7): one call returns a batch of entries; the
/// caller keeps calling until a `SSH_FX_EOF` status.
pub fn encode_readdir(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, handle);
    frame(constants::SSH_FXP_READDIR, &p)
}

fn encode_extended_handle(id: u32, name: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_u32(&mut p, id);
    put_str(&mut p, name);
    put_str(&mut p, handle);
    frame(constants::SSH_FXP_EXTENDED, &p)
}

/// `fsync@openssh.com` (OpenSSH extension): fsync(2) an open handle.
pub fn encode_fsync(id: u32, handle: &[u8]) -> Vec<u8> {
    encode_extended_handle(id, b"fsync@openssh.com", handle)
}

// ---------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------

/// One entry of a `SSH_FXP_NAME` response (sec 7). Kept as raw bytes --
/// see module docs for why this crate never converts to `str`/`Path`.
#[derive(Debug, Clone, PartialEq)]
pub struct NameEntry {
    pub filename: Vec<u8>,
    pub longname: Vec<u8>,
    pub attrs: FileAttrs,
    /// The raw `permissions` word off the wire (`SSH_FILEXFER_ATTR_PERMISSIONS`),
    /// if that flag was set -- independent of whether `attrs` itself could
    /// represent it. `FileAttrs` cannot carry file-type bits at all outside
    /// its own internal (validated) decode (see [`file_kind`]'s docs), and
    /// this crate refuses to let one entry's oddball mode value fail the
    /// whole listing (see [`decode_name`]'s docs), so the raw word is kept
    /// alongside `attrs` specifically so [`file_kind_from_raw`] still works
    /// for a mode the library itself would have rejected.
    pub raw_permissions: Option<u32>,
}

/// Coarse file type, resolved without letting a panic inside
/// `FileAttrs::get_filetype` escape into the caller. See [`file_kind`] for
/// why `get_filetype` is called at all (short version: it is the only
/// place in the library that exposes these bits) and how the panic is
/// contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    /// Anything else: socket, block/char device, FIFO, or (defensively)
    /// a bit pattern POSIX does not define at all. Deliberately not
    /// further broken down -- a file browser only needs to distinguish
    /// "open like a file", "browse like a directory", and "resolve like a
    /// symlink" from everything else.
    Other,
}

/// Resolve `attrs`' file type without letting `FileAttrs::get_filetype`'s
/// panic reach the caller. A `wasm32-wasip2` component has no process
/// boundary to contain a panic -- it traps the whole instance, mid-session,
/// for every other request in flight too -- and a directory listing is
/// exactly where an oddball mode value shows up (sockets, doors, whatever a
/// permissive or unusual `sftp-server` reports).
///
/// CONTRACT (deviation from this function's dispatch, flagged per house
/// rules): the ask was to mask `S_IFMT` (`0o170000`) directly out of the
/// raw permissions bits, bypassing `get_filetype` entirely -- mirroring how
/// this crate hand-decodes everything else the library's serde impls
/// cannot safely touch (see module docs). That does not work against
/// `openssh-sftp-protocol` 0.24.2 as pinned: `FileAttrs::get_permissions`
/// returns `Permissions::from_bits_truncate(st_mode)`, and the `Permissions`
/// bitflags type declares none of the `S_IFMT` bits at all, so
/// `get_permissions().bits()` NEVER carries file-type information, valid or
/// invalid (verified directly against the pinned dependency: constructing
/// `Permissions::from_bits_truncate(0o160644)` and reading `.bits()` back
/// yields `0o644` -- the type nibble is gone). `get_filetype` is therefore
/// the only public accessor that ever exposes these bits, and also the
/// only panicking one (`FileType::from_u32(..).unwrap()` on an `S_IFMT`
/// pattern outside the 7 POSIX file types).
///
/// This function calls `get_filetype` anyway, through `catch_unwind`, so a
/// panic there can never propagate. In practice this is defense-in-depth
/// rather than a live bug reachable through this crate's own decoder:
/// `FileAttrs`'s `Deserialize` impl already validates the `S_IFMT` bits at
/// decode time and rejects an invalid pattern with an ordinary `Err`
/// *before* a `FileAttrs` value is ever produced (confirmed directly: a
/// hand-built ATTRS body with mode `0o160644` fails `ssh_format::from_bytes`
/// with "invalid value: integer `57344`... Expected valid filetype
/// specified in POSIX", not a panic -- see
/// `attrs_with_invalid_posix_filetype_is_rejected_at_decode` below). There
/// is consequently no way to construct, through any public API this crate
/// exposes, a `FileAttrs` that would actually reach the panicking branch --
/// this is why the test suite below exercises `Other` via a value the
/// library DOES accept (`FileType::Socket`, not one of this crate's three
/// named kinds) rather than the literal example in the dispatch. The
/// `catch_unwind` stays anyway, because relying on an upstream dependency's
/// internal validation never being relaxed is exactly the kind of
/// assumption this crate does not make elsewhere.
///
/// For a [`NameEntry`] (i.e. a `READDIR` result), prefer
/// [`file_kind_from_raw`] over this function: `decode_name` preserves the
/// raw permissions word specifically so an unusual mode can be classified
/// directly, with no library validation and no `catch_unwind` in the way.
/// This function remains for `FileAttrs` obtained from a standalone
/// `SSH_FXP_ATTRS` response (`STAT`/`LSTAT`/`FSTAT`), which does not
/// currently preserve the raw word -- see module docs.
pub fn file_kind(attrs: &FileAttrs) -> Option<FileKind> {
    use openssh_sftp_protocol::file_attrs::FileType;

    let filetype = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| attrs.get_filetype()))
        .unwrap_or(None)?;
    Some(match filetype {
        FileType::Directory => FileKind::Directory,
        FileType::RegularFile => FileKind::Regular,
        FileType::Symlink => FileKind::Symlink,
        _ => FileKind::Other,
    })
}

/// Classify a raw `permissions` word (the `st_mode`-shaped value carried by
/// `SSH_FILEXFER_ATTR_PERMISSIONS`) directly, by masking `S_IFMT`
/// (`0o170000`) ourselves. Unlike [`file_kind`], this never touches the
/// library at all, so it is infallible and panic-free for ANY `u32` --
/// including an `S_IFMT` pattern outside all 7 POSIX file types, which is
/// exactly the case [`decode_name`] preserves [`NameEntry::raw_permissions`]
/// for.
pub fn file_kind_from_raw(mode: u32) -> FileKind {
    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    match mode & S_IFMT {
        S_IFDIR => FileKind::Directory,
        S_IFREG => FileKind::Regular,
        S_IFLNK => FileKind::Symlink,
        _ => FileKind::Other,
    }
}

/// The outcome carried by a `SSH_FXP_STATUS` response, with `SSH_FX_OK`
/// and `SSH_FX_EOF` split out of [`Error`] so a normal "no more data"/"no
/// more directory entries" condition can never be confused with a real
/// failure by a caller that forgets to check (see module docs, item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOutcome {
    Ok,
    /// `SSH_FX_EOF`: end of file on `READ`, or end of listing on
    /// `READDIR`. Not an error.
    Eof,
}

/// A `SSH_FXP_STATUS` response carrying any code other than
/// `SSH_FX_OK`/`SSH_FX_EOF`.
#[derive(Debug, Clone)]
pub struct StatusError {
    pub code: ErrorCode,
    pub message: String,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for StatusError {}

pub type StatusResult = core::result::Result<StatusOutcome, StatusError>;

/// Payload of an OpenSSH `limits@openssh.com` extended reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub packet_len: u64,
    pub read_len: u64,
    pub write_len: u64,
    pub open_handles: u64,
}

/// A fully decoded SFTP v3 response packet.
#[derive(Debug)]
pub enum Response {
    /// `SSH_FXP_VERSION`: the server's handshake reply to our `INIT`. Carries
    /// no request id (sec 3).
    Version(ServerVersion),
    Status {
        id: u32,
        result: StatusResult,
    },
    Handle {
        id: u32,
        handle: Vec<u8>,
    },
    Data {
        id: u32,
        data: Vec<u8>,
    },
    Name {
        id: u32,
        entries: Vec<NameEntry>,
    },
    Attrs {
        id: u32,
        attrs: FileAttrs,
    },
    /// `SSH_FXP_EXTENDED_REPLY`: an OpenSSH extension's response. The
    /// payload shape depends on which extension the correlated request
    /// asked for (the draft does not tag it) -- use [`parse_limits`] for
    /// `limits@openssh.com`; other extensions used here (`fsync@openssh.com`,
    /// `posix-rename@openssh.com`) reply with plain `SSH_FXP_STATUS`
    /// instead of an extended reply, so this variant is only expected for
    /// `limits@openssh.com` in practice.
    ExtendedReply {
        id: u32,
        payload: Vec<u8>,
    },
}

/// Decode one complete SFTP v3 packet body (the bytes [`Framer::take_packet`]
/// returns: packet-type byte + payload, length prefix already stripped).
pub fn decode_response(body: &[u8]) -> Result<Response> {
    let kind = *body.first().ok_or(Error::Truncated)?;
    match kind {
        constants::SSH_FXP_VERSION => decode_version(body),
        constants::SSH_FXP_NAME => decode_name(body),
        constants::SSH_FXP_DATA => decode_data(body),
        constants::SSH_FXP_EXTENDED_REPLY => decode_extended_reply(body),
        // STATUS, HANDLE, ATTRS have no non-UTF-8-hazard fields and are not
        // otherwise special -- let the verified library decode them.
        _ => decode_via_library(body),
    }
}

fn decode_version(body: &[u8]) -> Result<Response> {
    let mut de = ssh_format::Deserializer::from_bytes(body);
    let sv = ServerVersion::deserialize(&mut de).map_err(|e| Error::Malformed(e.to_string()))?;
    Ok(Response::Version(sv))
}

fn decode_data(body: &[u8]) -> Result<Response> {
    let mut r = Reader::new(&body[1..]);
    let id = r.u32()?;
    let data = r.string()?.to_vec();
    Ok(Response::Data { id, data })
}

fn decode_extended_reply(body: &[u8]) -> Result<Response> {
    let mut r = Reader::new(&body[1..]);
    let id = r.u32()?;
    Ok(Response::ExtendedReply {
        id,
        payload: r.rest().to_vec(),
    })
}

/// Parse a `limits@openssh.com` extended-reply payload (four `uint64`s, no
/// discriminant -- the caller already knows this is a limits reply because
/// it correlated the response id back to a `limits@openssh.com` request).
pub fn parse_limits(payload: &[u8]) -> Result<Limits> {
    let mut r = Reader::new(payload);
    Ok(Limits {
        packet_len: {
            let s = r.take(8)?;
            u64::from_be_bytes(s.try_into().unwrap())
        },
        read_len: {
            let s = r.take(8)?;
            u64::from_be_bytes(s.try_into().unwrap())
        },
        write_len: {
            let s = r.take(8)?;
            u64::from_be_bytes(s.try_into().unwrap())
        },
        open_handles: {
            let s = r.take(8)?;
            u64::from_be_bytes(s.try_into().unwrap())
        },
    })
}

/// `SSH_FXP_NAME` (sec 7): the ONE hand-rolled response decoder. See
/// module docs for why -- filenames and longnames are kept as raw `Vec<u8>`,
/// never routed through `str`/`Path`, and one malformed entry does not
/// abort the rest of the listing. Two independent hazards are guarded here,
/// both "one bad X must not spoil the batch":
///
/// - Non-UTF-8 filenames: never converted to `str`/`Path` at all, so there
///   is nothing to reject.
/// - An oddball ATTRS mode (an `S_IFMT` pattern outside the 7 POSIX file
///   types -- see [`file_kind`]'s docs): `FileAttrs`'s own `Deserialize`
///   validates and rejects this with an `Err`, so each entry's ATTRS block
///   is parsed by [`parse_attrs_defensive`] instead of the library's typed
///   decode, which walks the self-describing wire layout (draft-02 sec 5)
///   without ever validating the permissions value it finds.
///
/// A per-entry parse failure surfaces as `Err` for the whole packet only if
/// the BYTES themselves are truncated -- length prefixes that run past the
/// end of the packet, an EXTENDED count claiming more pairs than remain,
/// and so on. That is a real framing problem this crate cannot route
/// around; an unusual but well-framed VALUE (a filename byte, a mode word)
/// never is.
fn decode_name(body: &[u8]) -> Result<Response> {
    let mut r = Reader::new(&body[1..]);
    let id = r.u32()?;
    let count = r.u32()?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let filename = r.string()?.to_vec();
        let longname = r.string()?.to_vec();
        let tail = r.rest();
        let (attrs, raw_permissions, consumed) = parse_attrs_defensive(tail)?;
        r.advance(consumed)?;
        entries.push(NameEntry {
            filename,
            longname,
            attrs,
            raw_permissions,
        });
    }
    Ok(Response::Name { id, entries })
}

/// Bit for `SSH_FILEXFER_ATTR_EXTENDED` (draft-02 sec 5): the only ATTRS
/// flag not covered by an `openssh_sftp_protocol::constants::SSH_FILEXFER_ATTR_*`
/// name in this crate's dependency (its own decode handles it inline; we
/// need the bit value to walk past it ourselves).
const ATTR_EXTENDED: u32 = 0x8000_0000;

/// Parse one ATTRS block (draft-02 sec 5) directly off the wire, bypassing
/// `FileAttrs`'s validated `Deserialize`. See [`decode_name`]'s docs for
/// why: that validation rejects an `S_IFMT` pattern outside the 7 POSIX
/// file types with an `Err`, which would otherwise fail an entire directory
/// listing over one entry's mode value. The block is entirely
/// self-describing (a `flags` word, then a fixed field order gated bit by
/// bit), so it can always be walked correctly regardless of whether the
/// PERMISSIONS value itself is one the library would accept.
///
/// Returns the typed `FileAttrs` (size/uid+gid/permissions/time populated
/// via `FileAttrs`'s public, infallible setters -- note `set_permissions`
/// cannot represent file-type bits either way, library-validated or not:
/// see [`file_kind`]'s docs), the RAW permissions word if the flag was set
/// (so [`file_kind_from_raw`] works even when the typed path could not
/// represent the mode), and the number of bytes consumed.
fn parse_attrs_defensive(tail: &[u8]) -> Result<(FileAttrs, Option<u32>, usize)> {
    let mut r = Reader::new(tail);
    let flags = r.u32()?;
    let mut attrs = FileAttrs::new();
    let mut raw_permissions = None;

    if flags & constants::SSH_FILEXFER_ATTR_SIZE != 0 {
        attrs.set_size(r.u64()?);
    }
    if flags & constants::SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = r.u32()?;
        let gid = r.u32()?;
        attrs.set_id(uid, gid);
    }
    if flags & constants::SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        let mode = r.u32()?;
        raw_permissions = Some(mode);
        attrs.set_permissions(Permissions::from_bits_truncate(mode));
    }
    if flags & constants::SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let atime = r.u32()?;
        let mtime = r.u32()?;
        attrs.set_time(
            UnixTimeStamp::from_raw(atime).unwrap_or_else(UnixTimeStamp::unix_epoch),
            UnixTimeStamp::from_raw(mtime).unwrap_or_else(UnixTimeStamp::unix_epoch),
        );
    }
    if flags & ATTR_EXTENDED != 0 {
        let count = r.u32()?;
        for _ in 0..count {
            r.string()?; // extension name -- not interpreted
            r.string()?; // extension value -- not interpreted
        }
    }

    Ok((attrs, raw_permissions, r.pos()))
}

fn decode_via_library(body: &[u8]) -> Result<Response> {
    let (resp, _tail): (LibResponse, &[u8]) =
        ssh_format::from_bytes(body).map_err(|e| Error::Malformed(e.to_string()))?;
    let id = resp.response_id;
    Ok(match resp.response_inner {
        LibResponseInner::Status {
            status_code,
            err_msg,
        } => Response::Status {
            id,
            result: translate_status(status_code, err_msg),
        },
        LibResponseInner::Handle(h) => Response::Handle {
            id,
            handle: h.into_inner().to_vec(),
        },
        LibResponseInner::Attrs(attrs) => Response::Attrs { id, attrs },
        // NAME is intercepted in `decode_response` before we ever get here.
        LibResponseInner::Name(_) => unreachable!("SSH_FXP_NAME is handled by decode_name"),
    })
}

fn translate_status(
    status_code: LibStatusCode,
    err_msg: openssh_sftp_protocol::ErrMsg,
) -> StatusResult {
    match status_code {
        LibStatusCode::Success => Ok(StatusOutcome::Ok),
        LibStatusCode::Eof => Ok(StatusOutcome::Eof),
        LibStatusCode::Failure(code) => Err(StatusError {
            code,
            message: err_msg.get().0.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------
// Incremental framing
// ---------------------------------------------------------------------

/// Reject any packet whose declared length exceeds this many bytes, before
/// buffering its body. Generous relative to `limits@openssh.com` values
/// OpenSSH actually advertises (typically well under 256 KiB), but bounded
/// so a corrupt/hostile length prefix cannot be used to make us allocate
/// arbitrarily.
pub const MAX_PACKET_LEN: u32 = 1024 * 1024;

/// Reassembles `[u32 length][payload]` SFTP packets from transport chunks
/// that arrive with no alignment to packet boundaries. See module docs.
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
    poisoned: bool,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append newly-received bytes. No-op once [`Framer`] has poisoned
    /// itself on a hostile length prefix (see [`Self::take_packet`]).
    pub fn feed(&mut self, chunk: &[u8]) {
        if !self.poisoned {
            self.buf.extend_from_slice(chunk);
        }
    }

    /// Pull one complete packet (type byte + payload, length prefix
    /// stripped) off the front of the buffer, if one is fully available.
    /// Returns `Ok(None)` if more bytes are needed -- never panics on
    /// truncated or malformed input.
    ///
    /// Once this returns `Err`, the framer is poisoned (the stream is
    /// desynchronized -- there is no well-defined "next packet" to resume
    /// from) and every subsequent call also returns `Err`.
    pub fn take_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if self.poisoned {
            return Err(Error::Malformed("framer already poisoned".into()));
        }
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
        if len == 0 {
            self.poisoned = true;
            return Err(Error::Malformed(
                "zero-length packet (no room for the type byte)".into(),
            ));
        }
        if len > MAX_PACKET_LEN {
            self.poisoned = true;
            return Err(Error::PacketTooLarge(len));
        }
        let need = 4 + len as usize;
        if self.buf.len() < need {
            return Ok(None);
        }
        let body = self.buf[4..need].to_vec();
        self.buf.drain(..need);
        Ok(Some(body))
    }
}

// ---------------------------------------------------------------------
// Request-id allocation and response correlation
// ---------------------------------------------------------------------

/// Monotonic `u32` request-id allocator. Wraps at `u32::MAX` back to 0 --
/// with a pipeline depth measured in tens of outstanding requests, wrapping
/// back onto a still-pending id would require billions of requests in
/// flight simultaneously, which is not a regime this client (or any SFTP
/// client) operates in. [`Correlator`] still detects the collision (it
/// would simply see the id already occupied) rather than silently
/// misattributing a response.
#[derive(Debug, Default)]
pub struct IdAllocator(u32);

impl IdAllocator {
    pub fn new() -> Self {
        Self(0)
    }

    /// Allocate the next request id.
    pub fn alloc(&mut self) -> u32 {
        let id = self.0;
        self.0 = self.0.wrapping_add(1);
        id
    }
}

/// Correlates outstanding requests with their eventual responses, tagging
/// each with caller-chosen context `T` (e.g. "this is a READ for offset
/// 4096 into file X"). Supports pipelining: [`Self::submit`] may be called
/// any number of times before the matching [`Self::take`]s happen, and
/// responses may arrive in any order (sec 3 explicitly permits this).
///
/// Single-threaded by design -- `wosh-client` is a wasm component with no
/// threads, so this intentionally uses no locking.
#[derive(Debug, Default)]
pub struct Correlator<T> {
    ids: IdAllocator,
    pending: BTreeMap<u32, T>,
}

impl<T> Correlator<T> {
    pub fn new() -> Self {
        Self {
            ids: IdAllocator::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Allocate a request id, remember `tag` under it, and return the id to
    /// embed in the outgoing request packet.
    pub fn submit(&mut self, tag: T) -> u32 {
        let id = self.ids.alloc();
        self.pending.insert(id, tag);
        id
    }

    /// Match an incoming response's id back to its tag, removing it from
    /// the pending set (each request gets exactly one response in SFTP
    /// v3). Returns [`Error::UnknownRequestId`] if `id` has no pending
    /// entry -- a response we never asked for, or a duplicate.
    pub fn take(&mut self, id: u32) -> Result<T> {
        self.pending.remove(&id).ok_or(Error::UnknownRequestId(id))
    }

    /// Number of requests currently in flight.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Empty the pending set and hand back every outstanding `(id, tag)`
    /// pair. For when the transport itself dies (channel closed, WIT call
    /// failed) and every waiter needs to be failed at once rather than one
    /// at a time as responses that will never come don't arrive -- without
    /// this, a caller has to keep its own shadow list of live ids just to
    /// enumerate what [`Correlator`] already knows, purely because nothing
    /// else exposes it. After this call [`Self::pending_len`] is 0 and a
    /// later [`Self::take`] for any drained id returns
    /// [`Error::UnknownRequestId`], same as any other id we have no record
    /// of.
    pub fn drain_pending(&mut self) -> Vec<(u32, T)> {
        std::mem::take(&mut self.pending).into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden bytes below are hand-verified against draft-ietf-secsh-filexfer-02
    // and cross-checked against an independently hand-rolled SFTP v3 encoder
    // (see the dispatch for this crate) that was itself verified byte-identical
    // to openssh-sftp-protocol for 13 packet types.

    #[test]
    fn golden_init() {
        // sec 3: SSH_FXP_INIT(1), version=3. Body = [1][00 00 00 03].
        let want: Vec<u8> = vec![
            0, 0, 0, 5, // length = 1 (type) + 4 (version)
            1, // SSH_FXP_INIT
            0, 0, 0, 3, // version 3
        ];
        assert_eq!(encode_init(), want);
    }

    /// Patch a hand-written `want` vector's placeholder length prefix
    /// (`[0,0,0,0]`) to the actual body length, so golden-byte tests only
    /// need to get the BODY bytes right by hand -- the length prefix is
    /// mechanically derived, removing a whole class of arithmetic slips.
    fn with_len_prefix(mut body_after_prefix: Vec<u8>) -> Vec<u8> {
        let len = (body_after_prefix.len() as u32).to_be_bytes();
        let mut out = len.to_vec();
        out.append(&mut body_after_prefix);
        out
    }

    #[test]
    fn golden_open() {
        // sec 6.3: SSH_FXP_OPEN(3), id, path(string), pflags(uint32), attrs(ATTRS).
        // path = "a" (0x61), flags = SSH_FXF_READ (0x1), attrs = empty (flags=0).
        let want = with_len_prefix(vec![
            3, // SSH_FXP_OPEN
            0, 0, 0, 7, // request id
            0, 0, 0, 1, b'a', // path "a"
            0, 0, 0, 1, // pflags = SSH_FXF_READ
            0, 0, 0, 0, // attrs flags = 0 (empty)
        ]);
        let got = encode_open(7, b"a", constants::SSH_FXF_READ, FileAttrs::new());
        assert_eq!(got, want);
    }

    #[test]
    fn golden_close() {
        // sec 6.4: SSH_FXP_CLOSE(4), id, handle(string).
        let want = with_len_prefix(vec![4, 0, 0, 0, 1, 0, 0, 0, 2, b'h', b'1']);
        assert_eq!(encode_close(1, b"h1"), want);
    }

    #[test]
    fn golden_read() {
        // sec 6.5: SSH_FXP_READ(5), id, handle, offset(uint64), len(uint32).
        let want = with_len_prefix(vec![
            5, // SSH_FXP_READ
            0, 0, 0, 2, // id
            0, 0, 0, 2, b'h', b'2', // handle "h2"
            0, 0, 0, 0, 0, 0, 0, 100, // offset = 100
            0, 0, 1, 0, // len = 256
        ]);
        assert_eq!(encode_read(2, b"h2", 100, 256), want);
    }

    #[test]
    fn golden_write() {
        // sec 6.5: SSH_FXP_WRITE(6), id, handle, offset(uint64), data(string).
        let want = with_len_prefix(vec![
            6, // SSH_FXP_WRITE
            0, 0, 0, 3, // id
            0, 0, 0, 2, b'h', b'3', // handle "h3"
            0, 0, 0, 0, 0, 0, 0, 0, // offset = 0
            0, 0, 0, 3, b'a', b'b', b'c', // data "abc"
        ]);
        assert_eq!(encode_write(3, b"h3", 0, b"abc"), want);
    }

    #[test]
    fn golden_fstat() {
        // sec 6.8: SSH_FXP_FSTAT(8), id, handle.
        let want = with_len_prefix(vec![8, 0, 0, 0, 4, 0, 0, 0, 2, b'h', b'4']);
        assert_eq!(encode_fstat(4, b"h4"), want);
    }

    #[test]
    fn golden_stat() {
        // sec 6.8: SSH_FXP_STAT(17), id, path.
        let want = with_len_prefix(vec![17, 0, 0, 0, 5, 0, 0, 0, 2, b'/', b'x']);
        assert_eq!(encode_stat(5, b"/x"), want);
    }

    #[test]
    fn golden_lstat() {
        // sec 6.8: SSH_FXP_LSTAT(7), id, path.
        let want = with_len_prefix(vec![7, 0, 0, 0, 6, 0, 0, 0, 2, b'/', b'y']);
        assert_eq!(encode_lstat(6, b"/y"), want);
    }

    #[test]
    fn golden_realpath() {
        // sec 6.9: SSH_FXP_REALPATH(16), id, path.
        let want = with_len_prefix(vec![16, 0, 0, 0, 8, 0, 0, 0, 1, b'.']);
        assert_eq!(encode_realpath(8, b"."), want);
    }

    #[test]
    fn golden_opendir() {
        // sec 6.6: SSH_FXP_OPENDIR(11), id, path.
        let want = with_len_prefix(vec![11, 0, 0, 0, 9, 0, 0, 0, 1, b'.']);
        assert_eq!(encode_opendir(9, b"."), want);
    }

    #[test]
    fn golden_readdir() {
        // sec 6.7: SSH_FXP_READDIR(12), id, handle.
        let want = with_len_prefix(vec![12, 0, 0, 0, 10, 0, 0, 0, 2, b'h', b'5']);
        assert_eq!(encode_readdir(10, b"h5"), want);
    }

    #[test]
    fn golden_limits() {
        // OpenSSH limits@openssh.com: SSH_FXP_EXTENDED(200), id, extension-name(string).
        let want = with_len_prefix(vec![
            200, // SSH_FXP_EXTENDED
            0, 0, 0, 11, // id
            0, 0, 0, 18, // len("limits@openssh.com")
            b'l', b'i', b'm', b'i', b't', b's', b'@', b'o', b'p', b'e', b'n', b's', b's', b'h',
            b'.', b'c', b'o', b'm',
        ]);
        assert_eq!(encode_limits(11), want);
    }

    #[test]
    fn golden_fsync() {
        // OpenSSH fsync@openssh.com: SSH_FXP_EXTENDED(200), id, name(string), handle(string).
        let want = with_len_prefix(vec![
            200, // SSH_FXP_EXTENDED
            0, 0, 0, 12, // id
            0, 0, 0, 17, b'f', b's', b'y', b'n', b'c', b'@', b'o', b'p', b'e', b'n', b's', b's',
            b'h', b'.', b'c', b'o', b'm', // "fsync@openssh.com"
            0, 0, 0, 2, b'h', b'6', // handle "h6"
        ]);
        assert_eq!(encode_fsync(12, b"h6"), want);
    }

    #[test]
    fn golden_posix_rename() {
        // OpenSSH posix-rename@openssh.com: SSH_FXP_EXTENDED(200), id, name(string),
        // oldpath(string), newpath(string).
        let want = with_len_prefix(vec![
            200, // SSH_FXP_EXTENDED
            0, 0, 0, 13, // id
            0, 0, 0, 24, b'p', b'o', b's', b'i', b'x', b'-', b'r', b'e', b'n', b'a', b'm', b'e',
            b'@', b'o', b'p', b'e', b'n', b's', b's', b'h', b'.', b'c', b'o', b'm', 0, 0, 0, 1,
            b'a', // oldpath "a"
            0, 0, 0, 1, b'b', // newpath "b"
        ]);
        assert_eq!(encode_posix_rename(13, b"a", b"b"), want);
    }

    // ---------------- response decoding ----------------

    fn srv_status_body(id: u32, code: u32, msg: &str) -> Vec<u8> {
        let mut o = vec![constants::SSH_FXP_STATUS];
        put_u32(&mut o, id);
        put_u32(&mut o, code);
        put_str(&mut o, msg.as_bytes());
        put_str(&mut o, b"en");
        o
    }

    fn srv_handle_body(id: u32, handle: &[u8]) -> Vec<u8> {
        let mut o = vec![constants::SSH_FXP_HANDLE];
        put_u32(&mut o, id);
        put_str(&mut o, handle);
        o
    }

    fn srv_data_body(id: u32, data: &[u8]) -> Vec<u8> {
        let mut o = vec![constants::SSH_FXP_DATA];
        put_u32(&mut o, id);
        put_str(&mut o, data);
        o
    }

    fn srv_version_body(version: u32, exts: &[(&str, &str)]) -> Vec<u8> {
        let mut o = vec![constants::SSH_FXP_VERSION];
        put_u32(&mut o, version);
        for (n, v) in exts {
            put_str(&mut o, n.as_bytes());
            put_str(&mut o, v.as_bytes());
        }
        o
    }

    /// Raw SSH_FXP_NAME body with one entry per `(filename, longname)`, each
    /// with an empty (flags=0) ATTRS.
    fn srv_name_body(id: u32, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut o = vec![constants::SSH_FXP_NAME];
        put_u32(&mut o, id);
        put_u32(&mut o, entries.len() as u32);
        for (filename, longname) in entries {
            put_str(&mut o, filename);
            put_str(&mut o, longname);
            put_u32(&mut o, 0); // ATTRS flags = 0
        }
        o
    }

    fn frame_body(body: &[u8]) -> Vec<u8> {
        let mut o = Vec::new();
        put_u32(&mut o, body.len() as u32);
        o.extend_from_slice(body);
        o
    }

    #[test]
    fn decode_version_with_extensions() {
        let body = srv_version_body(
            3,
            &[
                ("posix-rename@openssh.com", "1"),
                ("limits@openssh.com", "1"),
            ],
        );
        match decode_response(&body).unwrap() {
            Response::Version(sv) => {
                assert_eq!(sv.version, 3);
                assert!(sv.extensions.contains(Extensions::POSIX_RENAME));
                assert!(sv.extensions.contains(Extensions::LIMITS));
                assert!(!sv.extensions.contains(Extensions::FSYNC));
            }
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn decode_status_ok() {
        let body = srv_status_body(1, constants::SSH_FX_OK, "");
        match decode_response(&body).unwrap() {
            Response::Status { id, result } => {
                assert_eq!(id, 1);
                assert_eq!(result.unwrap(), StatusOutcome::Ok);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// `SSH_FX_EOF` must be distinguishable from a real error (dispatch
    /// item: "EOF vs error").
    #[test]
    fn eof_is_not_an_error() {
        let read_eof = srv_status_body(2, constants::SSH_FX_EOF, "");
        let real_error = srv_status_body(3, constants::SSH_FX_PERMISSION_DENIED, "denied");

        match decode_response(&read_eof).unwrap() {
            Response::Status { result, .. } => {
                assert_eq!(result.unwrap(), StatusOutcome::Eof);
            }
            other => panic!("expected Status, got {other:?}"),
        }

        match decode_response(&real_error).unwrap() {
            Response::Status { result, .. } => {
                let err = result.unwrap_err();
                assert!(matches!(err.code, ErrorCode::PermDenied));
                assert_eq!(err.message, "denied");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn decode_handle_and_data() {
        match decode_response(&srv_handle_body(4, b"handle-bytes")).unwrap() {
            Response::Handle { id, handle } => {
                assert_eq!(id, 4);
                assert_eq!(handle, b"handle-bytes");
            }
            other => panic!("expected Handle, got {other:?}"),
        }

        match decode_response(&srv_data_body(5, b"payload")).unwrap() {
            Response::Data { id, data } => {
                assert_eq!(id, 5);
                assert_eq!(data, b"payload");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    /// The regression this crate exists to prevent: a non-UTF-8 filename
    /// (an obviously-synthetic name containing byte 0xff) must round-trip
    /// through SSH_FXP_NAME, and every other entry in the same listing
    /// must still decode.
    #[test]
    fn readdir_non_utf8_filename_round_trips() {
        let bad_name: &[u8] = b"weird-\xff-name";
        let body = srv_name_body(
            6,
            &[
                (b"normal.txt", b"-rw-r--r-- 1 u g 0 normal.txt"),
                (bad_name, b"-rw-r--r-- 1 u g 0 weird"),
                (b"after.txt", b"-rw-r--r-- 1 u g 0 after.txt"),
            ],
        );
        match decode_response(&body).unwrap() {
            Response::Name { id, entries } => {
                assert_eq!(id, 6);
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0].filename, b"normal.txt");
                assert_eq!(entries[1].filename, bad_name);
                assert!(std::str::from_utf8(&entries[1].filename).is_err());
                assert_eq!(entries[2].filename, b"after.txt");
            }
            other => panic!("expected Name, got {other:?}"),
        }
    }

    /// The mode-side counterpart of the filename fix above: an entry whose
    /// ATTRS mode is an `S_IFMT` pattern outside all 7 POSIX file types
    /// (the library's `FileAttrs::Deserialize` would reject this with an
    /// `Err`), and an entry with `SSH_FILEXFER_ATTR_EXTENDED` vendor
    /// attributes set, must both survive alongside normal entries -- one
    /// bad or unusual mode must not fail the whole listing, exactly the
    /// same rationale as the non-UTF-8 filename case. Do not delete this
    /// test: see `decode_name`'s and `parse_attrs_defensive`'s docs.
    #[test]
    fn readdir_survives_invalid_filetype_and_extended_attrs_entries() {
        let mut body = vec![constants::SSH_FXP_NAME];
        put_u32(&mut body, 7); // request id
        put_u32(&mut body, 4); // 4 entries

        // 1. normal regular file.
        put_str(&mut body, b"normal.txt");
        put_str(&mut body, b"-rw-r--r-- 1 u g 0 normal.txt");
        put_u32(&mut body, constants::SSH_FILEXFER_ATTR_PERMISSIONS);
        put_u32(&mut body, 0o100644);

        // 2. invalid S_IFMT pattern (0o160000 is not one of the 7 POSIX
        // file types) -- the entry the library's typed decode would choke on.
        put_str(&mut body, b"odd-mode");
        put_str(&mut body, b"?--------- 1 u g 0 odd-mode");
        put_u32(&mut body, constants::SSH_FILEXFER_ATTR_PERMISSIONS);
        put_u32(&mut body, 0o160644);

        // 3. vendor extended attributes (SSH_FILEXFER_ATTR_EXTENDED, bit
        // 0x80000000), one name/value pair, plus a normal permissions field.
        put_str(&mut body, b"with-ext-attrs");
        put_str(&mut body, b"-rw-r--r-- 1 u g 0 with-ext-attrs");
        put_u32(
            &mut body,
            constants::SSH_FILEXFER_ATTR_PERMISSIONS | 0x8000_0000,
        );
        put_u32(&mut body, 0o100600);
        put_u32(&mut body, 1); // one extension pair
        put_str(&mut body, b"vendor@example.com");
        put_str(&mut body, b"some-value");

        // 4. another normal entry, to prove decoding kept going afterwards.
        put_str(&mut body, b"after.txt");
        put_str(&mut body, b"-rw-r--r-- 1 u g 0 after.txt");
        put_u32(&mut body, constants::SSH_FILEXFER_ATTR_PERMISSIONS);
        put_u32(&mut body, 0o100644);

        let entries = match decode_response(&body).unwrap() {
            Response::Name { id, entries } => {
                assert_eq!(id, 7);
                entries
            }
            other => panic!("expected Name, got {other:?}"),
        };
        assert_eq!(entries.len(), 4, "all four entries must survive");

        assert_eq!(entries[0].filename, b"normal.txt");
        assert_eq!(entries[0].raw_permissions, Some(0o100644));
        assert_eq!(
            file_kind_from_raw(entries[0].raw_permissions.unwrap()),
            FileKind::Regular
        );

        // The odd entry: typed attrs cannot represent the file-type bits
        // (same limitation as any valid mode -- see `file_kind`'s docs), but
        // the raw word survives and classifies correctly as `Other`.
        assert_eq!(entries[1].filename, b"odd-mode");
        assert_eq!(entries[1].raw_permissions, Some(0o160644));
        assert_eq!(
            file_kind_from_raw(entries[1].raw_permissions.unwrap()),
            FileKind::Other
        );

        assert_eq!(entries[2].filename, b"with-ext-attrs");
        assert_eq!(entries[2].raw_permissions, Some(0o100600));
        assert_eq!(
            file_kind_from_raw(entries[2].raw_permissions.unwrap()),
            FileKind::Regular
        );

        assert_eq!(entries[3].filename, b"after.txt");
        assert_eq!(entries[3].raw_permissions, Some(0o100644));
    }

    /// The actual point of this crate, end to end: a non-UTF-8 filename
    /// decoded out of a `SSH_FXP_NAME` response must be usable AS A PATH in
    /// a follow-up request -- `open this file I just saw in the listing` --
    /// without this crate mangling or rejecting it. Do not delete this
    /// test: it is the regression guard for the rule stated in the module
    /// docs ("never let openssh-sftp-protocol's serde impls touch a path,
    /// a filename, or a handle"). If this ever regresses to requiring a
    /// UTF-8 path again, the crate is back to being a cosmetic fix.
    #[test]
    fn readdir_filename_round_trips_into_open_stat_realpath_even_non_utf8() {
        let bad_name: &[u8] = b"weird-\xff-name";
        let body = srv_name_body(1, &[(bad_name, b"-rw-r--r-- 1 u g 0 weird")]);
        let filename = match decode_response(&body).unwrap() {
            Response::Name { entries, .. } => entries.into_iter().next().unwrap().filename,
            other => panic!("expected Name, got {other:?}"),
        };
        assert_eq!(filename, bad_name);
        assert!(std::str::from_utf8(&filename).is_err());

        // Each of these encodes as [len:4][type:1][id:4][pathlen:4][path...];
        // the path field starts at a fixed offset of 13 bytes in.
        const PATH_FIELD_OFFSET: usize = 4 + 1 + 4 + 4;

        let open_pkt = encode_open(2, &filename, constants::SSH_FXF_READ, FileAttrs::new());
        assert_eq!(
            &open_pkt[PATH_FIELD_OFFSET..PATH_FIELD_OFFSET + filename.len()],
            filename.as_slice(),
            "OPEN path field must be byte-identical to the decoded filename"
        );

        let stat_pkt = encode_stat(3, &filename);
        assert_eq!(
            &stat_pkt[PATH_FIELD_OFFSET..PATH_FIELD_OFFSET + filename.len()],
            filename.as_slice(),
            "STAT path field must be byte-identical to the decoded filename"
        );

        let realpath_pkt = encode_realpath(4, &filename);
        assert_eq!(
            &realpath_pkt[PATH_FIELD_OFFSET..PATH_FIELD_OFFSET + filename.len()],
            filename.as_slice(),
            "REALPATH path field must be byte-identical to the decoded filename"
        );
    }

    #[test]
    fn limits_round_trip() {
        let mut payload = Vec::new();
        put_u64(&mut payload, 1 << 20);
        put_u64(&mut payload, 256 * 1024);
        put_u64(&mut payload, 256 * 1024);
        put_u64(&mut payload, 128);
        let limits = parse_limits(&payload).unwrap();
        assert_eq!(
            limits,
            Limits {
                packet_len: 1 << 20,
                read_len: 256 * 1024,
                write_len: 256 * 1024,
                open_handles: 128,
            }
        );
    }

    // ---------------- framer ----------------

    #[test]
    fn framer_reassembles_split_chunks() {
        let mut f = Framer::new();
        let packet = frame_body(&srv_status_body(9, constants::SSH_FX_OK, ""));
        f.feed(&packet[..3]);
        assert!(f.take_packet().unwrap().is_none());
        f.feed(&packet[3..]);
        let body = f.take_packet().unwrap().unwrap();
        assert_eq!(body, packet[4..]);
        assert!(f.take_packet().unwrap().is_none());
    }

    /// Chunk-boundary fuzzing: feed a known multi-packet stream split at
    /// EVERY possible offset and assert identical decoded output each time.
    #[test]
    fn framer_split_at_every_offset() {
        let p1 = frame_body(&srv_status_body(1, constants::SSH_FX_OK, ""));
        let p2 = frame_body(&srv_handle_body(2, b"abcxyz"));
        let p3 = frame_body(&srv_name_body(3, &[(b"a", b"a-long")]));
        let mut stream = Vec::new();
        stream.extend_from_slice(&p1);
        stream.extend_from_slice(&p2);
        stream.extend_from_slice(&p3);

        for split in 0..=stream.len() {
            let mut f = Framer::new();
            f.feed(&stream[..split]);
            f.feed(&stream[split..]);

            let mut got = Vec::new();
            while let Some(body) = f.take_packet().unwrap() {
                got.push(body);
            }
            assert_eq!(
                got,
                vec![p1[4..].to_vec(), p2[4..].to_vec(), p3[4..].to_vec()],
                "split at {split}"
            );
        }
    }

    /// Fine-grained variant: feed one byte at a time, still must reassemble.
    #[test]
    fn framer_byte_at_a_time() {
        let packet = frame_body(&srv_data_body(1, b"hello world"));
        let mut f = Framer::new();
        let mut got = None;
        for b in &packet {
            f.feed(std::slice::from_ref(b));
            if let Some(body) = f.take_packet().unwrap() {
                got = Some(body);
            }
        }
        assert_eq!(got.unwrap(), packet[4..]);
    }

    #[test]
    fn framer_rejects_hostile_length_prefix() {
        let mut f = Framer::new();
        // u32::MAX length prefix, no body -- must error without allocating
        // anything proportional to that length, and must not panic.
        f.feed(&u32::MAX.to_be_bytes());
        let err = f.take_packet().unwrap_err();
        assert!(matches!(err, Error::PacketTooLarge(n) if n == u32::MAX));
        // Framer stays poisoned afterwards.
        f.feed(b"more garbage");
        assert!(f.take_packet().is_err());
    }

    #[test]
    fn framer_rejects_zero_length_packet() {
        let mut f = Framer::new();
        f.feed(&0u32.to_be_bytes());
        assert!(f.take_packet().is_err());
    }

    #[test]
    fn decode_response_rejects_truncated_and_malformed() {
        // Empty body.
        assert!(matches!(decode_response(&[]), Err(Error::Truncated)));

        // A HANDLE packet that claims a handle longer than the bytes present.
        let mut bad = vec![constants::SSH_FXP_HANDLE];
        put_u32(&mut bad, 1);
        put_u32(&mut bad, 1000); // claims 1000-byte handle, none present
        assert!(decode_response(&bad).is_err());

        // An unknown packet type (STATUS/HANDLE/DATA/NAME/ATTRS/VERSION/
        // EXTENDED_REPLY are the only response types the client should ever
        // see; anything else is a protocol violation, not a panic).
        let unknown = vec![250, 0, 0, 0, 1];
        assert!(decode_response(&unknown).is_err());

        // NAME claiming more entries than bytes remain.
        let mut bad_name = vec![constants::SSH_FXP_NAME];
        put_u32(&mut bad_name, 1);
        put_u32(&mut bad_name, 5); // claims 5 entries, body has none
        assert!(decode_response(&bad_name).is_err());
    }

    // ---------------- correlation / pipelining ----------------

    #[test]
    fn pipelining_out_of_order_responses() {
        let mut c: Correlator<&'static str> = Correlator::new();
        let id_a = c.submit("read-offset-0");
        let id_b = c.submit("read-offset-4096");
        let id_c = c.submit("read-offset-8192");
        assert_eq!(c.pending_len(), 3);

        // Responses arrive out of order: b, then c, then a.
        assert_eq!(c.take(id_b).unwrap(), "read-offset-4096");
        assert_eq!(c.take(id_c).unwrap(), "read-offset-8192");
        assert_eq!(c.take(id_a).unwrap(), "read-offset-0");
        assert_eq!(c.pending_len(), 0);
    }

    #[test]
    fn unknown_request_id_is_an_error() {
        let mut c: Correlator<()> = Correlator::new();
        let id = c.submit(());
        c.take(id).unwrap();
        // Second take of the same id: nothing pending any more.
        assert!(matches!(c.take(id), Err(Error::UnknownRequestId(got)) if got == id));
        // An id we never submitted at all.
        assert!(matches!(c.take(9999), Err(Error::UnknownRequestId(9999))));
    }

    #[test]
    fn id_allocator_wraps() {
        let mut ids = IdAllocator(u32::MAX);
        assert_eq!(ids.alloc(), u32::MAX);
        assert_eq!(ids.alloc(), 0);
        assert_eq!(ids.alloc(), 1);
    }

    #[test]
    fn drain_pending_returns_everything_and_empties_the_map() {
        let mut c: Correlator<&'static str> = Correlator::new();
        let id_a = c.submit("a");
        let id_b = c.submit("b");
        let id_c = c.submit("c");

        let mut drained = c.drain_pending();
        drained.sort_by_key(|(id, _)| *id);
        assert_eq!(drained, vec![(id_a, "a"), (id_b, "b"), (id_c, "c")]);
        assert_eq!(c.pending_len(), 0);

        // A response for a drained id is indistinguishable from one we
        // never issued: the transfer engine treats both as "fail this
        // waiter", which is exactly what UnknownRequestId is for.
        assert!(matches!(c.take(id_b), Err(Error::UnknownRequestId(got)) if got == id_b));
    }

    // ---------------- file_kind ----------------

    fn attrs_with_mode(mode: u32) -> FileAttrs {
        let mut body = Vec::new();
        put_u32(&mut body, constants::SSH_FILEXFER_ATTR_PERMISSIONS);
        put_u32(&mut body, mode);
        let (attrs, _): (FileAttrs, &[u8]) = ssh_format::from_bytes(&body).unwrap();
        attrs
    }

    #[test]
    fn file_kind_recognizes_directory_regular_symlink() {
        assert_eq!(
            file_kind(&attrs_with_mode(0o040755)),
            Some(FileKind::Directory)
        );
        assert_eq!(
            file_kind(&attrs_with_mode(0o100644)),
            Some(FileKind::Regular)
        );
        assert_eq!(
            file_kind(&attrs_with_mode(0o120777)),
            Some(FileKind::Symlink)
        );
    }

    /// A `FileType` the library itself accepts (it is one of the 7 POSIX
    /// types) but that this crate's three-way [`FileKind`] does not name
    /// individually -- must fall back to `Other`, not panic. This is the
    /// closest reachable stand-in for the dispatch's literal "mode the
    /// library's enum does not cover" example; see the CONTRACT comment on
    /// [`file_kind`] for why the literal example (an S_IFMT pattern outside
    /// all 7 POSIX types) cannot be constructed as a live `FileAttrs` at
    /// all through this crate's decode path.
    #[test]
    fn file_kind_falls_back_to_other_for_uncategorized_but_valid_type() {
        assert_eq!(file_kind(&attrs_with_mode(0o140644)), Some(FileKind::Other)); // socket
        assert_eq!(file_kind(&attrs_with_mode(0o010644)), Some(FileKind::Other)); // FIFO
        assert_eq!(file_kind(&attrs_with_mode(0o060644)), Some(FileKind::Other));
        // block device
    }

    #[test]
    fn file_kind_is_none_when_permissions_absent() {
        assert_eq!(file_kind(&FileAttrs::new()), None);
    }

    /// Documents, and pins against regression, the fact established while
    /// investigating this function: the panic in `get_filetype` is not
    /// reachable through this crate's own decoder, because `FileAttrs`'s
    /// `Deserialize` impl already rejects an S_IFMT pattern outside the 7
    /// POSIX file types with an ordinary decode error. If a future
    /// dependency bump ever removes that upstream check, this test starts
    /// failing loudly (an `Ok` where it used to be `Err`) rather than this
    /// crate silently losing its only line of defense against the panic.
    #[test]
    fn attrs_with_invalid_posix_filetype_is_rejected_at_decode() {
        let mut body = vec![constants::SSH_FXP_ATTRS];
        put_u32(&mut body, 1); // request id
        put_u32(&mut body, constants::SSH_FILEXFER_ATTR_PERMISSIONS);
        put_u32(&mut body, 0o160644); // S_IFMT = 0o160000: not one of the 7 POSIX types
        assert!(decode_response(&body).is_err());
    }
}
