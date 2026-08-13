//! The listener's persistent iroh identity.
//!
//! A stable endpoint identity is what makes the browser's host-key
//! pinning useful: the pin store is keyed by this identity's public
//! key (via the connection string), so an identity that changed every
//! run would orphan every pin on every restart.
//!
//! The key pair lives at a fixed path inside the host's `wosh-data`
//! preopen; the host's `--identity-dir` flag picks the real directory
//! (default `${XDG_DATA_HOME:-~/.local/share}/wosh`). File layout,
//! version-prefixed like the connstring:
//!
//! ```text
//! byte 0:       version (currently 1)
//! bytes 1..33:  raw Ed25519 public key (32 bytes)
//! remaining:    PKCS#8 PrivateKeyInfo (DER, RFC 8410)
//! ```
//!
//! Key handling rides `polymorph:webcrypto` end to end -- the same
//! handles `identity-from-keys` consumes -- so the private key is in
//! this component's memory never, and in the platform provider's only
//! at mint/import. On load the signing key is imported
//! NON-extractable (the disk file holds the material; the live handle
//! need not), and `identity-from-keys` sign/verify-probes the pair,
//! so a corrupted or mismatched file fails at startup with one clear
//! error instead of as handshake failures against every peer.

use crate::bindings::polymorph::iroh::identity::Identity;
use crate::bindings::polymorph::iroh::identity_from_keys::from_keys;
use crate::bindings::polymorph::iroh::identity_generate::generate as identity_generate;
use crate::bindings::polymorph::webcrypto::ed25519_sign::{generate_key, import_signing_key_pkcs8};
use crate::bindings::polymorph::webcrypto::ed25519_verify::import_verifying_key_raw;
use crate::bindings::polymorph::webcrypto::signature::SigningKeyOptions;

/// Where the identity file lives, as a guest path: `wosh-data` is the
/// preopen the host mounts (see listener-host's `--identity-dir`).
pub const IDENTITY_PATH: &str = "wosh-data/identity";

const VERSION: u8 = 1;
const PUBKEY_LEN: usize = 32;

/// Load the persistent identity, minting and persisting one on first
/// run. `ephemeral` skips the file entirely (the old per-run behavior).
pub async fn load_or_create(ephemeral: bool) -> Result<Identity, String> {
    if ephemeral {
        return identity_generate()
            .await
            .map_err(|e| format!("identity: {e:?}"));
    }
    match std::fs::read(IDENTITY_PATH) {
        Ok(bytes) => load(&bytes).await,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_and_persist().await,
        Err(e) => Err(format!(
            "reading {IDENTITY_PATH}: {e} (run via a matching wosh-listener host, \
             which mounts the identity dir -- or pass --ephemeral-identity)"
        )),
    }
}

async fn load(bytes: &[u8]) -> Result<Identity, String> {
    // Minimum: version + pubkey + a non-empty PKCS#8 blob.
    if bytes.len() <= 1 + PUBKEY_LEN {
        return Err(format!("{IDENTITY_PATH}: truncated identity file"));
    }
    if bytes[0] != VERSION {
        return Err(format!(
            "{IDENTITY_PATH}: unsupported identity file version {}",
            bytes[0]
        ));
    }
    let pub_raw = &bytes[1..1 + PUBKEY_LEN];
    let pkcs8 = &bytes[1 + PUBKEY_LEN..];

    let opts = SigningKeyOptions::new();
    opts.can_sign(true); // deliberately NOT extractable on reload
    let signing = import_signing_key_pkcs8(pkcs8.to_vec(), opts)
        .await
        .map_err(|e| format!("{IDENTITY_PATH}: importing signing key: {e:?}"))?;
    let verifying = import_verifying_key_raw(pub_raw.to_vec())
        .await
        .map_err(|e| format!("{IDENTITY_PATH}: importing public key: {e:?}"))?;
    let identity = from_keys(signing, verifying)
        .await
        .map_err(|e| format!("{IDENTITY_PATH}: key pair rejected: {e:?}"))?;
    println!("identity: loaded from {IDENTITY_PATH}");
    Ok(identity)
}

async fn create_and_persist() -> Result<Identity, String> {
    let opts = SigningKeyOptions::new();
    opts.can_sign(true);
    opts.extractable(true); // exported once, below; persistence is the point
    let (signing, verifying) = generate_key(opts)
        .await
        .map_err(|e| format!("generating identity: {e:?}"))?;
    let pkcs8 = signing
        .export_key_pkcs8()
        .await
        .map_err(|e| format!("exporting signing key: {e:?}"))?;
    let pub_raw = verifying
        .export_key_raw()
        .await
        .map_err(|e| format!("exporting public key: {e:?}"))?;
    if pub_raw.len() != PUBKEY_LEN {
        return Err(format!(
            "public key is {} bytes, expected {PUBKEY_LEN}",
            pub_raw.len()
        ));
    }

    let mut buf = Vec::with_capacity(1 + PUBKEY_LEN + pkcs8.len());
    buf.push(VERSION);
    buf.extend_from_slice(&pub_raw);
    buf.extend_from_slice(&pkcs8);

    // Write-then-rename, so a crash can never leave a torn identity
    // file where the next start would try to parse it.
    let tmp = format!("{IDENTITY_PATH}.tmp");
    std::fs::write(&tmp, &buf).map_err(|e| {
        format!(
            "writing {tmp}: {e} (run via a matching wosh-listener host, which \
             mounts the identity dir -- or pass --ephemeral-identity)"
        )
    })?;
    std::fs::rename(&tmp, IDENTITY_PATH)
        .map_err(|e| format!("renaming {tmp} into place: {e}"))?;
    println!("identity: new key persisted to {IDENTITY_PATH}");

    // The freshly-minted handles serve this run directly; the file is
    // for the next one.
    from_keys(signing, verifying)
        .await
        .map_err(|e| format!("identity from generated keys: {e:?}"))
}
