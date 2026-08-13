//! The persistent pairing identity: this client's stable iroh name,
//! the thing a listener can remember it by.
//!
//! Same dance as the listener's own persisted identity
//! (listener-core/src/identity.rs), with the host's `pairing-store`
//! import standing in for the filesystem: the key pair rides
//! `polymorph:webcrypto` handles, minted extractable exactly once so
//! the material can be persisted, reimported NON-extractable on later
//! runs, and handed to `identity-from-keys`, which sign/verify-probes
//! the pair -- a corrupted blob fails legibly at dial time, not as
//! handshake failures against every listener.
//!
//! Blob layout (mirrors the listener's identity file):
//!
//! ```text
//! byte 0:       version (currently 1)
//! bytes 1..33:  raw Ed25519 public key (32 bytes)
//! remaining:    PKCS#8 PrivateKeyInfo (DER, RFC 8410)
//! ```
//!
//! Every failure degrades to a FRESH identity (`identity-generate`)
//! rather than a dead client: a host without durable storage, a
//! corrupt blob, a refused store -- each costs this run its pairing
//! continuity and nothing else. The pairing layer gates only the
//! tunnel; SSH is the real boundary.

use crate::bindings::polymorph::iroh::identity::Identity;
use crate::bindings::polymorph::iroh::identity_from_keys::from_keys;
use crate::bindings::polymorph::iroh::identity_generate::generate as identity_generate;
use crate::bindings::polymorph::webcrypto::ed25519_sign::{generate_key, import_signing_key_pkcs8};
use crate::bindings::polymorph::webcrypto::ed25519_verify::import_verifying_key_raw;
use crate::bindings::polymorph::webcrypto::signature::SigningKeyOptions;
use crate::bindings::wosh::terminal::pairing_store;

const VERSION: u8 = 1;
const PUBKEY_LEN: usize = 32;

/// The pairing identity: loaded from the host's store, minted (and
/// stored) on first use, or -- when anything at all goes wrong --
/// fresh for this run only.
pub async fn load_or_create() -> Result<Identity, String> {
    match pairing_store::load().await {
        Ok(Some(blob)) => match from_blob(&blob).await {
            Ok(identity) => return Ok(identity),
            Err(e) => {
                // A blob that no longer parses or probes is abandoned,
                // not fatal: continuity is lost, connecting is not.
                eprintln!("pairing identity: stored blob rejected ({e}); minting fresh");
            }
        },
        Ok(None) => {}
        Err(e) => eprintln!("pairing identity: store unavailable ({e}); minting fresh"),
    }
    create_and_store().await
}

async fn from_blob(blob: &[u8]) -> Result<Identity, String> {
    if blob.len() <= 1 + PUBKEY_LEN {
        return Err("truncated".into());
    }
    if blob[0] != VERSION {
        return Err(format!("unsupported version {}", blob[0]));
    }
    let pub_raw = &blob[1..1 + PUBKEY_LEN];
    let pkcs8 = &blob[1 + PUBKEY_LEN..];

    let opts = SigningKeyOptions::new();
    opts.can_sign(true); // deliberately NOT extractable on reload
    let signing = import_signing_key_pkcs8(pkcs8.to_vec(), opts)
        .await
        .map_err(|e| format!("importing signing key: {e:?}"))?;
    let verifying = import_verifying_key_raw(pub_raw.to_vec())
        .await
        .map_err(|e| format!("importing public key: {e:?}"))?;
    from_keys(signing, verifying)
        .await
        .map_err(|e| format!("key pair rejected: {e:?}"))
}

async fn create_and_store() -> Result<Identity, String> {
    let opts = SigningKeyOptions::new();
    opts.can_sign(true);
    opts.extractable(true); // exported once, below; persistence is the point
    let Ok((signing, verifying)) = generate_key(opts).await else {
        // No webcrypto generate (a host this degraded probably cannot
        // store either): fall back to a fully ephemeral identity.
        return identity_generate().await.map_err(|e| format!("iroh identity: {e:?}"));
    };
    let (Ok(pkcs8), Ok(pub_raw)) =
        (signing.export_key_pkcs8().await, verifying.export_key_raw().await)
    else {
        return identity_generate().await.map_err(|e| format!("iroh identity: {e:?}"));
    };
    if pub_raw.len() != PUBKEY_LEN {
        return Err(format!("public key is {} bytes, expected {PUBKEY_LEN}", pub_raw.len()));
    }

    let mut blob = Vec::with_capacity(1 + PUBKEY_LEN + pkcs8.len());
    blob.push(VERSION);
    blob.extend_from_slice(&pub_raw);
    blob.extend_from_slice(&pkcs8);
    match pairing_store::store(blob).await {
        Ok(()) => {}
        Err(e) => eprintln!("pairing identity: store refused ({e}); this run pairs fresh"),
    }

    // The freshly-minted handles serve this run directly; the stored
    // blob is for the next one.
    from_keys(signing, verifying)
        .await
        .map_err(|e| format!("identity from generated keys: {e:?}"))
}
