//! The passkey identity: a WebAuthn credential offered as an SSH key.
//!
//! This module is the seam between two host-side keepers and one SSH
//! core. `identity-store` holds an Ed25519 key and signs; `passkey-store`
//! runs WebAuthn ceremonies and hands back what the browser produced.
//! Neither speaks SSH. Everything SSH-shaped -- the key blob, the
//! `authorized_keys` line, the signature envelope -- is built here, on
//! top of `wosh-webauthn-ssh`, which owns the byte layouts and is
//! tested on its own.
//!
//! The reason a passkey needs a module and the browser key does not:
//! it has a LIFECYCLE. An Ed25519 pair is minted on demand and that is
//! the end of it, but a credential is enrolled by a human, may be
//! adopted from another device that already holds it, and can be
//! forgotten -- and the public half, which SSH must put on the wire,
//! is not recoverable from the credential itself. Hence
//! `adopt-passkey`, which takes the one string that carries it: the
//! `authorized_keys` line already installed on the target.

use crate::bindings::wosh::ssh_core::core::PublicKey as CoreKey;
use crate::bindings::wosh::terminal::passkey_store::{self, PasskeyIdentity};

use wosh_webauthn_ssh as wire;

/// The comment on the browser key's line, kept as it was.
pub const BROWSER_COMMENT: &str = "wosh-browser";
/// The comment on a passkey's line, so the two are told apart at a
/// glance in an `authorized_keys` file.
pub const PASSKEY_COMMENT: &str = "wosh-passkey";

/// The browser key, as the SSH core wants it offered.
pub fn browser_key(raw: &[u8]) -> Result<CoreKey, String> {
    Ok(CoreKey {
        algorithm: wire::SSH_ED25519_KEY_TYPE.to_string(),
        blob: wire::ed25519_key_blob(raw).map_err(|e| format!("ssh identity: {e}"))?,
    })
}

/// A passkey, as the SSH core wants it offered.
///
/// Note the deliberate mismatch: the blob is a plain
/// `sk-ecdsa-sha2-nistp256@openssh.com` key -- exactly the line in
/// `authorized_keys` -- while the algorithm is the webauthn one,
/// because that is the shape of the signature that will answer for it.
/// sshd resolves the algorithm name and compares it against the name
/// inside the signature, so this pairing is the only one it accepts.
pub fn passkey_key(identity: &PasskeyIdentity) -> Result<CoreKey, String> {
    Ok(CoreKey {
        algorithm: wire::WEBAUTHN_SK_ECDSA_ALGORITHM.to_string(),
        blob: wire::sk_ecdsa_key_blob(&identity.public_key, &identity.relying_party)
            .map_err(|e| format!("passkey identity: {e}"))?,
    })
}

/// The `authorized_keys` line for a passkey.
pub fn passkey_line(identity: &PasskeyIdentity) -> Result<String, String> {
    let blob = wire::sk_ecdsa_key_blob(&identity.public_key, &identity.relying_party)
        .map_err(|e| format!("passkey identity: {e}"))?;
    Ok(wire::authorized_keys_line(
        wire::SK_ECDSA_KEY_TYPE,
        &blob,
        PASSKEY_COMMENT,
    ))
}

/// The `authorized_keys` line for the browser's Ed25519 key.
pub fn browser_line(raw: &[u8]) -> Result<String, String> {
    let blob = wire::ed25519_key_blob(raw).map_err(|e| format!("ssh identity: {e}"))?;
    Ok(wire::authorized_keys_line(
        wire::SSH_ED25519_KEY_TYPE,
        &blob,
        BROWSER_COMMENT,
    ))
}

/// The enrolled passkey, if there is one.
pub async fn identity() -> Result<Option<PasskeyIdentity>, String> {
    passkey_store::identity()
        .await
        .map_err(|e| format!("read the passkey identity: {e}"))
}

/// Enrol, and hand back the line to install on the target.
pub async fn enroll() -> Result<String, String> {
    let identity = passkey_store::enroll()
        .await
        .map_err(|e| format!("enrol a passkey: {e}"))?;
    passkey_line(&identity)
}

/// Adopt an identity from the line another device printed.
///
/// The line is parsed here rather than passed through, so that a
/// mistyped or truncated paste fails immediately and locally, with a
/// message about the line -- and so that what comes back is the line as
/// this client understands it, which the caller can show for
/// comparison.
pub async fn adopt(line: &str) -> Result<String, String> {
    let (public_key, relying_party) =
        wire::parse_passkey_line(line).map_err(|e| format!("adopt a passkey: {e}"))?;
    let identity = PasskeyIdentity {
        public_key,
        relying_party,
    };
    passkey_store::adopt(identity.clone())
        .await
        .map_err(|e| format!("adopt a passkey: {e}"))?;
    passkey_line(&identity)
}

/// Stop offering the enrolled passkey.
pub async fn forget() -> Result<(), String> {
    passkey_store::forget()
        .await
        .map_err(|e| format!("forget the passkey: {e}"))
}

/// Run the ceremony the server's signature request calls for, and
/// shape the result into an SSH signature.
///
/// `challenge` is the core's parked blob, passed through untouched:
/// the browser embeds those exact bytes in the JSON it signs, and the
/// server rebuilds them from the same place.
pub async fn sign(challenge: &[u8]) -> Result<wire::SshSignature, String> {
    let assertion = passkey_store::assert(challenge.to_vec())
        .await
        .map_err(|e| format!("passkey ceremony: {e}"))?;
    wire::signature_from_assertion(
        wire::Assertion {
            authenticator_data: &assertion.authenticator_data,
            client_data_json: &assertion.client_data_json,
            signature: &assertion.signature,
        },
        challenge,
    )
    .map_err(|e| format!("passkey assertion: {e}"))
}
