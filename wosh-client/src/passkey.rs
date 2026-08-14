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

/// The two challenges the recovery ceremonies sign.
///
/// They are constants because nothing verifies them -- recovery reads
/// the signatures, not the messages -- and because a component with no
/// randomness of its own has no better source. What they must be is
/// DIFFERENT from each other: an authenticator may sign
/// deterministically and may report a zero counter, and two ceremonies
/// over identical input would then return identical signatures, which
/// carry identical ambiguity. (`wosh-webauthn-ssh` refuses that case
/// rather than guessing, so the worst outcome is a legible failure --
/// but the fix belongs here, where the challenges are chosen.)
const RECOVERY_CHALLENGES: [&[u8]; 2] = [
    b"wosh passkey recovery: first of two",
    b"wosh passkey recovery: second of two",
];

/// Work this client's passkey identity back out of the credential.
///
/// The situation: the passkey is still there, but whatever this browser
/// knew about it is not. Two assertions determine the public key that
/// made them, which is the only piece SSH actually needs.
pub async fn recover() -> Result<String, String> {
    let mut ceremonies: Vec<passkey_store::RecoveryAssertion> =
        Vec::with_capacity(RECOVERY_CHALLENGES.len());
    for challenge in RECOVERY_CHALLENGES {
        let ceremony = passkey_store::assert_unknown(challenge.to_vec())
            .await
            .map_err(|e| format!("passkey recovery ceremony: {e}"))?;

        // Check the relying party as each ceremony lands, not at the
        // end. It becomes the `application` field of the line this is
        // about to print, so a wrong one yields a line that can never
        // authenticate -- and catching it here costs the user one
        // touch instead of two. The string is checked against what was
        // actually SIGNED (the authenticator opens its signed data
        // with the hash of the relying party), so it is proof rather
        // than a claim.
        let expected = ceremonies
            .first()
            .map_or(ceremony.relying_party.as_str(), |c| c.relying_party.as_str());
        let signed_for = wire::asserted_for_rp(
            wire::Assertion {
                authenticator_data: &ceremony.assertion.authenticator_data,
                client_data_json: &ceremony.assertion.client_data_json,
                signature: &ceremony.assertion.signature,
            },
            expected,
        );
        if !signed_for || ceremony.relying_party != expected {
            return Err(format!(
                "passkey recovery: the authenticator did not sign for {expected:?}"
            ));
        }

        ceremonies.push(ceremony);
    }

    // Insisting on one credential up front turns "the user picked a
    // different passkey the second time" into a sentence about
    // passkeys, rather than a puzzle about keys that do not agree.
    let credential_id = ceremonies[0].credential_id.clone();
    if ceremonies
        .iter()
        .any(|c| c.credential_id != credential_id)
    {
        return Err("passkey recovery: a different passkey answered the second time -- \
                    choose the same one at both prompts"
            .to_string());
    }

    let assertions: Vec<wire::Assertion<'_>> = ceremonies
        .iter()
        .map(|c| wire::Assertion {
            authenticator_data: &c.assertion.authenticator_data,
            client_data_json: &c.assertion.client_data_json,
            signature: &c.assertion.signature,
        })
        .collect();
    let public_key = wire::recover_public_key(&assertions)
        .map_err(|e| format!("passkey recovery: {e}"))?;

    // The relying party comes from the ceremonies rather than being
    // recovered: it is just this site's domain, and the component has
    // no other way to learn its own origin. Every ceremony above was
    // checked to have signed for it.
    let identity = PasskeyIdentity {
        public_key,
        relying_party: ceremonies[0].relying_party.clone(),
    };
    passkey_store::remember(identity.clone(), credential_id)
        .await
        .map_err(|e| format!("passkey recovery: {e}"))?;
    passkey_line(&identity)
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
