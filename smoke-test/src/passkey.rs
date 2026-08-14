//! A software WebAuthn authenticator standing in for a real platform
//! authenticator (Secure Enclave / TPM / a browser's passkey prompt).
//!
//! The point of this module is not to simulate WebAuthn faithfully --
//! it is to produce the exact bytes a real authenticator would hand a
//! browser for the one signature algorithm OpenSSH understands
//! (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`), so `just
//! e2e-passkey` proves the *wire format* against a real, unmodified
//! sshd. The ceremony (user gesture, platform UI, attestation) is the
//! browser gate's to prove; this gate proves the bytes.
//!
//! State is a single freshly-generated P-256 key per process, an
//! "enrolled" flag, and a monotonically increasing signature counter
//! -- everything a soft authenticator needs to be self-consistent
//! across one run.

use anyhow::{anyhow, Result};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// The Relying Party ID this soft authenticator's credential is scoped
/// to. There is no real browser origin here, so this is a fixed
/// stand-in; what matters for the gate is only that it is
/// self-consistent between `identity()` (which reports it in
/// `passkey-identity.relying-party`, and so ends up as the
/// `authorized_keys` line's `application` field) and `assert()`
/// (which signs over `sha256(rp-id)` in `authenticator-data`).
pub const RP_ID: &str = "wosh.example";

/// The WebAuthn origin this soft authenticator asserts against. Real
/// WebAuthn ties `origin` to `rp-id` (the RP ID must be the origin's
/// domain, or a registrable suffix of it); the pairing here only has
/// to be internally consistent since nothing browser-side checks it.
pub const ORIGIN: &str = "https://wosh.example";

/// One WebAuthn assertion, verbatim as `passkey-store.assert` returns
/// it to the guest -- mirrors `wosh:terminal/passkey-store.assertion`
/// (see `wosh-client/wit/terminal.wit`), duplicated here as plain
/// Rust so this module has no bindgen dependency of its own.
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A software WebAuthn authenticator: one P-256 credential, enrolled
/// or not, with its own signature counter.
pub struct SoftAuthenticator {
    key: SigningKey,
    counter: u32,
    enrolled: bool,
}

impl SoftAuthenticator {
    pub fn new() -> Self {
        Self { key: SigningKey::random(&mut rand_core::OsRng), counter: 0, enrolled: false }
    }

    /// The uncompressed P-256 public point, `0x04 || X || Y` (65
    /// bytes) -- see `passkey-identity.public-key`'s doc comment in
    /// the WIT contract for why this exact encoding.
    fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    /// `identity()`: `none` until enrolled.
    pub fn identity(&self) -> Option<(Vec<u8>, String)> {
        self.enrolled.then(|| (self.public_key_bytes(), RP_ID.to_string()))
    }

    /// `enroll()`: mark enrolled (a real authenticator would run the
    /// registration ceremony and mint a new credential here; the soft
    /// authenticator only ever has the one key, generated at
    /// construction, so enrolling just starts offering it).
    pub fn enroll(&mut self) -> (Vec<u8>, String) {
        self.enrolled = true;
        (self.public_key_bytes(), RP_ID.to_string())
    }

    /// `adopt(identity)`: for this native gate there is only ever one
    /// authenticator and one key, so "adopting" a claimed identity is
    /// legitimate only when it names the exact key this authenticator
    /// already holds -- the direct comparison the WIT doc comment
    /// describes as what a browser host does indirectly (assert once,
    /// verify against the claimed public key).
    pub fn adopt(&mut self, public_key: &[u8], relying_party: &str) -> Result<()> {
        if relying_party != RP_ID {
            return Err(anyhow!(
                "adopt: relying party {relying_party:?} does not match this authenticator's {RP_ID:?}"
            ));
        }
        if public_key != self.public_key_bytes() {
            return Err(anyhow!(
                "adopt: claimed public key does not match this authenticator's credential"
            ));
        }
        self.enrolled = true;
        Ok(())
    }

    /// `forget()`: stop offering the credential (it is not deleted --
    /// exactly as the WIT doc comment for `forget-passkey` describes).
    pub fn forget(&mut self) {
        self.enrolled = false;
    }

    /// `assert(challenge)`: run a WebAuthn assertion ceremony over
    /// `challenge` (the raw SSH signature blob, per the WIT doc
    /// comment on `passkey-store.assert` -- NOT a hash of it).
    pub fn assert(&mut self, challenge: &[u8]) -> Assertion {
        // clientDataJSON: exact bytes, built by concatenation so field
        // order is exactly as written -- sshd prefix-matches this
        // string, so any reordering or re-serialization fails.
        //
        // The challenge is base64url-encoded WITHOUT padding: OpenSSH
        // strips padding when it reconstructs the expected prefix
        // (see the module's crate-level doc comment), so a padded
        // encoding here would fail that comparison.
        use base64::Engine;
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_b64}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
        )
        .into_bytes();

        // authenticatorData: sha256(rp-id) || flags || counter(BE).
        // flags = 0x05 = user-present (0x01) | user-verified (0x04);
        // no attested-credential-data (0x40) or extension-data (0x80)
        // bits, and no extension bytes follow, per the WIT doc comment
        // on `assert` ("request no authenticator extensions").
        self.counter = self.counter.wrapping_add(1);
        let rp_id_hash = Sha256::digest(RP_ID.as_bytes());
        let mut authenticator_data = Vec::with_capacity(32 + 1 + 4);
        authenticator_data.extend_from_slice(&rp_id_hash);
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&self.counter.to_be_bytes());

        // signature: ECDSA/P-256/SHA-256 over
        // authenticator-data || sha256(client-data-json), DER-encoded
        // (what WebAuthn's `AuthenticatorAssertionResponse.signature`
        // actually carries).
        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed_over = authenticator_data.clone();
        signed_over.extend_from_slice(&client_data_hash);
        let signature: Signature = self.key.sign(&signed_over);
        let signature = signature.to_der().as_bytes().to_vec();

        Assertion { authenticator_data, client_data_json, signature }
    }

    /// A stable synthetic credential id for this authenticator's one
    /// key, standing in for the real WebAuthn credential handle a
    /// platform authenticator would report. The only job it has here
    /// is letting a caller check that two `assert-unknown` ceremonies
    /// answered from the SAME credential -- `sha256(public key)` is a
    /// convenient, deterministic way to produce something with that
    /// shape without inventing state.
    fn credential_id(&self) -> Vec<u8> {
        Sha256::digest(self.public_key_bytes()).to_vec()
    }

    /// `assert_unknown(challenge)`: run the assertion ceremony WITHOUT
    /// consulting `enrolled` -- this is the entire point. Recovery
    /// exists for exactly the case where the stored record (and thus
    /// `enrolled`) is gone; a real authenticator does not require a
    /// prior "enrol" bit either; it just holds credentials and answers
    /// challenges. So this produces the identical assertion `assert`
    /// would, plus the credential id, regardless of `self.enrolled`.
    pub fn assert_unknown(&mut self, challenge: &[u8]) -> (Vec<u8>, String, Assertion) {
        let assertion = self.assert(challenge);
        (self.credential_id(), RP_ID.to_string(), assertion)
    }

    /// `remember(identity, credential_id)`: store an identity whose
    /// public half has already been PROVED (by two intersecting
    /// `assert-unknown` ceremonies), without asking for a confirming
    /// touch -- this is `adopt` minus the ceremony, per the WIT doc
    /// comment on `passkey-store.remember`. For this soft
    /// authenticator, which only ever holds one key, "already proved"
    /// is checked the same way `adopt` checks a claim: the public key
    /// must name the key this authenticator actually holds.
    pub fn remember(&mut self, public_key: &[u8], relying_party: &str) -> Result<()> {
        if relying_party != RP_ID {
            return Err(anyhow!(
                "remember: relying party {relying_party:?} does not match this authenticator's {RP_ID:?}"
            ));
        }
        if public_key != self.public_key_bytes() {
            return Err(anyhow!(
                "remember: claimed public key does not match this authenticator's credential"
            ));
        }
        self.enrolled = true;
        Ok(())
    }
}
