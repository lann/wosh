//! What the listener can honestly say about the sshd it is proxying to.
//!
//! The wosh listener is a dumb pipe: the SSH session is end to end
//! between a browser and sshd, and the browser is what verifies the
//! host key. But the operator standing at the terminal has nothing to
//! compare the phone's confirmation dialog against, and "type yes"
//! with nothing to check is not a decision.
//!
//! The one thing the listener can contribute without becoming a
//! middlebox: the server's host key crosses the wire IN THE CLEAR
//! during the handshake (encryption starts at NEWKEYS), and those
//! bytes are already flowing through this process. So we watch a COPY
//! of them, parse out `K_S`, and print its SHA256 fingerprint.
//!
//! A fingerprint printed by the very box that could be lying about it
//! is worth little on its own, which is why observing is only half of
//! this crate. The other half is [`policy`]: an observation is shown
//! when known_hosts corroborates it, or when the target is loopback
//! (the listener is then on the target machine, watching its own
//! sshd, and an attacker who could forge that already owns the box).
//! A CONTRADICTED observation is not a warning, it is a refusal.
//!
//! Everything here is pure and host-testable; the listener component
//! supplies the bytes, the known_hosts text and the printing. That
//! split is deliberate -- `listener-core` is a `cdylib` component and
//! cannot run `cargo test` at all.

mod known;
mod sniff;

pub use known::{fingerprint, host_lookup_key, lookup, Lookup};
// Re-exported so callers need not depend on `ssh-key` directly just
// to name the thing the sniffer hands them.
pub use sniff::{Sniffer, MAX_SCAN};
pub use ssh_key::PublicKey;

use std::net::SocketAddr;

/// What the listener should DO about an observed host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Print it: known_hosts says this is the key that belongs here.
    Corroborated,
    /// Print it, but say plainly that nothing corroborates it.
    Unverified,
    /// Tear the connection down. The observation contradicts
    /// known_hosts (or the key is revoked).
    Refuse,
    /// Print no fingerprint, only why there isn't one.
    Silent,
}

/// A verdict plus the exact line(s) to show the operator. Structured
/// rather than printed here so the whole policy table is testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    pub message: String,
}

impl Decision {
    /// True when the connection must not proceed.
    pub fn refuses(&self) -> bool {
        self.verdict == Verdict::Refuse
    }
}

/// Is this target on the machine we are running on? Loopback is the
/// case where observing the sshd's key is self-observation: the
/// listener and the sshd are the same host, so an attacker able to
/// forge the observation is already inside the box the key protects.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// The whole policy, as a pure function of what we saw and where.
///
/// `fingerprint` is the SHA256 fingerprint of the key just observed
/// (`SHA256:...`), `target` the address as the operator spelled it.
pub fn policy(
    lookup: &Lookup,
    fingerprint: &str,
    target: &SocketAddr,
    allow_mismatch: bool,
) -> Decision {
    let loopback = is_loopback(target);
    match lookup {
        Lookup::Match => Decision {
            verdict: Verdict::Corroborated,
            message: format!(
                "host key of {target}: {fingerprint} (matches known_hosts -- \
                 compare it with what your browser shows)"
            ),
        },
        // A revoked key is a stronger statement than a mismatch: the
        // operator did not merely fail to recognise this key, they
        // wrote down that it must never be accepted. --allow-host-key-mismatch
        // is an escape from "I have not updated known_hosts", not from
        // that, so it does NOT apply here.
        Lookup::Revoked => Decision {
            verdict: Verdict::Refuse,
            message: format!(
                "REFUSED: the host key {target} presented ({fingerprint}) is marked \
                 @revoked in known_hosts. This connection was torn down. \
                 --allow-host-key-mismatch does not override a revocation."
            ),
        },
        Lookup::Mismatch { known } => {
            let known = if known.is_empty() {
                "(none readable)".to_string()
            } else {
                known.join(", ")
            };
            if allow_mismatch {
                Decision {
                    verdict: Verdict::Unverified,
                    message: format!(
                        "WARNING: host key of {target}: {fingerprint} -- this does NOT \
                         match known_hosts, which has {known}. Proceeding only because \
                         --allow-host-key-mismatch was passed; this fingerprint is \
                         UNVERIFIED and may be an interposed server."
                    ),
                }
            } else {
                Decision {
                    verdict: Verdict::Refuse,
                    message: format!(
                        "REFUSED: the host key {target} presented ({fingerprint}) does \
                         not match known_hosts, which has {known}. This connection was \
                         torn down. If the target legitimately re-keyed, update \
                         known_hosts -- or pass --allow-host-key-mismatch to proceed \
                         with an unverified key."
                    ),
                }
            }
        }
        Lookup::Unknown if loopback => Decision {
            verdict: Verdict::Unverified,
            message: format!(
                "host key of {target}: {fingerprint} (observed on the local sshd; \
                 no known_hosts entry corroborates it -- compare it with what your \
                 browser shows)"
            ),
        },
        Lookup::Unknown => Decision {
            verdict: Verdict::Silent,
            message: format!(
                "host key of {target}: not shown -- there is no known_hosts entry for \
                 it and the target is not loopback, so an observed fingerprint would \
                 corroborate nothing. Add the host to known_hosts to have it checked."
            ),
        },
    }
}

/// The same policy for a target whose key CHANGED under us: we
/// already printed one fingerprint for this target and now see a
/// different one. Distinct wording because the contradiction is with
/// our own earlier observation, which known_hosts may know nothing
/// about.
pub fn policy_changed(
    previous: &str,
    fingerprint: &str,
    target: &SocketAddr,
    allow_mismatch: bool,
) -> Decision {
    if allow_mismatch {
        Decision {
            verdict: Verdict::Unverified,
            message: format!(
                "WARNING: the host key of {target} CHANGED mid-run: was {previous}, \
                 now {fingerprint}. Proceeding only because --allow-host-key-mismatch \
                 was passed; this fingerprint is UNVERIFIED."
            ),
        }
    } else {
        Decision {
            verdict: Verdict::Refuse,
            message: format!(
                "REFUSED: the host key of {target} CHANGED mid-run: was {previous}, \
                 now {fingerprint}. Something else is answering on that address. This \
                 connection was torn down; pass --allow-host-key-mismatch if you \
                 really did re-key the target under a running listener."
            ),
        }
    }
}

#[cfg(test)]
mod tests;
