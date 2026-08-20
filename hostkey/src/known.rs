//! known_hosts: what the operator has already written down.
//!
//! `ssh-key` parses the LINES; the matching is ours, because OpenSSH's
//! host-pattern rules (globs, negation, the `[host]:port` spelling,
//! hashed names) are not part of that crate. Getting the matching
//! wrong in the permissive direction would turn a mismatch into an
//! "unknown host", which is exactly the outcome this whole feature
//! exists to prevent -- so unparseable or unmatchable entries are
//! skipped, never treated as a match.

use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};
use ssh_key::{HashAlg, PublicKey};

/// What known_hosts says about the key we just watched go past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// A known_hosts entry for this host carries exactly this key.
    Match,
    /// This key matches a `@revoked` entry -- the operator wrote down
    /// that it must never be accepted.
    Revoked,
    /// The host IS in known_hosts, but with other keys. `known` are
    /// their fingerprints, so the refusal can name what it expected.
    Mismatch { known: Vec<String> },
    /// Nothing in known_hosts covers this host.
    Unknown,
}

/// How OpenSSH spells a host in known_hosts: bare on port 22,
/// `[host]:port` otherwise (`127.0.0.1`, `2001:db8::1`,
/// `[127.0.0.1]:2222`, `[2001:db8::1]:2222`). We must produce the
/// same string, since hashed entries hash exactly this and there is
/// no second chance at guessing.
pub fn host_lookup_key(addr: SocketAddr) -> String {
    let host = match addr {
        SocketAddr::V4(a) => a.ip().to_string(),
        SocketAddr::V6(a) => a.ip().to_string(),
    };
    if addr.port() == 22 {
        host
    } else {
        format!("[{host}]:{}", addr.port())
    }
}

/// Compare `presented` against every known_hosts entry covering
/// `lookup_key`.
///
/// `text` may be empty or unreadable garbage; that is simply a file
/// with no entries for this host.
pub fn lookup(text: &str, lookup_key: &str, presented: &PublicKey) -> Lookup {
    let want = fingerprint(presented);
    let mut known = Vec::new();
    let mut host_seen = false;

    for entry in KnownHosts::new(text).flatten() {
        if !patterns_match(entry.host_patterns(), lookup_key) {
            continue;
        }
        match entry.marker() {
            // A @cert-authority line is a CA that SIGNS host keys,
            // not a host key. Comparing a presented key against it
            // would be a category error in both directions: never a
            // match, and counting it as "a key this host is known to
            // have" would make a legitimate key look like a mismatch.
            Some(Marker::CertAuthority) => continue,
            Some(Marker::Revoked) => {
                if fingerprint(entry.public_key()) == want {
                    return Lookup::Revoked;
                }
                // A revocation for some OTHER key says nothing about
                // this one, and must not count as a key the host is
                // expected to present.
                continue;
            }
            None => {}
        }
        host_seen = true;
        let fp = fingerprint(entry.public_key());
        if fp == want {
            return Lookup::Match;
        }
        known.push(fp);
    }

    if host_seen {
        Lookup::Mismatch { known }
    } else {
        Lookup::Unknown
    }
}

/// `SHA256:...`, byte-identical to `ssh-keygen -lf` and to the Go
/// `ssh.FingerprintSHA256` the browser client shows. That identity is
/// the point: the operator compares these two strings by eye.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Does an entry's host field cover `lookup_key`?
fn patterns_match(patterns: &HostPatterns, lookup_key: &str) -> bool {
    match patterns {
        HostPatterns::Patterns(list) => {
            let mut positive = false;
            for pattern in list {
                match pattern.strip_prefix('!') {
                    // A matching negation disqualifies the entry
                    // outright, whatever else on the line matched.
                    Some(neg) => {
                        if glob_match(neg, lookup_key) {
                            return false;
                        }
                    }
                    None => {
                        if glob_match(pattern, lookup_key) {
                            positive = true;
                        }
                    }
                }
            }
            positive
        }
        // `ssh-keygen -Hf` rewrites host fields as
        // HMAC-SHA1(key = salt, msg = hostname). There is nothing to
        // glob against: either the MAC over this exact lookup key
        // reproduces the stored hash, or the entry is not ours.
        HostPatterns::HashedName { salt, hash } => {
            let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(salt) else {
                return false;
            };
            mac.update(lookup_key.as_bytes());
            mac.verify_slice(hash).is_ok()
        }
    }
}

/// OpenSSH host globbing: `*` matches any run of characters, `?`
/// exactly one, everything else is literal. Hostnames are
/// case-insensitive.
///
/// Iterative backtracking rather than recursion: the input is a file
/// the operator controls, but so is the pattern, and a recursive
/// matcher on `*a*a*a*...` is a stack the listener does not need to
/// risk.
fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let v: Vec<char> = value.to_ascii_lowercase().chars().collect();
    let (mut pi, mut vi) = (0usize, 0usize);
    // Where to resume if the current `*` turns out to have eaten too
    // little.
    let (mut star, mut star_vi) = (None, 0usize);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_vi = vi;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
