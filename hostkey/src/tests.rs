//! The unit tests are the deliverable's core: nothing in this crate
//! can be checked end to end without a real sshd, a browser and a
//! relay, so every rule that would otherwise only be exercised in the
//! field is pinned here instead.
//!
//! Transcripts are BUILT, not pasted: `packet()` frames a payload the
//! way RFC 4253 §6 says to, so a fixture says what it means and a
//! deliberately malformed one differs from a good one in exactly the
//! field under test.

use super::*;
use crate::known::fingerprint;
use ssh_key::PublicKey;
use std::net::SocketAddr;

// Real keys, generated with ssh-keygen for these tests only. They are
// public keys of throwaway pairs; the private halves were discarded.
const ED25519_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6LYq5cnPGSfgE3kJxIR0pkf0XkoXYzGNG6tEohn/Fg";
const ECDSA_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDfmvJmpJRAimfHv11IGVGHTram0+owTj+7J3LlNRLXDoccyQxtFUUrKTSxB+cUV/t/P0gsL95/IAzH09tQWbdM=";
const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdwsfyiJwlHzpcwI+MRpSsukEvWiWclA1KU34rRKd0aV+1xJv3mSHMpwN4QKxqpxs+MwpG7drc6A8GeqmS7SiZ8j46xpaHZ2TjMuyB3Fad3gNWLz+jyapBU4ClCss47mOowJwbSyRmHQgWp2PZ+2VWBY1FZ3FHpQJukZW8Xrgw33Uk/1QAtEEzHH0YQfdTyrwPKMuhRza2myT6bzd2eZNNHCaRzM3PZfpDicz3io+8IwxdBbiHmRT4ApMydj62AajmOquE3FQdLixcJmCxqNma9KwU54eJBnPFplMEgaEJlbOCQWxdX7TCPDdRU/O0vDoiL4YkapsSP4ZvvA9425sqdpXSRRbmKXZ0vF+khsoPEcYr1B/h0NdLl/xLvsS3iKoef86k4BgnaNQV+VRt5ScSyqmp1UzmlyT2gtvuohDc7KkZEUhoXZNgNJpKVoUmjeaFi42AU5j1b1mIhqI76wdYAYH0ueXrsl0bbmbVj6ZBK48tsngLCNZOOy0ZVU/l/uc=";
/// `ssh-keygen -H` output for `[127.0.0.1]:2222` + the ed25519 key
/// above: the hashed-host form, as OpenSSH actually writes it.
const HASHED_LINE: &str = "|1|FoeonMjmLyc3DGLw+nw7rDSxN84=|7SE3uZqtTvwIf1xtGdM5EG5u1Qg= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6LYq5cnPGSfgE3kJxIR0pkf0XkoXYzGNG6tEohn/Fg";

fn key(openssh: &str) -> PublicKey {
    PublicKey::from_openssh(openssh).expect("fixture key parses")
}

/// The wire-format blob of a public key -- exactly what `K_S` is.
fn blob(k: &PublicKey) -> Vec<u8> {
    k.to_bytes().expect("key encodes")
}

/// Frame a payload into a cleartext SSH binary packet.
fn packet(payload: &[u8]) -> Vec<u8> {
    // Padding must be >= 4 and bring the whole packet to a multiple
    // of 8; sshd does the same arithmetic.
    let mut pad = 8 - ((payload.len() + 5) % 8);
    if pad < 4 {
        pad += 8;
    }
    let packet_length = (payload.len() + pad + 1) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&packet_length.to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// `byte msg || string s`.
fn msg_with_string(msg: u8, s: &[u8]) -> Vec<u8> {
    let mut p = vec![msg];
    p.extend_from_slice(&(s.len() as u32).to_be_bytes());
    p.extend_from_slice(s);
    p
}

const IDENT: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";

/// A minimal but well-formed server transcript: ident line, a KEXINIT
/// stand-in, then the reply carrying K_S.
fn transcript(k: &PublicKey, reply_msg: u8) -> Vec<u8> {
    let mut out = Vec::from(IDENT);
    out.extend(packet(&[20u8; 40])); // KEXINIT, contents irrelevant here
    out.extend(packet(&msg_with_string(reply_msg, &blob(k))));
    out
}

/// Feed a transcript one byte at a time -- the pathological chunking
/// a real TCP read can hand us.
fn sniff_bytewise(data: &[u8]) -> Option<String> {
    let mut s = Sniffer::new();
    for b in data {
        s.feed(&[*b]);
    }
    s.key().map(fingerprint)
}

/// ...and in one blob.
fn sniff_blob(data: &[u8]) -> Option<String> {
    let mut s = Sniffer::new();
    s.feed(data);
    s.key().map(fingerprint)
}

// ------------------------------------------------------- the sniffer

#[test]
fn finds_an_ed25519_host_key() {
    let k = key(ED25519_PUB);
    assert_eq!(sniff_blob(&transcript(&k, 31)), Some(fingerprint(&k)));
}

#[test]
fn finds_an_ecdsa_host_key() {
    let k = key(ECDSA_PUB);
    assert_eq!(sniff_blob(&transcript(&k, 31)), Some(fingerprint(&k)));
}

#[test]
fn finds_an_rsa_host_key() {
    let k = key(RSA_PUB);
    assert_eq!(sniff_blob(&transcript(&k, 31)), Some(fingerprint(&k)));
}

#[test]
fn chunking_does_not_change_the_result() {
    let k = key(ED25519_PUB);
    let t = transcript(&k, 31);
    assert_eq!(sniff_bytewise(&t), sniff_blob(&t));
    assert_eq!(sniff_bytewise(&t), Some(fingerprint(&k)));
}

#[test]
fn skips_preamble_lines_before_the_ident_line() {
    let k = key(ED25519_PUB);
    let mut t = Vec::from(&b"a banner the server felt like sending\r\n"[..]);
    t.extend_from_slice(b"and another\r\n");
    t.extend(transcript(&k, 31));
    assert_eq!(sniff_blob(&t), Some(fingerprint(&k)));
}

#[test]
fn group_exchange_prime_on_31_does_not_fool_it() {
    // The trap this crate is most likely to fall into: under
    // diffie-hellman-group-exchange, message 31 is KEX_DH_GEX_GROUP
    // and its first field is an mpint prime, not K_S. Validating by
    // parse is what keeps a prime from being reported as a host key.
    let k = key(ED25519_PUB);
    let prime: Vec<u8> = std::iter::repeat_n(0xABu8, 256).collect();
    let mut t = Vec::from(IDENT);
    t.extend(packet(&msg_with_string(31, &prime)));
    t.extend(packet(&msg_with_string(33, &blob(&k))));
    assert_eq!(sniff_blob(&t), Some(fingerprint(&k)));
}

#[test]
fn first_parseable_key_wins() {
    let a = key(ED25519_PUB);
    let b = key(ECDSA_PUB);
    let mut t = Vec::from(IDENT);
    t.extend(packet(&msg_with_string(31, &blob(&a))));
    t.extend(packet(&msg_with_string(33, &blob(&b))));
    assert_eq!(sniff_blob(&t), Some(fingerprint(&a)));
}

#[test]
fn newkeys_stops_the_scan() {
    let k = key(ED25519_PUB);
    let mut t = Vec::from(IDENT);
    t.extend(packet(&[21u8])); // NEWKEYS
                               // Anything after this is ciphertext; a key-shaped run of bytes in
                               // it must not be reported.
    t.extend(packet(&msg_with_string(31, &blob(&k))));
    let mut s = Sniffer::new();
    s.feed(&t);
    assert_eq!(s.key().map(fingerprint), None);
    assert!(s.finished());
}

#[test]
fn a_malformed_length_disables_the_sniffer() {
    let k = key(ED25519_PUB);
    let mut t = Vec::from(IDENT);
    // padding_length 1: below the RFC's minimum of 4, so we have lost
    // sync and must stop rather than invent boundaries.
    t.extend_from_slice(&[0, 0, 0, 12, 1]);
    t.extend_from_slice(&[0u8; 12]);
    t.extend(packet(&msg_with_string(31, &blob(&k))));
    let mut s = Sniffer::new();
    s.feed(&t);
    assert!(s.finished());
    assert_eq!(s.key().map(fingerprint), None);
}

#[test]
fn an_oversized_packet_length_disables_the_sniffer() {
    let mut t = Vec::from(IDENT);
    t.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 8]);
    let mut s = Sniffer::new();
    s.feed(&t);
    assert!(s.finished());
    assert_eq!(s.key().map(fingerprint), None);
}

#[test]
fn garbage_is_survived_silently() {
    // Not SSH at all -- an HTTP server on the target port, say.
    let mut s = Sniffer::new();
    s.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(s.key().map(fingerprint), None);
    // Random bytes with no line ending at all.
    let mut s = Sniffer::new();
    s.feed(&vec![0x00u8; 4096]);
    assert!(s.finished());
    assert_eq!(s.key().map(fingerprint), None);
}

#[test]
fn the_scan_cap_gives_up() {
    // A stream that never completes an ident line would otherwise
    // buffer forever; the cap is what bounds this observer's memory.
    let mut s = Sniffer::new();
    let mut fed = 0usize;
    while !s.finished() && fed < MAX_SCAN * 2 {
        s.feed(&[b'x'; 4096]);
        fed += 4096;
    }
    assert!(s.finished());
    assert!(fed <= MAX_SCAN + 8192, "gave up after {fed} bytes");
}

#[test]
fn feeding_after_the_end_is_a_no_op() {
    let k = key(ED25519_PUB);
    let mut s = Sniffer::new();
    s.feed(&transcript(&k, 31));
    let again = s.feed(&transcript(&key(ECDSA_PUB), 31)).map(fingerprint);
    assert_eq!(again, None);
    assert_eq!(s.key().map(fingerprint), Some(fingerprint(&k)));
}

#[test]
fn feed_reports_the_key_exactly_once() {
    let k = key(ED25519_PUB);
    let t = transcript(&k, 31);
    let mut s = Sniffer::new();
    let mut reports = 0;
    for b in &t {
        if s.feed(&[*b]).is_some() {
            reports += 1;
        }
    }
    assert_eq!(reports, 1);
}

// --------------------------------------------------- the lookup key

#[test]
fn lookup_keys_match_openssh_spelling() {
    let k = |s: &str| host_lookup_key(s.parse::<SocketAddr>().unwrap());
    assert_eq!(k("127.0.0.1:22"), "127.0.0.1");
    assert_eq!(k("127.0.0.1:2222"), "[127.0.0.1]:2222");
    assert_eq!(k("[2001:db8::1]:22"), "2001:db8::1");
    assert_eq!(k("[2001:db8::1]:2222"), "[2001:db8::1]:2222");
}

// ------------------------------------------------------ known_hosts

fn kh_line(host: &str, pubkey: &str) -> String {
    format!("{host} {pubkey}\n")
}

#[test]
fn a_plain_entry_matches() {
    let k = key(ED25519_PUB);
    let text = kh_line("127.0.0.1", ED25519_PUB);
    assert_eq!(lookup(&text, "127.0.0.1", &k), Lookup::Match);
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let k = key(ED25519_PUB);
    let text = format!("# a comment\n\n   \n{}", kh_line("127.0.0.1", ED25519_PUB));
    assert_eq!(lookup(&text, "127.0.0.1", &k), Lookup::Match);
}

#[test]
fn a_different_key_for_a_known_host_is_a_mismatch() {
    let presented = key(ECDSA_PUB);
    let text = kh_line("127.0.0.1", ED25519_PUB);
    match lookup(&text, "127.0.0.1", &presented) {
        Lookup::Mismatch { known } => assert_eq!(known, vec![fingerprint(&key(ED25519_PUB))]),
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

#[test]
fn an_unlisted_host_is_unknown() {
    let k = key(ED25519_PUB);
    let text = kh_line("192.0.2.7", ED25519_PUB);
    assert_eq!(lookup(&text, "127.0.0.1", &k), Lookup::Unknown);
}

#[test]
fn a_bracketed_port_entry_matches_only_that_port() {
    let k = key(ED25519_PUB);
    let text = kh_line("[127.0.0.1]:2222", ED25519_PUB);
    assert_eq!(lookup(&text, "[127.0.0.1]:2222", &k), Lookup::Match);
    assert_eq!(lookup(&text, "127.0.0.1", &k), Lookup::Unknown);
}

#[test]
fn globs_and_comma_lists_match() {
    let k = key(ED25519_PUB);
    let text = kh_line("example.com,192.0.2.*", ED25519_PUB);
    assert_eq!(lookup(&text, "192.0.2.55", &k), Lookup::Match);
    assert_eq!(lookup(&text, "example.com", &k), Lookup::Match);
    assert_eq!(lookup(&text, "192.0.3.55", &k), Lookup::Unknown);

    let q = kh_line("192.0.2.?", ED25519_PUB);
    assert_eq!(lookup(&q, "192.0.2.5", &k), Lookup::Match);
    assert_eq!(lookup(&q, "192.0.2.55", &k), Lookup::Unknown);
}

#[test]
fn host_matching_is_case_insensitive() {
    let k = key(ED25519_PUB);
    let text = kh_line("Example.COM", ED25519_PUB);
    assert_eq!(lookup(&text, "example.com", &k), Lookup::Match);
}

#[test]
fn a_negation_excludes_the_entry() {
    let k = key(ED25519_PUB);
    let text = kh_line("192.0.2.*,!192.0.2.9", ED25519_PUB);
    assert_eq!(lookup(&text, "192.0.2.8", &k), Lookup::Match);
    // The negation wins over the glob on the same line -- so the host
    // is not merely a mismatch, it is not covered at all.
    assert_eq!(lookup(&text, "192.0.2.9", &k), Lookup::Unknown);
}

#[test]
fn a_hashed_entry_matches_its_host() {
    // Straight from `ssh-keygen -H`; the HMAC-SHA1 is the only way in.
    let k = key(ED25519_PUB);
    assert_eq!(lookup(HASHED_LINE, "[127.0.0.1]:2222", &k), Lookup::Match);
    assert_eq!(lookup(HASHED_LINE, "127.0.0.1", &k), Lookup::Unknown);
}

#[test]
fn a_hashed_entry_with_another_key_is_a_mismatch() {
    let presented = key(ECDSA_PUB);
    match lookup(HASHED_LINE, "[127.0.0.1]:2222", &presented) {
        Lookup::Mismatch { known } => assert_eq!(known, vec![fingerprint(&key(ED25519_PUB))]),
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

#[test]
fn a_revoked_key_is_reported_as_revoked() {
    let k = key(ED25519_PUB);
    let text = format!("@revoked {}", kh_line("127.0.0.1", ED25519_PUB));
    assert_eq!(lookup(&text, "127.0.0.1", &k), Lookup::Revoked);
}

#[test]
fn a_revocation_of_another_key_does_not_make_this_one_expected() {
    // The revoked key must not count towards the "keys this host is
    // known to have" set: a host with only a revocation on file is
    // still an UNKNOWN host for any other key.
    let presented = key(ECDSA_PUB);
    let text = format!("@revoked {}", kh_line("127.0.0.1", ED25519_PUB));
    assert_eq!(lookup(&text, "127.0.0.1", &presented), Lookup::Unknown);
}

#[test]
fn cert_authority_entries_are_skipped() {
    // A CA key signs host keys; it is never itself the host key, and
    // counting it would turn a legitimate key into a mismatch.
    let k = key(ECDSA_PUB);
    let text = format!("@cert-authority {}", kh_line("127.0.0.1", ED25519_PUB));
    assert_eq!(lookup(&text, "127.0.0.1", &k), Lookup::Unknown);
}

#[test]
fn empty_or_unparseable_known_hosts_is_simply_unknown() {
    let k = key(ED25519_PUB);
    assert_eq!(lookup("", "127.0.0.1", &k), Lookup::Unknown);
    assert_eq!(
        lookup("not a known_hosts file at all\n", "127.0.0.1", &k),
        Lookup::Unknown
    );
}

#[test]
fn several_keys_for_one_host_all_count() {
    let presented = key(RSA_PUB);
    let text = format!(
        "{}{}",
        kh_line("127.0.0.1", ED25519_PUB),
        kh_line("127.0.0.1", ECDSA_PUB)
    );
    match lookup(&text, "127.0.0.1", &presented) {
        Lookup::Mismatch { known } => assert_eq!(known.len(), 2),
        other => panic!("expected a mismatch, got {other:?}"),
    }
    // ...and the presented key matching the SECOND of them is a match.
    assert_eq!(lookup(&text, "127.0.0.1", &key(ECDSA_PUB)), Lookup::Match);
}

// ----------------------------------------------------- the policy

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

const LOOPBACK: &str = "127.0.0.1:22";
const REMOTE: &str = "192.0.2.10:22";
const FP: &str = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn policy_match_prints_with_corroboration() {
    for target in [LOOPBACK, REMOTE] {
        let d = policy(&Lookup::Match, FP, &addr(target), false);
        assert_eq!(d.verdict, Verdict::Corroborated);
        assert!(d.message.contains(FP));
        assert!(d.message.contains("matches known_hosts"));
    }
}

#[test]
fn policy_mismatch_refuses_unless_opted_out() {
    let known = Lookup::Mismatch {
        known: vec!["SHA256:other".into()],
    };
    let d = policy(&known, FP, &addr(REMOTE), false);
    assert_eq!(d.verdict, Verdict::Refuse);
    assert!(d.message.contains("SHA256:other"));
    assert!(d.message.contains("--allow-host-key-mismatch"));

    let d = policy(&known, FP, &addr(REMOTE), true);
    assert_eq!(d.verdict, Verdict::Unverified);
    assert!(d.message.contains("UNVERIFIED"));
}

#[test]
fn policy_mismatch_refuses_on_loopback_too() {
    // Loopback relaxes the UNKNOWN case only. A contradiction is a
    // contradiction wherever the target lives.
    let known = Lookup::Mismatch {
        known: vec!["SHA256:other".into()],
    };
    assert_eq!(
        policy(&known, FP, &addr(LOOPBACK), false).verdict,
        Verdict::Refuse
    );
}

#[test]
fn policy_revoked_refuses_even_with_the_opt_out() {
    for allow in [false, true] {
        let d = policy(&Lookup::Revoked, FP, &addr(REMOTE), allow);
        assert_eq!(d.verdict, Verdict::Refuse);
        assert!(d.message.contains("@revoked"));
    }
}

#[test]
fn policy_unknown_prints_only_for_loopback() {
    let d = policy(&Lookup::Unknown, FP, &addr(LOOPBACK), false);
    assert_eq!(d.verdict, Verdict::Unverified);
    assert!(d.message.contains(FP));

    let d = policy(&Lookup::Unknown, FP, &addr(REMOTE), false);
    assert_eq!(d.verdict, Verdict::Silent);
    // The whole point of the silent case: say WHY, and do not leak
    // the uncorroborated fingerprint into the operator's eye as if it
    // meant something.
    assert!(!d.message.contains(FP));
    assert!(d.message.contains("not shown"));
}

#[test]
fn policy_unknown_is_not_relaxed_by_the_opt_out() {
    // --allow-host-key-mismatch is about mismatches; it must not turn
    // the silent case into a printed, meaningless fingerprint.
    let d = policy(&Lookup::Unknown, FP, &addr(REMOTE), true);
    assert_eq!(d.verdict, Verdict::Silent);
}

#[test]
fn refuses_reports_exactly_the_refusing_verdicts() {
    assert!(policy(&Lookup::Revoked, FP, &addr(REMOTE), false).refuses());
    assert!(!policy(&Lookup::Match, FP, &addr(REMOTE), false).refuses());
    assert!(!policy(&Lookup::Unknown, FP, &addr(REMOTE), false).refuses());
}

#[test]
fn a_changed_key_mid_run_refuses() {
    let d = policy_changed("SHA256:first", FP, &addr(LOOPBACK), false);
    assert_eq!(d.verdict, Verdict::Refuse);
    assert!(d.message.contains("SHA256:first") && d.message.contains(FP));
    let d = policy_changed("SHA256:first", FP, &addr(LOOPBACK), true);
    assert_eq!(d.verdict, Verdict::Unverified);
}

#[test]
fn loopback_detection_covers_ipv6() {
    assert!(is_loopback(&addr("127.0.0.1:22")));
    assert!(is_loopback(&addr("[::1]:22")));
    assert!(!is_loopback(&addr("192.0.2.10:22")));
}

// ---------------------------------------------- sniffer -> policy

#[test]
fn end_to_end_observation_against_known_hosts() {
    // The one test that walks the whole path: bytes in, verdict out.
    let k = key(ED25519_PUB);
    let mut s = Sniffer::new();
    s.feed(&transcript(&k, 31));
    let observed = s.key().expect("a key was observed");
    let target = addr("127.0.0.1:2222");
    let text = kh_line("[127.0.0.1]:2222", ED25519_PUB);
    let l = lookup(&text, &host_lookup_key(target), observed);
    let d = policy(&l, &fingerprint(observed), &target, false);
    assert_eq!(d.verdict, Verdict::Corroborated);
}
