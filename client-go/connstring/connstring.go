// Package connstring decodes the wosh pairing connection string -- the
// Go mirror of the `wosh-connstring` Rust crate, which is the format's
// owner and PRODUCES these strings (in the listener). Kept free of WIT
// imports so it builds for the host too: `go test ./connstring` runs
// as part of the format's gate, against golden bytes pinned by the
// Rust crate's v2_golden_bytes test.
//
// The blob is one version byte, then the version's payload.
//
// Version 2 payload is postcard (postcard 1.x's stable wire format)
// for `{ pubkey: [u8;32], relay: Url(String)|WellKnown(u32),
// token: Option<[u8;16]> }` -- decoded by hand below, since the shape
// is four fixed rules: fixed-size arrays are raw bytes, enum
// discriminants and lengths/indices are unsigned LEB128 varints (Go's
// binary.Uvarint), strings are varint length + UTF-8, and Option is
// one byte (0/1) then the payload.
//
// Version 1 (older printed QR codes) is the original fixed layout:
//
//	bytes 1..33: 32-byte Ed25519 endpoint id (the iroh address)
//	byte 33:     flags (bit 0 = a pairing token follows)
//	[16 bytes]:  the pairing token, when that flag is set
//	remainder:   relay URL, UTF-8
package connstring

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	v1 = 1
	v2 = 2

	// PubkeyLen is the raw Ed25519 public key length.
	PubkeyLen = 32
	// TokenLen is the pairing token length, when present.
	TokenLen = 16

	flagHasToken = 0x01 // v1 only
)

// wellKnownRelays mirrors WELL_KNOWN_RELAYS in connstring/src/lib.rs:
// the public iroh relays a v2 connstring may name by index instead of
// spelling out. APPEND-ONLY, indices are NEVER reused or reordered --
// a connstring is a durable artifact (printed QR codes, bookmarks), so
// index n must mean the same relay to every decoder forever.
var wellKnownRelays = []string{
	"https://use1-1.relay.n0.iroh.link", // 0: NA East
	"https://usw1-1.relay.n0.iroh.link", // 1: NA West
	"https://euc1-1.relay.n0.iroh.link", // 2: EU Central
	"https://aps1-1.relay.n0.iroh.link", // 3: AP South
}

// ConnString is the decoded pairing blob from the QR link's fragment.
type ConnString struct {
	PubKey   []byte
	RelayURL string
	Token    []byte // nil when the listener runs in open mode
}

// Parse decodes the base64url blob. Accepts versions 1 and 2.
func Parse(s string) (*ConnString, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid base64url: %w", err)
	}
	if len(raw) < 1 {
		return nil, fmt.Errorf("truncated connection string")
	}
	switch raw[0] {
	case v2:
		return parseV2(raw[1:])
	case v1:
		return parseV1(raw[1:])
	default:
		return nil, fmt.Errorf("unsupported connection string version %d", raw[0])
	}
}

func parseV2(payload []byte) (*ConnString, error) {
	r := bytes.NewReader(payload)

	pubkey := make([]byte, PubkeyLen)
	if _, err := io.ReadFull(r, pubkey); err != nil {
		return nil, fmt.Errorf("truncated connection string")
	}
	cs := &ConnString{PubKey: pubkey}

	disc, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("malformed connection string payload")
	}
	switch disc {
	case 0: // Url(String)
		strLen, err := binary.ReadUvarint(r)
		if err != nil || strLen > uint64(r.Len()) {
			return nil, fmt.Errorf("malformed connection string payload")
		}
		urlBytes := make([]byte, strLen)
		if _, err := io.ReadFull(r, urlBytes); err != nil {
			return nil, fmt.Errorf("malformed connection string payload")
		}
		if !utf8.Valid(urlBytes) {
			return nil, fmt.Errorf("relay URL is not valid UTF-8")
		}
		cs.RelayURL = string(urlBytes)
	case 1: // WellKnown(u32)
		idx, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("malformed connection string payload")
		}
		if idx >= uint64(len(wellKnownRelays)) {
			return nil, fmt.Errorf(
				"well-known relay index %d is newer than this build's table", idx)
		}
		cs.RelayURL = wellKnownRelays[idx]
	default:
		return nil, fmt.Errorf("unknown relay encoding %d", disc)
	}

	hasToken, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("malformed connection string payload")
	}
	switch hasToken {
	case 0:
	case 1:
		token := make([]byte, TokenLen)
		if _, err := io.ReadFull(r, token); err != nil {
			return nil, fmt.Errorf("truncated pairing token")
		}
		cs.Token = token
	default:
		return nil, fmt.Errorf("malformed connection string payload")
	}

	// Trailing bytes are a malformed blob, not padding to shrug off
	// (the Rust decoder is equally strict).
	if r.Len() != 0 {
		return nil, fmt.Errorf("malformed connection string payload")
	}
	if cs.RelayURL == "" {
		return nil, fmt.Errorf("carries no relay URL")
	}
	return cs, nil
}

func parseV1(payload []byte) (*ConnString, error) {
	if len(payload) < PubkeyLen+1 {
		return nil, fmt.Errorf("truncated connection string")
	}
	cs := &ConnString{PubKey: payload[:PubkeyLen]}
	off := PubkeyLen
	flags := payload[off]
	off++
	if flags&flagHasToken != 0 {
		if len(payload) < off+TokenLen {
			return nil, fmt.Errorf("truncated pairing token")
		}
		cs.Token = payload[off : off+TokenLen]
		off += TokenLen
	}
	cs.RelayURL = string(payload[off:])
	if cs.RelayURL == "" {
		return nil, fmt.Errorf("carries no relay URL")
	}
	return cs, nil
}
