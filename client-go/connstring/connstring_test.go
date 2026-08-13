package connstring

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func samplePubkey() []byte {
	k := make([]byte, PubkeyLen)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// The same golden bytes the Rust crate pins in v2_golden_bytes: the
// two decoders agreeing with this vector is what "the format is
// shared" MEANS. Do not regenerate one side to match the other
// without understanding which one changed.
func TestGoldenV2WellKnownWithToken(t *testing.T) {
	raw := []byte{2}
	raw = append(raw, samplePubkey()...)
	raw = append(raw, 1, 2) // WellKnown, varint index 2
	raw = append(raw, 1)    // Some
	token := bytes.Repeat([]byte{9}, TokenLen)
	raw = append(raw, token...)

	cs, err := Parse(b64(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cs.RelayURL != "https://euc1-1.relay.n0.iroh.link" {
		t.Fatalf("relay = %q", cs.RelayURL)
	}
	if !bytes.Equal(cs.PubKey, samplePubkey()) || !bytes.Equal(cs.Token, token) {
		t.Fatalf("pubkey/token mismatch")
	}
}

func TestGoldenV2UrlNoToken(t *testing.T) {
	raw := []byte{2}
	raw = append(raw, samplePubkey()...)
	raw = append(raw, 0, 9) // Url, varint length 9
	raw = append(raw, []byte("https://x")...)
	raw = append(raw, 0) // None

	cs, err := Parse(b64(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cs.RelayURL != "https://x" || cs.Token != nil {
		t.Fatalf("got %+v", cs)
	}
}

func TestV1StillDecodes(t *testing.T) {
	raw := []byte{1}
	raw = append(raw, samplePubkey()...)
	raw = append(raw, flagHasToken)
	token := bytes.Repeat([]byte{7}, TokenLen)
	raw = append(raw, token...)
	raw = append(raw, []byte("https://relay.example.com")...)

	cs, err := Parse(b64(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cs.RelayURL != "https://relay.example.com" || !bytes.Equal(cs.Token, token) {
		t.Fatalf("got %+v", cs)
	}
}

func TestEveryWellKnownIndex(t *testing.T) {
	for i, want := range wellKnownRelays {
		raw := []byte{2}
		raw = append(raw, samplePubkey()...)
		raw = append(raw, 1, byte(i)) // small indices are one varint byte
		raw = append(raw, 0)
		cs, err := Parse(b64(raw))
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		if cs.RelayURL != want {
			t.Fatalf("index %d: got %q want %q", i, cs.RelayURL, want)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]struct {
		raw     []byte
		errPart string
	}{
		"empty":           {[]byte{}, "truncated"},
		"unknown version": {[]byte{99, 0, 0}, "unsupported connection string version 99"},
		"truncated v2":    {append([]byte{2}, samplePubkey()[:10]...), "truncated"},
		"unknown index": {
			append(append([]byte{2}, samplePubkey()...), 1, 63, 0),
			"index 63 is newer",
		},
		"unknown relay encoding": {
			append(append([]byte{2}, samplePubkey()...), 5, 0),
			"unknown relay encoding 5",
		},
		"trailing junk": {
			append(append([]byte{2}, samplePubkey()...), 1, 0, 0, 0xAA),
			"malformed",
		},
		"empty url": {
			append(append([]byte{2}, samplePubkey()...), 0, 0, 0),
			"no relay URL",
		},
		"bad option tag": {
			append(append([]byte{2}, samplePubkey()...), 1, 0, 2),
			"malformed",
		},
	}
	for name, c := range cases {
		if _, err := Parse(b64(c.raw)); err == nil || !strings.Contains(err.Error(), c.errPart) {
			t.Errorf("%s: err = %v, want containing %q", name, err, c.errPart)
		}
	}
}
