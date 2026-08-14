package core

// Publickey authentication whose private key lives OUTSIDE this
// component.
//
// The ssh stack needs an `ssh.Signer`. Rather than hold key material,
// this signer parks the auth goroutine and surfaces the to-be-signed
// bytes through `pending-signature`; the embedder (the Rust glue,
// which can make async WebCrypto or WebAuthn calls) produces the
// signature and returns it via `provide-signature`. The core therefore
// never sees a private key at all -- in the browser it is a
// non-extractable WebCrypto handle, or a passkey the authenticator
// will never surrender. Only the public half and the finished
// signature ever cross the interface.
//
// Nothing here knows any key ALGEBRA: the offered record is relayed
// verbatim in both directions, which is what makes a new signature
// algorithm (webauthn included) an embedder change rather than a
// change here.
//
// Parking across export calls is exactly the property this engine is
// built on (the shuttle conn does the same for network bytes), and it
// is why these exports stay synchronous: componentize-go's async
// runtime ends a task once the guest is idle with nothing pending in
// it, so long-lived cross-call parking belongs in the sync world.

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

type sigReply struct {
	sig Signature
	err string
}

// offeredKey is an ssh.PublicKey that reports the embedder's offered
// record VERBATIM and parses nothing.
//
// The two accessors feed two different places in x/crypto/ssh's
// userauth request, and the split matters. `Type()` is what
// pickSignatureAlgorithm takes as the key format, and -- for a plain
// ssh.Signer, whose supported-algorithm set is exactly {that format}
// -- it is also the public key algorithm NAME the request carries.
// `Marshal()` is the key blob that rides alongside it.
//
// For every ordinary algorithm those two agree. For OpenSSH's
// browser-webauthn algorithm they deliberately DISAGREE: the blob is a
// plain `sk-ecdsa-sha2-nistp256@openssh.com` key while the algorithm
// name is `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, and sshd
// requires exactly that pairing (it resolves the algorithm name and
// compares it against the name inside the signature). Reporting the
// record as given, rather than deriving either half from the other, is
// the whole reason this core needs no key parsing.
type offeredKey struct{ key PublicKey }

func (k offeredKey) Type() string { return k.key.Algorithm }

func (k offeredKey) Marshal() []byte { return k.key.Blob }

// Verify is never called on the client path: verification is the
// server's job, and this component holds no algebra to do it with.
func (k offeredKey) Verify(_ []byte, _ *ssh.Signature) error {
	return fmt.Errorf("this core does not verify signatures: it relays keys and signatures opaquely")
}

// externalSigner implements ssh.Signer by delegating to the embedder.
type externalSigner struct {
	s   *Engine
	key PublicKey
}

func (e *externalSigner) PublicKey() ssh.PublicKey { return offeredKey{key: e.key} }

func (e *externalSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	req := &SignRequest{
		Key:  e.key,
		Data: append([]byte(nil), data...),
	}

	e.s.mu.Lock()
	if e.s.sigClosed {
		e.s.mu.Unlock()
		return nil, fmt.Errorf("signing abandoned")
	}
	e.s.sigRequest = req
	if e.s.state != StateClosed {
		e.s.state = StateSigning
	}
	e.s.mu.Unlock()

	reply, ok := <-e.s.sigReply // parks across export calls
	if !ok {
		return nil, fmt.Errorf("signing abandoned")
	}
	if reply.err != "" {
		return nil, fmt.Errorf("%s", reply.err)
	}
	// The reply was validated by ProvideSignature, the only producer
	// of a success reply. Rest is `ssh:"rest"`-tagged in x/crypto and
	// is appended verbatim after format+blob -- it exists precisely
	// for the security-key algorithms' trailing fields, so relaying
	// webauthn signatures needs no fork.
	return &ssh.Signature{
		Format: reply.sig.Format,
		Blob:   reply.sig.Blob,
		Rest:   reply.sig.Trailer,
	}, nil
}

// newSigner wraps one offered key record as a parked signer. It cannot
// fail: the record was validated (and cloned) by the caller, and
// nothing here inspects it further.
func (s *Engine) newSigner(key PublicKey) ssh.Signer {
	return &externalSigner{s: s, key: key}
}

// PendingSignature backs `pending-signature`: the parked request --
// the publickey-auth signature blob (session id, user, service,
// algorithm, public key) to sign, and the offered key record it is
// for, echoed back so the embedder knows which keeper to ask -- or nil
// when nothing is parked.
func (s *Engine) PendingSignature() *SignRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sigRequest == nil {
		return nil
	}
	return &SignRequest{
		Key: PublicKey{
			Algorithm: s.sigRequest.Key.Algorithm,
			Blob:      append([]byte(nil), s.sigRequest.Key.Blob...),
		},
		Data: append([]byte(nil), s.sigRequest.Data...),
	}
}

// ProvideSignature backs `provide-signature`: resume authentication
// with a signature over exactly the bytes PendingSignature returned.
//
// Every validation failure LEAVES THE REQUEST PENDING: a malformed
// answer is the embedder's to retry, not a reason to fail the session.
func (s *Engine) ProvideSignature(sig Signature) error {
	// Clone: the bindings hand over zero-copy views of transferred
	// cabi memory that is recycled once the export returns, and the
	// auth goroutine reads these strictly after that.
	cp := Signature{
		Format:  strings.Clone(sig.Format),
		Blob:    append([]byte(nil), sig.Blob...),
		Trailer: append([]byte(nil), sig.Trailer...),
	}

	s.mu.Lock()
	if s.sigClosed || s.sigRequest == nil {
		s.mu.Unlock()
		return fmt.Errorf("no signature is pending")
	}
	// The format must be the pending key's algorithm. sshd resolves
	// the offered algorithm name and compares it against the name
	// inside the signature blob, so a mismatch becomes an opaque
	// authentication failure several round trips later; catching it
	// here is the difference between a legible error and a mystery.
	if want := s.sigRequest.Key.Algorithm; cp.Format != want {
		s.mu.Unlock()
		return fmt.Errorf("signature format %q does not match the pending key's algorithm %q",
			cp.Format, want)
	}
	if len(cp.Blob) == 0 {
		s.mu.Unlock()
		return fmt.Errorf("the signature blob is empty")
	}
	// A length check for the Ed25519 case ONLY, as legibility for the
	// common path. No other algorithm is second-guessed here: this
	// core does not know their encodings, and inventing rules for
	// them is how a valid signature gets refused.
	if cp.Format == ssh.KeyAlgoED25519 {
		if len(cp.Blob) != ed25519.SignatureSize {
			n := len(cp.Blob)
			s.mu.Unlock()
			return fmt.Errorf("signature is %d bytes, expected %d", n, ed25519.SignatureSize)
		}
		if len(cp.Trailer) != 0 {
			n := len(cp.Trailer)
			s.mu.Unlock()
			return fmt.Errorf("%s signatures carry no trailing fields, got %d bytes",
				ssh.KeyAlgoED25519, n)
		}
	}
	s.sigRequest = nil
	if s.state == StateSigning {
		s.state = StateAuthenticating
	}
	// Buffered (capacity 1) and strictly alternating with Sign's
	// receive -- x/crypto runs one auth method on one goroutine, so
	// only one signature is ever in flight -- so this never blocks;
	// done under mu so it cannot race the close in failGates.
	s.sigReply <- sigReply{sig: cp}
	s.mu.Unlock()

	gosched(16)
	return nil
}

// FailSignature backs `fail-signature`: abandon a pending signature so
// authentication fails legibly instead of parking forever.
func (s *Engine) FailSignature(reason string) {
	s.mu.Lock()
	if s.sigClosed || s.sigRequest == nil {
		s.mu.Unlock()
		return
	}
	s.sigRequest = nil
	if s.state == StateSigning {
		s.state = StateAuthenticating
	}
	s.sigReply <- sigReply{err: "signature refused: " + reason}
	s.mu.Unlock()

	gosched(16)
}
