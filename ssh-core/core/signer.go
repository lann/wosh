package core

// Publickey authentication whose private key lives OUTSIDE this
// component.
//
// The ssh stack needs an `ssh.Signer`. Rather than hold key material,
// this signer parks the auth goroutine and surfaces the to-be-signed
// bytes through `pending-signature`; the embedder (the Rust glue,
// which can make async WebCrypto calls) produces the signature and
// returns it via `provide-signature`. The core therefore never sees a
// private key at all -- in the browser it is a non-extractable
// WebCrypto handle that cannot be exported even by the code driving
// it. Only the public half and the finished signature ever cross the
// interface.
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

	"golang.org/x/crypto/ssh"
)

type sigReply struct {
	sig []byte
	err string
}

// externalSigner implements ssh.Signer by delegating to the embedder.
type externalSigner struct {
	s   *Engine
	pub ssh.PublicKey
}

func (e *externalSigner) PublicKey() ssh.PublicKey { return e.pub }

func (e *externalSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	cp := append([]byte(nil), data...)

	e.s.mu.Lock()
	if e.s.sigClosed {
		e.s.mu.Unlock()
		return nil, fmt.Errorf("signing abandoned")
	}
	e.s.sigRequest = cp
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
	// Length was validated by ProvideSignature, which is the only
	// producer of a success reply; re-checked here because a wrong
	// length would otherwise become an opaque server-side auth
	// failure two round trips later.
	if len(reply.sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, expected %d",
			len(reply.sig), ed25519.SignatureSize)
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: reply.sig}, nil
}

// newSigner wraps a raw 32-byte Ed25519 public key as the parked
// signer offered to the server.
func (s *Engine) newSigner(pub []byte) (ssh.Signer, error) {
	key, err := ed25519PublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("publickey: %w", err)
	}
	return &externalSigner{s: s, pub: key}, nil
}

// PendingSignature backs `pending-signature`: the publickey-auth
// signature blob (session id, user, service, algorithm, public key)
// the signer is parked on, or nil.
func (s *Engine) PendingSignature() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sigRequest) == 0 {
		return nil
	}
	return append([]byte(nil), s.sigRequest...)
}

// ProvideSignature backs `provide-signature`: resume authentication
// with the raw 64-byte Ed25519 signature over exactly the bytes
// PendingSignature returned.
func (s *Engine) ProvideSignature(signature []byte) error {
	cp := append([]byte(nil), signature...)

	s.mu.Lock()
	if s.sigClosed || s.sigRequest == nil {
		s.mu.Unlock()
		return fmt.Errorf("no signature is pending")
	}
	if len(cp) != ed25519.SignatureSize {
		n := len(cp)
		s.mu.Unlock()
		// Leave the request pending: a length mistake is the
		// embedder's to retry, not a reason to fail the session.
		return fmt.Errorf("signature is %d bytes, expected %d", n, ed25519.SignatureSize)
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
