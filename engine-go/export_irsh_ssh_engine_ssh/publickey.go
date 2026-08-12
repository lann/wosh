package export_irsh_ssh_engine_ssh

// Publickey authentication whose private key lives OUTSIDE this
// component.
//
// The ssh stack needs an `ssh.Signer`. Rather than hold key material,
// this signer parks the handshake goroutine and surfaces the
// to-be-signed bytes through `pending-signature`; the embedder (the
// Rust glue, which can make async webcrypto calls) produces the
// signature and returns it via `provide-signature`. The engine
// therefore never sees a private key at all -- in the browser it is a
// non-extractable WebCrypto handle that cannot be exported even by
// the code driving it.
//
// Parking across export calls is exactly the property this engine is
// built on (the shuttle conn does the same for network bytes), and it
// is why these exports stay synchronous: componentize-go's async
// runtime keeps a single global task state and requires a task to
// finish before the guest goes idle, so long-lived cross-call parking
// belongs in the sync world.

import (
	"crypto/ed25519"
	"fmt"
	"io"

	witTypes "go.bytecodealliance.org/pkg/wit/types"

	"golang.org/x/crypto/ssh"
)

type sigReply struct {
	sig []byte
	err string
}

// externalSigner implements ssh.Signer by delegating to the embedder.
type externalSigner struct {
	s   *Session
	pub ssh.PublicKey
}

func (e *externalSigner) PublicKey() ssh.PublicKey { return e.pub }

func (e *externalSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	cp := make([]byte, len(data))
	copy(cp, data)

	e.s.mu.Lock()
	e.s.sigRequest = cp
	e.s.mu.Unlock()

	reply, ok := <-e.s.sigReply // parks across export calls
	if !ok {
		return nil, fmt.Errorf("signing abandoned")
	}
	e.s.mu.Lock()
	e.s.sigRequest = nil
	e.s.mu.Unlock()

	if reply.err != "" {
		return nil, fmt.Errorf("%s", reply.err)
	}
	if len(reply.sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, expected %d",
			len(reply.sig), ed25519.SignatureSize)
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: reply.sig}, nil
}

// AuthenticatePublickey selects publickey auth, using `blob` (SSH
// wire-format public key) as the identity to offer.
func (s *Session) AuthenticatePublickey(blob []uint8) {
	cp := make([]byte, len(blob))
	copy(cp, blob)

	pub, err := ssh.ParsePublicKey(cp)
	if err != nil {
		s.mu.Lock()
		s.state = stateClosed
		s.errMsg = "publickey: " + err.Error()
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.signer = &externalSigner{s: s, pub: pub}
	s.credKind = "publickey"
	s.credsSet = true
	s.mu.Unlock()
}

func (s *Session) PendingSignature() witOptionBytes {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sigRequest) == 0 {
		return noneBytes()
	}
	return someBytes(s.sigRequest)
}

func (s *Session) ProvideSignature(signature []uint8) {
	cp := make([]byte, len(signature))
	copy(cp, signature)
	select {
	case s.sigReply <- sigReply{sig: cp}:
	default:
	}
	gosched(16)
}

func (s *Session) FailSignature(reason string) {
	select {
	case s.sigReply <- sigReply{err: "signature refused: " + reason}:
	default:
	}
	gosched(16)
}

// witOptionBytes keeps publickey.go free of the generated binding
// import; the aliases below are the same option type the WIT surface
// uses.
type witOptionBytes = witTypes.Option[[]uint8]

func noneBytes() witOptionBytes        { return witTypes.None[[]uint8]() }
func someBytes(b []byte) witOptionBytes { return witTypes.Some(b) }
