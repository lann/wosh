package export_wosh_terminal_terminal

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	witTypes "go.bytecodealliance.org/pkg/wit/types"
	"golang.org/x/crypto/ssh"

	identitystore "wit_component/wosh_terminal_identity_store"
)

// The browser's SSH identity lives behind the host's `identity-store`;
// this component holds only its PUBLIC half, fetched once per instance.
//
// The host owns the key pair BECAUSE persistence is a host concern:
// the private half is a non-extractable WebCrypto handle, and only the
// host can put such a handle somewhere durable (a browser stores the
// CryptoKey pair in IndexedDB by structured clone), so the same
// authorized_keys line keeps working across page reloads. The store's
// surface is sign-only -- no private-key handle exists anywhere in
// this component, and nothing here, nothing in the page, including an
// XSS payload, can read the key out. Compare an in-component Ed25519
// key, which would sit in linear memory for the lifetime of the tab.
var (
	identityOnce sync.Once
	identityPub  ed25519.PublicKey
	identityErr  error
)

func ensureIdentity() error {
	identityOnce.Do(func() {
		res := identitystore.PublicKey()
		if res.IsErr() {
			identityErr = fmt.Errorf("obtain ssh identity: %v", res.Err())
			return
		}
		raw := res.Ok()
		if len(raw) != ed25519.PublicKeySize {
			identityErr = fmt.Errorf("ssh public key is %d bytes, expected %d",
				len(raw), ed25519.PublicKeySize)
			return
		}
		identityPub = ed25519.PublicKey(append([]byte(nil), raw...))
	})
	return identityErr
}

// IdentityOpenssh backs the interface-level `identity-openssh` export.
func IdentityOpenssh() witTypes.Result[string, string] {
	if err := ensureIdentity(); err != nil {
		return witTypes.Err[string, string](err.Error())
	}
	pub, err := ssh.NewPublicKey(identityPub)
	if err != nil {
		return witTypes.Err[string, string]("wrap ssh public key: " + err.Error())
	}
	line := fmt.Sprintf("%s %s wosh-browser",
		pub.Type(), base64.StdEncoding.EncodeToString(pub.Marshal()))
	return witTypes.Ok[string, string](line)
}

// storeSigner implements ssh.Signer by delegating every signature to
// the host's identity-store.
type storeSigner struct {
	pub ssh.PublicKey
}

func browserSigner() (ssh.Signer, error) {
	if err := ensureIdentity(); err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(identityPub)
	if err != nil {
		return nil, fmt.Errorf("wrap ssh public key: %w", err)
	}
	return &storeSigner{pub: pub}, nil
}

func (w *storeSigner) PublicKey() ssh.PublicKey { return w.pub }

// Sign hands `data` (the SSH publickey-auth signature blob: session id,
// user, service, algorithm, public key) to the store and returns the
// raw 64-byte Ed25519 signature in SSH wire form.
//
// The signature is VERIFIED here against the public key the store
// reported, before it is offered to the server: the store is trusted
// to keep the key, not to be bug-free, and a store that signs with a
// different key than it reports should fail loudly at this client, not
// as an opaque rejection at the server.
func (w *storeSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	res := identitystore.Sign(data)
	if res.IsErr() {
		return nil, fmt.Errorf("identity-store sign: %v", res.Err())
	}
	sig := append([]byte(nil), res.Ok()...)
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("identity-store signature is %d bytes, expected %d",
			len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(identityPub, data, sig) {
		return nil, fmt.Errorf("identity-store signature does not verify under its own public key")
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: sig}, nil
}
