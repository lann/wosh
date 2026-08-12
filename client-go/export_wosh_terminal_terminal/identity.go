package export_wosh_terminal_terminal

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	witTypes "go.bytecodealliance.org/pkg/wit/types"
	"golang.org/x/crypto/ssh"

	ed25519sign "wit_component/polymorph_webcrypto_ed25519_sign"
	signature "wit_component/polymorph_webcrypto_signature"
)

// The browser's SSH identity, minted once per component instance.
//
// The private half is created NON-EXTRACTABLE through
// `polymorph:webcrypto`: this component holds only a capability handle
// it can ask to sign, never key bytes. Nothing here -- and nothing in
// the page, including an XSS payload -- can read the key out. Compare
// an in-component Ed25519 key, which would sit in linear memory for
// the lifetime of the tab.
var (
	identityOnce sync.Once
	identitySK   *signature.SigningKey
	identityPub  ed25519.PublicKey
	identityErr  error
)

func ensureIdentity() error {
	identityOnce.Do(func() {
		opts := signature.MakeSigningKeyOptions()
		opts.CanSign(true)
		// Deliberately NOT extractable: routing through webcrypto is
		// pointless if the key can come back out.
		opts.Extractable(false)

		res := ed25519sign.GenerateKey(opts)
		if res.IsErr() {
			identityErr = fmt.Errorf("generate ssh identity: %v", res.Err())
			return
		}
		identitySK = res.Ok().F0

		// The PUBLIC half is exported freely; that is what goes into
		// authorized_keys.
		pubRes := res.Ok().F1.ExportKeyRaw()
		if pubRes.IsErr() {
			identityErr = fmt.Errorf("export ssh public key: %v", pubRes.Err())
			return
		}
		raw := pubRes.Ok()
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

// webcryptoSigner implements ssh.Signer by delegating every signature
// to the authenticator behind the webcrypto handle.
type webcryptoSigner struct {
	pub ssh.PublicKey
	sk  *signature.SigningKey
}

func browserSigner() (ssh.Signer, error) {
	if err := ensureIdentity(); err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(identityPub)
	if err != nil {
		return nil, fmt.Errorf("wrap ssh public key: %w", err)
	}
	return &webcryptoSigner{pub: pub, sk: identitySK}, nil
}

func (w *webcryptoSigner) PublicKey() ssh.PublicKey { return w.pub }

// Sign hands `data` (the SSH publickey-auth signature blob: session id,
// user, service, algorithm, public key) to the authenticator and
// returns the raw 64-byte Ed25519 signature in SSH wire form.
//
// The webcrypto surface takes its input as a `stream<u8>`, so the bytes
// are written from a second goroutine while this one parks in the
// signing call. That works because the patched Go runtime keeps
// scheduling goroutines while one is parked on an async import -- the
// same property that lets several iroh reads and writes be in flight.
func (w *webcryptoSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	writer, reader := signature.MakeStreamU8()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		writer.WriteAll(data)
		writer.Drop() // end of input: the signature covers exactly these bytes
	}()

	res := w.sk.Sign(reader)
	wg.Wait()
	if res.IsErr() {
		return nil, fmt.Errorf("webcrypto sign: %v", res.Err())
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: res.Ok()}, nil
}
