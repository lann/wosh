package core

// Host-side behaviour tests for the sans-I/O SSH core.
//
// Every case drives a REAL `golang.org/x/crypto/ssh` server in the
// same process: the engine's shuttle is bridged to one end of a
// net.Pipe, so the bytes crossing feed/drain are genuine SSH protocol
// bytes and the properties asserted below are properties of the
// protocol exchange, not of a mock.
//
// The load-bearing property is the first one: NO CREDENTIAL LEAVES
// THIS COMPONENT BEFORE THE USER APPROVES THE HOST KEY. The server
// counts every authentication attempt it sees (including the "none"
// probe x/crypto's client opens with), so "the server saw zero auth
// attempts" is a direct observation of that guarantee on the wire.
//
// All key material is generated per test; nothing here is a real
// credential, and the scripted prompt answers are obviously synthetic
// fixtures.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// testDeadline bounds every poll loop. Host scheduling is
	// preemptive and timing-dependent, so the tests wait on
	// OBSERVED STATE with a generous deadline rather than sleeping a
	// fixed amount and hoping.
	testDeadline = 10 * time.Second
	pollInterval = 200 * time.Microsecond
	// eotSentinel tells the fixture shell to stop echoing and exit.
	// An obviously synthetic in-band marker; there is no real pty.
	eotSentinel = 0x04
)

// --- fixture ----------------------------------------------------------

type rig struct {
	eng          *Engine
	hostFP       string
	authAttempts *atomic.Int32
}

// start wires a fresh engine to an in-process x/crypto/ssh server over
// a net.Pipe and pumps bytes between them for the life of the test.
func start(t *testing.T, cfg *ssh.ServerConfig, shell func(ssh.Channel)) *rig {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg.AddHostKey(hostSigner)

	attempts := &atomic.Int32{}
	cfg.AuthLogCallback = func(_ ssh.ConnMetadata, _ string, _ error) {
		attempts.Add(1)
	}

	srvSide, cliSide := net.Pipe()
	eng := New("tester", 80, 24)

	go serveOne(srvSide, cfg, shell)

	stop := make(chan struct{})
	// Inbound: whatever the server writes becomes fed bytes. A read
	// error just stops the bridge -- it must NOT be reported as a
	// broken wire, or it would mask the legible failure the ssh stack
	// has usually already produced (e.g. an auth rejection).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := cliSide.Read(buf)
			if n > 0 {
				eng.Feed(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	// Outbound: drain the engine onto the wire on a tight cadence,
	// which is exactly what the embedder does after every
	// state-changing call.
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if out := eng.Drain(); len(out) > 0 {
				if _, err := cliSide.Write(out); err != nil {
					return
				}
				continue
			}
			time.Sleep(pollInterval)
		}
	}()

	t.Cleanup(func() {
		close(stop)
		eng.Close()
		_ = cliSide.Close()
		_ = srvSide.Close()
	})

	return &rig{eng: eng, hostFP: ssh.FingerprintSHA256(hostSigner.PublicKey()), authAttempts: attempts}
}

func serveOne(c net.Conn, cfg *ssh.ServerConfig, shell func(ssh.Channel)) {
	defer c.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return // includes failed-auth teardowns, which several tests want
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			// Grant what an interactive client asks for; there is no
			// real pty behind it, just the echo loop.
			for req := range chReqs {
				switch req.Type {
				case "pty-req", "shell", "window-change", "env":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
		if shell != nil {
			go shell(ch)
		}
	}
}

// echoShell is the fixture "shell": it echoes bytes back, and on the
// synthetic sentinel byte it reports `code` as its exit status and
// closes the channel -- enough to exercise the pty byte plane and the
// exit-status path without a real pty.
func echoShell(code uint32) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		buf := make([]byte, 256)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				data := buf[:n]
				if i := bytes.IndexByte(data, eotSentinel); i >= 0 {
					_, _ = ch.Write(data[:i])
					break
				}
				_, _ = ch.Write(data)
			}
			if err != nil {
				break
			}
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
		_ = ch.Close()
	}
}

// --- polling helpers --------------------------------------------------

func (r *rig) waitState(t *testing.T, want State) {
	t.Helper()
	r.waitUntil(t, "state "+stateName(want), func() bool {
		st, _ := r.eng.Status()
		return st == want
	})
}

func (r *rig) waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		r.eng.Pump()
		time.Sleep(pollInterval)
	}
	st, msg := r.eng.Status()
	t.Fatalf("timed out waiting for %s; status = %s(%q)", what, stateName(st), msg)
}

func stateName(s State) string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateHostKeyCheck:
		return "host-key-check"
	case StateAuthenticating:
		return "authenticating"
	case StateSigning:
		return "signing"
	case StateAuthPrompts:
		return "auth-prompts"
	case StateReady:
		return "ready"
	case StateClosed:
		return "closed"
	}
	return "?"
}

// --- 1. the gate ------------------------------------------------------

// TestHandshakeParksAtHostKeyGate defends the core promise of the
// component: the handshake stops at the fingerprint, and until the
// user rules on it the server has seen no authentication attempt at
// all -- not a password, not even a public-key probe.
func TestHandshakeParksAtHostKeyGate(t *testing.T) {
	r := start(t, &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	if got := r.eng.HostKeySha256(); got != r.hostFP {
		t.Fatalf("fingerprint = %q, want %q", got, r.hostFP)
	}

	// Stay parked a while and keep ticking: nothing may be attempted.
	for i := 0; i < 200; i++ {
		r.eng.Pump()
		time.Sleep(pollInterval)
	}
	if n := r.authAttempts.Load(); n != 0 {
		t.Fatalf("server saw %d auth attempts while parked at the host-key gate; want 0", n)
	}
	if st, _ := r.eng.Status(); st != StateHostKeyCheck {
		t.Fatalf("state drifted off the gate: %s", stateName(st))
	}

	// And credentials are refused outright while unconfirmed.
	err := r.eng.AuthenticatePassword("synthetic-not-a-real-password")
	if err == nil || err.Error() != hostKeyNotConfirmed {
		t.Fatalf("AuthenticatePassword before confirm = %v, want the host-key-gate refusal", err)
	}
	if n := r.authAttempts.Load(); n != 0 {
		t.Fatalf("a refused credential still produced %d auth attempts; want 0", n)
	}
}

// --- 2. rejection -----------------------------------------------------

func TestRejectedHostKeyClosesWithoutAuthenticating(t *testing.T) {
	r := start(t, &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(false)
	r.waitState(t, StateClosed)

	if n := r.authAttempts.Load(); n != 0 {
		t.Fatalf("server saw %d auth attempts after a rejected host key; want 0", n)
	}
	if _, msg := r.eng.Status(); !strings.Contains(msg, "host key rejected") {
		t.Fatalf("close reason = %q, want it to name the rejected host key", msg)
	}
	if !r.eng.Exited() {
		t.Fatal("Exited() should be true once closed")
	}
}

// --- 3. password end to end ------------------------------------------

func TestPasswordAuthReachesReadyAndCarriesBytes(t *testing.T) {
	const secret = "synthetic-fixture-password"
	r := start(t, &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != secret {
				return nil, errWrongPassword
			}
			return &ssh.Permissions{}, nil
		},
	}, echoShell(7))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	// Property 7: the accepting verdict is latched synchronously, so
	// this call cannot lose a race with the woken ssh goroutine.
	if err := r.eng.AuthenticatePassword(secret); err != nil {
		t.Fatalf("AuthenticatePassword right after confirm: %v", err)
	}
	r.waitState(t, StateReady)

	// Input typed before and after readiness both reach the shell.
	r.eng.WriteInput([]byte("hello-shuttle"))
	var got []byte
	r.waitUntil(t, "echoed input", func() bool {
		got = append(got, r.eng.DrainOutput()...)
		return bytes.Contains(got, []byte("hello-shuttle"))
	})

	r.eng.Resize(120, 40) // must not disturb the session
	r.eng.WriteInput([]byte{eotSentinel})

	r.waitState(t, StateClosed)
	r.waitUntil(t, "exit status", func() bool { return r.eng.ExitStatus() != nil })
	if code := *r.eng.ExitStatus(); code != 7 {
		t.Fatalf("exit status = %d, want 7", code)
	}
	if _, msg := r.eng.Status(); msg != "shell exited" {
		t.Fatalf("close reason = %q, want %q", msg, "shell exited")
	}
}

var errWrongPassword = &authError{"wrong password"}

type authError struct{ s string }

func (e *authError) Error() string { return e.s }

// --- 4. publickey: the parked signer ---------------------------------

// ed25519Offer builds the offer record for a freshly generated
// Ed25519 identity, the way an embedder would: the algorithm name and
// the key blob come from x/crypto itself, not from hand-rolled bytes.
func ed25519Offer(t *testing.T) (PublicKey, ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap identity: %v", err)
	}
	return PublicKey{Algorithm: sshPub.Type(), Blob: sshPub.Marshal()}, priv, sshPub
}

// ed25519Signature is what an embedder's key store hands back: the
// signature record for the offered key. The private half never enters
// the component.
func ed25519Signature(priv ed25519.PrivateKey, data []byte) Signature {
	return Signature{Format: ssh.KeyAlgoED25519, Blob: ed25519.Sign(priv, data)}
}

func TestPublickeyAuthParksForSignature(t *testing.T) {
	offer, priv, sshPub := ed25519Offer(t)

	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), sshPub.Marshal()) {
				return nil, &authError{"unknown key"}
			}
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey([]PublicKey{offer}); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}

	r.waitState(t, StateSigning)
	req := r.eng.PendingSignature()
	if req == nil || len(req.Data) == 0 {
		t.Fatal("status is signing but no signature request is pending")
	}
	// The request echoes the offered key byte for byte: that is how
	// an embedder holding several keepers knows which one to ask.
	if req.Key.Algorithm != offer.Algorithm || !bytes.Equal(req.Key.Blob, offer.Blob) {
		t.Fatalf("pending key = %q/%x, want %q/%x",
			req.Key.Algorithm, req.Key.Blob, offer.Algorithm, offer.Blob)
	}
	// A wrong-length Ed25519 signature is refused without disturbing
	// the park.
	if err := r.eng.ProvideSignature(Signature{
		Format: ssh.KeyAlgoED25519, Blob: []byte{0x00, 0x01, 0x02},
	}); err == nil {
		t.Fatal("ProvideSignature accepted a 3-byte Ed25519 signature")
	}
	if st, _ := r.eng.Status(); st != StateSigning {
		t.Fatalf("a rejected signature disturbed the park: %s", stateName(st))
	}

	if err := r.eng.ProvideSignature(ed25519Signature(priv, req.Data)); err != nil {
		t.Fatalf("ProvideSignature: %v", err)
	}
	r.waitState(t, StateReady)

	if err := r.eng.ProvideSignature(ed25519Signature(priv, req.Data)); err == nil {
		t.Fatal("ProvideSignature succeeded with nothing pending")
	}
}

// TestProvideSignatureRefusesAForeignFormat defends the legibility
// guard: sshd compares the offered algorithm name against the name
// inside the signature and answers a mismatch with an opaque failure
// several round trips later, so the core refuses it up front -- and,
// like every other malformed answer, leaves the request pending for
// the embedder to retry correctly.
func TestProvideSignatureRefusesAForeignFormat(t *testing.T) {
	offer, priv, _ := ed25519Offer(t)

	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey([]PublicKey{offer}); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}
	r.waitState(t, StateSigning)
	req := r.eng.PendingSignature()
	if req == nil {
		t.Fatal("no signature request pending")
	}

	wrong := ed25519Signature(priv, req.Data)
	wrong.Format = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
	err := r.eng.ProvideSignature(wrong)
	if err == nil {
		t.Fatal("ProvideSignature accepted a format that is not the pending key's algorithm")
	}
	if !strings.Contains(err.Error(), wrong.Format) || !strings.Contains(err.Error(), offer.Algorithm) {
		t.Fatalf("error %q should quote both the given format and the expected algorithm", err)
	}
	if st, _ := r.eng.Status(); st != StateSigning {
		t.Fatalf("a rejected format disturbed the park: %s", stateName(st))
	}
	if again := r.eng.PendingSignature(); again == nil || !bytes.Equal(again.Data, req.Data) {
		t.Fatal("the request should still be pending, unchanged")
	}

	// The retry with the right format still works.
	if err := r.eng.ProvideSignature(ed25519Signature(priv, req.Data)); err != nil {
		t.Fatalf("ProvideSignature after the refused one: %v", err)
	}
	r.waitState(t, StateReady)
}

// TestPublickeyFallsThroughToTheSecondKey defends the
// graceful-degradation path a passkey depends on: when the server will
// not take the first key's algorithm, the offer moves on to the next
// key WITHIN THE SAME CONNECTION, and only the key the server actually
// accepted is ever signed for. (In production the skipped key is a
// webauthn offer to a pre-8.4 sshd; here it is a made-up algorithm
// name over the same blob, which the server refuses on the same
// "algorithm not accepted" path.)
func TestPublickeyFallsThroughToTheSecondKey(t *testing.T) {
	offer, priv, sshPub := ed25519Offer(t)
	unsupported := PublicKey{
		Algorithm: "synthetic-unsupported-alg@wosh.test",
		Blob:      offer.Blob,
	}

	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), sshPub.Marshal()) {
				return nil, &authError{"unknown key"}
			}
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey([]PublicKey{unsupported, offer}); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}

	r.waitState(t, StateSigning)
	req := r.eng.PendingSignature()
	if req == nil {
		t.Fatal("no signature request pending")
	}
	// The park is for the SECOND key: the first was skipped without
	// ever asking the embedder for a signature.
	if req.Key.Algorithm != offer.Algorithm {
		t.Fatalf("parked for algorithm %q, want the second key's %q",
			req.Key.Algorithm, offer.Algorithm)
	}
	if !bytes.Equal(req.Key.Blob, offer.Blob) {
		t.Fatal("parked request does not echo the second key's blob")
	}
	if err := r.eng.ProvideSignature(ed25519Signature(priv, req.Data)); err != nil {
		t.Fatalf("ProvideSignature: %v", err)
	}
	r.waitState(t, StateReady)
}

// A server that refuses the offered key and then asks for a password
// must not be reported as a PASSWORD problem.
//
// This is the shape of nearly every real sshd: publickey plus password.
// When the key is refused -- an authorized_keys line that is absent, or
// an algorithm the server has not enabled -- x/crypto moves on to the
// next method the server says can continue, which lands in the password
// callback with a credential that offers no password. Declining is
// correct; the trap is that x/crypto returns the LAST error it saw, so
// a bare "password auth not selected" became the whole story of a
// failure that was never about passwords.
func TestRefusedKeyThenPasswordBlamesTheKey(t *testing.T) {
	offer, _, _ := ed25519Offer(t)

	r := start(t, &ssh.ServerConfig{
		// The key is not one this server knows.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, &authError{"unknown key"}
		},
		// ...and password is on offer, as it is nearly everywhere.
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, &authError{"no"}
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey([]PublicKey{offer}); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}

	r.waitState(t, StateClosed)
	_, msg := r.eng.Status()
	t.Logf("close message: %s", msg)
	// The message must point at the key that was refused, and name the
	// algorithm, since "the server has not enabled that algorithm" is
	// the most common cause and the one the user can act on.
	if !strings.Contains(msg, offer.Algorithm) {
		t.Errorf("close message does not name the refused key's algorithm %q: %s",
			offer.Algorithm, msg)
	}
	if !strings.Contains(msg, "did not accept") {
		t.Errorf("close message does not say the key was refused: %s", msg)
	}
	// And it must NOT blame passwords: nothing here was ever about one.
	if strings.Contains(msg, "password auth not selected") {
		t.Errorf("close message blames the password method for a publickey failure: %s", msg)
	}
}

func TestFailedSignatureClosesLegibly(t *testing.T) {
	offer, _, _ := ed25519Offer(t)
	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey([]PublicKey{offer}); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}
	r.waitState(t, StateSigning)
	r.eng.FailSignature("the signer is unavailable")

	r.waitState(t, StateClosed)
	if _, msg := r.eng.Status(); !strings.Contains(msg, "signer is unavailable") {
		t.Fatalf("close reason = %q, want it to carry the refusal reason", msg)
	}
}

// TestPublickeyRejectsMalformedOffers pins the synchronous refusals.
// The core parses no key blob, so "malformed" here means only what it
// can judge: a missing algorithm name, a missing blob, or an offer of
// nothing at all. Each must be refused BEFORE anything is latched --
// proven by a legitimate authenticate call still succeeding after.
func TestPublickeyRejectsMalformedOffers(t *testing.T) {
	offer, priv, _ := ed25519Offer(t)
	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))
	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)

	if err := r.eng.AuthenticatePublickey(nil); err == nil {
		t.Fatal("AuthenticatePublickey accepted an empty offer")
	}
	if err := r.eng.AuthenticatePublickey([]PublicKey{{Blob: offer.Blob}}); err == nil {
		t.Fatal("AuthenticatePublickey accepted a key with no algorithm name")
	}
	if err := r.eng.AuthenticatePublickey([]PublicKey{{Algorithm: offer.Algorithm}}); err == nil {
		t.Fatal("AuthenticatePublickey accepted a key with no blob")
	}
	// A bad key anywhere in the list rejects the whole offer.
	if err := r.eng.AuthenticatePublickey([]PublicKey{offer, {Algorithm: "x"}}); err == nil {
		t.Fatal("AuthenticatePublickey accepted a list with a malformed second key")
	}
	// Nothing was latched: the real offer still authenticates.
	if err := r.eng.AuthenticatePublickey([]PublicKey{offer}); err != nil {
		t.Fatalf("AuthenticatePublickey after refused offers: %v", err)
	}
	r.waitState(t, StateSigning)
	req := r.eng.PendingSignature()
	if req == nil {
		t.Fatal("no signature request pending")
	}
	if err := r.eng.ProvideSignature(ed25519Signature(priv, req.Data)); err != nil {
		t.Fatalf("ProvideSignature: %v", err)
	}
	r.waitState(t, StateReady)
}

// --- 5. keyboard-interactive -----------------------------------------

// The scripted exchange, mirroring the kbdint-sshd fixture: a first
// batch mixing an echoed and a masked prompt (which pins the echo-flag
// plumbing), then a second round proving multi-batch works.
var kbdRounds = []struct {
	instruction string
	prompts     []string
	echos       []bool
	answers     []string
}{
	{
		instruction: "wosh keyboard-interactive gate: scripted round one",
		prompts:     []string{"token code (visible): ", "passphrase (hidden): "},
		echos:       []bool{true, false},
		answers:     []string{"gate-token-123", "gate-passphrase-456"},
	},
	{
		instruction: "",
		prompts:     []string{"second factor: "},
		echos:       []bool{false},
		answers:     []string{"gate-otp-789"},
	},
}

func kbdServerConfig() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for i, round := range kbdRounds {
				got, err := client(conn.User(), round.instruction, round.prompts, round.echos)
				if err != nil {
					return nil, err
				}
				if len(got) != len(round.answers) {
					return nil, &authError{"answer count mismatch"}
				}
				for j := range round.answers {
					if got[j] != round.answers[j] {
						return nil, &authError{"wrong answer in round " + string(rune('1'+i))}
					}
				}
			}
			return &ssh.Permissions{}, nil
		},
	}
}

func TestKeyboardInteractiveWalksEveryBatch(t *testing.T) {
	r := start(t, kbdServerConfig(), echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticateInteractive(); err != nil {
		t.Fatalf("AuthenticateInteractive: %v", err)
	}

	for i, round := range kbdRounds {
		r.waitState(t, StateAuthPrompts)
		batch := r.eng.PendingPrompts()
		if batch == nil {
			t.Fatalf("round %d: status is auth-prompts but no batch is pending", i+1)
		}
		if batch.Instruction != round.instruction {
			t.Fatalf("round %d: instruction = %q, want %q", i+1, batch.Instruction, round.instruction)
		}
		if len(batch.Prompts) != len(round.prompts) {
			t.Fatalf("round %d: %d prompts, want %d", i+1, len(batch.Prompts), len(round.prompts))
		}
		for j, p := range batch.Prompts {
			if p.Text != round.prompts[j] || p.Echo != round.echos[j] {
				t.Fatalf("round %d prompt %d = %+v, want text %q echo %v",
					i+1, j, p, round.prompts[j], round.echos[j])
			}
		}
		// Strict alternation: answering an already-answered batch fails.
		if err := r.eng.AnswerPrompts(round.answers); err != nil {
			t.Fatalf("round %d: AnswerPrompts: %v", i+1, err)
		}
		if err := r.eng.AnswerPrompts(round.answers); err == nil {
			t.Fatalf("round %d: AnswerPrompts succeeded with no batch pending", i+1)
		}
	}

	r.waitState(t, StateReady)
}

func TestKeyboardInteractiveWrongAnswerCloses(t *testing.T) {
	r := start(t, kbdServerConfig(), echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticateInteractive(); err != nil {
		t.Fatalf("AuthenticateInteractive: %v", err)
	}
	r.waitState(t, StateAuthPrompts)
	batch := r.eng.PendingPrompts()
	if batch == nil {
		t.Fatal("no batch pending")
	}
	// Count mismatch is caught locally, before anything is sent.
	if err := r.eng.AnswerPrompts([]string{"only-one"}); err == nil {
		t.Fatal("AnswerPrompts accepted 1 answer for 2 prompts")
	}
	if err := r.eng.AnswerPrompts([]string{"wrong-token", "wrong-passphrase"}); err != nil {
		t.Fatalf("AnswerPrompts: %v", err)
	}

	r.waitState(t, StateClosed)
	if _, msg := r.eng.Status(); !strings.Contains(msg, "ssh:") {
		t.Fatalf("close reason = %q, want the ssh stack's auth failure", msg)
	}
}

// --- 6. auto ----------------------------------------------------------

func autoServerConfig(t *testing.T, accept ssh.PublicKey, password string) *ssh.ServerConfig {
	t.Helper()
	return &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if accept == nil || !bytes.Equal(key.Marshal(), accept.Marshal()) {
				return nil, &authError{"unknown key"}
			}
			return &ssh.Permissions{}, nil
		},
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != password {
				return nil, errWrongPassword
			}
			return &ssh.Permissions{}, nil
		},
	}
}

func TestAutoPrefersPublickeyWhenAKeyIsSupplied(t *testing.T) {
	offer, priv, sshPub := ed25519Offer(t)
	r := start(t, autoServerConfig(t, sshPub, "synthetic-fixture-password"), echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticateAuto([]PublicKey{offer}); err != nil {
		t.Fatalf("AuthenticateAuto: %v", err)
	}

	r.waitState(t, StateSigning)
	req := r.eng.PendingSignature()
	if req == nil {
		t.Fatal("no signature request pending")
	}
	if err := r.eng.ProvideSignature(ed25519Signature(priv, req.Data)); err != nil {
		t.Fatalf("ProvideSignature: %v", err)
	}
	r.waitState(t, StateReady)

	// Silent: publickey succeeded without ever asking the user
	// anything.
	if batch := r.eng.PendingPrompts(); batch != nil {
		t.Fatalf("publickey auto path surfaced a prompt batch: %+v", batch)
	}
}

func TestAutoFallsBackToAOneWayMaskedPasswordPrompt(t *testing.T) {
	const secret = "synthetic-fixture-password"
	r := start(t, autoServerConfig(t, nil, secret), echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	// An empty offer is legal here and simply declines publickey.
	if err := r.eng.AuthenticateAuto(nil); err != nil {
		t.Fatalf("AuthenticateAuto: %v", err)
	}

	r.waitState(t, StateAuthPrompts)
	batch := r.eng.PendingPrompts()
	if batch == nil || len(batch.Prompts) != 1 {
		t.Fatalf("auto password round = %+v, want exactly one prompt", batch)
	}
	if batch.Prompts[0].Echo {
		t.Fatal("the auto password prompt must be masked (echo=false)")
	}
	if !strings.Contains(batch.Prompts[0].Text, "password for tester") {
		t.Fatalf("prompt text = %q, want it to name the login user", batch.Prompts[0].Text)
	}
	if err := r.eng.AnswerPrompts([]string{secret}); err != nil {
		t.Fatalf("AnswerPrompts: %v", err)
	}
	r.waitState(t, StateReady)
}

// --- wire failures ----------------------------------------------------

// TestWireBrokenAtTheGateClosesWithTheGivenReason pins the teardown
// path the embedder relies on when the tunnel dies underneath a parked
// session: the reason it reported is the reason that surfaces, and no
// goroutine is left waiting on an answer that can no longer come.
func TestWireBrokenAtTheGateClosesWithTheGivenReason(t *testing.T) {
	r := start(t, &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.WireBroken("iroh tunnel closed")
	r.waitState(t, StateClosed)
	if _, msg := r.eng.Status(); msg != "iroh tunnel closed" {
		t.Fatalf("close reason = %q, want the wire reason", msg)
	}
	if n := r.authAttempts.Load(); n != 0 {
		t.Fatalf("server saw %d auth attempts; want 0", n)
	}
}
