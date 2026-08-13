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

func TestPublickeyAuthParksForSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap identity: %v", err)
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
	if err := r.eng.AuthenticatePublickey(pub); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}

	r.waitState(t, StateSigning)
	blob := r.eng.PendingSignature()
	if len(blob) == 0 {
		t.Fatal("status is signing but no signature blob is pending")
	}
	// A wrong-length signature is refused without disturbing the park.
	if err := r.eng.ProvideSignature([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("ProvideSignature accepted a 3-byte signature")
	}
	if st, _ := r.eng.Status(); st != StateSigning {
		t.Fatalf("a rejected signature disturbed the park: %s", stateName(st))
	}

	// The private half never enters the component: the test signs on
	// its own, exactly as the embedder's key store would.
	if err := r.eng.ProvideSignature(ed25519.Sign(priv, blob)); err != nil {
		t.Fatalf("ProvideSignature: %v", err)
	}
	r.waitState(t, StateReady)

	if err := r.eng.ProvideSignature(make([]byte, ed25519.SignatureSize)); err == nil {
		t.Fatal("ProvideSignature succeeded with nothing pending")
	}
}

func TestFailedSignatureClosesLegibly(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey(pub); err != nil {
		t.Fatalf("AuthenticatePublickey: %v", err)
	}
	r.waitState(t, StateSigning)
	r.eng.FailSignature("the signer is unavailable")

	r.waitState(t, StateClosed)
	if _, msg := r.eng.Status(); !strings.Contains(msg, "signer is unavailable") {
		t.Fatalf("close reason = %q, want it to carry the refusal reason", msg)
	}
}

func TestPublickeyRejectsMalformedKey(t *testing.T) {
	r := start(t, &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(0))
	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePublickey([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("AuthenticatePublickey accepted a 3-byte public key")
	}
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap identity: %v", err)
	}
	r := start(t, autoServerConfig(t, sshPub, "synthetic-fixture-password"), echoShell(0))

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticateAuto(pub); err != nil {
		t.Fatalf("AuthenticateAuto: %v", err)
	}

	r.waitState(t, StateSigning)
	blob := r.eng.PendingSignature()
	if err := r.eng.ProvideSignature(ed25519.Sign(priv, blob)); err != nil {
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
