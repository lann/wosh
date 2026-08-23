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
	"sync"
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
	// requests records every channel request type the fixture server
	// saw, in order (pty-req, shell/exec, window-change, env, ...),
	// so tests can assert exec ran in place of shell (or vice versa)
	// without inspecting server internals.
	requests *requestLog
	// execCommand is set from the fixture server's "exec" request
	// payload, once one arrives (RFC 4254 s6.5): the command string,
	// byte for byte, so tests can pin it against what New() was given.
	execCommand *stringBox
}

// requestLog is a tiny concurrency-safe recorder: the fixture server's
// request-handling goroutine writes, the test goroutine reads.
type requestLog struct {
	mu    sync.Mutex
	types []string
}

func (l *requestLog) add(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.types = append(l.types, t)
}

func (l *requestLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.types...)
}

// stringBox is the same concurrency-safe capture for the exec payload.
type stringBox struct {
	mu  sync.Mutex
	set bool
	val string
}

func (b *stringBox) set_(v string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.set, b.val = true, v
}

func (b *stringBox) get() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.val, b.set
}

// start wires a fresh engine to an in-process x/crypto/ssh server over
// a net.Pipe and pumps bytes between them for the life of the test.
func start(t *testing.T, cfg *ssh.ServerConfig, shell func(ssh.Channel)) *rig {
	return startWithCommand(t, cfg, shell, "")
}

// startWithCommand is start, but the engine connects with `command`:
// present, this drives the fixture's exec path (RFC 4254 s6.5), used
// by the reattach-to-session-manager tests below; empty reproduces
// start's plain-shell behaviour exactly.
func startWithCommand(t *testing.T, cfg *ssh.ServerConfig, shell func(ssh.Channel), command string) *rig {
	t.Helper()
	return startFull(t, cfg, shell, command, nil, nil)
}

// startWithProbe is start, but the fixture server also answers a
// SECOND session channel (the probe channel a ready session opens via
// ProbeStart) with probeShell, which receives the exec command and the
// probe's own channel -- distinct from the interactive channel `shell`
// serves.
func startWithProbe(t *testing.T, cfg *ssh.ServerConfig, shell func(ssh.Channel), probeShell func(command string, ch ssh.Channel)) *rig {
	t.Helper()
	return startFull(t, cfg, shell, "", probeShell, nil)
}

// startWithBulk is start, but the fixture server answers the SUBSYSTEM
// and exec requests a bulk channel makes (see channel_test.go) through
// `bulk`. Refusing there is how a server with no matching `Subsystem`
// line is reproduced.
func startWithBulk(t *testing.T, cfg *ssh.ServerConfig, shell func(ssh.Channel), bulk bulkServer) *rig {
	t.Helper()
	return startFull(t, cfg, shell, "", nil, bulk)
}

// bulkServer decides what a non-interactive channel's `subsystem` or
// `exec` request is granted. Returning nil REFUSES the request, which
// is what an sshd without the named subsystem does; otherwise the
// returned func serves the channel once the grant has been replied.
type bulkServer func(kind, arg string, ch ssh.Channel) func(ssh.Channel)

// startFull is the shared setup behind start / startWithCommand /
// startWithProbe / startWithBulk.
func startFull(t *testing.T, cfg *ssh.ServerConfig, shell func(ssh.Channel), command string, probeShell func(command string, ch ssh.Channel), bulk bulkServer) *rig {
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
	eng := New("tester", 80, 24, command)

	requests := &requestLog{}
	execCommand := &stringBox{}
	go serveOne(srvSide, cfg, shell, requests, execCommand, probeShell, bulk)


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

	return &rig{
		eng:          eng,
		hostFP:       ssh.FingerprintSHA256(hostSigner.PublicKey()),
		authAttempts: attempts,
		requests:     requests,
		execCommand:  execCommand,
	}
}

func serveOne(c net.Conn, cfg *ssh.ServerConfig, shell func(ssh.Channel), requests *requestLog, execCommand *stringBox, probeShell func(command string, ch ssh.Channel), bulk bulkServer) {
	defer c.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return // includes failed-auth teardowns, which several tests want
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	// The first session channel opened on a connection is the
	// interactive one (plain shell or the reattach `exec`, per
	// `command`); serving each incoming channel concurrently -- which
	// this loop already did, one channel at a time in earlier phases
	// -- is what lets a probe open a SECOND channel on the very same
	// connection without disturbing the first. Later channels are
	// probes: their `exec` command is handed to probeShell instead of
	// running the interactive `shell`.
	first := true
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		isFirst := first
		first = false
		go func() {
			// Grant what an interactive client asks for; there is no
			// real pty behind it, just the echo loop.
			for req := range chReqs {
				requests.add(req.Type)
				switch req.Type {
				case "pty-req", "shell", "window-change", "env":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "exec":
					// RFC 4254 s6.5: a single uint32-length-prefixed
					// command string, nothing else.
					var payload struct{ Command string }
					if err := ssh.Unmarshal(req.Payload, &payload); err == nil {
						if isFirst {
							execCommand.set_(payload.Command)
						}
						// A later channel's exec belongs to whichever
						// plane the test installed: the probe plane's
						// one-shot command, or the bulk plane's
						// long-lived pipe (the `sftp -s` fallback).
						if !isFirst && probeShell == nil && bulk != nil {
							serve := bulk("exec", payload.Command, ch)
							if req.WantReply {
								_ = req.Reply(serve != nil, nil)
							}
							if serve != nil {
								go serve(ch)
							}
							continue
						}
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						if !isFirst && probeShell != nil {
							go probeShell(payload.Command, ch)
						}
						continue
					}
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "subsystem":
					// RFC 4254 s6.5 again, one string: the subsystem
					// name. A server with no matching `Subsystem`
					// line replies false HERE, which is exactly what
					// a nil bulk handler reproduces.
					var payload struct{ Name string }
					var serve func(ssh.Channel)
					if err := ssh.Unmarshal(req.Payload, &payload); err == nil && bulk != nil {
						serve = bulk("subsystem", payload.Name, ch)
					}
					if req.WantReply {
						_ = req.Reply(serve != nil, nil)
					}
					if serve != nil {
						go serve(ch)
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
		if isFirst && shell != nil {
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
	// The plain-shell path must still ask for "shell", never "exec" --
	// pinned here so the exec addition below cannot silently regress it.
	reqs := r.requests.snapshot()
	if !containsStr(reqs, "shell") {
		t.Fatalf("requests = %v, want a \"shell\" request", reqs)
	}
	if containsStr(reqs, "exec") {
		t.Fatalf("requests = %v, plain connect must never send \"exec\"", reqs)
	}
}

// TestConnectWithCommandSendsExecInsteadOfShell defends the
// reattach-to-session-manager feature this engine exists to support:
// a `command` given to New (dtach -A, tmux new -AD, abduco -A and
// friends) rides an RFC 4254 s6.5 `exec` request in place of the
// default `shell` request, on the very same channel and pty, and the
// command's own exit status -- not any inner shell's -- is what
// `exit-status` reports.
func TestConnectWithCommandSendsExecInsteadOfShell(t *testing.T) {
	const command = `dtach -A /tmp/wosh-synthetic-test.sock -z bash`
	r := startWithCommand(t, &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}, echoShell(3), command)

	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePassword("synthetic-fixture-password"); err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}
	r.waitState(t, StateReady)

	// Same channel, same pty, same byte plane: input still round-trips.
	r.eng.WriteInput([]byte("hello-from-exec-path"))
	var got []byte
	r.waitUntil(t, "echoed input", func() bool {
		got = append(got, r.eng.DrainOutput()...)
		return bytes.Contains(got, []byte("hello-from-exec-path"))
	})
	r.eng.WriteInput([]byte{eotSentinel})

	r.waitState(t, StateClosed)
	r.waitUntil(t, "exit status", func() bool { return r.eng.ExitStatus() != nil })
	if code := *r.eng.ExitStatus(); code != 3 {
		t.Fatalf("exit status = %d, want 3 (the fixture command's own exit, not a shell's)", code)
	}

	// The server saw an exec request carrying the command byte for
	// byte, and no shell request at all.
	got2, ok := r.execCommand.get()
	if !ok {
		t.Fatal("server never received an exec request")
	}
	if got2 != command {
		t.Fatalf("exec command = %q, want %q", got2, command)
	}
	reqs := r.requests.snapshot()
	if !containsStr(reqs, "exec") {
		t.Fatalf("requests = %v, want an \"exec\" request", reqs)
	}
	if containsStr(reqs, "shell") {
		t.Fatalf("requests = %v, a command connect must never also send \"shell\"", reqs)
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
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

// --- 7. the probe -------------------------------------------------

// simplePasswordConfig is the fixture server config every probe test
// authenticates against; the probe plane has nothing to do with which
// auth method got the connection to `ready`.
func simplePasswordConfig() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
}

// reachReady drives a rig from the host-key gate to StateReady over a
// plain password exchange, the common setup every probe test needs
// before ProbeStart is legal.
func (r *rig) reachReady(t *testing.T) {
	t.Helper()
	r.waitState(t, StateHostKeyCheck)
	r.eng.ConfirmHostKey(true)
	if err := r.eng.AuthenticatePassword("synthetic-fixture-password"); err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}
	r.waitState(t, StateReady)
}

// waitProbe polls ProbePoll until the in-flight probe finishes.
func (r *rig) waitProbe(t *testing.T) *ProbeResult {
	t.Helper()
	var result *ProbeResult
	r.waitUntil(t, "probe result", func() bool {
		result = r.eng.ProbePoll()
		return result != nil
	})
	return result
}

// probeEcho is a probe-channel fixture: it writes `stdout` and
// `stderr` (skipping either when empty), reports `code` as the exit
// status, and closes -- the probe-side analogue of echoShell, minus
// the pty byte-plane behaviour a probe never uses.
func probeEcho(stdout, stderr []byte, code uint32) func(command string, ch ssh.Channel) {
	return func(_ string, ch ssh.Channel) {
		if len(stdout) > 0 {
			_, _ = ch.Write(stdout)
		}
		if len(stderr) > 0 {
			_, _ = ch.Stderr().Write(stderr)
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
		_ = ch.Close()
	}
}

// probeGated is probeEcho but parked on `release` first, letting a
// test hold a probe "in flight" for as long as it likes -- used to
// exercise the one-probe-at-a-time gate deterministically instead of
// racing a real command's completion.
func probeGated(release <-chan struct{}, stdout []byte, code uint32) func(command string, ch ssh.Channel) {
	return func(_ string, ch ssh.Channel) {
		<-release
		if len(stdout) > 0 {
			_, _ = ch.Write(stdout)
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
		_ = ch.Close()
	}
}

// probeFlood writes exactly `total` bytes of filler to stdout before
// reporting `code` -- the fixture side of the truncation test, well
// past probeOutputCap.
func probeFlood(total int, code uint32) func(command string, ch ssh.Channel) {
	return func(_ string, ch ssh.Channel) {
		chunk := bytes.Repeat([]byte{'z'}, 4096)
		for written := 0; written < total; {
			n := len(chunk)
			if remaining := total - written; remaining < n {
				n = remaining
			}
			if _, err := ch.Write(chunk[:n]); err != nil {
				break
			}
			written += n
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
		_ = ch.Close()
	}
}

// TestProbeRunsOnASecondChannelWithoutDisturbingTheFirst defends the
// whole point of the probe plane: it rides its OWN session channel, so
// the interactive one keeps working exactly as before, both while the
// probe is in flight and after it finishes.
func TestProbeRunsOnASecondChannelWithoutDisturbingTheFirst(t *testing.T) {
	probeStdout := []byte("synthetic-probe-stdout")
	probeStderr := []byte("synthetic-probe-stderr")
	r := startWithProbe(t, simplePasswordConfig(), echoShell(0), probeEcho(probeStdout, probeStderr, 3))
	r.reachReady(t)

	if err := r.eng.ProbeStart("wosh-probe: which-session-manager"); err != nil {
		t.Fatalf("ProbeStart: %v", err)
	}
	result := r.waitProbe(t)
	if result.ExitStatus == nil || *result.ExitStatus != 3 {
		t.Fatalf("probe exit status = %v, want 3", result.ExitStatus)
	}
	if !bytes.Contains(result.Output, probeStdout) {
		t.Fatalf("probe output = %q, want it to contain the stdout bytes", result.Output)
	}
	if !bytes.Contains(result.Output, probeStderr) {
		t.Fatalf("probe output = %q, want it to contain the stderr bytes too", result.Output)
	}

	// The interactive channel is undisturbed: it still round-trips
	// bytes AFTER the probe has completed.
	r.eng.WriteInput([]byte("hello-after-the-probe"))
	var got []byte
	r.waitUntil(t, "echoed input after the probe", func() bool {
		got = append(got, r.eng.DrainOutput()...)
		return bytes.Contains(got, []byte("hello-after-the-probe"))
	})
}

// TestProbeOneAtATime defends the park-and-poll discipline
// wit/core.wit documents: a second ProbeStart while one is in flight
// is refused, and the refusal lifts only once the first result has
// been observed via ProbePoll.
func TestProbeOneAtATime(t *testing.T) {
	release := make(chan struct{})
	r := startWithProbe(t, simplePasswordConfig(), echoShell(0), probeGated(release, []byte("first-probe-output"), 0))
	r.reachReady(t)

	if err := r.eng.ProbeStart("first"); err != nil {
		t.Fatalf("ProbeStart (first): %v", err)
	}
	if err := r.eng.ProbeStart("second"); err == nil {
		t.Fatal("ProbeStart succeeded while a probe was in flight")
	}

	close(release) // let the fixture finish the first probe
	result := r.waitProbe(t)
	if result.ExitStatus == nil || *result.ExitStatus != 0 {
		t.Fatalf("first probe exit status = %v, want 0", result.ExitStatus)
	}

	// Polled: a new probe is legal again.
	if err := r.eng.ProbeStart("third"); err != nil {
		t.Fatalf("ProbeStart after the first was polled: %v", err)
	}
}

// TestProbeStartBeforeReadyErrors defends the other half of the gate:
// a probe channel makes no sense before the interactive one has even
// authenticated.
func TestProbeStartBeforeReadyErrors(t *testing.T) {
	r := startWithProbe(t, simplePasswordConfig(), echoShell(0), probeEcho(nil, nil, 0))
	r.waitState(t, StateHostKeyCheck)
	if err := r.eng.ProbeStart("too-early"); err == nil {
		t.Fatal("ProbeStart succeeded before the session reached ready")
	}
}

// TestProbeOutputIsTruncatedAtTheCap defends probeOutputCap: a probe
// is a question, not a transfer, so a runaway answer is capped rather
// than buffered without bound -- and the exit status still arrives,
// because truncation is not failure.
func TestProbeOutputIsTruncatedAtTheCap(t *testing.T) {
	const flood = probeOutputCap + 64*1024
	r := startWithProbe(t, simplePasswordConfig(), echoShell(0), probeFlood(flood, 5))
	r.reachReady(t)

	if err := r.eng.ProbeStart("flood"); err != nil {
		t.Fatalf("ProbeStart: %v", err)
	}
	result := r.waitProbe(t)
	if len(result.Output) != probeOutputCap {
		t.Fatalf("probe output length = %d, want the %d-byte cap", len(result.Output), probeOutputCap)
	}
	if result.ExitStatus == nil || *result.ExitStatus != 5 {
		t.Fatalf("probe exit status = %v, want 5 even though the output was truncated", result.ExitStatus)
	}
}

// TestProbePollHandsTheResultOverExactlyOnce defends ProbePoll's
// consume-once contract: a second poll right after the first sees
// nothing, because the first already cleared it.
func TestProbePollHandsTheResultOverExactlyOnce(t *testing.T) {
	r := startWithProbe(t, simplePasswordConfig(), echoShell(0), probeEcho([]byte("x"), nil, 0))
	r.reachReady(t)

	if err := r.eng.ProbeStart("once"); err != nil {
		t.Fatalf("ProbeStart: %v", err)
	}
	if first := r.waitProbe(t); first == nil {
		t.Fatal("first poll returned nil")
	}
	if second := r.eng.ProbePoll(); second != nil {
		t.Fatalf("second poll returned %+v, want none", second)
	}
}

// TestCloseDuringInFlightProbeDoesNotDeadlock defends the teardown
// path ProbeStart's doc merely asserts: closing the session while a
// probe goroutine sits parked inside sess.Run must not deadlock or
// panic. x/crypto unblocks Run with an error once the transport it is
// reading dies, so the goroutine is expected to run to completion
// either way -- this pins that Close() actually delivers that
// unblock, and that whatever ProbePoll then reports is honest: either
// nothing (the goroutine never got to store a result) or a result
// with NO exit status (the channel died without the server ever
// reporting one), never a fabricated status standing in for a
// probe that in truth never got an answer.
func TestCloseDuringInFlightProbeDoesNotDeadlock(t *testing.T) {
	release := make(chan struct{})
	r := startWithProbe(t, simplePasswordConfig(), echoShell(0), probeGated(release, []byte("never-observed"), 0))
	r.reachReady(t)

	if err := r.eng.ProbeStart("parked-forever"); err != nil {
		t.Fatalf("ProbeStart: %v", err)
	}
	// Confirm it is genuinely in flight before tearing down: a second
	// probe must still be refused.
	if err := r.eng.ProbeStart("second"); err == nil {
		t.Fatal("ProbeStart succeeded while a probe was in flight")
	}

	r.eng.Close() // tear down while the probe's goroutine is parked in sess.Run

	// Give the parked goroutine a bounded chance to observe the
	// teardown and store a result. Unlike waitProbe/waitUntil, timing
	// out here is NOT a failure: "no result ever arrives" is one of
	// the two outcomes this test accepts, so the loop below only
	// looks for a result -- it never fails on its own account. A
	// shorter bound than testDeadline is deliberate: both accepted
	// outcomes are the test passing, so there is nothing to gain by
	// waiting the full deadline out.
	deadline := time.Now().Add(2 * time.Second)
	var result *ProbeResult
	for time.Now().Before(deadline) {
		if result = r.eng.ProbePoll(); result != nil {
			break
		}
		r.eng.Pump()
		time.Sleep(pollInterval)
	}
	if result != nil && result.ExitStatus != nil {
		t.Fatalf("probe result after Close = %+v, want no fabricated exit status", result)
	}

	// Free the fixture's goroutine (still parked on <-release) so it
	// does not leak into later tests.
	close(release)
}
