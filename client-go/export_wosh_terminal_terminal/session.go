// Package export_wosh_terminal_terminal implements wosh:terminal --
// the whole browser SSH client, in one component.
//
// Shape: `golang.org/x/crypto/ssh` running over a real net.Conn that
// wraps an iroh bi stream. The iroh endpoint is a WIT import whose
// async methods componentize-go surfaces as ordinary blocking Go
// calls, so this reads like a normal networked Go program --
// goroutines, channels, a net.Conn -- with no sans-I/O shuttling and
// no host-driven tick.
//
// Two rules shape everything here:
//
//  1. A goroutine may only touch an async import while an async-lifted
//     export task is on the stack. Every export in the WIT is
//     therefore async.
//  2. componentize-go ends a task once the guest is idle with no
//     Component-Model waitable pending, which also describes a
//     goroutine parked on a Go channel awaiting the next export call.
//     `Keepalive` (below) deliberately never returns, so there is
//     always a live task hosting the SSH goroutines.
package export_wosh_terminal_terminal

import (
	"fmt"
	"net"
	"runtime"
	"sync"

	witTypes "go.bytecodealliance.org/pkg/wit/types"
	"golang.org/x/crypto/ssh"

	types "wit_component/wosh_terminal_terminal"
	clock "wit_component/wasi_clocks_monotonic_clock"
)

// Keepalive holds this component's async runtime open; see the WIT doc
// comment for why it is load-bearing. It parks on a timer forever, so
// its task always has a pending subtask: the host keeps resuming it,
// and every resume runs all runnable goroutines.
func Keepalive() {
	for {
		clock.WaitFor(250 * 1_000_000) // an async import: the task always has one pending
	}
}

const (
	stateConnecting = iota
	stateHostKeyCheck
	stateAuthenticating
	stateReady
	stateClosed
)

// credential is what the page supplied via an authenticate-* call.
type credential struct {
	kind     string // "password" | "publickey"
	password string
}

// Session is the exported resource. The generated bindings require the
// handle/pinner fields and the OnDrop hook.
type Session struct {
	handle int32
	pinner runtime.Pinner

	mu       sync.Mutex
	state    int
	closeMsg string
	hostFP   string
	exitCode *int32
	exited   bool

	conn      *irohConn
	client    *ssh.Client
	sshSess   *ssh.Session
	stdinPipe stdinWriter

	// The host-key callback parks here until the page rules on the
	// fingerprint. x/crypto/ssh runs authentication strictly after
	// that callback returns, which makes "nothing is sent before the
	// user approves" structural rather than merely intended.
	hostKeyDecision chan bool
	decisionOnce    sync.Once

	// Latched credentials. The auth callbacks park on credsReady,
	// which closes exactly once when an authenticate-* call lands.
	creds       credential
	credsReady  chan struct{}
	credsOnce   sync.Once
	authOutcome chan error

	out       lockedBuf // pty output awaiting the page
	pendingIn lockedBuf // input typed before the shell's stdin existed

	cols, rows uint16
}

type stdinWriter interface{ Write(p []byte) (int, error) }

func (s *Session) setState(st int, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stateClosed { // terminal and latched
		return
	}
	s.state = st
	if msg != "" {
		s.closeMsg = msg
	}
}

// fail marks the session dead and releases anything waiting on auth.
func (s *Session) fail(msg string) {
	s.mu.Lock()
	if s.state != stateClosed {
		s.state = stateClosed
		s.closeMsg = msg
	}
	s.mu.Unlock()
	select {
	case s.authOutcome <- fmt.Errorf("%s", msg):
	default:
	}
}

// SessionConnect backs `session.connect`.
func SessionConnect(connstring string, user string, cols uint16, rows uint16) witTypes.Result[*Session, string] {
	cs, err := ParseConnString(connstring)
	if err != nil {
		return witTypes.Err[*Session, string]("connection string: " + err.Error())
	}

	conn, err := dial(cs)
	if err != nil {
		return witTypes.Err[*Session, string](err.Error())
	}

	s := &Session{
		state:           stateConnecting,
		conn:            conn,
		hostKeyDecision: make(chan bool, 1),
		credsReady:      make(chan struct{}),
		authOutcome:     make(chan error, 1),
		cols:            cols,
		rows:            rows,
	}

	// The ssh lifecycle runs on its own goroutine so this export can
	// return: the page must observe `host-key-check` and show the
	// fingerprint while the handshake sits parked mid-kex.
	go s.run(user)
	runtime.Gosched()

	return witTypes.Ok[*Session, string](s)
}

// run drives the whole ssh lifecycle: handshake (parking at the
// host-key gate), authentication, then pty + shell.
func (s *Session) run(user string) {
	cfg := &ssh.ClientConfig{
		User: user,
		// Both methods are registered up front because x/crypto/ssh
		// snapshots its config before the handshake. Their callbacks
		// park until the page supplies a credential, and each declines
		// unless it is the kind the page chose -- x/crypto records a
		// declining method's error and moves on to the next.
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(s.publicKeysCallback),
			ssh.PasswordCallback(s.passwordCallback),
		},
		HostKeyCallback: s.hostKeyCallback,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(s.conn, "wosh-tunnel:22", cfg)
	if err != nil {
		s.fail("ssh: " + err.Error())
		return
	}
	s.mu.Lock()
	s.client = ssh.NewClient(sshConn, chans, reqs)
	client := s.client
	s.mu.Unlock()

	sess, err := client.NewSession()
	if err != nil {
		s.fail("open session channel: " + err.Error())
		return
	}
	s.mu.Lock()
	s.sshSess = sess
	s.mu.Unlock()
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		s.fail("stdin pipe: " + err.Error())
		return
	}
	sess.Stdout = &s.out
	sess.Stderr = &s.out

	s.mu.Lock()
	cols, rows := s.cols, s.rows
	s.mu.Unlock()
	if err := sess.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		s.fail("pty request: " + err.Error())
		return
	}
	if err := sess.Shell(); err != nil {
		s.fail("shell request: " + err.Error())
		return
	}

	// Take the live pipe, then flush anything typed before it existed.
	s.mu.Lock()
	s.stdinPipe = stdin
	s.mu.Unlock()
	if buffered := s.pendingIn.drain(); len(buffered) > 0 {
		_, _ = stdin.Write(buffered)
	}

	s.setState(stateReady, "")
	select {
	case s.authOutcome <- nil:
	default:
	}

	waitErr := sess.Wait()
	code := int32(0)
	_, isExit := waitErr.(*ssh.ExitError)
	if ee, ok := waitErr.(*ssh.ExitError); ok {
		code = int32(ee.ExitStatus())
	}
	s.mu.Lock()
	s.exited = true
	if waitErr == nil || isExit {
		s.exitCode = &code
	}
	s.mu.Unlock()
	s.setState(stateClosed, "shell exited")
}

func (s *Session) hostKeyCallback(_ string, _ net.Addr, key ssh.PublicKey) error {
	s.mu.Lock()
	s.hostFP = ssh.FingerprintSHA256(key)
	s.state = stateHostKeyCheck
	s.mu.Unlock()

	accepted, ok := <-s.hostKeyDecision // parks the handshake here
	if !ok || !accepted {
		return fmt.Errorf("host key rejected by the user")
	}
	s.setState(stateAuthenticating, "")
	return nil
}

// waitCreds parks until the page supplies a credential.
func (s *Session) waitCreds() credential {
	<-s.credsReady
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creds
}

func (s *Session) passwordCallback() (string, error) {
	c := s.waitCreds()
	if c.kind != "password" {
		return "", fmt.Errorf("password auth not selected")
	}
	return c.password, nil
}

func (s *Session) publicKeysCallback() ([]ssh.Signer, error) {
	c := s.waitCreds()
	if c.kind != "publickey" {
		return nil, fmt.Errorf("publickey auth not selected")
	}
	signer, err := browserSigner()
	if err != nil {
		return nil, err
	}
	return []ssh.Signer{signer}, nil
}

// supplyCreds latches a credential and releases the parked auth
// callbacks. It RETURNS IMMEDIATELY; the caller polls `status` until
// `ready` or `closed`.
//
// Returning promptly is a hard requirement, not a style choice. An
// async-lifted export must never block on a Go channel: componentize-go
// ends a task the moment the guest is idle with nothing pending IN THAT
// TASK, and the ssh goroutines legitimately reach points where they
// park on language-level primitives with no Component-Model waitable
// outstanding. An export blocked on a channel at that instant is
// declared complete without ever calling task-return, which surfaces as
// "async-lifted export failed to produce a result". The keepalive task
// keeps BACKGROUND goroutines running; it cannot rescue a blocked
// export closure, because the exit decision is per-task.
func (s *Session) supplyCreds(c credential) witTypes.Result[witTypes.Unit, string] {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state == stateConnecting || state == stateHostKeyCheck {
		return witTypes.Err[witTypes.Unit, string](
			"the host key fingerprint has not been confirmed yet -- credentials are never " +
				"sent to an unapproved server")
	}

	s.mu.Lock()
	s.creds = c
	s.mu.Unlock()
	s.credsOnce.Do(func() { close(s.credsReady) })
	runtime.Gosched()
	return witTypes.Ok[witTypes.Unit, string](witTypes.Unit{})
}

func (s *Session) AuthenticatePassword(password string) witTypes.Result[witTypes.Unit, string] {
	return s.supplyCreds(credential{kind: "password", password: password})
}

func (s *Session) AuthenticatePublickey() witTypes.Result[witTypes.Unit, string] {
	return s.supplyCreds(credential{kind: "publickey"})
}

func (s *Session) OnDrop() {
	s.decisionOnce.Do(func() { close(s.hostKeyDecision) })
	s.credsOnce.Do(func() { close(s.credsReady) })
	s.mu.Lock()
	client, conn := s.client, s.conn
	s.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
}

// --- exported methods ------------------------------------------------

func (s *Session) Status() types.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case stateHostKeyCheck:
		return types.MakeStatusHostKeyCheck()
	case stateAuthenticating:
		return types.MakeStatusAuthenticating()
	case stateReady:
		return types.MakeStatusReady()
	case stateClosed:
		return types.MakeStatusClosed(s.closeMsg)
	default:
		return types.MakeStatusConnecting()
	}
}

func (s *Session) HostKeyFingerprint() witTypes.Option[string] {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hostFP == "" {
		return witTypes.None[string]()
	}
	return witTypes.Some(s.hostFP)
}

func (s *Session) ConfirmHostKey(accept bool) {
	s.decisionOnce.Do(func() {
		s.hostKeyDecision <- accept // buffered: never blocks this export
		close(s.hostKeyDecision)
	})
	runtime.Gosched()
}

func (s *Session) WriteInput(data []uint8) {
	// Clone: the bindings hand over a zero-copy view of transferred
	// cabi memory that is recycled once this export returns.
	cp := make([]byte, len(data))
	copy(cp, data)

	s.mu.Lock()
	pipe := s.stdinPipe
	s.mu.Unlock()
	if pipe != nil {
		_, _ = pipe.Write(cp)
	} else {
		s.pendingIn.Write(cp)
	}
	runtime.Gosched()
}

func (s *Session) Resize(cols uint16, rows uint16) {
	s.mu.Lock()
	s.cols, s.rows = cols, rows
	sess := s.sshSess
	s.mu.Unlock()
	if sess != nil {
		_ = sess.WindowChange(int(rows), int(cols))
	}
	runtime.Gosched()
}

func (s *Session) DrainOutput() []uint8 {
	runtime.Gosched()
	return s.out.drain()
}

func (s *Session) Exited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exited || s.state == stateClosed
}

func (s *Session) ExitStatus() witTypes.Option[int32] {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exitCode == nil {
		return witTypes.None[int32]()
	}
	return witTypes.Some(*s.exitCode)
}

func (s *Session) Detach() {
	s.OnDrop()
	s.setState(stateClosed, "detached")
	runtime.Gosched()
}

// lockedBuf is a mutex-guarded byte buffer. Goroutines can yield
// mid-method under wasm (allocation and GC safepoints are yield
// points), and an unguarded buffer tears when the pty writer and the
// page's drain race -- an observed bug class in this component family,
// not a theoretical one.
type lockedBuf struct {
	mu  sync.Mutex
	buf []byte
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *lockedBuf) drain() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return nil
	}
	out := b.buf
	b.buf = nil
	return out
}
