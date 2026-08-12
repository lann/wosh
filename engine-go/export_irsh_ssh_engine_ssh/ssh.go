// Package export_irsh_ssh_engine_ssh implements the irsh:ssh-engine/ssh
// export: x/crypto/ssh (Go's well-vetted, widely production-used SSH
// client) as a fully synchronous, sans-I/O component export. This
// mirrors wosh's own M7 ssh engine shape almost exactly (see that
// project's README findings 22-23): the blocking ssh stack runs on
// goroutines parked on an in-memory conn, every export returns
// promptly, and the host drives progress by feeding bytes and running
// bounded scheduler rounds on a tick cadence. x/crypto/ssh's client
// path (NewClientConn, mux, session, exec/shell) is timer-free, so no
// wall-time coupling exists beyond the peer's own responses.
//
// Extension over wosh's M7 scope: a full interactive pty + shell
// (RequestPty + Shell + WindowChange), not a single non-interactive
// exec. Deliberately still v0-scoped: password auth only (see the
// project README for why publickey-via-WebCrypto is a follow-up, not
// implemented here) and one shell per session.
package export_irsh_ssh_engine_ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	witTypes "go.bytecodealliance.org/pkg/wit/types"

	"golang.org/x/crypto/ssh"

	types "wit_component/irsh_ssh_engine_ssh"
)

// gosched gives parked-but-runnable goroutines bounded scheduler
// rounds. Cooperative single-threaded scheduling (wasm) means this is
// deterministic: each round runs every runnable goroutine to its next
// park point. Mirrors wosh's engine-go exactly (proven at M0/M7).
func gosched(rounds int) {
	for i := 0; i < rounds; i++ {
		runtime.Gosched()
	}
}

// shuttleConn is the sans-I/O net.Conn the ssh stack blocks on. Read
// parks the calling goroutine until push() feeds bytes (or Close);
// Write appends to an outbox the host drains. Single-threaded
// cooperative scheduling makes the check-then-park race-free: there is
// no yield point between the buffer check and the channel receive.
type shuttleConn struct {
	inbox  bytes.Buffer
	outbox bytes.Buffer
	closed bool
	wake   chan struct{} // 1-buffered read wakeup
}

func newShuttleConn() *shuttleConn {
	return &shuttleConn{wake: make(chan struct{}, 1)}
}

func (c *shuttleConn) Read(b []byte) (int, error) {
	for c.inbox.Len() == 0 {
		if c.closed {
			return 0, fmt.Errorf("shuttle conn closed")
		}
		<-c.wake // parks across export calls
	}
	return c.inbox.Read(b)
}

func (c *shuttleConn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("shuttle conn closed")
	}
	return c.outbox.Write(b)
}

func (c *shuttleConn) push(data []byte) {
	c.inbox.Write(data)
	c.signal()
}

func (c *shuttleConn) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *shuttleConn) drainOutbox() []byte {
	if c.outbox.Len() == 0 {
		return nil
	}
	out := make([]byte, c.outbox.Len())
	c.outbox.Read(out)
	return out
}

func (c *shuttleConn) Close() error {
	c.closed = true
	c.signal()
	return nil
}

type shuttleAddr struct{}

func (shuttleAddr) Network() string { return "shuttle" }
func (shuttleAddr) String() string  { return "shuttle" }

func (c *shuttleConn) LocalAddr() net.Addr                { return shuttleAddr{} }
func (c *shuttleConn) RemoteAddr() net.Addr               { return shuttleAddr{} }
func (c *shuttleConn) SetDeadline(t time.Time) error      { return nil }
func (c *shuttleConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *shuttleConn) SetWriteDeadline(t time.Time) error { return nil }

// lockedBuf synchronizes byte accumulation across goroutines. Even
// under wasm's single-threaded scheduler goroutines can yield
// MID-METHOD (allocation -> GC safepoints), and an unguarded
// bytes.Buffer tears -- ledgered as a real wosh M7 bug (a torn exec
// buffer, "lockedBuf" fix). The pty's Stdout/Stderr writers and
// DrainOutput's reader, and the stdin writer and WriteInput's writer,
// each cross exactly that hazard.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) drain() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() == 0 {
		return nil
	}
	out := make([]byte, b.buf.Len())
	b.buf.Read(out)
	return out
}

const (
	stateConnecting = iota
	stateHostKeyCheck
	stateReady
	stateClosed
)

// Session is the exported resource. The generated wit_bindings.go
// requires the handle/pinner fields and the OnDrop hook.
type Session struct {
	handle int32
	pinner runtime.Pinner

	conn     *shuttleConn
	mu       sync.Mutex // guards state/errMsg/exitStatus/exited (set from ssh goroutines, read from exports)
	state    int
	errMsg   string
	hostFP   string // base64 SHA-256, set during kex
	exited   bool
	exitCode *int32

	// The host-key callback goroutine parks here until the embedder
	// rules on the fingerprint; authentication only starts after an
	// accept (x/crypto/ssh authenticates strictly after a successful
	// host-key callback).
	hostKeyDecision chan bool

	// Deferred password (Authenticate): the config is built with the
	// user but NO password; the embedder grants it while the host-key
	// callback is parked, BEFORE releasing it with accept. See wosh's
	// engine-go for the full rationale (identical shape here).
	password string
	credsSet bool

	cols, rows uint16 // pty size at connect; Resize updates it live

	// resizeLive is set once the shell's session exists, wrapping its
	// WindowChange call; nil before then (Resize just updates
	// cols/rows for the eventual RequestPty).
	resizeMu   sync.Mutex
	resizeLive func(cols, rows uint16)

	client *ssh.Client

	stdin      *lockedBuf // WriteInput appends here until the pipe is up
	stdinPipe  stdinWriter
	stdinReady bool
	ptyOut     lockedBuf // pty stdout+stderr, interleaved
}

// stdinWriter is set once the shell's stdin pipe exists; WriteInput
// flushes anything buffered in `stdin` into it at that point, then
// writes straight through.
type stdinWriter interface {
	Write(p []byte) (int, error)
}

func (s *Session) setState(state int, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	if errMsg != "" {
		s.errMsg = errMsg
	}
}

func (s *Session) getState() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.errMsg
}

// SessionConnect backs `connect: static func(user, cols, rows)`
// (password deferred -- see Authenticate). Spawns the handshake
// goroutine and returns immediately; progress happens on feed/pump.
func SessionConnect(user string, cols uint16, rows uint16) *Session {
	s := &Session{
		conn:            newShuttleConn(),
		state:           stateConnecting,
		hostKeyDecision: make(chan bool),
		stdin:           &lockedBuf{},
		cols:            cols,
		rows:            rows,
	}
	// Clone: the bindings pass a zero-copy view over transferred cabi
	// memory, and the handshake reads it well after this export
	// returns (recycled-buffer corruption otherwise).
	user = strings.Clone(user)
	go func() {
		cfg := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
				s.mu.Lock()
				set, pw := s.credsSet, s.password
				s.mu.Unlock()
				if !set {
					return "", fmt.Errorf("host key accepted without credentials (authenticate was never called)")
				}
				return pw, nil
			})},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				sum := sha256.Sum256(key.Marshal())
				s.mu.Lock()
				s.hostFP = base64.StdEncoding.EncodeToString(sum[:])
				s.state = stateHostKeyCheck
				s.mu.Unlock()
				if <-s.hostKeyDecision { // parks until host-key-decision
					s.setState(stateConnecting, "")
					return nil
				}
				return fmt.Errorf("host key rejected by client policy")
			},
		}
		conn, chans, reqs, err := ssh.NewClientConn(s.conn, "forwarded:22", cfg)
		if err != nil {
			s.setState(stateClosed, err.Error())
			return
		}
		s.client = ssh.NewClient(conn, chans, reqs)

		// Authenticated: open the interactive session in the SAME
		// goroutine, immediately -- no separate trigger needed, the
		// caller only ever wanted one shell per session.
		sess, err := s.client.NewSession()
		if err != nil {
			s.setState(stateClosed, fmt.Sprintf("new session: %v", err))
			return
		}
		defer sess.Close()

		stdin, err := sess.StdinPipe()
		if err != nil {
			s.setState(stateClosed, fmt.Sprintf("stdin pipe: %v", err))
			return
		}
		sess.Stdout = &s.ptyOut
		sess.Stderr = &s.ptyOut

		s.mu.Lock()
		rows, cols := s.rows, s.cols
		s.mu.Unlock()
		if err := sess.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{}); err != nil {
			s.setState(stateClosed, fmt.Sprintf("pty request: %v", err))
			return
		}
		if err := sess.Shell(); err != nil {
			s.setState(stateClosed, fmt.Sprintf("shell request: %v", err))
			return
		}

		// Live resizes from here on ride the session directly.
		s.resizeMu.Lock()
		s.resizeLive = func(cols, rows uint16) {
			_ = sess.WindowChange(int(rows), int(cols))
		}
		s.resizeMu.Unlock()

		// Flush anything WriteInput buffered before the pipe existed,
		// then hand future WriteInput calls the live pipe directly.
		s.mu.Lock()
		buffered := s.stdin.drain()
		s.stdinPipe = stdin
		s.stdinReady = true
		s.mu.Unlock()
		if len(buffered) > 0 {
			_, _ = stdin.Write(buffered)
		}

		s.setState(stateReady, "")

		waitErr := sess.Wait() // parks until the shell exits
		code := int32(0)
		if waitErr != nil {
			var exitErr *ssh.ExitError
			if ee, ok := waitErr.(*ssh.ExitError); ok {
				exitErr = ee
				code = int32(exitErr.ExitStatus())
			}
			// A non-ExitError failure (connection drop mid-session)
			// still marks exited, with no recoverable exit code.
		}
		s.mu.Lock()
		s.exited = true
		if waitErr == nil {
			s.exitCode = &code
		} else if _, ok := waitErr.(*ssh.ExitError); ok {
			s.exitCode = &code
		}
		s.mu.Unlock()
		s.setState(stateClosed, "shell exited")
	}()
	gosched(8) // let the goroutine emit the client version banner
	return s
}

// Authenticate grants the deferred password. Called while the
// host-key callback is parked, before HostKeyDecision(true) releases
// it -- nothing here yields, so the handshake goroutine cannot
// observe a half-set state.
//
// The string MUST be cloned: the generated bindings pass a zero-copy
// view over transferred cabi memory that gets recycled well before
// the handshake goroutine reads it otherwise.
func (s *Session) Authenticate(password string) {
	s.mu.Lock()
	s.password = strings.Clone(password)
	s.credsSet = true
	s.mu.Unlock()
}

func (s *Session) Feed(data []uint8) {
	// Clone: retained across the export boundary by the shuttle's
	// inbox buffer, read well after this call returns.
	cp := make([]byte, len(data))
	copy(cp, data)
	s.conn.push(cp)
	gosched(16)
}

func (s *Session) Drain() []uint8 {
	gosched(4)
	return s.conn.drainOutbox()
}

func (s *Session) Pump() {
	gosched(16)
}

func (s *Session) Status() types.Status {
	state, errMsg := s.getState()
	switch state {
	case stateHostKeyCheck:
		return types.MakeStatusHostKeyCheck()
	case stateReady:
		return types.MakeStatusReady()
	case stateClosed:
		return types.MakeStatusClosed(errMsg)
	default:
		return types.MakeStatusConnecting()
	}
}

func (s *Session) HostKeySha256() witTypes.Option[string] {
	s.mu.Lock()
	fp := s.hostFP
	s.mu.Unlock()
	if fp == "" {
		return witTypes.None[string]()
	}
	return witTypes.Some(fp)
}

func (s *Session) HostKeyDecision(accept bool) {
	state, _ := s.getState()
	if state != stateHostKeyCheck {
		return
	}
	s.hostKeyDecision <- accept // handoff to the parked callback
	gosched(16)
}

// WriteInput queues keystrokes/pasted bytes for the remote shell's
// stdin. Safe to call before the pipe exists (buffered and flushed
// once the shell comes up); the clone matters for the same reason as
// Feed/Authenticate.
func (s *Session) WriteInput(data []uint8) {
	cp := make([]byte, len(data))
	copy(cp, data)

	s.mu.Lock()
	ready, pipe := s.stdinReady, s.stdinPipe
	s.mu.Unlock()

	if ready && pipe != nil {
		_, _ = pipe.Write(cp)
	} else {
		s.stdin.Write(cp)
	}
	gosched(8)
}

func (s *Session) DrainOutput() []uint8 {
	gosched(4)
	return s.ptyOut.drain()
}

// Resize propagates a terminal resize as an SSH window-change request.
// Before the shell exists this just updates the size RequestPty will
// use; once ready, resizeLive (set by the connect goroutine right
// after Shell()) sends window-change on the live session.
func (s *Session) Resize(cols uint16, rows uint16) {
	s.mu.Lock()
	s.cols, s.rows = cols, rows
	s.mu.Unlock()

	s.resizeMu.Lock()
	fn := s.resizeLive
	s.resizeMu.Unlock()
	if fn != nil {
		fn(cols, rows)
	}
	gosched(4)
}

func (s *Session) Exited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exited
}

func (s *Session) ExitStatus() witTypes.Option[int32] {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exitCode == nil {
		return witTypes.None[int32]()
	}
	return witTypes.Some(*s.exitCode)
}

func (s *Session) OnDrop() {
	if s.client != nil {
		s.client.Close()
	}
	s.conn.Close()
	// Give the ssh goroutines a chance to observe the close and
	// unwind (they park forever otherwise -- harmless, but tidy).
	gosched(8)
}
