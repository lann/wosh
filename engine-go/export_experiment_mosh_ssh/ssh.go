package export_experiment_mosh_ssh

// The experiment:mosh/ssh implementation: x/crypto/ssh as a fully
// synchronous, sans-I/O component export (M7, workstream F). The
// blocking ssh stack runs on goroutines parked on an in-memory conn;
// finding 22 (sync spike): parked goroutines survive across export
// calls and resume when fed and scheduler-pumped. Every export here
// returns promptly — feed/drain/pump move bytes and run bounded
// scheduler rounds; the ~8 ms tick cadence of the embedder drives
// progress. x/crypto/ssh's client path (NewClientConn, mux, session,
// exec) is timer-free (audited at v0.49.0), so no wall-time coupling
// exists beyond the peer's own responses.

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

	types "wit_component/experiment_mosh_ssh"
)

// gosched gives parked-but-runnable goroutines bounded scheduler
// rounds. Cooperative single-threaded scheduling (wasm) means this is
// deterministic: each round runs every runnable goroutine to its next
// park point.
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

// lockedBuf synchronizes the exec output accumulation. Three
// goroutines touch it: x/crypto's stdout and stderr copiers (Session
// Stdout/Stderr both point here) and the ReadOutput export draining
// it. Even under wasm's single-threaded scheduler goroutines can
// yield MID-METHOD (allocation → GC safepoints), and an unguarded
// bytes.Buffer tears: observed as Len() going negative and truncated
// output racing the exit status.
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

type shuttleAddr struct{}

func (shuttleAddr) Network() string { return "shuttle" }
func (shuttleAddr) String() string  { return "shuttle" }

func (c *shuttleConn) LocalAddr() net.Addr                { return shuttleAddr{} }
func (c *shuttleConn) RemoteAddr() net.Addr               { return shuttleAddr{} }
func (c *shuttleConn) SetDeadline(t time.Time) error      { return nil }
func (c *shuttleConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *shuttleConn) SetWriteDeadline(t time.Time) error { return nil }

const (
	stateConnecting = iota
	stateHostKeyCheck
	stateReady
	stateFailed
)

// SshSession is the exported resource. The generated wit_bindings.go
// requires the handle/pinner fields and the OnDrop hook.
type SshSession struct {
	handle int32
	pinner runtime.Pinner

	conn   *shuttleConn
	state  int
	errMsg string
	hostFP string // base64 SHA-256, set during kex

	// The host-key callback goroutine parks here until the embedder
	// rules on the fingerprint; authentication only starts after an
	// accept (x/crypto/ssh authenticates strictly after a successful
	// host-key callback).
	hostKeyDecision chan bool

	// Deferred password (Authenticate): the config is built with the
	// user but NO password; the embedder grants it while the host-key
	// callback is parked, BEFORE releasing it with accept. The user
	// name must be known up front — NewClientConn snapshots the
	// config by value (fullConf := *config) before the handshake, so
	// late User mutation never reaches the copy — but it is only ever
	// SENT in auth requests, which start strictly after the host-key
	// callback returns. The password flows through the callback
	// closure below, so it IS late-bound: the engine never holds a
	// password while an unapproved key is on the table.
	password string
	credsSet bool

	client *ssh.Client

	execStarted bool
	execOut     lockedBuf
	exitStatus  *int32
}

// SshSessionConnect backs `connect: static func(user)` (password
// deferred — see Authenticate). Spawns the handshake goroutines and
// returns immediately; progress happens on feed/pump.
func SshSessionConnect(user string) *SshSession {
	s := &SshSession{
		conn:            newShuttleConn(),
		state:           stateConnecting,
		hostKeyDecision: make(chan bool),
	}
	// Clone: the bindings pass a zero-copy view over transferred cabi
	// memory, and the handshake reads it well after this export
	// returns (recycled-buffer corruption otherwise).
	user = strings.Clone(user)
	go func() {
		cfg := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
				if !s.credsSet {
					return "", fmt.Errorf("host key accepted without credentials (authenticate was never called)")
				}
				return s.password, nil
			})},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				sum := sha256.Sum256(key.Marshal())
				s.hostFP = base64.StdEncoding.EncodeToString(sum[:])
				s.state = stateHostKeyCheck
				if <-s.hostKeyDecision { // parks until host-key-decision
					s.state = stateConnecting
					return nil
				}
				return fmt.Errorf("host key rejected by client policy")
			},
		}
		c, chans, reqs, err := ssh.NewClientConn(s.conn, "forwarded:22", cfg)
		if err != nil {
			s.state = stateFailed
			s.errMsg = err.Error()
			return
		}
		s.client = ssh.NewClient(c, chans, reqs)
		s.state = stateReady
	}()
	gosched(8) // let the goroutine emit the client version banner
	return s
}

// Authenticate grants the deferred password (password auth v0).
// Called while the host-key callback is parked, before
// HostKeyDecision(true) releases it — nothing here yields, so the
// handshake goroutine cannot observe a half-set state.
//
// The string MUST be cloned: the generated bindings pass a zero-copy
// view over transferred cabi memory, and it outlives this export call
// by many feed/drain rounds (whose allocations recycle that memory —
// observed as auth failures with the correct password).
func (s *SshSession) Authenticate(password string) {
	s.password = strings.Clone(password)
	s.credsSet = true
}

func (s *SshSession) Feed(data []uint8) {
	s.conn.push(data)
	gosched(16)
}

func (s *SshSession) Drain() []uint8 {
	gosched(4)
	return s.conn.drainOutbox()
}

func (s *SshSession) Pump() {
	gosched(16)
}

func (s *SshSession) Status() types.SshStatus {
	switch s.state {
	case stateHostKeyCheck:
		return types.MakeSshStatusHostKeyCheck()
	case stateReady:
		return types.MakeSshStatusReady()
	case stateFailed:
		return types.MakeSshStatusFailed(s.errMsg)
	default:
		return types.MakeSshStatusConnecting()
	}
}

func (s *SshSession) HostKeySha256() witTypes.Option[string] {
	if s.hostFP == "" {
		return witTypes.None[string]()
	}
	return witTypes.Some(s.hostFP)
}

func (s *SshSession) HostKeyDecision(accept bool) {
	if s.state != stateHostKeyCheck {
		return
	}
	s.hostKeyDecision <- accept // handoff to the parked callback
	gosched(16)
}

func (s *SshSession) Exec(command string) witTypes.Result[struct{}, string] {
	if s.state != stateReady {
		return witTypes.Err[struct{}, string]("ssh session is not ready")
	}
	if s.execStarted {
		return witTypes.Err[struct{}, string]("exec already ran on this session (v0: one exec per session)")
	}
	s.execStarted = true
	go func() {
		sess, err := s.client.NewSession()
		if err != nil {
			s.state = stateFailed
			s.errMsg = fmt.Sprintf("new session: %v", err)
			return
		}
		defer sess.Close()
		sess.Stdout = &s.execOut
		sess.Stderr = &s.execOut
		err = sess.Run(command) // parks until the command finishes
		code := int32(0)
		if err != nil {
			var exitErr *ssh.ExitError
			if ok := asExitError(err, &exitErr); ok {
				code = int32(exitErr.ExitStatus())
			} else {
				s.state = stateFailed
				s.errMsg = fmt.Sprintf("exec: %v", err)
				return
			}
		}
		s.exitStatus = &code
	}()
	gosched(8)
	return witTypes.Ok[struct{}, string](struct{}{})
}

func asExitError(err error, target **ssh.ExitError) bool {
	if ee, ok := err.(*ssh.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func (s *SshSession) ReadOutput() []uint8 {
	gosched(4)
	return s.execOut.drain()
}

func (s *SshSession) ExitStatus() witTypes.Option[int32] {
	if s.exitStatus == nil {
		return witTypes.None[int32]()
	}
	return witTypes.Some(*s.exitStatus)
}

func (s *SshSession) OnDrop() {
	if s.client != nil {
		s.client.Close()
	}
	s.conn.Close()
	// Give the ssh goroutines a chance to observe the close and
	// unwind (they park forever otherwise — harmless, but tidy).
	gosched(8)
}
