package core

// The bulk channel plane: long-lived, flow-controlled byte pipes on
// their own SSH channels, opened on the same authenticated connection
// as the interactive session. SFTP is why this exists, but nothing
// here knows that -- this end moves bytes and applies backpressure,
// exactly as the tunnel below it moves bytes without looking inside
// the SSH stream.
//
// The probe plane (session.go) is the precedent: a second channel via
// client.NewSession(), work on a goroutine that parks on the shared
// shuttle conn, every entry point returning promptly. A probe asks one
// question and hands back a capped answer; a bulk channel streams for
// as long as the transfer lasts, which is the whole reason the
// buffering below is bounded in both directions rather than simply
// accumulating the way ProbeResult.Output does.

import (
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ChannelState enumerates the readable bulk-channel states; it maps
// 1:1 onto the `channel-state` variant in wit/core.wit.
type ChannelState int

const (
	// ChannelOpen: both directions live.
	ChannelOpen ChannelState = iota
	// ChannelEOF: the REMOTE sent EOF and will produce no more
	// bytes. Anything already buffered here is still drainable --
	// see the sticky-eof note on markEOF.
	ChannelEOF
	// ChannelClosed: terminal. Buffers are discarded and the state
	// never changes again.
	ChannelClosed
)

// channelReadAheadCap bounds the inbound bytes ONE bulk channel holds
// for the embedder. While the buffer is at the cap this core stops
// reading from the ssh.Channel entirely; x/crypto only issues a window
// adjustment for bytes actually read, so the server's window closes
// and it stops sending. That is the whole backpressure chain, from the
// embedder's storage back to sshd, with no signal crossing the WIT
// interface.
//
// 256 KiB is chosen against the two numbers that bracket it. Below:
// x/crypto hands over at most one 32 KiB packet per read, so the cap
// must be several packets deep or a transfer stalls waiting for the
// embedder's next tick instead of for the wire -- eight packets of
// slack keeps the pipe busy at a 100 ms embedder cadence. Above:
// x/crypto's own per-channel window is 2 MiB, which is already
// buffered inside the ssh stack whether we like it or not, so making
// OUR buffer large enough to matter beside it would only inflate the
// component's heap without moving the stall point anywhere useful.
// Worst case per channel is therefore this cap plus that window, which
// is bounded -- the property that matters -- rather than minimal.
const channelReadAheadCap = 256 * 1024

// channelWriteAheadCap bounds the outbound bytes one channel accepts
// before `write` starts reporting short. Symmetric with the read-ahead
// cap for the same reason: enough depth that the writer goroutine
// always has a full packet or more to push while the embedder is away,
// small enough that a stalled server cannot grow this heap.
const channelWriteAheadCap = 256 * 1024

// channelReadChunk is the largest single read from the ssh.Channel:
// one maximum SSH packet, so a read never asks for more than the
// stack can hand over in one go.
const channelReadChunk = 32 * 1024

// channelStderrTailCap bounds the stderr diagnostics kept for the
// close message. A bulk channel's stderr is not part of the protocol
// the embedder speaks, but it is often the ONLY legible account of a
// failure (`exec /usr/lib/openssh/sftp-server` on a host without it
// says so on stderr and nowhere else), so a short head of it is worth
// keeping. It must still be READ and discarded past the cap: stderr
// shares the channel's flow-control window in x/crypto, so an unread
// stderr would permanently consume window and eventually wedge the
// data direction too.
const channelStderrTailCap = 8 * 1024

// Channel is one bulk channel. One per `channel` resource.
//
// The two goroutines behind it -- a reader parked on the ssh channel
// and a writer parked on pending outbound bytes -- park on the same
// shuttle conn as every other ssh goroutine in this component, so they
// advance on feed/pump ticks and survive across export calls. Every
// method here returns promptly.
type Channel struct {
	eng *Engine

	mu       sync.Mutex
	state    ChannelState
	closeMsg string

	// inbound is the read-ahead buffer (capped at
	// channelReadAheadCap); outbound is what `write` has accepted but
	// the writer goroutine has not yet pushed (capped at
	// channelWriteAheadCap).
	inbound  []byte
	outbound []byte

	sess  *ssh.Session
	stdin io.WriteCloser // nil until the open request succeeded

	// finishAsked is Finish()'s promise to write no more; finishDone
	// records that the writer goroutine has drained the outbound
	// buffer and sent the SSH EOF.
	finishAsked bool
	finishDone  bool

	stderrTail []byte

	// Wakeups for the two goroutines. 1-buffered and signalled
	// without blocking, the shuttleConn pattern: a signal landing
	// between a state check and the receive leaves a token behind and
	// cannot be lost. Never closed -- the loops re-read state after
	// every wake, so teardown is a signal, not a close.
	readWake  chan struct{}
	writeWake chan struct{}
}

func newChannel(eng *Engine) *Channel {
	return &Channel{
		eng:       eng,
		state:     ChannelOpen,
		readWake:  make(chan struct{}, 1),
		writeWake: make(chan struct{}, 1),
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// --- the engine's entry points ----------------------------------------

// OpenSubsystem backs `session.open-subsystem`: a new channel of the
// same authenticated connection carrying an RFC 4254 s6.5 subsystem,
// no pty, so nothing cooks the bytes.
func (s *Engine) OpenSubsystem(name string) (*Channel, error) {
	return s.openChannel(channelKindSubsystem, name)
}

// OpenExecChannel backs `session.open-exec-channel`: the same, started
// through an `exec` request instead. This is the fallback for an sshd
// with no `Subsystem sftp` line -- OpenSSH's sftp-server speaks its
// protocol on stdin and stdout however it was started, which is what
// `sftp -s` relies on too.
func (s *Engine) OpenExecChannel(command string) (*Channel, error) {
	return s.openChannel(channelKindExec, command)
}

type channelKind int

const (
	channelKindSubsystem channelKind = iota
	channelKindExec
)

func (k channelKind) String() string {
	if k == channelKindSubsystem {
		return "open-subsystem"
	}
	return "open-exec-channel"
}

// openChannel is the shared body of both open entry points.
//
// The result carries only the refusals decidable HERE, without the
// wire: the session is not ready, or the connection is already gone.
// A SERVER's refusal is a round trip away, and this core cannot block
// to hear it -- the reply arrives on a later `feed`, and an export
// that parked waiting for one would violate the interface's promise
// that every call returns promptly. So a server-side refusal surfaces
// later, as `channel-state.closed(reason)`, which is what
// wit/core.wit's `open-subsystem` doc specifies and what its
// `channel-state.open` doc means by "not yet failed", not "granted".
//
// The practical consequence, worth stating where the code lives: a
// channel is born `open` before the server has agreed to anything, so
// "it opened" is not observable on its own. The embedder's move is
// protocol-shaped anyway -- write the first request, and treat the
// reply-or-`closed` race as the verdict.
func (s *Engine) openChannel(kind channelKind, arg string) (*Channel, error) {
	// Clone: the bindings hand over a zero-copy view of transferred
	// cabi memory that is recycled once the export returns, and the
	// open goroutine reads it strictly after that.
	arg = string(append([]byte(nil), arg...))

	s.mu.Lock()
	if s.state != StateReady {
		s.mu.Unlock()
		return nil, fmt.Errorf("%s: session is not ready", kind)
	}
	client := s.client
	if client == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("%s: no ssh connection", kind)
	}
	c := newChannel(s)
	s.channels[c] = struct{}{}
	s.mu.Unlock()

	go c.open(client, kind, arg)
	gosched(16)
	return c, nil
}

// forgetChannel drops a terminal channel from the session's registry
// so a long-lived session that opens many transfers does not
// accumulate them.
func (s *Engine) forgetChannel(c *Channel) {
	s.mu.Lock()
	delete(s.channels, c)
	s.mu.Unlock()
}

// closeAllChannels implements the lifetime rule in `resource
// channel`'s doc: closing or losing the session moves every channel to
// `closed`. It is called from closeWith, the one funnel through which
// this engine goes terminal, so there is no path to a closed session
// with a live channel hanging off it.
//
// The registry snapshot is taken under mu and released before any
// channel is touched: markClosed calls back into forgetChannel, which
// takes the same mutex.
func (s *Engine) closeAllChannels(reason string) {
	s.mu.Lock()
	live := make([]*Channel, 0, len(s.channels))
	for c := range s.channels {
		live = append(live, c)
	}
	s.channels = map[*Channel]struct{}{}
	s.mu.Unlock()

	for _, c := range live {
		c.markClosed(reason)
	}
}

// --- opening ----------------------------------------------------------

// open runs the channel-open round trip on its own goroutine and, if
// it succeeds, becomes the channel's writer for the rest of its life.
// It parks on the shared shuttle conn exactly as the probe goroutine
// does, so it advances on the embedder's feed/pump ticks.
func (c *Channel) open(client *ssh.Client, kind channelKind, arg string) {
	sess, err := client.NewSession()
	if err != nil {
		c.markClosed(fmt.Sprintf("%s: the server refused a new channel: %v", kind, err))
		return
	}

	// Take all three streams as PIPES. That is not cosmetic: with
	// pipes taken, x/crypto adds no copier goroutines of its own
	// (see session.go's stdin/stdout/stderr in x/crypto v0.49.0),
	// which is what leaves this file in charge of when a read
	// happens -- and therefore in charge of the window adjustments
	// that carry backpressure. It also makes the subsystem path work
	// at all: RequestSubsystem never calls the session's start(), so
	// a Stdout set as a plain io.Writer would never be copied to.
	stdin, err := sess.StdinPipe()
	var stdout, stderr io.Reader
	if err == nil {
		stdout, err = sess.StdoutPipe()
	}
	if err == nil {
		stderr, err = sess.StderrPipe()
	}
	if err != nil {
		_ = sess.Close()
		c.markClosed(fmt.Sprintf("%s: %v", kind, err))
		return
	}

	switch kind {
	case channelKindSubsystem:
		err = sess.RequestSubsystem(arg)
		if err != nil {
			// The legible failure the embedder falls back on. An
			// sshd with no matching `Subsystem` line refuses exactly
			// here, and says nothing more about why, so the advice
			// has to come from this side.
			_ = sess.Close()
			c.markClosed(fmt.Sprintf(
				"the server refused the %q subsystem (%v) -- an sshd with no matching "+
					"`Subsystem %s` line refuses here; starting the same server through "+
					"an exec channel reaches it anyway", arg, err, arg))
			return
		}
	default:
		if err = sess.Start(arg); err != nil {
			_ = sess.Close()
			c.markClosed(fmt.Sprintf("the server refused to exec %q: %v", arg, err))
			return
		}
	}

	c.mu.Lock()
	if c.state == ChannelClosed {
		// close() or a session teardown landed while the open was in
		// flight. Cancellation here costs nothing, which is the
		// point of the plane having no futures: drop the session and
		// leave the terminal state alone.
		c.mu.Unlock()
		_ = sess.Close()
		return
	}
	c.sess, c.stdin = sess, stdin
	c.mu.Unlock()

	go c.readLoop(stdout)
	go c.stderrLoop(stderr)
	c.writeLoop(stdin) // this goroutine becomes the writer
}

// --- the reader -------------------------------------------------------

// readLoop is where inbound flow control actually happens. It reads at
// most the room remaining under channelReadAheadCap, and when there is
// no room it PARKS rather than reading: not reading is the signal, and
// read-and-discard would defeat the entire chain by telling x/crypto
// to reopen the window for bytes nobody wanted.
func (c *Channel) readLoop(r io.Reader) {
	scratch := make([]byte, channelReadChunk)
	for {
		room := c.awaitRoom()
		if room == 0 {
			return // terminal
		}
		if room > len(scratch) {
			room = len(scratch)
		}
		n, err := r.Read(scratch[:room])
		if n > 0 {
			c.mu.Lock()
			if c.state == ChannelClosed {
				c.mu.Unlock()
				return
			}
			c.inbound = append(c.inbound, scratch[:n]...)
			c.mu.Unlock()
		}
		if err != nil {
			if err == io.EOF {
				c.markEOF()
			} else {
				c.markClosed("channel read: " + err.Error())
			}
			return
		}
	}
}

// awaitRoom parks until the read-ahead buffer has room (Drain signals
// it) and returns how much, or 0 once the channel is terminal.
func (c *Channel) awaitRoom() int {
	for {
		c.mu.Lock()
		if c.state == ChannelClosed {
			c.mu.Unlock()
			return 0
		}
		if room := channelReadAheadCap - len(c.inbound); room > 0 {
			c.mu.Unlock()
			return room
		}
		c.mu.Unlock()
		<-c.readWake // parks across export calls
	}
}

// stderrLoop keeps a short head of the channel's diagnostics for the
// close message and discards the rest. Discarding is right here and
// wrong for the data direction: stderr is not the protocol the
// embedder speaks, but it does share the channel's flow-control
// window, so leaving it unread would eventually stall the data
// direction as well.
func (c *Channel) stderrLoop(r io.Reader) {
	scratch := make([]byte, 4096)
	for {
		n, err := r.Read(scratch)
		if n > 0 {
			c.mu.Lock()
			if room := channelStderrTailCap - len(c.stderrTail); room > 0 {
				if room > n {
					room = n
				}
				c.stderrTail = append(c.stderrTail, scratch[:room]...)
			}
			c.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// --- the writer -------------------------------------------------------

// writeLoop pushes accepted bytes at whatever pace the far end's
// window allows. It exists so `write` never blocks: a direct write to
// the ssh channel parks once the remote window is exhausted, and an
// export that parks is the one thing this component must not do.
func (c *Channel) writeLoop(stdin io.WriteCloser) {
	for {
		c.mu.Lock()
		if c.state == ChannelClosed {
			c.mu.Unlock()
			return
		}
		if len(c.outbound) == 0 {
			if c.finishAsked && !c.finishDone {
				c.finishDone = true
				c.mu.Unlock()
				// sessionStdin.Close is CloseWrite: an SSH EOF on
				// this channel, leaving the read direction live so
				// the reply tail still arrives.
				_ = stdin.Close()
				continue
			}
			c.mu.Unlock()
			<-c.writeWake // parks across export calls
			continue
		}
		// Take the whole buffer: the write below may park for a long
		// time on the remote window, and freeing the buffer first
		// lets the embedder keep handing over bytes meanwhile, which
		// is what keeps a transfer moving rather than lock-stepping
		// it to the wire.
		chunk := c.outbound
		c.outbound = nil
		c.mu.Unlock()

		if _, err := stdin.Write(chunk); err != nil {
			c.markClosed("channel write: " + err.Error())
			return
		}
	}
}

// --- state transitions -------------------------------------------------

// markEOF records that the remote will produce no more bytes.
//
// It is deliberately STICKY: a channel whose far end has finished
// stays at `eof` and is never promoted to `closed` on its own.
// Promoting would be the trap wit/core.wit's `channel-state` doc calls
// out -- `closed` discards the buffers, so an engine that closed
// itself the moment the remote hung up would eat the tail of every
// reply that arrived faster than the embedder drained it. Only
// close(), a write failure, or losing the session goes terminal.
func (c *Channel) markEOF() {
	c.mu.Lock()
	if c.state == ChannelOpen {
		c.state = ChannelEOF
	}
	c.mu.Unlock()
}

// markClosed is the one way into the terminal state: it latches the
// reason, discards both buffers (per the `closed` variant's doc),
// closes the ssh session so the parked loops unwind, and wakes anyone
// parked on the in-memory gates. Idempotent, because it is reached
// from close(), the resource destructor, a failed open, a dead
// transport, and session teardown alike.
func (c *Channel) markClosed(reason string) {
	c.mu.Lock()
	if c.state == ChannelClosed {
		c.mu.Unlock()
		return
	}
	c.state = ChannelClosed
	// Stderr is usually the only account of why an exec-started
	// helper died, so fold whatever it said into the reason.
	if tail := c.stderrTail; len(tail) > 0 {
		reason = reason + " (stderr: " + string(tail) + ")"
	}
	c.closeMsg = reason
	c.inbound = nil
	c.outbound = nil
	sess := c.sess
	c.sess = nil
	c.mu.Unlock()

	if sess != nil {
		_ = sess.Close()
	}
	signal(c.readWake)
	signal(c.writeWake)
	if c.eng != nil {
		c.eng.forgetChannel(c)
	}
}

// --- the WIT surface ---------------------------------------------------

// Write backs `channel.write`: append to the bounded outbound buffer
// and report how many bytes were ACCEPTED. A short write -- including
// zero -- is the ordinary backpressure signal and is NOT an error; the
// embedder retries the remainder after the next tick.
func (c *Channel) Write(data []byte) (uint32, error) {
	c.mu.Lock()
	if c.state == ChannelClosed {
		msg := c.closeMsg
		c.mu.Unlock()
		return 0, fmt.Errorf("channel is closed: %s", msg)
	}
	// `finish` is a promise to write no more, and wit/core.wit holds
	// the caller to it: the SSH EOF it sends is irrevocable, so bytes
	// handed over afterwards could never reach the far end. Accepting
	// them would report a success that is a lie, and a short write of
	// zero would spin an embedder that reasonably retries. An error
	// is the only honest answer, which is why `write` errors on this
	// as well as on a channel that is no longer `open`.
	if c.finishAsked {
		c.mu.Unlock()
		return 0, fmt.Errorf("channel: finish() already sent EOF; no more bytes can be written")
	}
	room := channelWriteAheadCap - len(c.outbound)
	if room > len(data) {
		room = len(data)
	}
	if room <= 0 {
		c.mu.Unlock()
		return 0, nil
	}
	// Copy: the bindings hand over a zero-copy view of transferred
	// cabi memory that is recycled once the export returns, and the
	// writer goroutine reads it strictly after that.
	c.outbound = append(c.outbound, data[:room]...)
	c.mu.Unlock()

	signal(c.writeWake)
	gosched(4)
	return uint32(room), nil
}

// Drain backs `channel.drain`: up to `max` buffered inbound bytes, in
// order. Empty means nothing is ready RIGHT NOW, never end-of-stream.
//
// Freeing room here is what restarts inbound flow: the reader
// goroutine is parked in awaitRoom whenever the buffer sits at the
// cap, and this is the wake that releases it.
func (c *Channel) Drain(max uint32) []byte {
	gosched(4)

	c.mu.Lock()
	n := len(c.inbound)
	if uint32(n) > max {
		n = int(max)
	}
	if n == 0 {
		c.mu.Unlock()
		return nil
	}
	out := c.inbound[:n:n]
	c.inbound = c.inbound[n:]
	// Reclaim the backing array once it is empty; otherwise a long
	// transfer would keep re-slicing a buffer that only ever grows.
	if len(c.inbound) == 0 {
		c.inbound = nil
	}
	c.mu.Unlock()

	signal(c.readWake)
	return out
}

// State backs `channel.state`; the second result is meaningful only
// for ChannelClosed.
func (c *Channel) State() (ChannelState, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.closeMsg
}

// Finish backs `channel.finish`: promise to write no more, while
// staying open to read what the far end still owes. The EOF is sent by
// the writer goroutine AFTER it has drained whatever `write` already
// accepted -- sending it here would truncate bytes the embedder was
// told had been taken.
//
// A no-op on a channel that is already terminal, per the lifetime rule.
func (c *Channel) Finish() {
	c.mu.Lock()
	if c.state == ChannelClosed {
		c.mu.Unlock()
		return
	}
	c.finishAsked = true
	c.mu.Unlock()

	signal(c.writeWake)
	gosched(8)
}

// Close backs `channel.close` (and the resource destructor): both
// directions, buffers discarded, session untouched.
func (c *Channel) Close() {
	c.markClosed("channel closed")
	gosched(4)
}
