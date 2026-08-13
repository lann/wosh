package core

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

// gosched gives parked-but-runnable goroutines bounded scheduler
// rounds. Under wasm's cooperative single-threaded scheduler this is
// deterministic: each round runs every runnable goroutine to its next
// park point, so a state change published by an export is observable
// by the time that export returns. On the host (unit tests) it is a
// hint only -- real preemption does the work, and the tests poll with
// deadlines rather than assuming a fixed number of rounds.
func gosched(rounds int) {
	for i := 0; i < rounds; i++ {
		runtime.Gosched()
	}
}

// shuttleConn is the sans-I/O net.Conn the ssh stack blocks on: Read
// parks the calling goroutine until push() feeds bytes (or the conn is
// broken/closed); Write appends to an outbox the embedder drains.
//
// The old engine relied on wasm's cooperative scheduling to make the
// check-then-park sequence race-free (no yield point between the
// buffer check and the channel receive). This version takes an
// explicit mutex instead, because the same code runs under `go test`
// on the host where preemption is real. The wake channel is
// 1-buffered and signalled without blocking, so a push landing between
// the unlock and the receive leaves a token behind and cannot be lost.
type shuttleConn struct {
	mu     sync.Mutex
	inbox  bytes.Buffer
	outbox bytes.Buffer
	closed bool
	err    error         // set by breakWire: what Read returns once drained
	wake   chan struct{} // 1-buffered read wakeup
}

func newShuttleConn() *shuttleConn {
	return &shuttleConn{wake: make(chan struct{}, 1)}
}

func (c *shuttleConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.inbox.Len() > 0 {
			n, err := c.inbox.Read(b)
			c.mu.Unlock()
			return n, err
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.mu.Unlock()
		<-c.wake // parks across export calls
	}
}

func (c *shuttleConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.err != nil {
		return 0, fmt.Errorf("shuttle conn closed")
	}
	return c.outbox.Write(b)
}

func (c *shuttleConn) push(data []byte) {
	c.mu.Lock()
	if !c.closed && c.err == nil {
		c.inbox.Write(data)
	}
	c.mu.Unlock()
	c.signal()
}

func (c *shuttleConn) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *shuttleConn) drainOutbox() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outbox.Len() == 0 {
		return nil
	}
	out := make([]byte, c.outbox.Len())
	_, _ = c.outbox.Read(out)
	return out
}

// breakWire makes every subsequent Read fail, which is how the ssh
// stack learns the transport is gone: it unwinds NewClientConn / the
// mux read loop with that error instead of parking forever. Bytes
// already fed are deliberately discarded -- the wire is dead, and a
// half-packet would only produce a less legible failure.
func (c *shuttleConn) breakWire(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		c.inbox.Reset()
	}
	c.mu.Unlock()
	c.signal()
}

func (c *shuttleConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
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

// lockedBuf is a mutex-guarded byte buffer. Goroutines can yield
// mid-method even under wasm (allocation and GC safepoints are yield
// points), and an unguarded buffer tears when the pty writer and the
// embedder's drain race -- an observed bug class in this component
// family, not a theoretical one.
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
