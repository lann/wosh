package mosh

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Client is a mosh client. It connects to a mosh server over UDP,
// handles the SSP transport, and provides send/recv for terminal I/O.
type Client struct {
	conn      Conn
	transport *Transport
	ocb       *OCB

	mu      sync.Mutex
	output  []byte // accumulated terminal output
	outputC chan struct{}

	// Action tracking for cumulative diffs.
	actionsMu        sync.Mutex
	actions          []UserInstruction
	ackedActionCount int  // actions the server has definitely applied
	inFlightCovers   int  // len(actions) covered by the pending diff
	inFlight         bool // a diff is pending in the transport
	dirty            bool // true = new actions since last tick

	done chan struct{}
	wg   sync.WaitGroup
}

// Dial connects to a mosh server over UDP. The key is the base64-encoded
// mosh key (with or without padding).
func Dial(host string, port int, key string) (*Client, error) {
	// Pad key for base64 if needed.
	for len(key)%4 != 0 {
		key += "="
	}
	rawKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("mosh: bad key: %w", err)
	}

	ocb, err := NewOCB(rawKey)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	})
	if err != nil {
		return nil, err
	}

	return DialConn(conn, ocb)
}

// DialConn creates a mosh client over an existing datagram connection.
// Use this with WebTransport or other non-UDP transports.
func DialConn(conn Conn, ocb *OCB) (*Client, error) {
	c := &Client{
		conn:             conn,
		transport:        NewTransport(ocb, false),
		ocb:              ocb,
		outputC:          make(chan struct{}, 1),
		done:             make(chan struct{}),
	}

	c.wg.Add(2)
	go c.recvLoop()
	go c.sendLoop()

	// Send initial keepalive to associate with the server.
	c.transport.ForceNextSend()
	c.tick()

	return c, nil
}

// DialConnManual creates a mosh client without an internal sendLoop.
// The caller must call Tick() periodically (e.g., every 8-16ms) to flush
// outgoing datagrams. Use this in WASM where Go timers are unreliable.
func DialConnManual(conn Conn, ocb *OCB) (*Client, error) {
	c := &Client{
		conn:             conn,
		transport:        NewTransport(ocb, false),
		ocb:              ocb,
		outputC:          make(chan struct{}, 1),
		done:             make(chan struct{}),
	}

	c.wg.Add(1)
	go c.recvLoop()

	// Send initial keepalive to associate with the server.
	c.transport.ForceNextSend()
	c.tick()

	return c, nil
}

// DialConnRaw creates a mosh client with no internal goroutines.
// The caller must call Tick() for sending AND RecvRaw() for receiving.
// Use this when the caller needs raw transport diffs (e.g., for
// framebuffer state tracking in the WASM client).
func DialConnRaw(conn Conn, ocb *OCB) (*Client, error) {
	return DialConnRawSeq(conn, ocb, 0)
}

// DialConnRawSeq is DialConnRaw with an initial crypto-layer sequence:
// the first datagram is sent with initialSeq+1. Reattach flows pass a
// persisted floor (plus margin) so a fresh client never reuses a
// sequence the server has already seen under this key — the sequence
// must be set before the association datagram below, or the first
// send would burn a low (possibly replayed) nonce.
//
// A non-zero initialSeq also enables resume adoption: SSP state
// numbering is learned from the first instruction the server sends
// (Transport.EnableResumeAdopt) — a fresh process cannot know the
// server's retained-state window, and unlike the crypto sequence it
// does not need to be persisted, because the server's view is frozen
// while no client is attached.
func DialConnRawSeq(conn Conn, ocb *OCB, initialSeq uint64) (*Client, error) {
	c := &Client{
		conn:      conn,
		transport: NewTransport(ocb, false),
		ocb:       ocb,
		outputC:   make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	c.transport.SetSeqOut(initialSeq)
	if initialSeq > 0 {
		c.transport.EnableResumeAdopt()
	}

	c.transport.ForceNextSend()
	c.tick()

	return c, nil
}

// RecvRaw reads one datagram from the connection and processes it
// through the transport. Returns the raw diff payload, or nil if
// no complete message was received (timeout, fragment, replay).
// The caller can use Transport().LastRecvOldNum()/LastRecvNewNum()
// to get the state numbers for this diff.
func (c *Client) RecvRaw(timeout time.Duration) []byte {
	buf := make([]byte, maxPayload+64)

	c.conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil
	}
	if n < minDatagram {
		return nil
	}

	data := make([]byte, n)
	copy(data, buf[:n])
	return c.transport.Recv(data)
}

// Send sends keystrokes to the server.
func (c *Client) Send(keys []byte) {
	c.actionsMu.Lock()
	c.actions = append(c.actions, UserInstruction{Keys: append([]byte{}, keys...)})
	c.dirty = true
	c.actionsMu.Unlock()
}

// Resize sends a resize to the server.
func (c *Client) Resize(cols, rows uint16) {
	c.actionsMu.Lock()
	c.actions = append(c.actions, UserInstruction{Width: int32(cols), Height: int32(rows)})
	c.dirty = true
	c.actionsMu.Unlock()
}


// Recv reads accumulated terminal output, blocking until output is available
// or the timeout expires. Returns nil on timeout.
func (c *Client) Recv(timeout time.Duration) []byte {
	// Check if output is already available.
	c.mu.Lock()
	if len(c.output) > 0 {
		out := c.output
		c.output = nil
		c.mu.Unlock()
		return out
	}
	c.mu.Unlock()

	// Wait for output or timeout.
	select {
	case <-c.outputC:
	case <-time.After(timeout):
		return nil
	case <-c.done:
		return nil
	}

	c.mu.Lock()
	out := c.output
	c.output = nil
	c.mu.Unlock()
	return out
}

// Close shuts down the client.
func (c *Client) Close() {
	select {
	case <-c.done:
		return
	default:
		close(c.done)
	}
	c.conn.Close()
	c.wg.Wait()
}

// Transport returns the underlying SSP transport for advanced use
// (e.g., capability negotiation).
func (c *Client) Transport() *Transport {
	return c.transport
}

// Tick flushes pending actions as mosh datagrams. Call this periodically
// from an external timer (e.g., JS setInterval in WASM) when the internal
// sendLoop is not used.
func (c *Client) Tick() {
	c.tick()
}

func (c *Client) tick() {
	// At most one unacked state in flight (matches the Dart mosh
	// client): keystrokes accumulate until the ack arrives, then the
	// next tick sends them all as a single new state. The transport
	// clears its pending diff exactly when the state carrying it is
	// acked — advance the action base then, and only then. (Keying
	// this off state numbers breaks when resume adoption moves them;
	// the pending-diff lifecycle is number-agnostic.)
	c.actionsMu.Lock()
	if c.inFlight && !c.transport.HasPending() {
		c.ackedActionCount = c.inFlightCovers
		c.inFlight = false
	}
	if c.dirty && !c.inFlight && c.transport.AckedByRemote() >= c.transport.SentNum() {
		c.dirty = false
		newActions := c.actions[c.ackedActionCount:]
		c.transport.SetPending(MarshalUserMessage(newActions))
		c.inFlight = true
		c.inFlightCovers = len(c.actions)
	}
	c.actionsMu.Unlock()

	for _, dg := range c.transport.Tick() {
		c.conn.Write(dg)
	}
}

func (c *Client) recvLoop() {
	defer c.wg.Done()
	buf := make([]byte, maxPayload+64)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := c.conn.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			return
		}
		if n < minDatagram {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		diff := c.transport.Recv(data)
		if diff == nil {
			continue
		}

		instrs, err := UnmarshalHostMessage(diff)
		if err != nil || len(instrs) == 0 {
			continue
		}

		var output []byte
		for _, hi := range instrs {
			output = append(output, hi.Hoststring...)
		}
		if len(output) == 0 {
			continue
		}

		c.mu.Lock()
		c.output = append(c.output, output...)
		c.mu.Unlock()

		select {
		case c.outputC <- struct{}{}:
		default:
		}
	}
}

func (c *Client) sendLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.tick()
		}
	}
}
