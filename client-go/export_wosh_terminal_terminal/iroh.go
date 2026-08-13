package export_wosh_terminal_terminal

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"wit_component/connstring"
	endpoint "wit_component/polymorph_iroh_endpoint"
	identityGen "wit_component/polymorph_iroh_identity_generate"
	irohTypes "wit_component/polymorph_iroh_types"
)

// alpn must match the listener's.
const alpn = "wosh/1"

// The connstring format lives in its own WIT-free package so the
// format's decoder tests run on the host (`go test ./connstring`),
// against the same golden bytes the Rust crate pins.
type ConnString = connstring.ConnString

// ParseConnString decodes the base64url pairing blob (versions 1
// and 2); see the connstring package for the wire format.
func ParseConnString(s string) (*ConnString, error) {
	return connstring.Parse(s)
}

// irohConn adapts an iroh bidirectional stream to net.Conn, which is
// all x/crypto/ssh needs. Read and Write map onto the endpoint's async
// WIT methods, which componentize-go presents as blocking Go calls, so
// the ssh stack blocks on the network exactly as it would over TCP.
type irohConn struct {
	conn *endpoint.Connection
	send *endpoint.SendStream
	recv *endpoint.RecvStream

	readMu sync.Mutex
	buf    []byte // bytes read past what the last Read asked for

	closeOnce sync.Once
}

// dial performs the whole outbound path: mint an identity, bind an
// endpoint on the connstring's relay, connect to the peer by public
// key, open the tunnel stream, and present the pairing token.
func dial(cs *ConnString) (*irohConn, error) {
	idRes := identityGen.Generate()
	if idRes.IsErr() {
		return nil, fmt.Errorf("iroh identity: %v", idRes.Err())
	}

	opts := endpoint.MakeEndpointOptions(idRes.Ok())
	opts.AddAlpn([]byte(alpn))
	opts.RelayUrl(cs.RelayURL)
	// No udp-bind-addr: a browser has no direct UDP path, and the
	// wasi:sockets providers there are fail-on-call stubs. WebRTC is
	// the only upgrade off the relay available to us, and the listener
	// answers that signaling.
	opts.Webrtc(true)

	epRes := endpoint.EndpointBind(opts)
	if epRes.IsErr() {
		return nil, fmt.Errorf("iroh bind: %v", epRes.Err())
	}

	addr := irohTypes.EndpointAddr{
		EndpointId: cs.PubKey,
		Addrs: []irohTypes.TransportAddr{
			irohTypes.MakeTransportAddrRelay(cs.RelayURL),
			irohTypes.MakeTransportAddrWebrtc(cs.RelayURL),
		},
	}
	connRes := epRes.Ok().Connect(addr, []byte(alpn))
	if connRes.IsErr() {
		return nil, fmt.Errorf("iroh connect: %v", connRes.Err())
	}
	conn := connRes.Ok()

	biRes := conn.OpenBi()
	if biRes.IsErr() {
		return nil, fmt.Errorf("iroh open-bi: %v", biRes.Err())
	}

	c := &irohConn{conn: conn, send: biRes.Ok().F0, recv: biRes.Ok().F1}

	// The pairing frame: [len:u8][token]. Everything after it on this
	// stream is the raw SSH byte stream. A rejected token means the
	// listener drops the connection, which surfaces as the ssh
	// handshake seeing the stream end.
	hello := append([]byte{byte(len(cs.Token))}, cs.Token...)
	if w := c.send.Write(hello); w.IsErr() {
		return nil, fmt.Errorf("pairing: %v", w.Err())
	}
	return c, nil
}

func (c *irohConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.buf) == 0 {
		r := c.recv.Read(uint32(len(p)))
		if r.IsErr() {
			return 0, fmt.Errorf("iroh read: %v", r.Err())
		}
		chunk := r.Ok()
		if chunk.IsNone() {
			return 0, io.EOF // the peer's FIN: the only clean end
		}
		c.buf = append(c.buf, chunk.Some()...)
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *irohConn) Write(p []byte) (int, error) {
	// Copy: the write crosses the component boundary and the ssh stack
	// reuses its packet buffers immediately afterwards.
	cp := make([]byte, len(p))
	copy(cp, p)
	if w := c.send.Write(cp); w.IsErr() {
		return 0, fmt.Errorf("iroh write: %v", w.Err())
	}
	return len(p), nil
}

func (c *irohConn) Close() error {
	c.closeOnce.Do(func() {
		c.conn.Close(0, "wosh session over")
		// Close-then-await: a bare close races the CONNECTION_CLOSE
		// frame reaching the wire, and the peer would then only learn
		// of the close via idle timeout.
		c.conn.WaitClosed()
	})
	return nil
}

type irohAddr struct{}

func (irohAddr) Network() string { return "iroh" }
func (irohAddr) String() string  { return "wosh-tunnel" }

func (c *irohConn) LocalAddr() net.Addr  { return irohAddr{} }
func (c *irohConn) RemoteAddr() net.Addr { return irohAddr{} }

// Deadlines are unsupported: this transport has no timer surface here,
// and x/crypto/ssh's client path never sets one (its only deadline use
// is in port forwarding, which this client does not do).
func (c *irohConn) SetDeadline(time.Time) error      { return nil }
func (c *irohConn) SetReadDeadline(time.Time) error  { return nil }
func (c *irohConn) SetWriteDeadline(time.Time) error { return nil }
