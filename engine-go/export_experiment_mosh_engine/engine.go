package export_experiment_mosh_engine

// The experiment:mosh/engine implementation: a fully synchronous,
// sans-I/O wrapper around mosh-go's DialConnRaw client. The host owns
// all I/O and time; the engine's only "socket" is memConn, an in-memory
// mailbox the host fills (handle-datagram) and drains (tick).

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	witTypes "go.bytecodealliance.org/pkg/wit/types"

	mosh "github.com/unixshells/mosh-go"

	types "wit_component/experiment_mosh_engine"
)

// memConn implements mosh.Conn without any real I/O. Read pops the
// inbox or fails immediately with a timeout error (DialConnRaw's
// RecvRaw treats any error as "no datagram"); Write appends to the
// outbox, which tick drains. Deadlines are ignored — nothing blocks.
type memConn struct {
	inbox  [][]byte
	outbox [][]byte
}

var errNoDatagram = errors.New("memconn: inbox empty")

func (c *memConn) Read(b []byte) (int, error) {
	if len(c.inbox) == 0 {
		return 0, errNoDatagram
	}
	d := c.inbox[0]
	c.inbox = c.inbox[1:]
	return copy(b, d), nil
}

func (c *memConn) Write(b []byte) (int, error) {
	d := make([]byte, len(b))
	copy(d, b)
	c.outbox = append(c.outbox, d)
	return len(b), nil
}

func (c *memConn) SetReadDeadline(time.Time) error { return nil }
func (c *memConn) Close() error                    { return nil }

func (c *memConn) push(d []byte) {
	cp := make([]byte, len(d))
	copy(cp, d)
	c.inbox = append(c.inbox, cp)
}

func (c *memConn) drainOutbox() [][]byte {
	out := c.outbox
	c.outbox = nil
	return out
}

// Session is the exported resource. The generated wit_bindings.go in
// this package requires the handle/pinner fields and the OnDrop hook.
type Session struct {
	handle int32
	pinner runtime.Pinner

	conn    *memConn
	client  *mosh.Client
	tracker *stateTracker
}

// SessionConnect backs `connect: static func(...)`. The key is the
// base64 field of `MOSH CONNECT <port> <key>` (padding optional).
func SessionConnect(key string, cols uint16, rows uint16) witTypes.Result[*Session, string] {
	for len(key)%4 != 0 {
		key += "="
	}
	rawKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return witTypes.Err[*Session, string](fmt.Sprintf("bad key: %v", err))
	}
	ocb, err := mosh.NewOCB(rawKey)
	if err != nil {
		return witTypes.Err[*Session, string](fmt.Sprintf("bad key: %v", err))
	}

	conn := &memConn{}
	// DialConnRaw starts no goroutines and no timers; it queues the
	// initial association datagram into conn for the first tick.
	client, err := mosh.DialConnRaw(conn, ocb)
	if err != nil {
		return witTypes.Err[*Session, string](err.Error())
	}

	// Real mosh clients announce the terminal size as their first user
	// instruction — the server has no other way to learn it, and the C
	// mosh-server sends no screen content until this first client
	// state arrives (verified against mosh 1.4.0).
	client.Resize(cols, rows)

	return witTypes.Ok[*Session, string](&Session{
		conn:    conn,
		client:  client,
		tracker: newStateTracker(int(cols), int(rows)),
	})
}

func (s *Session) FeedKeys(keys []uint8) {
	s.client.Send(keys)
	s.tracker.keystroke(keys)
}

func (s *Session) Resize(cols uint16, rows uint16) {
	s.client.Resize(cols, rows)
	s.tracker.resize(int(cols), int(rows))
}

func (s *Session) HandleDatagram(data []uint8) {
	s.conn.push(data)
	diff := s.client.RecvRaw(0)
	if diff == nil {
		return
	}
	t := s.client.Transport()
	s.tracker.applyDiff(diff, t.LastRecvOldNum(), t.LastRecvNewNum(), t.ThrowawayNum())
}

func (s *Session) Tick() []types.Datagram {
	s.client.Tick()
	return s.conn.drainOutbox()
}

func (s *Session) DrainOutput() []uint8 {
	return s.tracker.poll()
}

func (s *Session) Stats() types.SessionStats {
	t := s.client.Transport()

	lastRecvAge := witTypes.None[uint64]()
	if lr := t.LastRecv(); !lr.IsZero() {
		age := time.Since(lr)
		if age < 0 {
			age = 0
		}
		lastRecvAge = witTypes.Some(uint64(age.Milliseconds()))
	}

	return types.SessionStats{
		SentNum:         t.SentNum(),
		AckedNum:        t.AckedByRemote(),
		RecvNum:         t.LastRecvNewNum(),
		LastRecvAgeMs:   lastRecvAge,
		RtoMs:           uint64(t.RTO().Milliseconds()),
		PredictorActive: s.tracker.predictorActive(),
		TrackedStates:   uint32(s.tracker.stateCount()),
	}
}

func (s *Session) OnDrop() {
	s.client.Close()
}

// Version reports the engine build identity: the pinned mosh-go
// revision straight from the module graph, so it cannot go stale.
func Version() string {
	moshGo := "mosh-go unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/unixshells/mosh-go" {
				moshGo = "mosh-go " + dep.Version
			}
		}
	}
	return "experiment-mosh engine (" + moshGo + ")"
}
