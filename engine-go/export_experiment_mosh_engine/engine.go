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

	// Reattach resize dance (finding 20): a resumed session attaches
	// one row off and snaps to the true size once the first content
	// diff lands. A size change is the only full-repaint forcing
	// function a mosh client has (mosh 1.4.0 terminaldisplay.cc emits
	// clear + full redraw whenever a diff crosses a size boundary),
	// and a fresh process needs one: the server only ever diffs
	// against screen states we were not there to receive.
	dancePending bool
	danceCols    uint16
	danceRows    uint16
}

// SessionConnect backs `connect: static func(...)`. The key is the
// base64 field of `MOSH CONNECT <port> <key>` (padding optional).
// initialSeq (reattach flows, finding 13) must be applied before the
// association datagram — DialConnRawSeq guarantees that ordering.
func SessionConnect(key string, cols uint16, rows uint16, initialSeq witTypes.Option[uint64]) witTypes.Result[*Session, string] {
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

	seq := initialSeq.SomeOr(0)
	conn := &memConn{}
	// DialConnRawSeq starts no goroutines and no timers; it queues the
	// initial association datagram into conn for the first tick. A
	// non-zero seq also enables resume adoption in the transport (SSP
	// state numbers are learned from the server's first instruction).
	client, err := mosh.DialConnRawSeq(conn, ocb, seq)
	if err != nil {
		return witTypes.Err[*Session, string](err.Error())
	}

	s := &Session{
		conn:    conn,
		client:  client,
		tracker: newStateTracker(int(cols), int(rows)),
	}

	// Real mosh clients announce the terminal size as their first user
	// instruction — the server has no other way to learn it, and the C
	// mosh-server sends no screen content until this first client
	// state arrives (verified against mosh 1.4.0). On resume, announce
	// a deliberately-off size instead: the first leg of the resize
	// dance (see Session.dancePending).
	if seq > 0 {
		danceRows := rows - 1
		if rows <= 1 {
			danceRows = rows + 1
		}
		client.Resize(cols, danceRows)
		s.dancePending, s.danceCols, s.danceRows = true, cols, rows
	} else {
		client.Resize(cols, rows)
	}

	return witTypes.Ok[*Session, string](s)
}

func (s *Session) FeedKeys(keys []uint8) {
	s.client.Send(keys)
	s.tracker.keystroke(keys)
}

func (s *Session) Resize(cols uint16, rows uint16) {
	// An embedder-driven resize is itself a size change (full repaint
	// server-side) — it supersedes a pending dance.
	s.dancePending = false
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
	if s.dancePending && len(diff) > 0 {
		// First content diff after a resume — the off-size repaint
		// arrived. Snap to the true size: the second full repaint
		// leaves both the screen and the server pty correct.
		s.dancePending = false
		s.client.Resize(s.danceCols, s.danceRows)
		s.tracker.resize(int(s.danceCols), int(s.danceRows))
	}
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
		CurrentSeq:      t.SeqOut(),
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
