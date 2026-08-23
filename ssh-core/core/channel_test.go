package core

// Host-side behaviour tests for the bulk channel plane (channel.go),
// on the same real-x/crypto/ssh-server harness as core_test.go: the
// engine's shuttle is bridged to one end of a net.Pipe, so the bytes
// crossing feed/drain are genuine SSH protocol bytes and everything
// asserted here is a property of the protocol exchange.
//
// The properties that matter most, and are easiest to get subtly
// wrong, are the two the WIT doc spends its longest paragraphs on:
// backpressure must actually stop the far end rather than quietly
// growing this component's heap, and `eof` must not eat the tail of a
// reply that arrived before the embedder drained it.
//
// All payloads are obviously synthetic filler; nothing here is a
// credential.

import (
	"bytes"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- fixtures ---------------------------------------------------------

// bulkAccept is the common shape of a bulkServer that grants
// everything and serves it with `serve`.
func bulkAccept(serve func(ssh.Channel)) bulkServer {
	return func(_, _ string, _ ssh.Channel) func(ssh.Channel) { return serve }
}

// bulkRefuse is the sshd with no matching `Subsystem` line: it replies
// false to the request and never serves anything.
func bulkRefuse() bulkServer {
	return func(_, _ string, _ ssh.Channel) func(ssh.Channel) { return nil }
}

// bulkEchoGreeting serves a bulk channel by announcing `greeting` and
// then echoing every byte back until the client sends EOF. The
// greeting is what lets the two-channels-at-once test prove each
// channel reached its OWN server instance rather than merely that
// bytes came back.
func bulkEchoGreeting(greeting []byte) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		if len(greeting) > 0 {
			_, _ = ch.Write(greeting)
		}
		_, _ = io.Copy(ch, ch) // returns on the client's EOF
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
}

// bulkEOFWaiter is the helper an `exec`-started server acts like: it
// reads until EOF before producing anything. Without `finish` it never
// terminates, which is the whole reason `finish` exists.
func bulkEOFWaiter(reply []byte) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		got, _ := io.ReadAll(ch) // parks until the client's finish() EOF
		_, _ = ch.Write(append(append([]byte(nil), reply...), got...))
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
}

// bulkSayThenEOF writes `payload`, sends EOF on the data direction
// only, and then holds the channel open. That is the exact ordering
// the `eof` variant warns about: the remote is finished while this
// side still has every one of those bytes buffered.
func bulkSayThenEOF(payload []byte, hold <-chan struct{}) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		_, _ = ch.Write(payload)
		_ = ch.CloseWrite()
		<-hold
		_ = ch.Close()
	}
}

// bulkFlood writes `total` bytes of filler as fast as the window
// allows, recording its own progress. The counter is what makes the
// backpressure chain observable from the SERVER end: while the
// embedder refuses to drain, the server's own writes must stall.
func bulkFlood(total int, sent *atomic.Int64) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		chunk := bytes.Repeat([]byte{'f'}, 32*1024)
		for written := 0; written < total; {
			n := len(chunk)
			if remaining := total - written; remaining < n {
				n = remaining
			}
			w, err := ch.Write(chunk[:n])
			written += w
			sent.Store(int64(written))
			if err != nil {
				return
			}
		}
		_ = ch.CloseWrite()
	}
}

// bulkSilent never reads and never writes: the far end of a transfer
// that has stopped consuming, which is what drives the outbound
// buffer to its cap and makes `write` report short.
func bulkSilent(release <-chan struct{}) func(ssh.Channel) {
	return func(ch ssh.Channel) {
		<-release
		_ = ch.Close()
	}
}

// --- helpers ----------------------------------------------------------

// buffered reports both buffer depths. Test-only, and deliberately
// not part of the engine's surface: the WIT interface exposes
// backpressure as short writes and empty drains, never as a byte
// count, and nothing outside these tests should be able to look.
func (c *Channel) buffered() (inbound, outbound int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inbound), len(c.outbound)
}

func (r *rig) openSubsystem(t *testing.T, name string) *Channel {
	t.Helper()
	ch, err := r.eng.OpenSubsystem(name)
	if err != nil {
		t.Fatalf("OpenSubsystem(%q): %v", name, err)
	}
	return ch
}

func (r *rig) openExec(t *testing.T, command string) *Channel {
	t.Helper()
	ch, err := r.eng.OpenExecChannel(command)
	if err != nil {
		t.Fatalf("OpenExecChannel(%q): %v", command, err)
	}
	return ch
}

func channelStateName(s ChannelState) string {
	switch s {
	case ChannelOpen:
		return "open"
	case ChannelEOF:
		return "eof"
	case ChannelClosed:
		return "closed"
	}
	return "?"
}

func (r *rig) waitChannelState(t *testing.T, c *Channel, want ChannelState) string {
	t.Helper()
	var msg string
	r.waitUntil(t, "channel state "+channelStateName(want), func() bool {
		var st ChannelState
		st, msg = c.State()
		return st == want
	})
	return msg
}

// writeAll hands `data` over across as many ticks as the outbound
// buffer needs, which is how an embedder is meant to use `write`: a
// short result is backpressure, not failure.
func (r *rig) writeAll(t *testing.T, c *Channel, data []byte) {
	t.Helper()
	r.waitUntil(t, "the channel to accept the whole payload", func() bool {
		n, err := c.Write(data)
		if err != nil {
			t.Fatalf("Channel.Write: %v", err)
		}
		data = data[n:]
		return len(data) == 0
	})
}

// drainUntil accumulates drained bytes until `want` appears, which is
// the only correct way to read this plane: an empty drain means
// nothing right now, never end-of-stream.
func (r *rig) drainUntil(t *testing.T, c *Channel, want []byte) []byte {
	t.Helper()
	var got []byte
	r.waitUntil(t, "the channel to produce the expected bytes", func() bool {
		got = append(got, c.Drain(64*1024)...)
		return bytes.Contains(got, want)
	})
	return got
}

// drainAll drains until the channel has produced nothing for a short
// settling window, then reports the total. Used where the assertion is
// about a byte COUNT rather than about a marker arriving.
func (r *rig) drainAll(t *testing.T, c *Channel, want int) int {
	t.Helper()
	total := 0
	r.waitUntil(t, "the channel to produce every flooded byte", func() bool {
		total += len(c.Drain(64 * 1024))
		return total >= want
	})
	return total
}

// --- opening ----------------------------------------------------------

// TestSubsystemChannelRoundTripsBytes is the base case: a second
// channel of the same authenticated connection carrying a subsystem,
// bytes both ways, closed cleanly, with the interactive channel
// undisturbed throughout.
func TestSubsystemChannelRoundTripsBytes(t *testing.T) {
	greeting := []byte("synthetic-subsystem-greeting")
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEchoGreeting(greeting)))
	r.reachReady(t)

	ch := r.openSubsystem(t, "sftp")
	r.drainUntil(t, ch, greeting)

	payload := []byte("synthetic-request-bytes")
	r.writeAll(t, ch, payload)
	r.drainUntil(t, ch, payload)

	ch.Close()
	if st, _ := ch.State(); st != ChannelClosed {
		t.Fatalf("state after Close = %s, want closed", channelStateName(st))
	}

	// The session is untouched, exactly as `channel.close` promises:
	// the interactive channel still round-trips.
	r.eng.WriteInput([]byte("hello-after-the-subsystem"))
	var echoed []byte
	r.waitUntil(t, "echoed input after the bulk channel closed", func() bool {
		echoed = append(echoed, r.eng.DrainOutput()...)
		return bytes.Contains(echoed, []byte("hello-after-the-subsystem"))
	})
}

// TestExecChannelRoundTripsBytes covers the `sftp -s` fallback path:
// the same channel in every respect, started through an `exec`
// request instead of a subsystem name.
func TestExecChannelRoundTripsBytes(t *testing.T) {
	greeting := []byte("synthetic-exec-greeting")
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEchoGreeting(greeting)))
	r.reachReady(t)

	ch := r.openExec(t, "/usr/lib/openssh/sftp-server")
	r.drainUntil(t, ch, greeting)

	payload := []byte("synthetic-exec-request-bytes")
	r.writeAll(t, ch, payload)
	r.drainUntil(t, ch, payload)
	ch.Close()
}

// TestRefusedSubsystemFailsLegibly defends the signal the embedder
// falls back on. An sshd with no `Subsystem sftp` line says nothing
// but "no", so the reason string has to supply the diagnosis itself --
// it is the only thing that tells a user why an otherwise healthy
// server will not do file transfer.
func TestRefusedSubsystemFailsLegibly(t *testing.T) {
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0), bulkRefuse())
	r.reachReady(t)

	ch := r.openSubsystem(t, "sftp")
	msg := r.waitChannelState(t, ch, ChannelClosed)

	for _, want := range []string{"sftp", "Subsystem", "exec"} {
		if !bytes.Contains([]byte(msg), []byte(want)) {
			t.Fatalf("refusal reason %q does not mention %q", msg, want)
		}
	}

	// Every method stays legal on the refused channel.
	if _, err := ch.Write([]byte("x")); err == nil {
		t.Fatal("Write on a refused channel returned no error")
	}
	if got := ch.Drain(16); got != nil {
		t.Fatalf("Drain on a refused channel = %q, want nil", got)
	}
	ch.Finish()
	ch.Close()
}

// TestOpenBeforeReadyErrors: a bulk channel makes no sense before the
// connection it would ride has authenticated, and that refusal IS
// decidable without the wire, so it is the one that comes back through
// the WIT `result` rather than through `state`.
func TestOpenBeforeReadyErrors(t *testing.T) {
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEchoGreeting(nil)))
	r.waitState(t, StateHostKeyCheck)

	if _, err := r.eng.OpenSubsystem("sftp"); err == nil {
		t.Fatal("OpenSubsystem succeeded before the session reached ready")
	}
	if _, err := r.eng.OpenExecChannel("sftp-server"); err == nil {
		t.Fatal("OpenExecChannel succeeded before the session reached ready")
	}
}

// --- flow control -----------------------------------------------------

// TestInboundBufferStopsAtTheReadAheadCap is the heart of the plane.
// An embedder that stops draining must stop the SERVER, not grow this
// component's heap: the read-ahead buffer holds at the cap, this core
// stops reading, x/crypto stops issuing window adjustments, and the
// far end's own writes stall. Draining then releases the whole chain
// and every flooded byte still arrives, in order.
func TestInboundBufferStopsAtTheReadAheadCap(t *testing.T) {
	// Comfortably past the cap AND past x/crypto's own 2 MiB
	// per-channel window, so the stall has to reach the server rather
	// than merely filling the ssh stack's internal pending buffer.
	const flood = 3 * 1024 * 1024
	sent := &atomic.Int64{}
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkFlood(flood, sent)))
	r.reachReady(t)

	ch := r.openSubsystem(t, "sftp")

	// Do not drain: wait for the buffer to fill up to the cap. A read
	// hands over at most one SSH packet, so the last read before the
	// cap may leave up to a packet of slack.
	r.waitUntil(t, "the read-ahead buffer to reach its cap", func() bool {
		in, _ := ch.buffered()
		if in > channelReadAheadCap {
			t.Fatalf("read-ahead buffer = %d bytes, past the %d cap", in, channelReadAheadCap)
		}
		return in >= channelReadAheadCap-channelReadChunk
	})

	// Still not draining: the cap must HOLD, and the server must
	// notice. Sampling both across a settling window is what
	// distinguishes real backpressure from a buffer that merely
	// happened to be at the cap when it was first looked at.
	settle := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(settle) {
		if in, _ := ch.buffered(); in > channelReadAheadCap {
			t.Fatalf("read-ahead buffer grew to %d bytes past the %d cap", in, channelReadAheadCap)
		}
		r.eng.Pump()
		time.Sleep(pollInterval)
	}
	stalledAt := sent.Load()
	if stalledAt >= flood {
		t.Fatalf("the server wrote all %d bytes while the embedder never drained: "+
			"backpressure never reached it", flood)
	}

	// Draining resumes the flow, all the way back to the server.
	if got := r.drainAll(t, ch, flood); got != flood {
		t.Fatalf("drained %d bytes, want the full %d flood", got, flood)
	}
	if resumed := sent.Load(); resumed <= stalledAt {
		t.Fatalf("the server made no further progress after draining (%d then %d)",
			stalledAt, resumed)
	}
	ch.Close()
}

// TestWriteGoesShortWhenTheFarEndStopsReading is the same chain in the
// other direction, where the signal is `write`'s accepted count. A far
// end that never reads exhausts its own window; the writer goroutine
// parks; the outbound buffer fills to its cap; and `write` then
// reports short -- including zero -- WITHOUT erroring, because a full
// buffer is ordinary backpressure and not a failure.
func TestWriteGoesShortWhenTheFarEndStopsReading(t *testing.T) {
	release := make(chan struct{})
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkSilent(release)))
	r.reachReady(t)
	t.Cleanup(func() { close(release) })

	ch := r.openSubsystem(t, "sftp")

	chunk := bytes.Repeat([]byte{'w'}, 64*1024)
	// Bounded well above x/crypto's 2 MiB window plus this plane's
	// own outbound cap: if the writer really parks, a short write
	// arrives long before this ceiling.
	const ceiling = 8 * 1024 * 1024
	accepted := 0
	sawShort := false
	r.waitUntil(t, "write to report a short accept", func() bool {
		n, err := ch.Write(chunk)
		if err != nil {
			t.Fatalf("Write reported an error rather than a short accept: %v", err)
		}
		accepted += int(n)
		if int(n) < len(chunk) {
			sawShort = true
			return true
		}
		if accepted > ceiling {
			t.Fatalf("write accepted %d bytes without ever going short: "+
				"the outbound buffer is not bounded", accepted)
		}
		return false
	})
	if !sawShort {
		t.Fatal("write never reported a short accept")
	}
	if _, out := ch.buffered(); out > channelWriteAheadCap {
		t.Fatalf("outbound buffer = %d bytes, past the %d cap", out, channelWriteAheadCap)
	}
	ch.Close()
}

// --- eof ordering -----------------------------------------------------

// TestBufferedBytesSurviveRemoteEOF defends the trap wit/core.wit's
// `channel-state` doc calls out by name: `eof` describes the REMOTE,
// not this side's buffer. An embedder that sees `eof` and stops
// draining would lose the tail of every reply, so the bytes buffered
// before the EOF must still be there afterwards -- which in turn means
// this engine must never promote a remote EOF into `closed` on its
// own, since `closed` discards the buffers.
func TestBufferedBytesSurviveRemoteEOF(t *testing.T) {
	payload := bytes.Repeat([]byte("synthetic-tail-"), 4096) // 60 KiB, under the cap
	hold := make(chan struct{})
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkSayThenEOF(payload, hold)))
	r.reachReady(t)
	t.Cleanup(func() { close(hold) })

	ch := r.openSubsystem(t, "sftp")

	// Deliberately drain NOTHING until the remote EOF is visible.
	r.waitChannelState(t, ch, ChannelEOF)

	var got []byte
	r.waitUntil(t, "the buffered tail to drain after eof", func() bool {
		got = append(got, ch.Drain(8*1024)...)
		return len(got) >= len(payload)
	})
	if !bytes.Equal(got, payload) {
		t.Fatalf("drained %d bytes after eof, want the %d buffered before it",
			len(got), len(payload))
	}
	// Still `eof`, not `closed`: the remote is finished, this channel
	// is not, and only close() or losing the session makes it so.
	if st, _ := ch.State(); st != ChannelEOF {
		t.Fatalf("state after draining = %s, want eof", channelStateName(st))
	}
	ch.Close()
}

// --- finish -----------------------------------------------------------

// TestFinishLetsAnEofWaitingHelperTerminate: an `exec`-started helper
// that reads to EOF before replying hangs forever without `finish`,
// and `finish` must send that EOF only AFTER the bytes `write`
// already accepted have gone out -- otherwise it would truncate a
// request the embedder was told had been taken.
func TestFinishLetsAnEofWaitingHelperTerminate(t *testing.T) {
	reply := []byte("synthetic-reply-after-eof:")
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEOFWaiter(reply)))
	r.reachReady(t)

	ch := r.openExec(t, "/usr/lib/openssh/sftp-server")

	request := bytes.Repeat([]byte("synthetic-request-"), 1024) // 18 KiB
	r.writeAll(t, ch, request)
	ch.Finish()

	got := r.drainUntil(t, ch, reply)
	r.waitUntil(t, "the helper's echoed request to arrive in full", func() bool {
		got = append(got, ch.Drain(64*1024)...)
		return len(got) >= len(reply)+len(request)
	})
	if !bytes.Equal(got[:len(reply)], reply) {
		t.Fatalf("reply prefix = %q, want %q", got[:len(reply)], reply)
	}
	if !bytes.Equal(got[len(reply):len(reply)+len(request)], request) {
		t.Fatal("the helper did not receive the whole request: finish() truncated " +
			"bytes that write had already accepted")
	}

	// finish is a promise, and this engine holds the caller to it
	// rather than accepting bytes that can never be sent.
	if _, err := ch.Write([]byte("too late")); err == nil {
		t.Fatal("Write after Finish returned no error")
	}
	ch.Close()
}

// --- several at once ---------------------------------------------------

// TestTwoChannelsCarryIndependentData: an upload and a download are
// two channels, so more than one must be able to be open at a time
// with no crosstalk. Distinct greetings prove each reached its own
// server instance, not merely that some bytes came back.
func TestTwoChannelsCarryIndependentData(t *testing.T) {
	// The fixture serves each channel according to the argument the
	// client asked for, so the two ends are genuinely distinct.
	bulk := func(_, arg string, _ ssh.Channel) func(ssh.Channel) {
		return bulkEchoGreeting([]byte("greeting-for-" + arg))
	}
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0), bulk)
	r.reachReady(t)

	up := r.openSubsystem(t, "alpha")
	down := r.openSubsystem(t, "beta")

	gotUp := r.drainUntil(t, up, []byte("greeting-for-alpha"))
	gotDown := r.drainUntil(t, down, []byte("greeting-for-beta"))
	if bytes.Contains(gotUp, []byte("beta")) || bytes.Contains(gotDown, []byte("alpha")) {
		t.Fatalf("crosstalk between the two channels: %q / %q", gotUp, gotDown)
	}

	upPayload := bytes.Repeat([]byte("AAAA"), 8192)   // 32 KiB
	downPayload := bytes.Repeat([]byte("BBBB"), 8192) // 32 KiB
	r.writeAll(t, up, upPayload)
	r.writeAll(t, down, downPayload)

	gotUp = append(gotUp, r.drainUntil(t, up, upPayload[:64])...)
	gotDown = append(gotDown, r.drainUntil(t, down, downPayload[:64])...)
	if bytes.Contains(gotUp, []byte("BBBB")) {
		t.Fatal("the first channel received the second channel's bytes")
	}
	if bytes.Contains(gotDown, []byte("AAAA")) {
		t.Fatal("the second channel received the first channel's bytes")
	}

	// Closing one leaves the other alone.
	up.Close()
	if st, _ := down.State(); st == ChannelClosed {
		t.Fatal("closing one channel closed the other")
	}
	r.writeAll(t, down, []byte("still-alive"))
	r.drainUntil(t, down, []byte("still-alive"))
	down.Close()
}

// --- lifetime ----------------------------------------------------------

// TestSessionDeathClosesEveryChannel defends the lifetime paragraph:
// a channel belongs to the session but is not owned by it, so losing
// the session moves every channel to `closed` -- and afterwards every
// method must be a legal no-op or error. Never a trap, never a panic;
// the embedder holds these resources and will keep calling into them
// while it unwinds its own transfer.
func TestSessionDeathClosesEveryChannel(t *testing.T) {
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEchoGreeting([]byte("greeting"))))
	r.reachReady(t)

	first := r.openSubsystem(t, "sftp")
	second := r.openExec(t, "sftp-server")
	r.drainUntil(t, first, []byte("greeting"))
	r.drainUntil(t, second, []byte("greeting"))

	r.eng.Close()

	for _, ch := range []*Channel{first, second} {
		msg := r.waitChannelState(t, ch, ChannelClosed)
		if msg == "" {
			t.Fatal("a channel closed by session teardown carries no reason")
		}
		if _, err := ch.Write([]byte("after the session died")); err == nil {
			t.Fatal("Write on a channel of a dead session returned no error")
		}
		if got := ch.Drain(4096); got != nil {
			t.Fatalf("Drain on a channel of a dead session = %q, want nil", got)
		}
		// No-ops, and idempotent: the embedder's own teardown calls
		// these in whatever order it unwinds.
		ch.Finish()
		ch.Close()
		ch.Close()
		if st, _ := ch.State(); st != ChannelClosed {
			t.Fatalf("state = %s after teardown, want closed", channelStateName(st))
		}
	}
}

// TestBrokenWireClosesEveryChannel is the same rule reached by the
// path an embedder actually hits: the tunnel dies under a transfer.
// It goes through closeWith rather than Close, which is why both are
// worth pinning.
func TestBrokenWireClosesEveryChannel(t *testing.T) {
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEchoGreeting([]byte("greeting"))))
	r.reachReady(t)

	ch := r.openSubsystem(t, "sftp")
	r.drainUntil(t, ch, []byte("greeting"))

	r.eng.WireBroken("the tunnel went away mid-transfer")

	msg := r.waitChannelState(t, ch, ChannelClosed)
	if !bytes.Contains([]byte(msg), []byte("the tunnel went away mid-transfer")) {
		t.Fatalf("channel close reason = %q, want the wire failure named in it", msg)
	}
	if _, err := ch.Write([]byte("x")); err == nil {
		t.Fatal("Write after the wire broke returned no error")
	}
	ch.Close()
}

// TestCloseDuringAnInFlightOpenDoesNotDeadlock: cancellation is free
// on this plane precisely because no method blocks and no future is
// ever in flight, so abandoning a channel whose open round trip has
// not even come back must be a plain no-op rather than a torn state.
func TestCloseDuringAnInFlightOpenDoesNotDeadlock(t *testing.T) {
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkEchoGreeting([]byte("greeting"))))
	r.reachReady(t)

	ch := r.openSubsystem(t, "sftp")
	ch.Close() // very likely before the server's grant has arrived

	if st, _ := ch.State(); st != ChannelClosed {
		t.Fatalf("state after closing mid-open = %s, want closed", channelStateName(st))
	}
	// The state is terminal and STAYS terminal: a grant landing after
	// the fact must not resurrect the channel.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if st, _ := ch.State(); st != ChannelClosed {
			t.Fatalf("a late channel grant moved a closed channel to %s",
				channelStateName(st))
		}
		r.eng.Pump()
		time.Sleep(pollInterval)
	}

	// The session is unharmed and still opens channels.
	next := r.openSubsystem(t, "sftp")
	r.drainUntil(t, next, []byte("greeting"))
	next.Close()
}

// --- allocation pressure ----------------------------------------------

// TestGCBudgetBoundsTheHeap measures what the collection budget in
// export_wosh_ssh_core_core/gc.go is actually buying.
//
// That file turns Go's automatic garbage collection OFF, because a
// collection begun inside `cabi_realloc` traps the whole component
// instance, and asks for one explicitly every gcBudgetBytes of traffic
// across the ABI instead. The budget is denominated in boundary bytes
// but what it has to bound is the HEAP, so the multiplier between the
// two is the number that decides whether the budget is sane. This
// pins it rather than leaving it asserted in a comment.
//
// The figure is deliberately pessimistic: the fixture server shares
// this process, so the total below includes ITS x/crypto allocations
// as well as the engine's. Real component-side pressure is lower than
// what this reports, which is the right direction for a ceiling.
func TestGCBudgetBoundsTheHeap(t *testing.T) {
	const flood = 2 * 1024 * 1024
	sent := &atomic.Int64{}
	r := startWithBulk(t, simplePasswordConfig(), echoShell(0),
		bulkAccept(bulkFlood(flood, sent)))
	r.reachReady(t)
	ch := r.openSubsystem(t, "sftp")

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	if got := r.drainAll(t, ch, flood); got != flood {
		t.Fatalf("drained %d bytes, want %d", got, flood)
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	perByte := float64(allocated) / float64(flood)
	t.Logf("moved %d boundary bytes, allocated %d bytes (both ends): %.1fx amplification; "+
		"a %d-byte budget therefore holds ~%.1f MiB of garbage between collections",
		flood, allocated, perByte, gcBudgetBytesForTest,
		perByte*float64(gcBudgetBytesForTest)/(1024*1024))

	// The ceiling the budget is chosen against. Well clear of the
	// measured value, so ordinary drift does not fail the gate, but
	// low enough that a regression which starts copying the stream an
	// extra few times over is caught here rather than as an
	// out-of-memory in a browser tab.
	const maxAmplification = 24.0
	if perByte > maxAmplification {
		t.Fatalf("allocation amplification %.1fx exceeds the %.1fx the collection budget "+
			"in gc.go is sized against: a %d-byte budget would hold %.1f MiB between "+
			"collections", perByte, maxAmplification, gcBudgetBytesForTest,
			perByte*float64(gcBudgetBytesForTest)/(1024*1024))
	}
}

// gcBudgetBytesForTest mirrors gcBudgetBytes in
// export_wosh_ssh_core_core/gc.go. It is duplicated rather than
// imported because that package is the wasm-only ABI shim and cannot
// be built for the host test binary; the test above only uses it to
// state the ceiling in the units the budget is written in.
const gcBudgetBytesForTest = 4 << 20
