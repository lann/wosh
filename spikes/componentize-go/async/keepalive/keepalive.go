// Package keepalive implements the wait-for-based liveness helpers for
// componentize-go's async ABI bridge (finding 31 / wosh#25; PLAN.md risk 3's
// "shim timers via explicit wait-for-based helpers" contingency).
//
// The bridge (go.bytecodealliance.org/pkg wit/async) decides, at every
// scheduler-idle point of a task slice, between CALLBACK_CODE_EXIT (no
// pending CM waitables) and CALLBACK_CODE_WAIT (park on the waitable set).
// Only Component Model waitables count: goroutines blocked on Go-native
// primitives — time.Sleep, time.After, channels fed by later export calls —
// are invisible, so a task left with only those EXITs: a trap if the export
// has not called task.return yet (finding 3a), silent stranding of
// background goroutines if it has.
//
// Both helpers keep a wasi:clocks@0.3 wait-for subtask pending — a real CM
// waitable backed by a host timer — so the task parks WAIT and gets a slice
// every period, during which the Go scheduler runs every runnable goroutine
// (expired Go timers fire then). Progress BETWEEN export calls additionally
// requires the host to deliver timer completions while no call is in
// flight: wasmtime does while the embedder dwells in run_concurrent; deltic
// does unconditionally since the settlement pump (embedder-api amendment
// A11, deltic#121) — which is exactly what spike-keepalive-deltic asserts.
package keepalive

import (
	"sync"
	"sync/atomic"

	clock "wit_component/wasi_clocks_monotonic_clock"
)

// Guard holds the CURRENT task open (WAIT, not EXIT) until released: arm at
// export entry, `defer g.Release()`, and Go-native timers inside the export
// fire at period resolution instead of trapping the task.
type Guard struct {
	released atomic.Bool
	period   uint64 // ms
}

// NewGuard arms a guard on the current task. The spawned goroutine is
// runnable immediately and the scheduler cannot go idle with a runnable
// goroutine, so its first wait-for registers in this task's pending set
// before any idle decision can happen — the arming is race-free by the
// scheduler's own rules.
func NewGuard(periodMs uint64) *Guard {
	g := &Guard{period: periodMs}
	go func() {
		for !g.released.Load() {
			clock.WaitFor(g.period * 1_000_000)
		}
	}()
	return g
}

// Release lets the guard goroutine exit after its in-flight wait-for
// settles; the task lingers at most one period past the handler's return.
// (No cancel path: the bridge panics "todo" on TASK_CANCELLED, so the
// in-flight wait is always allowed to complete.)
func (g *Guard) Release() { g.released.Store(true) }

var tickerOnce sync.Once

// EnsureTicker arms the instance-wide eternal ticker: one goroutine looping
// wait-for(period) forever. Whichever task's slice first runs it becomes a
// permanently WAIT-parked task whose periodic slices run every runnable
// goroutine in the instance — the timer wheel that revives background
// goroutines no live task is watching.
//
// Lazy-armed from inside an export on purpose. NEVER arm from init(): a
// goroutine touching CM operations outside any task slice nil-derefs the
// bridge's per-task state.
func EnsureTicker(periodMs uint64) {
	tickerOnce.Do(func() {
		go func() {
			for {
				clock.WaitFor(periodMs * 1_000_000)
			}
		}()
	})
}
