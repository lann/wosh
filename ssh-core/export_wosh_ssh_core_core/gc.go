package export_wosh_ssh_core_core

// Keeping the Go garbage collector out of the canonical ABI's
// may-leave-false windows.
//
// THE DEFECT. When the host lowers a value into this component -- a
// `list<u8>` for `feed`, say -- the canonical ABI calls this module's
// `cabi_realloc` to obtain the memory, and for the duration of that
// lift/lower window the instance's `may_leave` flag is false: calling
// an import is a trap, not an error. componentize-go's `cabi_realloc`
// satisfies the request with an ordinary Go `make([]byte, n)`, so a
// large enough allocation reaches `runtime.mallocgcLarge`, which may
// decide it is time to collect. `runtime.gcStart` then stops and
// restarts the world, and `startTheWorldWithSema` calls
// `runtime.netpoll` -- which on wasip2 is the `poll_oneoff` import.
// The instance traps with "cannot leave component instance" and is
// poisoned; the session dies mid-transfer.
//
// Observed at wosh's `e2e-transfer` gate with this backtrace, which
// names every step:
//
//	poll_oneoff <- runtime.netpoll <- runtime.startTheWorldWithSema
//	  <- runtime.gcStart <- runtime.mallocgcLarge <- runtime.makeslice
//	  <- witRuntime.allocateRaw <- witRuntime.cabiRealloc <- cabi_realloc
//
// The interactive plane never hit it because keystrokes are a few
// bytes; the bulk plane's 256 KiB feeds changed the odds, not the
// defect.
//
// WHAT UPSTREAM ALREADY DOES, AND WHY IT IS NOT ENOUGH.
// go.bytecodealliance.org/pkg (v0.2.2 and v0.2.3, byte-identical here)
// knows about this bug class: its `cabi_realloc` brackets the
// allocation with `adapter_monotonic_clock_set_paused`, so that a GC
// measuring its own phase timings reads a cached clock instead of
// calling `monotonic_clock::now`. That closes ONE door. It does
// nothing for `netpoll`/`poll_oneoff`, which `startTheWorldWithSema`
// calls unconditionally on every collection. Upgrading the dependency
// does not help; there is no knob to turn.
//
// THE FIX, and why it is a fix rather than a narrowing of the odds.
// Automatic collection is turned off entirely, and collection is
// instead requested explicitly from inside export bodies, where
// `may_leave` is true and calling imports is legal. Reading the Go
// 1.24 runtime, `debug.SetGCPercent(-1)` closes every automatic path:
//
//   - `gcTriggerHeap`: with `gcPercent < 0`, `gcControllerState.commit`
//     stores a `gcPercentHeapGoal` of `^uint64(0)`, so the heap trigger
//     can never be reached.
//   - `gcTriggerTime`: `test()` returns false immediately when
//     `gcPercent < 0`, so the two-minute forced collection is off too.
//
// which leaves `runtime.GC()` as the only way a collection can begin.
//
// THE ONE REMAINING DOOR, deliberately left shut: the soft memory
// limit. `heapGoalInternal` takes the SMALLER of the gcPercent goal
// and `memoryLimitHeapGoal()`, so a limit set with
// `debug.SetMemoryLimit` would resurrect the heap trigger -- and a
// limit-driven collection starts from `mallocgc`, which is to say from
// inside `cabi_realloc`, which is the exact trap this file exists to
// prevent. A memory limit is the intuitive backstop here and it is the
// wrong one. It stays at its default of `math.MaxInt64`. Do not set
// it; bound the heap with the collection budget below instead.

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
)

func init() {
	// Off, permanently. See the file comment: every automatic
	// collection path is a potential trap, because the runtime may
	// choose to take it inside `cabi_realloc`.
	debug.SetGCPercent(-1)
}

// gcBudgetBytes is how much traffic may cross this ABI boundary
// between explicit collections.
//
// It is a proxy for allocation, not a heap size: what it bounds
// directly is bytes handed over by, or handed back to, the embedder,
// and the heap follows from that with a multiplier. Measured on the
// host against a real x/crypto/ssh server (TestGCBudgetBoundsTheHeap
// in core, which gates the number), moving bytes through this core
// allocates 6.2x their count -- the lowered buffer, the ssh stack's
// packet and cipher buffers, and the channel's read-ahead copy -- and
// that figure counts the fixture SERVER's allocations too, so the
// component's own share is lower still. A 4 MiB budget therefore
// holds under ~25 MiB of garbage between collections at the
// pessimistic multiplier, which is unremarkable for a wasm instance
// already moving multi-megabyte files, while asking for a collection
// only once every sixteen 256 KiB feeds: a handful across an entire
// transfer, each on a heap small enough to be sub-millisecond.
//
// Raising it trades memory for fewer collections; lowering it does the
// reverse. Neither can reintroduce the trap, which is the point: the
// budget governs cost, not correctness.
const gcBudgetBytes = 4 << 20

// gcCallToll is charged on every export call regardless of payload, so
// that a session which is merely being polled -- `pump` and an empty
// `drain` on a cadence, the idle terminal case -- still collects
// eventually rather than accumulating small garbage forever. At this
// toll a pure-poll workload collects once per 1024 calls.
const gcCallToll = 4 << 10

var gcOwed atomic.Int64

// gcCharge records traffic without collecting. It is safe to call
// anywhere; only gcCollect must be placed carefully.
func gcCharge(n int) {
	gcOwed.Add(int64(n) + gcCallToll)
}

// gcCollect runs a collection if the budget has been used up.
//
// PLACEMENT IS LOAD-BEARING, for a reason that is not obvious. The
// generated shim calls `witRuntime.Unpin()` BEFORE invoking the method
// body, and the `[]uint8` / `string` parameters it passes are
// `unsafe.Slice`/`unsafe.String` views built from a raw address. After
// that unpin, nothing the collector can trace refers to the buffer
// `cabi_realloc` allocated -- so a collection while such a view is
// still live could reclaim the bytes out from under the reader. That
// hazard predates this file (an automatic collection could always have
// landed there), but turning collection into something this component
// requests deliberately means the request has to be placed where it
// cannot fire into that window.
//
// The rule, applied at every call site below: collect only where no
// borrowed cabi view is live and no return value has been built yet.
// In practice that means AFTER the body has copied its parameters into
// Go-owned memory, or BEFORE it has allocated anything to return.
func gcCollect() {
	for {
		owed := gcOwed.Load()
		if owed < gcBudgetBytes {
			return
		}
		if gcOwed.CompareAndSwap(owed, 0) {
			break
		}
	}
	runtime.GC()
}
