package export_experiment_spike_async_probes

import (
	"sync"
	"sync/atomic"
	"time"

	"wit_component/keepalive"
	clock "wit_component/wasi_clocks_monotonic_clock"
)

func elapsedMs(f func()) uint64 {
	start := time.Now()
	f()
	return uint64(time.Since(start) / time.Millisecond)
}

func SleepEcho(ms uint64) uint64 {
	return elapsedMs(func() { time.Sleep(time.Duration(ms) * time.Millisecond) })
}

func ConcurrentSleeps(count uint32, ms uint64) uint64 {
	return elapsedMs(func() {
		var wg sync.WaitGroup
		for i := uint32(0); i < count; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}()
		}
		wg.Wait()
	})
}

// ChanPipeline runs items through a chain of stages goroutines connected
// by channels (pure compute, no host waits) and returns the sum of the
// final stage. Behind a sync export: the Go scheduler must multiplex
// goroutines inside one export call without yielding to the host.
func ChanPipeline(stages, items uint32) uint64 {
	in := make(chan uint64)
	prev := in
	for s := uint32(0); s < stages; s++ {
		next := make(chan uint64)
		go func(from, to chan uint64) {
			for v := range from {
				to <- v + 1
			}
			close(to)
		}(prev, next)
		prev = next
	}
	go func() {
		for i := uint32(0); i < items; i++ {
			in <- uint64(i)
		}
		close(in)
	}()
	var sum uint64
	for v := range prev {
		sum += v
	}
	return sum
}

func SleepInSync(ms uint64) uint64 {
	return elapsedMs(func() { time.Sleep(time.Duration(ms) * time.Millisecond) })
}

func SpinPipeline(stages, items uint32) uint64 {
	return ChanPipeline(stages, items)
}

func waitForMs(ms uint64) {
	clock.WaitFor(ms * 1_000_000)
}

func clockElapsedMs(f func()) uint64 {
	start := clock.Now()
	f()
	return (clock.Now() - start) / 1_000_000
}

func WaitForEcho(ms uint64) uint64 {
	return clockElapsedMs(func() { waitForMs(ms) })
}

func ConcurrentWaitFors(count uint32, ms uint64) uint64 {
	return clockElapsedMs(func() {
		var wg sync.WaitGroup
		for i := uint32(0); i < count; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				waitForMs(ms)
			}()
		}
		wg.Wait()
	})
}

func WaitForInSync(ms uint64) uint64 {
	return clockElapsedMs(func() { waitForMs(ms) })
}

// --- keep-alive probes (finding 31, wosh#25) --------------------------------

// The guard/ticker period: coarse enough to be obviously not busy-waiting,
// fine enough that probe latencies read clearly against 30-50ms sleeps.
const keepAlivePeriodMs = 5

// SleepGuarded is SleepEcho (the finding-3a trap canary) plus a guard: the
// guard's pending wait-for makes the idle decision WAIT instead of EXIT, so
// the plain time.Sleep fires instead of trapping the task.
func SleepGuarded(ms uint64) uint64 {
	g := keepalive.NewGuard(keepAlivePeriodMs)
	defer g.Release()
	return elapsedMs(func() { time.Sleep(time.Duration(ms) * time.Millisecond) })
}

// SelectTimeoutGuarded pins the select-with-timeout shape: the timeout arm
// must fire (at guard-period resolution) even though nothing else in the
// task ever becomes ready.
func SelectTimeoutGuarded(ms uint64) bool {
	g := keepalive.NewGuard(keepAlivePeriodMs)
	defer g.Release()
	never := make(chan struct{})
	select {
	case <-never:
		return false
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return true
	}
}

// bgFired holds (elapsed-ms-at-fire + 1); 0 = not fired. The +1 keeps a
// legitimate 0ms elapse distinguishable from "unfired".
var bgFired atomic.Uint64

// SpawnBg arms the eternal ticker and spawns a goroutine that OUTLIVES this
// task: the export returns immediately, the goroutine sleeps ms and then
// records how long after the spawn its timer actually fired. Whether it
// fires without another export call is exactly the host-liveness question.
func SpawnBg(ms uint64) {
	keepalive.EnsureTicker(keepAlivePeriodMs)
	bgFired.Store(0)
	start := clock.Now()
	go func() {
		time.Sleep(time.Duration(ms) * time.Millisecond)
		bgFired.Store((clock.Now()-start)/1_000_000 + 1)
	}()
}

// ReadMarker reports SpawnBg's goroutine: 0 while unfired, else the
// milliseconds from spawn to fire.
func ReadMarker() uint64 {
	v := bgFired.Load()
	if v == 0 {
		return 0
	}
	return v - 1
}
