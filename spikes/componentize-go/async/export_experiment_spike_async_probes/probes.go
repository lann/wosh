package export_experiment_spike_async_probes

import (
	"sync"
	"time"

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
