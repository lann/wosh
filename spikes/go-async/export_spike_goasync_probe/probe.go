package export_spike_goasync_probe

import (
	"fmt"
	"runtime"
	"sync/atomic"

	clock "wit_component/wasi_clocks_monotonic_clock"
)

// --- (1) sync vs async lifting, calling the SAME async import -------

func SyncCallsAsync(ms uint64) string {
	start := clock.Now()
	clock.WaitFor(ms * 1_000_000)
	return fmt.Sprintf("sync export survived; waited ~%dms", (clock.Now()-start)/1_000_000)
}

func AsyncCallsAsync(ms uint64) string {
	start := clock.Now()
	clock.WaitFor(ms * 1_000_000)
	return fmt.Sprintf("async export survived; waited ~%dms", (clock.Now()-start)/1_000_000)
}

// --- (2) goroutine parking ACROSS separate export calls -------------

var (
	parkCh     = make(chan uint64)
	doneCh     = make(chan struct{})
	parkResult string
)

func Park() {
	go func() {
		v := <-parkCh // parks here; the export below returns meanwhile
		parkResult = fmt.Sprintf("goroutine resumed across export calls with %d", v)
		close(doneCh)
	}()
	runtime.Gosched() // let it reach the park point
}

func Release(v uint64) string {
	parkCh <- v
	<-doneCh
	return parkResult
}

// --- (3) does a never-returning keepalive host background work? -----

var bgCount uint64

func Keepalive() {
	for {
		clock.WaitFor(50 * 1_000_000) // async import; never returns
	}
}

func StartBg() {
	go func() {
		for i := 0; i < 20; i++ {
			clock.WaitFor(10 * 1_000_000) // async import, background goroutine
			atomic.AddUint64(&bgCount, 1)
		}
	}()
	runtime.Gosched()
}

func BgCount() uint64 { return atomic.LoadUint64(&bgCount) }
