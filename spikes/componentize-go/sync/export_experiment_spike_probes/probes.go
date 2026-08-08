package export_experiment_spike_probes

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"time"
)

func Add(a, b int32) int32 { return a + b }

func EchoBytes(data []uint8) []uint8 {
	out := make([]uint8, len(data))
	copy(out, data)
	return out
}

func HashHex(data []uint8) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TickBatch returns n distinct pseudo-datagrams, the shape of the mosh
// engine's tick() -> outbound datagrams.
func TickBatch(n uint32) [][]uint8 {
	out := make([][]uint8, n)
	for i := range out {
		out[i] = []uint8{byte(i), byte(i >> 8), 0xAB, 0xCD}
	}
	return out
}

// --- M7 parked-goroutine probes (see wit) ----------------------------------

var (
	pokeC        chan uint32
	parkedResult uint32
	sleepDone    uint32
)

func gosched(rounds int) {
	for i := 0; i < rounds; i++ {
		runtime.Gosched()
	}
}

func SpawnParked() {
	parkedResult = 0
	pokeC = make(chan uint32) // unbuffered: a real park + handoff
	stage2 := make(chan uint32)
	go func() {
		v := <-pokeC    // parks across export calls until Poke
		stage2 <- v + 1 // parks until the second goroutine receives
	}()
	go func() {
		parkedResult = (<-stage2) * 2
	}()
}

func Poke(value uint32) {
	pokeC <- value // handoff: parks this export goroutine briefly
	gosched(16)    // run the chain to quiescence
}

func ParkedResult() uint32 { return parkedResult }

func SpawnSleeper(ms uint32) {
	sleepDone = 0
	go func() {
		time.Sleep(time.Duration(ms) * time.Millisecond)
		sleepDone = 1
	}()
	gosched(4) // let it reach the sleep
}

func Pump() { gosched(16) }

func SleepResult() uint32 { return sleepDone }
