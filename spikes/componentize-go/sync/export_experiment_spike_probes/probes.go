package export_experiment_spike_probes

import (
	"crypto/sha256"
	"encoding/hex"
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
