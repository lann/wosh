package export_experiment_spike_counters

import "runtime"

// Counter is the exported resource. The generated wit_bindings.go in this
// package requires the handle/pinner fields and the OnDrop hook.
type Counter struct {
	handle int32
	pinner runtime.Pinner
	n      uint32
}

func MakeCounter(start uint32) *Counter { return &Counter{n: start} }

func (c *Counter) Increment() uint32 {
	c.n++
	return c.n
}

func (c *Counter) Value() uint32 { return c.n }

func (c *Counter) OnDrop() {}
