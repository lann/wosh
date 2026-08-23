// Channel is the second exported resource: the thin componentize-go
// shim over one bulk channel in wit_component/core. Same split as
// Session above -- no logic here, only Canonical-ABI translation.

package export_wosh_ssh_core_core

import (
	"runtime"

	witTypes "go.bytecodealliance.org/pkg/wit/types"

	"wit_component/core"
	types "wit_component/wosh_ssh_core_core"
)

// Channel is the exported `channel` resource. The generated
// wit_bindings.go requires the handle/pinner fields and the OnDrop
// hook; everything else lives in the engine's Channel.
type Channel struct {
	handle int32
	pinner runtime.Pinner

	ch *core.Channel
}

// OnDrop runs on the resource destructor. Dropping the resource closes
// the channel, per the lifetime paragraph in wit/core.wit; Close is
// idempotent.
func (c *Channel) OnDrop() { c.ch.Close() }

// Write collects AFTER the engine has copied the accepted prefix of
// the borrowed cabi view into its outbound buffer -- see gc.go.
func (c *Channel) Write(data []uint8) witTypes.Result[uint32, string] {
	n, err := c.ch.Write(data)
	gcCharge(len(data))
	gcCollect()
	if err != nil {
		return witTypes.Err[uint32, string](err.Error())
	}
	return witTypes.Ok[uint32, string](n)
}

// Drain collects BEFORE the drained slice exists, for the same reason
// Session.Drain does. This is the hottest export of a download, so it
// is also where most of a transfer's collections land.
func (c *Channel) Drain(max uint32) []uint8 {
	gcCollect()
	out := c.ch.Drain(max)
	gcCharge(len(out))
	return out
}

func (c *Channel) State() types.ChannelState {
	state, msg := c.ch.State()
	switch state {
	case core.ChannelEOF:
		return types.MakeChannelStateEof()
	case core.ChannelClosed:
		return types.MakeChannelStateClosed(msg)
	default:
		return types.MakeChannelStateOpen()
	}
}

func (c *Channel) Finish() { c.ch.Finish() }

func (c *Channel) Close() { c.ch.Close() }

// --- the session's bulk plane -----------------------------------------

func (s *Session) OpenSubsystem(name string) witTypes.Result[*Channel, string] {
	return channelResult(s.eng.OpenSubsystem(name))
}

func (s *Session) OpenExecChannel(command string) witTypes.Result[*Channel, string] {
	return channelResult(s.eng.OpenExecChannel(command))
}

// channelResult wraps a freshly opened engine channel as the owned
// resource the WIT `result<channel, string>` hands back.
func channelResult(ch *core.Channel, err error) witTypes.Result[*Channel, string] {
	if err != nil {
		return witTypes.Err[*Channel, string](err.Error())
	}
	return witTypes.Ok[*Channel, string](&Channel{ch: ch})
}
