// Package export_wosh_ssh_core_core is the thin componentize-go shim
// over the sans-I/O SSH engine in wit_component/core.
//
// It holds NO logic on purpose: every method here is a translation
// between Canonical-ABI-shaped values (witTypes.Option/Result, the
// generated Status variant) and the plain Go engine, which is
// therefore testable with ordinary `go test` on the host. That split
// mirrors client-go's generated-glue-vs-logic layout.
//
// Every export in this world is a plain synchronous func, and this
// component imports nothing asynchronous. None of componentize-go's
// async-lifting hazards apply: there is no keepalive task, no
// task-exit race, and no rule against an export that parks -- though
// none of these do. The parking happens on the ssh goroutines behind
// the shuttle conn, which survive across export calls, and each
// method below hands them scheduler rounds before returning.
package export_wosh_ssh_core_core

import (
	"runtime"

	witTypes "go.bytecodealliance.org/pkg/wit/types"

	"wit_component/core"
	types "wit_component/wosh_ssh_core_core"
)

// Session is the exported resource. The generated wit_bindings.go
// requires the handle/pinner fields and the OnDrop hook; everything
// else lives in the engine.
type Session struct {
	handle int32
	pinner runtime.Pinner

	eng *core.Engine
}

// SessionConnect backs `session.connect`. It cannot fail: the engine
// starts its handshake goroutine and the embedder watches `status`.
func SessionConnect(user string, cols uint16, rows uint16) *Session {
	return &Session{eng: core.New(user, cols, rows)}
}

// OnDrop runs on the resource destructor; Close is idempotent.
func (s *Session) OnDrop() { s.eng.Close() }

// --- the byte plane ---------------------------------------------------

func (s *Session) Feed(data []uint8) { s.eng.Feed(data) }

func (s *Session) Drain() []uint8 { return s.eng.Drain() }

func (s *Session) WireBroken(reason string) { s.eng.WireBroken(reason) }

func (s *Session) Pump() { s.eng.Pump() }

// --- the control plane ------------------------------------------------

func (s *Session) Status() types.Status {
	state, msg := s.eng.Status()
	switch state {
	case core.StateHostKeyCheck:
		return types.MakeStatusHostKeyCheck()
	case core.StateAuthenticating:
		return types.MakeStatusAuthenticating()
	case core.StateSigning:
		return types.MakeStatusSigning()
	case core.StateAuthPrompts:
		return types.MakeStatusAuthPrompts()
	case core.StateReady:
		return types.MakeStatusReady()
	case core.StateClosed:
		return types.MakeStatusClosed(msg)
	default:
		return types.MakeStatusConnecting()
	}
}

func (s *Session) HostKeySha256() witTypes.Option[string] {
	fp := s.eng.HostKeySha256()
	if fp == "" {
		return witTypes.None[string]()
	}
	return witTypes.Some(fp)
}

func (s *Session) ConfirmHostKey(accept bool) { s.eng.ConfirmHostKey(accept) }

func (s *Session) AuthenticatePassword(password string) witTypes.Result[witTypes.Unit, string] {
	return unit(s.eng.AuthenticatePassword(password))
}

func (s *Session) AuthenticatePublickey(keys []types.PublicKey) witTypes.Result[witTypes.Unit, string] {
	return unit(s.eng.AuthenticatePublickey(engineKeys(keys)))
}

func (s *Session) AuthenticateInteractive() witTypes.Result[witTypes.Unit, string] {
	return unit(s.eng.AuthenticateInteractive())
}

func (s *Session) AuthenticateAuto(keys []types.PublicKey) witTypes.Result[witTypes.Unit, string] {
	return unit(s.eng.AuthenticateAuto(engineKeys(keys)))
}

func (s *Session) PendingSignature() witTypes.Option[types.SignRequest] {
	req := s.eng.PendingSignature()
	if req == nil {
		return witTypes.None[types.SignRequest]()
	}
	return witTypes.Some(types.SignRequest{
		Key:  types.PublicKey{Algorithm: req.Key.Algorithm, Blob: req.Key.Blob},
		Data: req.Data,
	})
}

func (s *Session) ProvideSignature(sig types.Signature) witTypes.Result[witTypes.Unit, string] {
	return unit(s.eng.ProvideSignature(core.Signature{
		Format:  sig.Format,
		Blob:    sig.Blob,
		Trailer: sig.Trailer,
	}))
}

func (s *Session) FailSignature(reason string) { s.eng.FailSignature(reason) }

func (s *Session) PendingPrompts() witTypes.Option[types.PromptBatch] {
	batch := s.eng.PendingPrompts()
	if batch == nil {
		return witTypes.None[types.PromptBatch]()
	}
	prompts := make([]types.Prompt, len(batch.Prompts))
	for i, p := range batch.Prompts {
		prompts[i] = types.Prompt{Text: p.Text, Echo: p.Echo}
	}
	return witTypes.Some(types.PromptBatch{Instruction: batch.Instruction, Prompts: prompts})
}

func (s *Session) AnswerPrompts(answers []string) witTypes.Result[witTypes.Unit, string] {
	return unit(s.eng.AnswerPrompts(answers))
}

// --- the terminal plane -----------------------------------------------

func (s *Session) WriteInput(data []uint8) { s.eng.WriteInput(data) }

func (s *Session) DrainOutput() []uint8 { return s.eng.DrainOutput() }

func (s *Session) Resize(cols uint16, rows uint16) { s.eng.Resize(cols, rows) }

func (s *Session) Exited() bool { return s.eng.Exited() }

func (s *Session) ExitStatus() witTypes.Option[int32] {
	code := s.eng.ExitStatus()
	if code == nil {
		return witTypes.None[int32]()
	}
	return witTypes.Some(*code)
}

func (s *Session) Close() { s.eng.Close() }

// engineKeys translates the offered key records; an empty list stays
// empty, which is how `authenticate-auto` says "do not offer
// publickey" now that the option wrapper is gone.
func engineKeys(keys []types.PublicKey) []core.PublicKey {
	out := make([]core.PublicKey, len(keys))
	for i, k := range keys {
		out[i] = core.PublicKey{Algorithm: k.Algorithm, Blob: k.Blob}
	}
	return out
}

// unit maps a Go error onto the WIT `result<_, string>` every
// fallible export returns.
func unit(err error) witTypes.Result[witTypes.Unit, string] {
	if err != nil {
		return witTypes.Err[witTypes.Unit, string](err.Error())
	}
	return witTypes.Ok[witTypes.Unit, string](witTypes.Unit{})
}
