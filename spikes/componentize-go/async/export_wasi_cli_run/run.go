package export_wasi_cli_run

import (
	witTypes "go.bytecodealliance.org/pkg/wit/types"
)

// Run satisfies the wasi:cli/command include; the probe's real surface is
// experiment:spike/async-probes.
func Run() witTypes.Result[struct{}, struct{}] {
	return witTypes.Ok[struct{}, struct{}](struct{}{})
}
