// Leg (b) of the M1 conformance harness: mosh-go's native server behind
// the same MOSH CONNECT contract as the stock C mosh-server. Prints the
// connect line on stdout and serves in the foreground until killed (or
// the shell exits).
package main

import (
	"fmt"
	"os"

	mosh "github.com/unixshells/mosh-go"
)

func main() {
	shell := os.Getenv("MOSHGO_SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	srv, err := mosh.NewServer(shell, 61000, 61999)
	if err != nil {
		fmt.Fprintln(os.Stderr, "moshgo-server:", err)
		os.Exit(1)
	}

	fmt.Println(srv.ConnectLine())

	if err := srv.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "moshgo-server:", err)
		os.Exit(1)
	}
}
