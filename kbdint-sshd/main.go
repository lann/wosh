// The keyboard-interactive gate fixture: a minimal SSH server whose
// ONLY auth method is keyboard-interactive, driving a scripted
// two-batch challenge (echo and masked prompts, then a second round).
//
// Why not the real OpenSSH sshd the e2e gate already uses? sshd's
// keyboard-interactive backends are PAM and BSDAuth: a user-mode sshd
// on Linux has neither, so it can never issue prompts. x/crypto/ssh's
// server side implements the same RFC 4256 exchange and is the other
// half of the library the client itself uses -- a faithful stand-in
// for verifying the client's prompt plumbing, which is what this gate
// is about (the OpenSSH leg keeps covering transport/pty/publickey).
//
// After authentication the "shell" is a byte echo: whatever the client
// types comes straight back, which is all the smoke-test needs to
// prove the session reached an interactive state.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// The scripted exchange. Two batches: the first mixes an echoed and a
// masked prompt (gating the echo-flag plumbing end to end), the second
// proves multi-round works. Values are obviously synthetic fixtures.
var rounds = []struct {
	instruction string
	prompts     []string
	echos       []bool
	answers     []string
}{
	{
		instruction: "wosh keyboard-interactive gate: scripted round one",
		prompts:     []string{"token code (visible): ", "passphrase (hidden): "},
		echos:       []bool{true, false},
		answers:     []string{"gate-token-123", "gate-passphrase-456"},
	},
	{
		instruction: "",
		prompts:     []string{"second factor: "},
		echos:       []bool{false},
		answers:     []string{"gate-otp-789"},
	},
}

func challenge(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	for i, r := range rounds {
		got, err := client(conn.User(), r.instruction, r.prompts, r.echos)
		if err != nil {
			return nil, err
		}
		if len(got) != len(r.answers) {
			return nil, fmt.Errorf("round %d: %d answers for %d prompts", i+1, len(got), len(r.prompts))
		}
		for j := range r.answers {
			if got[j] != r.answers[j] {
				log.Printf("auth failed for %q: wrong answer in round %d", conn.User(), i+1)
				return nil, fmt.Errorf("keyboard-interactive: wrong answer in round %d", i+1)
			}
		}
	}
	log.Printf("auth ok for %q", conn.User())
	return &ssh.Permissions{}, nil
}

func main() {
	port := flag.Int("port", 2223, "listen port on 127.0.0.1")
	flag.Parse()

	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		log.Fatalf("host signer: %v", err)
	}

	cfg := &ssh.ServerConfig{KeyboardInteractiveCallback: challenge}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	// Parsed by the gate recipe; keep the shapes stable.
	fmt.Printf("fingerprint: %s\n", ssh.FingerprintSHA256(signer.PublicKey()))
	fmt.Printf("listening on 127.0.0.1:%d\n", *port)
	os.Stdout.Sync()

	for {
		tcp, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go serve(tcp, cfg)
	}
}

func serve(tcp net.Conn, cfg *ssh.ServerConfig) {
	defer tcp.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(tcp, cfg)
	if err != nil {
		log.Printf("handshake: %v", err) // includes failed-auth teardowns
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			log.Printf("channel accept: %v", err)
			return
		}
		go func() {
			// Grant what an interactive client asks for; there is no
			// real pty behind it, just the echo loop below.
			for req := range chReqs {
				switch req.Type {
				case "pty-req", "shell", "window-change", "env":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
		go func() {
			_, _ = io.Copy(ch, ch) // the echo "shell"
			_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			_ = ch.Close()
		}()
	}
}
