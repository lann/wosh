// Package core is the sans-I/O SSH client engine behind
// `wosh:ssh-core/core`: `golang.org/x/crypto/ssh` (well-vetted, in
// wide production use) wrapped as a pure byte-and-tick machine. It
// performs NO I/O and holds NO private keys.
//
// It is a plain Go package on purpose. The componentize-go-generated
// export package is a thin shim over this type, which keeps the whole
// state machine -- host-key gate, credential latching, prompt
// batches, the parked signer -- testable with ordinary `go test`
// against a real x/crypto/ssh server (see core_test.go). That split
// mirrors client-go's generated-glue-vs-logic layout.
//
// Shape, inherited from wosh's M7 engine: the blocking ssh stack runs
// on goroutines parked on an in-memory conn and on channels, every
// entry point returns promptly, and the embedder drives progress by
// feeding bytes and running bounded scheduler rounds. Parked
// goroutines survive across export calls. x/crypto/ssh's client path
// is timer-free, so no wall-time coupling exists beyond the peer's own
// responses.
package core

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// State enumerates the readable session states; it maps 1:1 onto the
// `status` variant in wit/core.wit.
type State int

const (
	StateConnecting State = iota
	StateHostKeyCheck
	StateAuthenticating
	StateSigning
	StateAuthPrompts
	StateReady
	StateClosed
)

// Prompt mirrors the WIT `prompt` record.
type Prompt struct {
	Text string
	Echo bool
}

// PromptBatch mirrors the WIT `prompt-batch` record.
type PromptBatch struct {
	Instruction string
	Prompts     []Prompt
}

// PublicKey mirrors the WIT `public-key` record: a key offered for
// publickey authentication, in the two parts SSH actually puts on the
// wire.
//
// This engine is deliberately ignorant of key ALGEBRA: it never parses
// Blob, never holds a private half, and cannot check a signature it
// relays. It only needs the two strings RFC 4252 s7 asks of it, which
// is why a new algorithm is an embedder change and not a change here.
//
// The two fields usually carry the same name, which is exactly why it
// is worth spelling out that they are not the same THING. Algorithm
// names the SIGNATURE and rides the userauth request (and the blob
// that gets signed); Blob encodes the KEY and carries its own name
// inside. OpenSSH's browser-webauthn algorithm is the case that
// separates them: a plain `sk-ecdsa-sha2-nistp256@openssh.com` key
// blob -- exactly what sits in authorized_keys -- is offered under the
// algorithm `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, because the
// bytes the browser signs are shaped by WebAuthn rather than by SSH.
// sshd resolves the algorithm name and compares it against the name
// inside the signature, so getting the pairing backwards is rejected:
// the split is load-bearing, not cosmetic.
type PublicKey struct {
	// The public key algorithm name for the userauth request: the
	// name the SIGNATURE will carry.
	Algorithm string
	// The public key blob (RFC 4253 s6.6): length-prefixed name
	// followed by algorithm-specific fields. Opaque here.
	Blob []byte
}

// Signature mirrors the WIT `signature` record: a finished signature
// in the three parts an SSH signature blob is built from -- `string
// format`, `string blob`, then whatever the algorithm appends.
//
// Trailer exists for the security-key algorithms, which hang extra
// fields off the end of the standard two (authenticator flags, the
// signature counter, and for webauthn the origin and clientData the
// browser signed). It is appended verbatim, already SSH-encoded by
// whoever produced the signature; for every ordinary algorithm it is
// empty. x/crypto/ssh's ssh.Signature.Rest field is `ssh:"rest"`-
// tagged and exists for precisely this, so no fork is needed.
type Signature struct {
	// The signature algorithm name, which must be the Algorithm of
	// the key this signature answers for.
	Format string
	// The algorithm's own signature encoding (for Ed25519 the raw 64
	// bytes; for ECDSA an `mpint r, mpint s` pair).
	Blob []byte
	// Extra algorithm-specific fields, SSH-encoded, appended after
	// Blob. Empty for everything but the security-key algorithms.
	Trailer []byte
}

// SignRequest mirrors the WIT `sign-request` record: the bytes to
// sign, and the key they are to be signed for.
//
// The key rides along because an embedder may offer more than one (a
// browser key and a passkey, say), and only it knows which keeper
// holds which private half. Key is one of the records handed to
// AuthenticatePublickey or AuthenticateAuto, echoed back verbatim.
type SignRequest struct {
	// Which offered key the server accepted and now wants proof of.
	Key PublicKey
	// The SSH publickey-auth signature blob (session id, user,
	// service, algorithm, public key) to sign, verbatim. Not a hash:
	// hashing, if the algorithm wants any, belongs to the signer.
	Data []byte
}

// hostKeyNotConfirmed is the exact message every authenticate-* entry
// point returns before the host-key gate resolves. It is part of the
// observable contract (the embedder surfaces it verbatim), so it lives
// in one place.
const hostKeyNotConfirmed = "the host key fingerprint has not been confirmed yet -- " +
	"credentials are never sent to an unapproved server"

// credential is what the embedder supplied via an Authenticate* call.
type credential struct {
	kind     string // "password" | "publickey" | "keyboard-interactive" | "auto"
	password string
	// publickey / auto: the parked external signers, one per offered
	// key, in offer order. Empty when no key was offered.
	signers []ssh.Signer
	// The same keys as records, kept only so a decline can name what
	// was offered. Signers deliberately expose no way back to them.
	keys []PublicKey
}

// offers reports whether this credential lets `method` proceed: the
// method the embedder chose explicitly, or every method under "auto",
// where the server steers selection (x/crypto walks the registered
// methods in config order, constrained to the server's
// methods-that-can-continue list).
func (c credential) offers(method string) bool {
	return c.kind == method || c.kind == "auto"
}

// Engine is the whole session. One per `session` resource.
type Engine struct {
	conn *shuttleConn

	mu         sync.Mutex
	state      State
	closeMsg   string
	hostFP     string // "SHA256:..." as `ssh-keygen -lf` prints it
	wireReason string // set by WireBroken; wins over derived close messages
	exitCode   *int32
	exited     bool
	user       string // login user, for the auto-mode password prompt text

	client    *ssh.Client
	sshSess   *ssh.Session
	stdinPipe io.Writer

	// The host-key callback parks here until the embedder rules on
	// the fingerprint. x/crypto/ssh runs authentication strictly
	// after that callback returns, which makes "nothing is sent
	// before the user approves" structural rather than merely
	// intended.
	hostKeyDecision chan bool
	decisionOnce    sync.Once
	// confirmed is latched (under mu) by ConfirmHostKey(true) ITSELF,
	// not by the ssh goroutine it wakes: supplyCreds gates on it, and
	// the gate must be observable the instant the confirm export
	// returns. Gating on s.state instead would race the woken
	// goroutine's state update against the embedder's next call --
	// the embedder legitimately calls authenticate-* immediately
	// after confirm-host-key returns.
	confirmed bool

	// Set once the publickey callback has handed the offered keys to
	// x/crypto, so a later method's decline can tell "the server
	// refused the key" from "the server never asked for one".
	keysOffered bool

	// Latched credentials. The auth callbacks park on credsReady,
	// which closes exactly once when an Authenticate* call lands.
	creds      credential
	credsReady chan struct{}
	credsOnce  sync.Once

	// Keyboard-interactive (and auto's password round): the callback
	// publishes the batch it is parked on here (nil = none pending)
	// and receives answers over promptAnswers. Strictly alternating
	// -- x/crypto runs one auth method at a time on one auth
	// goroutine, so there is never more than one batch in flight --
	// so a 1-buffered channel serves every round. The send happens
	// under mu with promptsClosed checked, and teardown closes under
	// the same mu: a send can never race the close.
	batch         *PromptBatch
	promptAnswers chan []string
	promptsClosed bool // guarded by mu
	promptsOnce   sync.Once

	// The external signer's park-and-poll surface: the bytes awaiting
	// a signature, and the reply channel the embedder resolves.
	sigRequest *SignRequest // guarded by mu; non-nil exactly while parked
	sigReply   chan sigReply
	sigClosed  bool // guarded by mu
	sigOnce    sync.Once

	out       lockedBuf // pty output awaiting the embedder
	pendingIn lockedBuf // input typed before the shell's stdin existed

	cols, rows uint16
	// The command to run in place of the default shell (RFC 4254
	// s6.5 `exec` vs `shell`), empty for a plain interactive shell.
	// See wit/core.wit's `connect` doc for the create-or-attach
	// session manager rationale.
	command string
}

// New constructs the session and starts the handshake goroutine. It
// never fails: everything the embedder can learn arrives through
// Status. The client version banner is drainable as soon as this
// returns, which the scheduler rounds below guarantee.
//
// command, when non-empty, is run via an `exec` request instead of
// the default `shell` request once authenticated -- see run() and the
// `connect` doc in wit/core.wit.
func New(user string, cols, rows uint16, command string) *Engine {
	s := &Engine{
		conn:            newShuttleConn(),
		state:           StateConnecting,
		user:            strings.Clone(user),
		hostKeyDecision: make(chan bool, 1),
		credsReady:      make(chan struct{}),
		promptAnswers:   make(chan []string, 1),
		sigReply:        make(chan sigReply, 1),
		cols:            cols,
		rows:            rows,
		command:         strings.Clone(command),
	}
	// The ssh lifecycle runs on its own goroutine so this entry point
	// can return: the embedder must observe `host-key-check` and show
	// the fingerprint while the handshake sits parked mid-kex.
	go s.run()
	gosched(8) // let the goroutine emit the client version banner
	return s
}

func (s *Engine) setState(st State, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateClosed { // terminal and latched
		return
	}
	s.state = st
	if msg != "" {
		s.closeMsg = msg
	}
}

// closeWith moves to the terminal state. A recorded wire failure wins
// over whatever the ssh stack derived from it: "connection lost" is
// the true cause, and the EOF the mux reports is only its shadow.
func (s *Engine) closeWith(msg string) {
	s.mu.Lock()
	if s.state != StateClosed {
		if s.wireReason != "" {
			msg = s.wireReason
		}
		s.state = StateClosed
		s.closeMsg = msg
	}
	s.mu.Unlock()
}

// run drives the whole ssh lifecycle: handshake (parking at the
// host-key gate), authentication, then pty + shell.
func (s *Engine) run() {
	cfg := &ssh.ClientConfig{
		User: s.user,
		// Every method is registered up front because x/crypto/ssh
		// snapshots its config before the handshake. Their callbacks
		// park until the embedder supplies a credential, and each
		// declines unless the credential offers it -- the kind the
		// embedder chose, or any of them under "auto" (x/crypto
		// records a declining method's error and moves on to the
		// next; which methods run at all, and in what order, is its
		// negotiation with the server over this
		// publickey-password-interactive list).
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(s.publicKeysCallback),
			ssh.PasswordCallback(s.passwordCallback),
			ssh.KeyboardInteractive(s.keyboardInteractiveCallback),
		},
		HostKeyCallback: s.hostKeyCallback,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(s.conn, "wosh-tunnel:22", cfg)
	if err != nil {
		s.closeWith("ssh: " + err.Error())
		return
	}
	s.mu.Lock()
	s.client = ssh.NewClient(sshConn, chans, reqs)
	client := s.client
	s.mu.Unlock()

	sess, err := client.NewSession()
	if err != nil {
		s.closeWith("open session channel: " + err.Error())
		return
	}
	s.mu.Lock()
	s.sshSess = sess
	s.mu.Unlock()
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		s.closeWith("stdin pipe: " + err.Error())
		return
	}
	sess.Stdout = &s.out
	sess.Stderr = &s.out

	s.mu.Lock()
	cols, rows := s.cols, s.rows
	s.mu.Unlock()
	if err := sess.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		s.closeWith("pty request: " + err.Error())
		return
	}
	s.mu.Lock()
	command := s.command
	s.mu.Unlock()
	if command != "" {
		if err := sess.Start(command); err != nil {
			s.closeWith("exec request: " + err.Error())
			return
		}
	} else {
		if err := sess.Shell(); err != nil {
			s.closeWith("shell request: " + err.Error())
			return
		}
	}

	// Take the live pipe, then flush anything typed before it existed.
	s.mu.Lock()
	s.stdinPipe = stdin
	s.mu.Unlock()
	if buffered := s.pendingIn.drain(); len(buffered) > 0 {
		_, _ = stdin.Write(buffered)
	}

	s.setState(StateReady, "")

	waitErr := sess.Wait() // parks until the shell exits
	code := int32(0)
	ee, isExit := waitErr.(*ssh.ExitError)
	if isExit {
		code = int32(ee.ExitStatus())
	}
	s.mu.Lock()
	s.exited = true
	if waitErr == nil || isExit {
		s.exitCode = &code
	}
	s.mu.Unlock()
	// A clean shell exit is not a wire failure: closeWith still
	// prefers a recorded wire reason, which is what distinguishes
	// "the shell ended" from "the tunnel died under it".
	//
	// The message stays "shell exited" for the exec path too, ON
	// PURPOSE: it marks "the channel's program ended" generically,
	// downstream close-kind classification is structural (on State),
	// not string-matched -- but the string itself is user-visible and
	// its exact spelling is part of the observable contract, so it is
	// not worth forking into "exec exited" for what is, structurally,
	// the same event.
	s.closeWith("shell exited")
}

func (s *Engine) hostKeyCallback(_ string, _ net.Addr, key ssh.PublicKey) error {
	s.mu.Lock()
	s.hostFP = ssh.FingerprintSHA256(key)
	if s.state != StateClosed {
		s.state = StateHostKeyCheck
	}
	s.mu.Unlock()

	accepted, ok := <-s.hostKeyDecision // parks the handshake here
	if !ok || !accepted {
		return fmt.Errorf("host key rejected by the user")
	}
	s.setState(StateAuthenticating, "")
	return nil
}

// waitCreds parks until the embedder supplies a credential.
func (s *Engine) waitCreds() credential {
	<-s.credsReady
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creds
}

func (s *Engine) passwordCallback() (string, error) {
	c := s.waitCreds()
	if !c.offers("password") {
		return "", s.declined(c, "a password")
	}
	if c.kind == "password" {
		return c.password, nil
	}
	// Auto mode latched no password up front -- deliberately: it is
	// collected only once the server has actually steered to password
	// auth, through the same prompt machinery keyboard-interactive
	// uses, so the embedder needs no standing password input.
	answers, err := s.surfacePrompts("", []Prompt{
		{Text: "password for " + s.user + ": ", Echo: false},
	})
	if err != nil {
		return "", err
	}
	// AnswerPrompts enforces one answer per prompt, so answers has
	// exactly one element.
	return answers[0], nil
}

func (s *Engine) publicKeysCallback() ([]ssh.Signer, error) {
	c := s.waitCreds()
	if !c.offers("publickey") {
		return nil, fmt.Errorf("publickey auth not selected")
	}
	if len(c.signers) == 0 {
		// Reached under "auto" when no key was supplied: decline so
		// x/crypto moves on to password / keyboard-interactive.
		return nil, fmt.Errorf("no public key was offered")
	}
	// Note that the keys reached the server, so a later method's
	// decline can say whether they were refused or never tried. Only
	// this callback knows: x/crypto walks the methods the SERVER
	// allows, and an sshd that offers no publickey method never calls
	// this at all.
	s.mu.Lock()
	s.keysOffered = true
	s.mu.Unlock()

	// Every offered key, in order. x/crypto probes them one at a time
	// and only parks this engine's signer for one the server says it
	// will accept, so offering several costs at most one ceremony --
	// which is what lets a passkey fall back to an ordinary key
	// inside a single connection.
	return append([]ssh.Signer(nil), c.signers...), nil
}

// declined explains, as an error, why this engine will not answer the
// method the server just steered to.
//
// It matters more than a decline usually would. x/crypto returns the
// LAST error any auth method produced, so whatever this says becomes
// the whole story of the failure -- and the honest story is almost
// never about the method being declined. The common case by far is a
// server that refused the offered key (no matching authorized_keys
// line, or an algorithm it has not enabled) and then asked for a
// password; blaming the password there sends the user looking in
// exactly the wrong place.
func (s *Engine) declined(c credential, method string) error {
	s.mu.Lock()
	offered := s.keysOffered
	s.mu.Unlock()

	switch {
	case offered:
		names := make([]string, 0, len(c.keys))
		for _, k := range c.keys {
			names = append(names, k.Algorithm)
		}
		return fmt.Errorf(
			"the server did not accept the offered key (%s), then asked for %s, "+
				"which this session did not offer",
			strings.Join(names, ", "), method)
	case len(c.keys) > 0:
		return fmt.Errorf(
			"the server did not offer publickey authentication, and asked for %s, "+
				"which this session did not offer", method)
	default:
		return fmt.Errorf(
			"the server asked for %s, which this session did not offer", method)
	}
}

// keyboardInteractiveCallback answers RFC 4256 challenges. x/crypto/ssh
// calls it once per server-issued batch, on the auth goroutine; each
// call surfaces the batch through surfacePrompts. The server decides
// how many rounds there are; this runs as often as it calls.
func (s *Engine) keyboardInteractiveCallback(_, instruction string, questions []string, echos []bool) ([]string, error) {
	c := s.waitCreds()
	if !c.offers("keyboard-interactive") {
		return nil, s.declined(c, "keyboard-interactive answers")
	}

	// A batch with no prompts carries nothing to collect (servers use
	// it to signal progress); answer it without an embedder
	// round-trip. Its instruction text is dropped -- a
	// simplification, noted.
	if len(questions) == 0 {
		return nil, nil
	}

	prompts := make([]Prompt, len(questions))
	for i, q := range questions {
		echo := i < len(echos) && echos[i]
		prompts[i] = Prompt{Text: q, Echo: echo}
	}
	return s.surfacePrompts(instruction, prompts)
}

// surfacePrompts publishes one batch for the embedder -- `status`
// flips to auth-prompts -- and PARKS the calling auth goroutine on
// promptAnswers until AnswerPrompts supplies the answers: the exact
// shape of the host-key gate. Both prompt-bearing credential paths
// ride it -- server-issued keyboard-interactive batches, and the
// password auto mode collects -- and they never overlap: x/crypto runs
// one auth method at a time on the one auth goroutine, so the strict
// batch/answer alternation the channel relies on holds by
// construction.
func (s *Engine) surfacePrompts(instruction string, prompts []Prompt) ([]string, error) {
	s.mu.Lock()
	if s.state == StateClosed || s.promptsClosed {
		s.mu.Unlock()
		return nil, fmt.Errorf("session closed")
	}
	s.batch = &PromptBatch{Instruction: instruction, Prompts: prompts}
	s.state = StateAuthPrompts
	s.mu.Unlock()

	answers, ok := <-s.promptAnswers // parks the auth exchange here
	if !ok {
		return nil, fmt.Errorf("session dropped while prompts were pending")
	}
	return answers, nil
}

// supplyCreds latches a credential and releases the parked auth
// callbacks. It RETURNS IMMEDIATELY; the embedder polls Status until
// ready or closed. Authentication itself proceeds on later feed/pump
// ticks, when the server's replies arrive.
func (s *Engine) supplyCreds(c credential) error {
	s.mu.Lock()
	confirmed := s.confirmed
	s.mu.Unlock()
	// Gate on the latched verdict, NOT on s.state: the state is
	// advanced by the ssh goroutine after it wakes from the decision
	// channel, so it lags ConfirmHostKey's return by a scheduling
	// handoff. The flag is set synchronously inside that call, which
	// makes "confirm resolved, then authenticate" -- the only
	// ordering a caller can honor -- sufficient by construction.
	if !confirmed {
		return fmt.Errorf("%s", hostKeyNotConfirmed)
	}

	s.mu.Lock()
	s.creds = c
	s.mu.Unlock()
	s.credsOnce.Do(func() { close(s.credsReady) })
	gosched(16)
	return nil
}

// AuthenticatePassword backs `authenticate-password`.
func (s *Engine) AuthenticatePassword(password string) error {
	// Clone: the bindings hand over a zero-copy view of transferred
	// cabi memory that is recycled once the export returns, and the
	// auth goroutine reads it strictly after that.
	return s.supplyCreds(credential{kind: "password", password: strings.Clone(password)})
}

// AuthenticatePublickey backs `authenticate-publickey`: offer `keys`,
// in order. The private halves deliberately live outside this
// component (see signer.go). An empty offer is a caller mistake, not
// an authentication attempt, so it fails synchronously -- before
// anything is latched.
func (s *Engine) AuthenticatePublickey(keys []PublicKey) error {
	signers, offered, err := s.offerSigners(keys)
	if err != nil {
		return err
	}
	if len(signers) == 0 {
		return fmt.Errorf("no public key was offered: publickey auth needs at least one key")
	}
	return s.supplyCreds(credential{kind: "publickey", signers: signers, keys: offered})
}

// AuthenticateInteractive backs `authenticate-interactive`.
func (s *Engine) AuthenticateInteractive() error {
	return s.supplyCreds(credential{kind: "keyboard-interactive"})
}

// AuthenticateAuto backs `authenticate-auto`: offer every method and
// let the server steer. `keys` may be empty, which simply declines to
// offer publickey -- the publickey method then declines itself and the
// server steers to password / keyboard-interactive.
func (s *Engine) AuthenticateAuto(keys []PublicKey) error {
	signers, offered, err := s.offerSigners(keys)
	if err != nil {
		return err
	}
	return s.supplyCreds(credential{kind: "auto", signers: signers, keys: offered})
}

// offerSigners validates and clones the offered key records, then
// wraps each as a parked external signer. It validates EVERY key
// before latching anything: a rejected offer must leave the session
// exactly as it found it, free to be authenticated properly later.
func (s *Engine) offerSigners(keys []PublicKey) ([]ssh.Signer, []PublicKey, error) {
	signers := make([]ssh.Signer, 0, len(keys))
	cloned := make([]PublicKey, 0, len(keys))
	for i, k := range keys {
		if k.Algorithm == "" {
			return nil, nil, fmt.Errorf("public key %d has an empty algorithm name", i)
		}
		if len(k.Blob) == 0 {
			return nil, nil, fmt.Errorf("public key %d (%s) has an empty key blob", i, k.Algorithm)
		}
		// Clone: the bindings hand over zero-copy views of transferred
		// cabi memory that is recycled once the export returns, and
		// the auth goroutine reads these strictly after that.
		key := PublicKey{
			Algorithm: strings.Clone(k.Algorithm),
			Blob:      append([]byte(nil), k.Blob...),
		}
		cloned = append(cloned, key)
		signers = append(signers, s.newSigner(key))
	}
	return signers, cloned, nil
}

// PendingPrompts backs `pending-prompts`.
func (s *Engine) PendingPrompts() *PromptBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batch == nil {
		return nil
	}
	cp := PromptBatch{
		Instruction: s.batch.Instruction,
		Prompts:     append([]Prompt(nil), s.batch.Prompts...),
	}
	return &cp
}

// AnswerPrompts latches the embedder's answers and releases the parked
// challenge callback. Same contract as the credential entry points: it
// RESOLVES AT ONCE and the caller polls Status.
func (s *Engine) AnswerPrompts(answers []string) error {
	// Clone deeply: the bindings hand over zero-copy views of
	// transferred cabi memory that is recycled once the export
	// returns, and these strings are consumed by the auth goroutine
	// strictly after that.
	cp := make([]string, len(answers))
	for i, a := range answers {
		cp[i] = strings.Clone(a)
	}

	s.mu.Lock()
	if s.promptsClosed {
		s.mu.Unlock()
		return fmt.Errorf("session closed")
	}
	batch := s.batch
	if batch == nil {
		s.mu.Unlock()
		return fmt.Errorf("no prompt batch is pending")
	}
	if len(cp) != len(batch.Prompts) {
		n := len(batch.Prompts)
		s.mu.Unlock()
		return fmt.Errorf("answer count mismatch: %d answers for %d prompts", len(cp), n)
	}
	s.batch = nil
	if s.state == StateAuthPrompts {
		s.state = StateAuthenticating
	}
	// Buffered (capacity 1) and strictly alternating with the
	// callback's receive, so this send never blocks; done under mu so
	// it cannot race the close in Close().
	s.promptAnswers <- cp
	s.mu.Unlock()

	gosched(16)
	return nil
}

// --- the byte plane --------------------------------------------------

// Feed backs `feed`.
func (s *Engine) Feed(data []byte) {
	// Clone: retained across the export boundary by the shuttle's
	// inbox, read well after the call returns.
	cp := make([]byte, len(data))
	copy(cp, data)
	s.conn.push(cp)
	gosched(16)
}

// Drain backs `drain`.
func (s *Engine) Drain() []byte {
	gosched(4)
	return s.conn.drainOutbox()
}

// Pump backs `pump`.
func (s *Engine) Pump() {
	gosched(16)
}

// WireBroken backs `wire-broken`: the transport is gone. Breaking the
// shuttle's reads is what unwinds the ssh stack, but a goroutine
// parked on one of the control-plane gates is not reading the wire at
// all -- it would sit there forever waiting for an answer that can no
// longer matter. So every gate is failed too, and the recorded reason
// becomes the close message.
func (s *Engine) WireBroken(reason string) {
	reason = strings.Clone(reason)
	s.mu.Lock()
	if s.wireReason == "" {
		s.wireReason = reason
	}
	s.mu.Unlock()

	s.conn.breakWire(fmt.Errorf("%s: %w", reason, io.ErrUnexpectedEOF))
	s.failGates()
	gosched(16)
	s.closeWith(reason)
}

// failGates releases every park-and-poll surface exactly once, so no
// goroutine is left waiting on an answer that will never come.
func (s *Engine) failGates() {
	s.decisionOnce.Do(func() { close(s.hostKeyDecision) })
	s.credsOnce.Do(func() { close(s.credsReady) })
	s.promptsOnce.Do(func() {
		s.mu.Lock()
		s.promptsClosed = true
		s.batch = nil
		close(s.promptAnswers)
		s.mu.Unlock()
	})
	s.sigOnce.Do(func() {
		s.mu.Lock()
		s.sigClosed = true
		s.sigRequest = nil
		close(s.sigReply)
		s.mu.Unlock()
	})
}

// --- the control plane ------------------------------------------------

// Status backs `status`; the second result is meaningful only for
// StateClosed.
func (s *Engine) Status() (State, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.closeMsg
}

// HostKeySha256 backs `host-key-sha256`; "" means none yet.
func (s *Engine) HostKeySha256() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostFP
}

// ConfirmHostKey backs `confirm-host-key`. The first verdict wins, and
// an accepting one is latched under mu INSIDE the once -- before the
// parked handshake goroutine is woken -- so it is already visible to
// supplyCreds by the time this returns.
func (s *Engine) ConfirmHostKey(accept bool) {
	s.decisionOnce.Do(func() {
		if accept {
			s.mu.Lock()
			s.confirmed = true
			s.mu.Unlock()
		}
		s.hostKeyDecision <- accept // buffered: never blocks the caller
		close(s.hostKeyDecision)
	})
	gosched(16)
}

// --- the terminal plane -----------------------------------------------

// WriteInput backs `write-input`. Bytes arriving before the shell's
// stdin exists are buffered and flushed to it in order.
func (s *Engine) WriteInput(data []byte) {
	// Clone: the bindings hand over a zero-copy view of transferred
	// cabi memory that is recycled once the export returns.
	cp := make([]byte, len(data))
	copy(cp, data)

	s.mu.Lock()
	pipe := s.stdinPipe
	s.mu.Unlock()
	if pipe != nil {
		_, _ = pipe.Write(cp)
	} else {
		s.pendingIn.Write(cp)
	}
	gosched(8)
}

// DrainOutput backs `drain-output`.
func (s *Engine) DrainOutput() []byte {
	gosched(4)
	return s.out.drain()
}

// Resize backs `resize`. Before the shell exists this only updates the
// size the eventual RequestPty will use.
func (s *Engine) Resize(cols, rows uint16) {
	s.mu.Lock()
	s.cols, s.rows = cols, rows
	sess := s.sshSess
	s.mu.Unlock()
	if sess != nil {
		_ = sess.WindowChange(int(rows), int(cols))
	}
	gosched(8)
}

// Exited backs `exited`.
func (s *Engine) Exited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exited || s.state == StateClosed
}

// ExitStatus backs `exit-status`; nil means not known.
func (s *Engine) ExitStatus() *int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exitCode == nil {
		return nil
	}
	code := *s.exitCode
	return &code
}

// Close backs `close` (and the resource destructor): fail every parked
// gate, close the ssh stack, and go terminal. The scheduler rounds at
// the end let the unwinding goroutines observe the teardown rather
// than parking forever -- harmless either way, but tidy.
func (s *Engine) Close() {
	s.failGates()
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	_ = s.conn.Close()
	gosched(16)
	s.closeWith("session closed")
}
