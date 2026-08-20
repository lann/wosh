# Spike: terminal crates directly against WASI 0.3

Question: can `crossterm` (or another terminal crate) work directly
against wasi 0.3 -- istty via
`wasi:cli/terminal-stdin@0.3.0#get-terminal-stdin` -- without forking
anything?

## Verdict

No stock terminal-manipulation crate compiles for wasi today; they all
hard-assume unix-or-windows. But **ratatui needs none of them**: its
core compiles clean on wasi, and a ~150-line custom `Backend` (ANSI
over stdout) plus the stock `wasip3` crate for istty gives a working
TUI on wasi 0.3 with zero forks. That is what `src/main.rs` proves.

## Crate survey (all stock, `--target wasm32-wasip2`)

| crate | compiles | notes |
|---|---|---|
| crossterm 0.29, `default-features = false` | no (5 errors) | closest: only holes are raw-mode/size in `terminal/sys` + no `IsTty` impl. Default `events` feature adds mio+signal-hook, unportable. |
| termion 4.0.6 | no (5 errors) | whole `sys` module is cfg'd out (`sys/unix`, `sys/redox`); everything routes through it. Cleanest upstream slot for a `sys/wasi/`. |
| termwiz 0.23.3 | no (dies in deps) | unconditional `wezterm-blob-leases -> mac_address` (no wasi backend), `filedescriptor`, `terminfo`, `libc`; no features to cut them. Deepest POSIX assumptions (termios, poll, SIGWINCH, /dev/tty, terminfo db on disk). |
| ratatui 0.30, `default-features = false` | **yes** | pure computation over `Write`; backends are separate crates it doesn't need. |

## What the demo proves (`src/main.rs`)

Built as a normal `wasm32-wasip2` cdylib-less bin; rustc's
wasm-component-ld happily emits a component importing *both*
`wasi:cli/*@0.2.6` (std/libc plumbing) and `wasi:cli/terminal-*@0.3.0`
(from the `wasip3` bindings crate):

- istty: `wasip3::cli::terminal_stdin::get_terminal_stdin().is_some()`
  (and stdout/stderr twins). Plain sync imports, no async ABI involved.
- rendering: custom `ratatui::backend::Backend` emitting ECMA-48 over
  `std::io::Stdout`.

Verified under wasmtime 47 (`wasmtime run`, no flags -- `-S p3`
defaults to on; `-S p3=n` fails to link, proving the istty answers come
from the 0.3.0 imports):

- on a pty: `stdin: true stdout: true stderr: true`, frame renders
- piped: all false

```
cargo build --target wasm32-wasip2
wasmtime run target/wasm32-wasip2/debug/terminal-wasip3-spike.wasm
```

## What WASI 0.3 still cannot express

`wasi:cli` terminal.wit explicitly defers all of these "to the future";
every port would shim them identically:

- **raw mode**: no API. In wosh's deployment the host side of the pipe
  (xterm.js / SSH pty) is already raw; a guest-side no-op is correct.
- **terminal size / resize**: no API. Spike falls back to
  COLUMNS/LINES env, then 80x24. Real answer for wosh: the host owns
  size and can deliver it over `wosh:terminal` (which already exists).
- **input events**: not a WASI gap per se -- read stdin bytes and
  parse. crossterm's parser is cfg-locked behind its unix backend; the
  `vte` crate (pure, no platform deps) is the natural piece for a
  follow-up.

## If upstreaming a wasi backend anyway

crossterm is the smallest diff (one sys module + one `IsTty` impl);
termion is the cleanest structural fit (third `sys/` variant). Neither
is needed for the ratatui path.
