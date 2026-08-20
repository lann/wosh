//! Spike: ratatui on wasi 0.3 with NO forked crates.
//!
//! - istty comes from `wasi:cli/terminal-stdin@0.3.0#get-terminal-stdin`
//!   (and the stdout/stderr twins) via the stock `wasip3` bindings crate.
//! - Rendering is a custom `ratatui_core::backend::Backend` that emits
//!   ANSI over std::io::Stdout. No termios anywhere: WASI 0.3 has no raw
//!   mode and no size query, so size falls back to COLUMNS/LINES.

use std::io::{self, Write};

use ratatui::backend::{Backend, ClearType, WindowSize};
use ratatui::layout::{Position, Size};
use ratatui::style::{Color, Modifier};

/// ANSI-escape backend over any `Write`. The only platform assumptions
/// are "the peer understands ECMA-48" -- exactly what a pty/xterm.js on
/// the host side of a wasi component provides.
struct WasiAnsiBackend<W: Write> {
    writer: W,
    /// Last position we *set*; DSR round-trips need an input loop that
    /// WASI 0.3 stdin can serve, but that is out of scope for the spike.
    cursor_pos: Position,
}

impl<W: Write> WasiAnsiBackend<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            cursor_pos: Position::ORIGIN,
        }
    }

    fn sgr_color(buf: &mut String, c: Color, fg: bool) {
        use std::fmt::Write as _;
        let base = if fg { 30 } else { 40 };
        match c {
            Color::Reset => write!(buf, ";{}", base + 9).unwrap(),
            Color::Black => write!(buf, ";{base}").unwrap(),
            Color::Red => write!(buf, ";{}", base + 1).unwrap(),
            Color::Green => write!(buf, ";{}", base + 2).unwrap(),
            Color::Yellow => write!(buf, ";{}", base + 3).unwrap(),
            Color::Blue => write!(buf, ";{}", base + 4).unwrap(),
            Color::Magenta => write!(buf, ";{}", base + 5).unwrap(),
            Color::Cyan => write!(buf, ";{}", base + 6).unwrap(),
            Color::Gray => write!(buf, ";{}", base + 7).unwrap(),
            Color::DarkGray => write!(buf, ";{}", base + 60).unwrap(),
            Color::LightRed => write!(buf, ";{}", base + 61).unwrap(),
            Color::LightGreen => write!(buf, ";{}", base + 62).unwrap(),
            Color::LightYellow => write!(buf, ";{}", base + 63).unwrap(),
            Color::LightBlue => write!(buf, ";{}", base + 64).unwrap(),
            Color::LightMagenta => write!(buf, ";{}", base + 65).unwrap(),
            Color::LightCyan => write!(buf, ";{}", base + 66).unwrap(),
            Color::White => write!(buf, ";{}", base + 67).unwrap(),
            Color::Indexed(i) => write!(buf, ";{};5;{i}", base + 8).unwrap(),
            Color::Rgb(r, g, b) => write!(buf, ";{};2;{r};{g};{b}", base + 8).unwrap(),
        }
    }
}

impl<W: Write> Backend for WasiAnsiBackend<W> {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
    {
        for (x, y, cell) in content {
            // Unconditional reset+restyle per cell: correct, not optimal.
            let mut sgr = String::from("0");
            let m = cell.modifier;
            if m.contains(Modifier::BOLD) {
                sgr.push_str(";1");
            }
            if m.contains(Modifier::DIM) {
                sgr.push_str(";2");
            }
            if m.contains(Modifier::ITALIC) {
                sgr.push_str(";3");
            }
            if m.contains(Modifier::UNDERLINED) {
                sgr.push_str(";4");
            }
            if m.contains(Modifier::REVERSED) {
                sgr.push_str(";7");
            }
            Self::sgr_color(&mut sgr, cell.fg, true);
            Self::sgr_color(&mut sgr, cell.bg, false);
            write!(
                self.writer,
                "\x1b[{};{}H\x1b[{}m{}",
                y + 1,
                x + 1,
                sgr,
                cell.symbol()
            )?;
        }
        write!(self.writer, "\x1b[0m")
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        write!(self.writer, "\x1b[?25l")
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        write!(self.writer, "\x1b[?25h")
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(self.cursor_pos)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        let pos = position.into();
        self.cursor_pos = pos;
        write!(self.writer, "\x1b[{};{}H", pos.y + 1, pos.x + 1)
    }

    fn clear(&mut self) -> io::Result<()> {
        write!(self.writer, "\x1b[2J")
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        let seq = match clear_type {
            ClearType::All => "\x1b[2J",
            ClearType::AfterCursor => "\x1b[0J",
            ClearType::BeforeCursor => "\x1b[1J",
            ClearType::CurrentLine => "\x1b[2K",
            ClearType::UntilNewLine => "\x1b[0K",
        };
        write!(self.writer, "{seq}")
    }

    /// WASI 0.3 has no terminal-size API (terminal.wit defers it), so:
    /// COLUMNS/LINES env, else 80x24. In wosh the host owns the real
    /// answer and can pass it via env or a custom interface.
    fn size(&self) -> io::Result<Size> {
        let dim = |k: &str, dflt: u16| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(dflt)
        };
        Ok(Size::new(dim("COLUMNS", 80), dim("LINES", 24)))
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: self.size()?,
            pixels: Size::new(0, 0),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// terminput's `Event::parse_from` parses a leading event, tolerates
/// trailing bytes, and reports "incomplete" -- but not a consumed byte
/// count. So: shortest parseable prefix wins (n=1 upward), which is
/// correct because escape sequences return incomplete (not Some) until
/// their terminator arrives. One exception: a lone ESC parses as the Esc
/// key at n=1, so while continuation bytes exist we start at n=2 --
/// ESC+tail then resolves as the sequence or as Alt+char, matching
/// crossterm. An ESC that ends the chunk is treated as the Esc key,
/// wrong only when a read() boundary splits a sequence (crossterm
/// disambiguates with an is-more-input-pending flag; same caveat here).
fn drain_events(pending: &mut Vec<u8>, out: &mut Vec<terminput::Event>) {
    use terminput::Event;
    while !pending.is_empty() {
        let start = if pending[0] == 0x1b && pending.len() > 1 { 2 } else { 1 };
        let mut consumed = 0;
        for n in start..=pending.len() {
            if let Ok(Some(ev)) = Event::parse_from(&pending[..n]) {
                out.push(ev);
                consumed = n;
                break;
            }
        }
        if consumed == 0 {
            match Event::parse_from(pending) {
                // Incomplete prefix of a valid sequence: await more bytes.
                Ok(None) => return,
                // Unparseable head: skip one byte and retry.
                _ => {
                    pending.remove(0);
                }
            }
        } else {
            pending.drain(..consumed);
        }
    }
}

fn describe(ev: &terminput::Event) -> String {
    use terminput::{Event, KeyCode};
    match ev {
        Event::Key(k) => {
            let mut s = String::new();
            if k.modifiers.intersects(terminput::KeyModifiers::CTRL) {
                s.push_str("Ctrl+");
            }
            if k.modifiers.intersects(terminput::KeyModifiers::ALT) {
                s.push_str("Alt+");
            }
            match k.code {
                KeyCode::Char(c) => s.push(c),
                code => s.push_str(&format!("{code:?}")),
            }
            s
        }
        other => format!("{other:?}"),
    }
}

fn main() {
    use std::io::Read;

    // Half 1: istty straight from the wasi 0.3 imports.
    let stdin_tty = wasip3::cli::terminal_stdin::get_terminal_stdin().is_some();
    let stdout_tty = wasip3::cli::terminal_stdout::get_terminal_stdout().is_some();
    let stderr_tty = wasip3::cli::terminal_stderr::get_terminal_stderr().is_some();

    // Half 2: a ratatui frame through the ANSI backend, redrawn per
    // input event decoded by terminput. Quit: q, Ctrl+C, or EOF.
    let backend = WasiAnsiBackend::new(io::stdout());
    let mut term = ratatui::Terminal::new(backend).unwrap();
    let mut events: Vec<terminput::Event> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut quit = false;

    loop {
        term.draw(|f| {
            use ratatui::style::Style;
            use ratatui::widgets::{Block, Borders, Paragraph};
            let mut lines = vec![format!(
                "istty via wasi:cli@0.3.0 -- stdin: {stdin_tty}  stdout: {stdout_tty}  stderr: {stderr_tty}",
            )];
            let recent: Vec<String> = events.iter().rev().take(8).map(describe).collect();
            lines.push(format!("keys (terminput): {}", recent.join("  ")));
            lines.push("q / Ctrl+C / EOF quits".to_string());
            let p = Paragraph::new(lines.join("\n"))
                .style(Style::new().bold())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("ratatui + terminput on wasip3 (no forks)"),
                );
            f.render_widget(p, f.area());
        })
        .unwrap();
        term.backend_mut().flush().unwrap();

        if quit {
            break;
        }

        let mut buf = [0u8; 1024];
        // Blocking read on std stdin (wasi 0.2 streams under the hood;
        // the p3-native path would be an async stream read instead).
        let n = io::stdin().lock().read(&mut buf).unwrap_or(0);
        if n == 0 {
            break; // EOF
        }
        pending.extend_from_slice(&buf[..n]);
        let before = events.len();
        drain_events(&mut pending, &mut events);
        for ev in &events[before..] {
            use terminput::{Event, KeyCode, KeyModifiers};
            if let Event::Key(k) = ev {
                let ctrl_c = k.code == KeyCode::Char('c')
                    && k.modifiers.intersects(KeyModifiers::CTRL);
                if ctrl_c || (k.code == KeyCode::Char('q') && k.modifiers.is_empty()) {
                    quit = true;
                }
            }
        }
    }

    // Park the cursor under the frame, then emit a plain-text summary of
    // everything terminput decoded (assertion target for the test run).
    let h = term.size().unwrap().height;
    print!("\x1b[{};1H", h.min(6) + 1);
    let decoded: Vec<String> = events.iter().map(|e| describe(e)).collect();
    println!("decoded: {}", decoded.join(" "));
    io::stdout().flush().unwrap();
}
