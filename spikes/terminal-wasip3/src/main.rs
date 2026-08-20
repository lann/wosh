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

fn main() {
    // Half 1: istty straight from the wasi 0.3 imports.
    let stdin_tty = wasip3::cli::terminal_stdin::get_terminal_stdin().is_some();
    let stdout_tty = wasip3::cli::terminal_stdout::get_terminal_stdout().is_some();
    let stderr_tty = wasip3::cli::terminal_stderr::get_terminal_stderr().is_some();

    // Half 2: render one ratatui frame through the ANSI backend.
    let backend = WasiAnsiBackend::new(io::stdout());
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| {
        use ratatui::style::Style;
        use ratatui::widgets::{Block, Borders, Paragraph};
        let text = format!(
            "istty via wasi:cli@0.3.0 -- stdin: {stdin_tty}  stdout: {stdout_tty}  stderr: {stderr_tty}",
        );
        let p = Paragraph::new(text)
            .style(Style::new().bold())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("ratatui on wasip3 (no forks)"),
            );
        f.render_widget(p, f.area());
    })
    .unwrap();

    // Park the cursor under the frame so the shell prompt lands sanely.
    let h = term.size().unwrap().height;
    print!("\x1b[{};1H", h.min(6) + 1);
    io::stdout().flush().unwrap();
}
