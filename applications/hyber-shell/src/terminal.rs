//! Hosted terminal adapter only. Editing/history decisions live in Controller.
use hyber_shell::{
    input::{Controller, Event, Outcome},
    profiles::Profiles,
};
use std::io::{self, Write};

struct Raw(libc::termios);
impl Raw {
    fn enter() -> io::Result<Self> {
        let mut old = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr initializes the supplied termios on success.
        if unsafe { libc::tcgetattr(0, old.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let old = unsafe { old.assume_init() };
        let mut raw = old;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(old))
    }
}
impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: the saved termios belongs to stdin and remains initialized.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.0);
        }
        let _ = io::stdout().write_all(b"\x1b[?2004l\r\n");
        let _ = io::stdout().flush();
    }
}
/// Read directly from the terminal fd. `std::io::Stdin` may buffer several
/// keys, while `poll(2)` only sees bytes still in the kernel queue; mixing the
/// two makes adjacent CSI sequences such as Up/Up/Down unreliable.
fn byte() -> io::Result<Option<u8>> {
    let mut b = [0];
    // SAFETY: fd 0 is the shell's stdin and `b` is a valid one-byte output
    // buffer for the duration of this syscall.
    match unsafe { libc::read(0, b.as_mut_ptr().cast(), b.len()) } {
        0 => Ok(None),
        1 => Ok(Some(b[0])),
        _ if std::io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => byte(),
        _ => Err(io::Error::last_os_error()),
    }
}
/// Escape sequences can be fragmented by a terminal multiplexer, remote PTY,
/// or scheduler. A short probe turns a delayed `ESC [ A` into literal
/// `[A` input.  Keep the wait bounded so a literal Escape still cannot stall
/// the shell indefinitely, but long enough for a normal fragmented sequence.
const ESCAPE_SEQUENCE_WAIT_MS: i32 = 300;
const ESCAPE_SEQUENCE_CONTINUATION_WAIT_MS: i32 = 1_000;

fn ready(timeout_ms: i32) -> bool {
    let mut fd = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: a single valid pollfd entry, short bounded timeout.
    unsafe { libc::poll(&mut fd, 1, timeout_ms) > 0 }
}

const KEY_RIGHT: u8 = 0x80;
const KEY_LEFT: u8 = 0x81;
const KEY_HOME: u8 = 0x82;
const KEY_END: u8 = 0x83;
const KEY_DELETE: u8 = 0x84;
const KEY_BRACKETED_PASTE: u8 = 0x85;

fn escape_sequence_complete(sequence: &[u8]) -> bool {
    sequence.len() > 1
        && matches!(
            sequence.last(),
            Some(byte) if byte.is_ascii_alphabetic() || *byte == b'~'
        )
}

fn escape_key(sequence: &[u8]) -> Option<u8> {
    match sequence {
        b"[A" => Some(16),
        b"[B" => Some(14),
        b"[C" => Some(KEY_RIGHT),
        b"[D" => Some(KEY_LEFT),
        b"[H" | b"[1~" => Some(KEY_HOME),
        b"[F" | b"[4~" => Some(KEY_END),
        b"[3~" => Some(KEY_DELETE),
        b"[200~" => Some(KEY_BRACKETED_PASTE),
        _ => None,
    }
}

pub fn read(
    controller: &mut Controller,
    profiles: &mut Profiles,
    prompt: &str,
) -> Result<Option<String>, String> {
    let _raw = Raw::enter().map_err(|e| e.to_string())?;
    let mut out = io::stdout();
    out.write_all(b"\x1b[?2004h").map_err(|e| e.to_string())?;
    let mut search = None;
    // Retain a partially-read CSI sequence across reads. Some PTYs expose
    // `ESC`, `[`, and `A` in separate readiness notifications; discarding the
    // partial `[` was the source of literal `[A` commands.
    let mut pending_escape = Vec::new();
    loop {
        // Position by printing the prefix again, avoiding incorrect byte-based
        // cursor movement for UTF-8/wide glyphs.
        write!(
            out,
            "\r\x1b[2K{prompt}{}\r{prompt}{}",
            controller.buffer(),
            &controller.buffer()[..controller.cursor()]
        )
        .map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
        let Some(mut b) = byte().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        if !pending_escape.is_empty() {
            pending_escape.push(b);
            if !escape_sequence_complete(&pending_escape) {
                if pending_escape.len() >= 8 {
                    pending_escape.clear();
                }
                continue;
            }
            let sequence = std::mem::take(&mut pending_escape);
            let Some(key) = escape_key(&sequence) else {
                continue;
            };
            b = key;
        } else if b == 27 {
            let mut sequence = Vec::new();
            while sequence.len() < 8
                && ready(if sequence.first() == Some(&b'[') {
                    ESCAPE_SEQUENCE_CONTINUATION_WAIT_MS
                } else {
                    ESCAPE_SEQUENCE_WAIT_MS
                })
            {
                let Some(byte) = byte().map_err(|e| e.to_string())? else {
                    break;
                };
                sequence.push(byte);
                if escape_sequence_complete(&sequence) {
                    break;
                }
            }
            if sequence.is_empty() {
                continue;
            }
            if !escape_sequence_complete(&sequence) {
                pending_escape = sequence;
                continue;
            }
            let Some(key) = escape_key(&sequence) else {
                continue;
            };
            b = key;
        }
        let (key, mut event) = match b {
            b'\r' | b'\n' => ("Enter", Event::Submit),
            3 => ("CtrlC", Event::Cancel),
            4 => (
                "CtrlD",
                if controller.buffer().is_empty() {
                    Event::Eof
                } else {
                    Event::Delete
                },
            ),
            1 => ("CtrlA", Event::Home),
            5 => ("CtrlE", Event::End),
            16 => ("CtrlP", Event::Previous),
            14 => ("CtrlN", Event::Next),
            18 => (
                "CtrlR",
                Event::Search(
                    search
                        .get_or_insert_with(|| controller.buffer().to_string())
                        .clone(),
                ),
            ),
            127 | 8 => ("Backspace", Event::Backspace),
            9 => {
                let prefix = controller.buffer().to_string();
                let mut suggestions = profiles.complete(&prefix)?;
                if suggestions.is_empty() {
                    suggestions.extend(
                        profiles
                            .aliases
                            .entries()
                            .keys()
                            .filter(|k| k.starts_with(&prefix))
                            .cloned(),
                    );
                }
                suggestions.sort();
                suggestions.dedup();
                if suggestions.len() == 1 && suggestions[0].starts_with(&prefix) {
                    controller.dispatch(Event::End)?;
                    controller.dispatch(Event::Insert(suggestions[0][prefix.len()..].into()))?;
                } else if !suggestions.is_empty() {
                    write!(out, "\r\n{}\r\n", suggestions.join("  ")).map_err(|e| e.to_string())?;
                }
                continue;
            }
            KEY_RIGHT => ("Right", Event::Right),
            KEY_LEFT => ("Left", Event::Left),
            KEY_HOME => ("Home", Event::Home),
            KEY_END => ("End", Event::End),
            KEY_DELETE => ("Delete", Event::Delete),
            KEY_BRACKETED_PASTE => {
                let mut paste = Vec::new();
                let mut oversized = false;
                let mut tail = Vec::new();
                loop {
                    let Some(c) = byte().map_err(|e| e.to_string())? else {
                        return Ok(None);
                    };
                    tail.push(c);
                    if tail.len() > 6 {
                        tail.remove(0);
                    }
                    if !oversized {
                        paste.push(c);
                        oversized = paste.len() > 4096 + 6;
                    }
                    if tail == b"\x1b[201~" {
                        if !oversized {
                            paste.truncate(paste.len() - 6);
                        }
                        break;
                    }
                }
                // Drain the entire paste before rejecting it: its remaining
                // newlines must never become subsequent command submissions.
                if oversized {
                    return Err("paste too large".into());
                }
                let text = String::from_utf8(paste).map_err(|_| "invalid UTF-8 paste")?;
                // Multiline paste is rejected, never submitted automatically.
                let _ = controller.dispatch(Event::Insert(text));
                continue;
            }
            b if b >= 32 => {
                let count = if b < 128 {
                    1
                } else if b < 224 {
                    2
                } else if b < 240 {
                    3
                } else {
                    4
                };
                let mut bytes = vec![b];
                for _ in 1..count {
                    if let Some(c) = byte().map_err(|e| e.to_string())? {
                        bytes.push(c);
                    }
                }
                let Ok(text) = String::from_utf8(bytes) else {
                    continue;
                };
                ("Text", Event::Insert(text))
            }
            _ => continue,
        };
        if let Some(action) = profiles.bindings.get(key) {
            event = match action.as_str() {
                "previous" => Event::Previous,
                "next" => Event::Next,
                "home" => Event::Home,
                "end" => Event::End,
                "cancel" => Event::Cancel,
                "search" => Event::Search(
                    search
                        .get_or_insert_with(|| controller.buffer().into())
                        .clone(),
                ),
                _ => event,
            };
        }
        if !matches!(event, Event::Search(_)) {
            search = None;
        }
        match controller.dispatch(event) {
            Ok(Outcome::Submitted(line)) => return Ok(Some(line)),
            Ok(Outcome::Eof) => return Ok(None),
            Ok(Outcome::Cancelled) => {
                write!(out, "^C\r\n").map_err(|e| e.to_string())?;
            }
            _ => (),
        }
    }
}
