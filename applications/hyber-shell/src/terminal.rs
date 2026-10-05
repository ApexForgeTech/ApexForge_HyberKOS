//! Hosted terminal adapter only. Editing/history decisions live in Controller.
use hyber_shell::{
    input::{Controller, Event, Outcome},
    profiles::Profiles,
};
use std::io::{self, Read, Write};

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
fn byte(input: &mut impl Read) -> io::Result<Option<u8>> {
    let mut b = [0];
    match input.read(&mut b)? {
        0 => Ok(None),
        _ => Ok(Some(b[0])),
    }
}
fn ready() -> bool {
    let mut fd = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: a single valid pollfd entry, short bounded timeout.
    unsafe { libc::poll(&mut fd, 1, 40) > 0 }
}
pub fn read(
    controller: &mut Controller,
    profiles: &mut Profiles,
    prompt: &str,
) -> Result<Option<String>, String> {
    let _raw = Raw::enter().map_err(|e| e.to_string())?;
    let mut input = io::stdin();
    let mut out = io::stdout();
    out.write_all(b"\x1b[?2004h").map_err(|e| e.to_string())?;
    let mut search = None;
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
        let Some(b) = byte(&mut input).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
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
            27 => {
                let mut seq = Vec::new();
                while seq.len() < 8 && ready() {
                    if let Some(c) = byte(&mut input).map_err(|e| e.to_string())? {
                        seq.push(c);
                        if seq.len() > 1 && (c.is_ascii_alphabetic() || c == b'~') {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                match seq.as_slice() {
                    b"[A" => ("Up", Event::Previous),
                    b"[B" => ("Down", Event::Next),
                    b"[C" => ("Right", Event::Right),
                    b"[D" => ("Left", Event::Left),
                    b"[H" | b"[1~" => ("Home", Event::Home),
                    b"[F" | b"[4~" => ("End", Event::End),
                    b"[3~" => ("Delete", Event::Delete),
                    b"[200~" => {
                        let mut paste = Vec::new();
                        let mut oversized = false;
                        let mut tail = Vec::new();
                        loop {
                            let Some(c) = byte(&mut input).map_err(|e| e.to_string())? else {
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
                    _ => continue,
                }
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
                    if let Some(c) = byte(&mut input).map_err(|e| e.to_string())? {
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
