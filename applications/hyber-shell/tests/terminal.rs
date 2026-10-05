#![cfg(target_os = "linux")]
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::FromRawFd,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn receive(file: &mut File, pending: &mut String, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if let Some(position) = pending.find(needle) {
            let rest = pending.split_off(position + needle.len());
            return std::mem::replace(pending, rest);
        }
        let mut buffer = [0; 8192];
        match file.read(&mut buffer) {
            Ok(n) if n > 0 => {
                pending.push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("terminal did not produce {needle:?}: {pending}");
}

#[test]
fn real_terminal_navigation_cancel_alias_and_eof() {
    let directory = std::env::temp_dir().join(format!("hyber-pty-{}", std::process::id()));
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: valid output fd pointers; optional name/settings are null.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut input = unsafe { File::from_raw_fd(master) };
    let terminal = unsafe { File::from_raw_fd(slave) };
    unsafe {
        libc::fcntl(master, libc::F_SETFL, libc::O_NONBLOCK);
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_hyber-shell"))
        .args(["--host-root", directory.to_str().unwrap()])
        .stdin(Stdio::from(terminal.try_clone().unwrap()))
        .stdout(Stdio::from(terminal.try_clone().unwrap()))
        .stderr(Stdio::from(terminal))
        .spawn()
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pending = String::new();
        receive(&mut input, &mut pending, "hyber> ");
        // Persistent history is deliberately opt-in. Enable it before the
        // command that must survive a complete shell restart.
        input.write_all(b"history save on\r").unwrap();
        receive(&mut input, &mut pending, "\x1b[?2004l");
        receive(&mut input, &mut pending, "hyber> ");
        input.write_all(b"alias md='mkdir'\r").unwrap();
        receive(&mut input, &mut pending, "\x1b[?2004l");
        receive(&mut input, &mut pending, "hyber> ");
        input.write_all(b"md /users/root/pty-result\r").unwrap();
        // Wait for side effect, not just the input echo.
        let deadline = Instant::now() + Duration::from_secs(4);
        while !directory.join("users/root/pty-result").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(directory.join("users/root/pty-result").is_dir());
        receive(&mut input, &mut pending, "\x1b[?2004l");
        receive(&mut input, &mut pending, "hyber> ");
        // Exercise real cursor editing. Start with kX, move left to insert e,
        // move right, remove X, then append y: the executed path must be key.
        input
            .write_all(b"mkdir /users/root/kX\x1b[De\x1b[C\x7fy\r")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while !directory.join("users/root/key").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(directory.join("users/root/key").is_dir());
        receive(&mut input, &mut pending, "\x1b[?2004l");
        receive(&mut input, &mut pending, "hyber> ");
        // Home followed by End must leave the cursor at the end; remove the
        // deliberately added X before submitting the valid command.
        input
            .write_all(b"mkdir /users/root/endX\x1b[H\x1b[F\x7f\r")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while !directory.join("users/root/end").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(directory.join("users/root/end").is_dir());
        receive(&mut input, &mut pending, "\x1b[?2004l");
        receive(&mut input, &mut pending, "hyber> ");
        // Aliases are intentionally session-scoped unless a profile defines
        // them, so use a built-in command as the persisted-history fixture.
        input
            .write_all(b"mkdir /users/root/persistent-history-result\r")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while !directory
            .join("users/root/persistent-history-result")
            .exists()
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(directory
            .join("users/root/persistent-history-result")
            .is_dir());
        receive(&mut input, &mut pending, "\x1b[?2004l");
        receive(&mut input, &mut pending, "hyber> ");
        // Up recalls md; Ctrl-C must cancel without executing it again.
        // A PTY/multiplexer may split an escape sequence across scheduler
        // turns. It must remain one Up event, never literal "[A" input.
        input.write_all(b"\x1b").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        input.write_all(b"[A\x03").unwrap();
        let output = receive(&mut input, &mut pending, "^C");
        assert!(!output.contains("Error:"), "{output}");
        // Even an oversized paste containing a newline and a valid command
        // must be completely consumed, never interpreted as later input.
        let mut paste = b"\x1b[200~".to_vec();
        paste.extend(vec![b'x'; 4200]);
        paste.extend(b"\nmkdir /users/root/paste-must-not-run\n\x1b[201~");
        input.write_all(&paste).unwrap();
        receive(&mut input, &mut pending, "paste too large");
        receive(&mut input, &mut pending, "hyber> ");
        assert!(!directory.join("users/root/paste-must-not-run").exists());
        input.write_all(b"\x04").unwrap();
        receive(&mut input, &mut pending, "Goodbye from HyberKOS!");
    }));
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    assert!(status.success());

    // Open a completely new shell process on a fresh PTY but the same Hyber
    // HostFS root. Navigate up twice (newer built-in command, then older
    // session-only alias) and down once. Down must restore the newer built-in
    // command; executing it attempts to create the existing directory.
    // Literal `[A`/`[B` would instead produce an unknown-command error.
    let mut second_master = -1;
    let mut second_slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut second_master,
                &mut second_slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut second_input = unsafe { File::from_raw_fd(second_master) };
    let second_terminal = unsafe { File::from_raw_fd(second_slave) };
    unsafe {
        libc::fcntl(second_master, libc::F_SETFL, libc::O_NONBLOCK);
    }
    let mut second_child = Command::new(env!("CARGO_BIN_EXE_hyber-shell"))
        .args(["--host-root", directory.to_str().unwrap()])
        .stdin(Stdio::from(second_terminal.try_clone().unwrap()))
        .stdout(Stdio::from(second_terminal.try_clone().unwrap()))
        .stderr(Stdio::from(second_terminal))
        .spawn()
        .unwrap();
    let restored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pending = String::new();
        receive(&mut second_input, &mut pending, "hyber> ");
        second_input.write_all(b"\x1b").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        second_input.write_all(b"[A\x1b[A\x1b[B\r").unwrap();
        let output = receive(&mut second_input, &mut pending, "already exists");
        assert!(
            !output.contains("Unknown command: [A") && !output.contains("Unknown command: [B"),
            "{output}"
        );
        receive(&mut second_input, &mut pending, "hyber> ");
        second_input.write_all(b"\x04").unwrap();
        receive(&mut second_input, &mut pending, "Goodbye from HyberKOS!");
    }));
    if restored.is_err() {
        let _ = second_child.kill();
    }
    let second_status = second_child.wait().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    result.unwrap();
    restored.unwrap();
    assert!(second_status.success());
}
