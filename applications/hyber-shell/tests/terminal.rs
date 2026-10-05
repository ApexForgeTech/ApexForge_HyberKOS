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
        // Up recalls md; Ctrl-C must cancel without executing it again.
        input.write_all(b"\x1b[A\x03").unwrap();
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
    std::fs::remove_dir_all(directory).unwrap();
    result.unwrap();
    assert!(status.success());
}
