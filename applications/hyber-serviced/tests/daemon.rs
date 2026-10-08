use hyber_auth::{AuthService, SessionKind, SystemClock};
use hyber_core::SecurityContext;
use hyber_fs::{FileDevice, Volume};
use hyber_identity::AccountState;
use hyber_manifest::{CapabilityName, GrantPolicy};
use hyber_package::{HyberFsPackageStore, KeyState, PackageManager, TrustStore, TrustedKey};
use hyber_package_format::*;
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PASSWORD: &[u8] = b"daemon integration root password";
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wait_text(master: &mut File, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut text = String::new();
    while Instant::now() < deadline {
        let mut bytes = [0; 4096];
        match master.read(&mut bytes) {
            Ok(length) => text.push_str(&String::from_utf8_lossy(&bytes[..length])),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("terminal failed: {error}; output: {text}"),
        }
        if text.contains(expected) {
            return;
        }
        assert!(text.len() < 65536);
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("missing {expected:?}, received {text:?}");
}
#[test]
fn signed_package_authenticated_daemon_and_client_independence() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("hyber-daemon-test-{}-{unique}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let image = directory.join("system.img");
    let socket = directory.join("control.sock");
    let mut volume = Volume::format(FileDevice::create(&image, 256, false).unwrap()).unwrap();
    let mut auth = AuthService::provision(PASSWORD, Arc::new(SystemClock)).unwrap();
    let admin = auth
        .login("root", PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    let uid = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("payload")?;
            accounts.create_user("payload", group, AccountState::Service)
        })
        .unwrap();
    auth.set_password(&admin, uid, b"payload service credential")
        .unwrap();
    let observer = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("observer")?;
            accounts.create_user("observer", group, AccountState::Active)
        })
        .unwrap();
    auth.set_password(&admin, observer, b"observer integration password")
        .unwrap();
    let operator = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("operator")?;
            let uid = accounts.create_user("operator", group, AccountState::Active)?;
            accounts.grant_capability(uid, "CAP_SYS_ADMIN")?;
            Ok(uid)
        })
        .unwrap();
    auth.set_password(&admin, operator, PASSWORD).unwrap();
    auth.save(&mut volume, "/auth.store").unwrap();
    let manifest = "format_version=1\napp_id='payload'\nversion='1.0.0'\npublisher='test'\ndisplay_name='Payload'\nentrypoint='main.lua'\nruntime='lua'\nexecution='service'\nrequested_capabilities=['service.background']\n[resources]\nmemory_bytes=134217728\ncpu_shares=8\nhandles=64\nstorage_bytes=1024\n";
    let declaration = "return { format_version=1, service_id='payload', application_id='payload', startup='automatic', restart='on-failure', health_check='ipc-readiness', entrypoint='main.lua', requested_capabilities={'service.background'}, max_message_bytes=8192 }";
    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let package = SignedPackage::sign(
        PackageInput {
            metadata: PackageMetadata {
                key: PackageKey {
                    id: PackageId("payload".into()),
                    version: PackageVersion::parse("1.0.0").unwrap(),
                },
                application_id: "payload".into(),
                publisher: "test".into(),
                dependencies: vec![],
            },
            application_manifest: manifest.into(),
            files: vec![
                PackageFile {
                    path: "hyber.toml".into(),
                    bytes: manifest.as_bytes().to_vec(),
                },
                PackageFile {
                    path: "main.lua".into(),
                    bytes: b"hyber.service.ready(); while hyber.service.wait(20) do end".to_vec(),
                },
                PackageFile {
                    path: "service.lua".into(),
                    bytes: declaration.as_bytes().to_vec(),
                },
            ],
        },
        "test",
        &key,
    )
    .unwrap();
    let mut trust = TrustStore::default();
    trust
        .add(
            &SecurityContext::root(),
            TrustedKey {
                key_id: "test".into(),
                publisher: "test".into(),
                package_prefix: None,
                state: KeyState::Trusted,
                verifying_key: key.verifying_key(),
            },
        )
        .unwrap();
    let mut packages = PackageManager::default();
    packages
        .repository
        .import(&trust, &package.encode().unwrap())
        .unwrap();
    let mut policy = GrantPolicy::deny_all();
    policy.allow_service = true;
    policy
        .capabilities
        .insert(CapabilityName("service.background".into()));
    packages
        .install_and_save(
            &mut volume,
            &HyberFsPackageStore,
            &SecurityContext::root(),
            &trust,
            &policy,
            &[Dependency {
                package: PackageId("payload".into()),
                requirement: VersionRequirement::Exact(PackageVersion::parse("1.0.0").unwrap()),
            }],
        )
        .unwrap();
    drop(volume);
    let (mut master_fd, mut slave_fd) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    assert_eq!(
        unsafe { libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    // Do not leak the controlling-terminal master into the daemon or payloads.
    assert_eq!(
        unsafe { libc::fcntl(master_fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_hyber-serviced"));
    command
        .arg("serve")
        .arg(&image)
        .args(["256", "root"])
        .arg(&image)
        .arg("256")
        .arg(&socket)
        .arg("payload=payload")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut daemon = Running(command.spawn().unwrap());
    wait_text(&mut master, "Password:");
    master.write_all(PASSWORD).unwrap();
    master.write_all(b"\n").unwrap();
    wait_text(&mut master, "Hyber service supervisor ready");
    let request = |command, id| {
        hyber_service_host::client::request(
            &socket,
            "root",
            std::str::from_utf8(PASSWORD).unwrap(),
            command,
            id,
        )
    };
    let await_state = |expected: &str| {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let status = request("status", Some("payload")).unwrap();
            if status.contains(expected) {
                return status;
            }
            assert!(Instant::now() < deadline, "expected {expected}: {status}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let first = await_state("Ready: true");
    // Opt-in cross-binary PTY test after `cargo build --workspace`. The ordinary
    // test has no dependency on an old shell binary left in target/debug.
    if let Ok(binary) = std::env::var("HYBER_SHELL_TEST_BINARY") {
        exercise_shell(&binary, &directory, &image, &socket, "root");
        exercise_shell(&binary, &directory, &image, &socket, "operator");
        assert!(request("status", Some("payload"))
            .unwrap()
            .contains("Ready: true"));
    }
    assert!(hyber_service_host::client::request(
        &socket,
        "observer",
        "observer integration password",
        "stop",
        Some("payload")
    )
    .is_err());
    // Every request disconnects and logs out its interactive client session.
    assert!(request("status", Some("payload"))
        .unwrap()
        .contains("Ready: true"));
    request("restart", Some("payload")).unwrap();
    let second = await_state("Ready: true");
    assert_ne!(
        first.lines().find(|l| l.starts_with("Process:")),
        second.lines().find(|l| l.starts_with("Process:"))
    );
    request("stop", Some("payload")).unwrap();
    await_state("State: Stopped");
    request("disable", Some("payload")).unwrap();
    assert!(request("start", Some("payload")).is_err());
    request("enable", Some("payload")).unwrap();
    await_state("Ready: true");
    request("shutdown", None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!socket.exists());
    std::fs::remove_file(&image).unwrap();
    std::fs::remove_dir(&directory).unwrap();
}

fn exercise_shell(
    binary: &str,
    directory: &std::path::Path,
    image: &std::path::Path,
    socket: &std::path::Path,
    username: &str,
) {
    let host = directory.join(format!("shell-host-{username}"));
    let (mut master_fd, mut slave_fd) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    assert_eq!(
        unsafe { libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    assert_eq!(
        unsafe { libc::fcntl(master_fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let mut command = Command::new(binary);
    command
        .arg("--service-socket")
        .arg(socket)
        .arg("--host-root")
        .arg(&host)
        .arg("--auth")
        .arg(image)
        .args(["256", username])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut shell = Running(command.spawn().unwrap());
    let password = |master: &mut File| {
        master.write_all(PASSWORD).unwrap();
        master.write_all(b"\n").unwrap();
    };
    wait_text(&mut master, "Password:");
    password(&mut master);
    wait_text(&mut master, "Service authority password:");
    password(&mut master);
    wait_text(&mut master, "hyber>");
    master.write_all(b"svc status payload\n").unwrap();
    wait_text(&mut master, "Service authority password:");
    password(&mut master);
    wait_text(&mut master, "Ready: true");
    master.write_all(b"acquire /services/payload rw\n").unwrap();
    wait_text(
        &mut master,
        if username == "root" {
            "service projection supports only read/enumerate rights"
        } else {
            "WRITE permission missing"
        },
    );
    master.write_all(b"chmod 777 /services/payload\n").unwrap();
    wait_text(
        &mut master,
        "service projection metadata is authority-owned",
    );
    master.write_all(b"rights /services/payload\n").unwrap();
    wait_text(&mut master, "WRITE:   No");
    master.write_all(b"acquire /services/payload r\n").unwrap();
    wait_text(&mut master, "Acquired Handle");
    master.write_all(b"ls /services\n").unwrap();
    wait_text(&mut master, "payload");
    master.write_all(b"exit\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = shell.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "shell did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    // This tree was created exclusively by this test under its unique directory.
    std::fs::remove_dir_all(host).unwrap();
}
