//! Linux-only hosted payload adapter. No host PID, FD or pathname is exposed
//! through ServiceRunner. A missing sandbox is an error, never a fallback.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use hyber_auth::SessionGuard;
use hyber_core::{ProcessId, SecurityContext};
use hyber_manifest::ApplicationGrant;
use hyber_object::ObjectManager;
use hyber_process::ProcessManager;
use hyber_service::supervisor::{ProcessObservation, ServiceRunner};
use hyber_service_contract::{ServiceDefinition, ServiceId, ServicePayload};
use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

const FRAME_LIMIT: usize = 8192;
const MAX_LOGS: usize = 128;
pub mod client;
struct Instance {
    service: ServiceId,
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    buffer: Vec<u8>,
    ready: bool,
    session: SessionGuard,
    stopping: bool,
    frame_limit: usize,
}
pub struct HostedRunner {
    worker: PathBuf,
    payloads: BTreeMap<ServiceId, Vec<u8>>,
    live: BTreeMap<ProcessId, Instance>,
    processes: ProcessManager,
    objects: ObjectManager,
    logs: VecDeque<(ServiceId, String)>,
}
impl HostedRunner {
    pub fn new(worker: PathBuf) -> Result<Self, String> {
        if !worker.is_absolute() || !worker.is_file() {
            return Err("invalid trusted worker executable".into());
        }
        Ok(Self {
            worker,
            payloads: BTreeMap::new(),
            live: BTreeMap::new(),
            processes: ProcessManager::new(),
            objects: ObjectManager::new(),
            logs: VecDeque::new(),
        })
    }
    /// Trusted activation only: bytes must originate from a verified package.
    pub fn insert_payload(&mut self, id: ServiceId, bytes: Vec<u8>) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 || self.payloads.contains_key(&id) {
            return Err("invalid or duplicate service payload".into());
        }
        self.payloads.insert(id, bytes);
        Ok(())
    }
    pub fn take_logs(&mut self) -> Vec<(ServiceId, String)> {
        self.logs.drain(..).collect()
    }
    pub fn live_count(&self) -> usize {
        self.live.len()
    }
    fn instance(&mut self, id: &ServiceId, process: ProcessId) -> Result<&mut Instance, String> {
        self.live
            .get_mut(&process)
            .filter(|i| &i.service == id)
            .ok_or_else(|| "unknown service process".into())
    }
}
impl ServiceRunner for HostedRunner {
    fn start(
        &mut self,
        definition: &ServiceDefinition,
        context: &SecurityContext,
        grant: &ApplicationGrant,
        session: &SessionGuard,
    ) -> Result<ProcessId, String> {
        definition
            .validate_against(grant)
            .map_err(|e| e.to_string())?;
        let current = session.context().map_err(|_| "invalid service session")?;
        if session.kind().map_err(|_| "invalid service session")?
            != hyber_auth::SessionKind::Service
            || context.group_id != definition.identity.group_id
            || !context.capabilities.is_empty()
            || !context.supplementary_groups.is_empty()
        {
            return Err("service launch context is not attenuated".into());
        }
        if current.user_id != context.user_id
            || context.user_id != definition.identity.user_id
            || (current.group_id != context.group_id
                && !current.supplementary_groups.contains(&context.group_id))
        {
            return Err("service identity mismatch".into());
        }
        // Phase 20 is not bypassed by inheriting host network access.
        if definition.socket_policy.inbound || definition.socket_policy.outbound {
            return Err("network service adapter is not available before Phase 20".into());
        }
        let limits = grant.manifest.resources;
        if limits.memory_bytes < 64 * 1024 * 1024 || limits.handles < 16 {
            return Err("hosted runtime requires at least 64 MiB and 16 handles".into());
        }
        if self.live.len() >= 64 {
            return Err("hosted service process limit reached".into());
        }
        let bytes = self
            .payloads
            .get(&definition.service_id)
            .ok_or("service payload not activated")?;
        let payload = memfile(bytes)?;
        let filter = memfile(&seccomp_filter())?;
        let mut command = Command::new("/usr/bin/bwrap");
        command
            .env_clear()
            .args([
                "--unshare-all",
                "--unshare-user",
                "--new-session",
                "--die-with-parent",
                "--disable-userns",
                "--cap-drop",
                "ALL",
                "--clearenv",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind",
                "/lib64",
                "/lib64",
                "--dir",
                "/dev",
                "--ro-bind",
                "/dev/null",
                "/dev/null",
                "--perms",
                "0500",
                "--ro-bind-data",
            ])
            .arg(payload.as_raw_fd().to_string())
            .arg("/payload")
            .args(["--seccomp"])
            .arg(filter.as_raw_fd().to_string());
        match &definition.payload {
            ServicePayload::Lua { .. } => {
                command
                    .arg("--ro-bind")
                    .arg(&self.worker)
                    .arg("/worker")
                    .args(["--remount-ro", "/", "--", "/worker", "--worker", "/payload"])
                    .arg(limits.memory_bytes.to_string())
                    .arg(limits.cpu_shares.to_string());
            }
            ServicePayload::Go(go) => {
                command
                    .args(["--setenv", "GOMAXPROCS"])
                    .arg(go.max_concurrency.to_string())
                    .args(["--setenv", "GOMEMLIMIT"])
                    .arg((limits.memory_bytes / 2).to_string())
                    .args(["--remount-ro", "/", "--", "/payload"])
                    .args(&go.arguments);
            }
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let inherited = [payload.as_raw_fd(), filter.as_raw_fd()];
        let nice = (19_i32 - limits.cpu_shares.max(1).ilog2() as i32).clamp(0, 19);
        // Only async-signal-safe libc calls run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setpriority(libc::PRIO_PROCESS, 0, nice) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in inherited {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                for (resource, limit) in [
                    (libc::RLIMIT_AS, limits.memory_bytes),
                    (libc::RLIMIT_NOFILE, u64::from(limits.handles)),
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_FSIZE, 16 * 1024 * 1024),
                ] {
                    let value = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &value) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| "failed to launch sandbox")?;
        let result = (|| {
            let input = child.stdin.take().ok_or("missing control pipe")?;
            let output = child.stdout.take().ok_or("missing event pipe")?;
            nonblocking(input.as_raw_fd())?;
            nonblocking(output.as_raw_fd())?;
            let pid =
                self.processes
                    .create_process(&mut self.objects, None, context.clone(), None)?;
            self.processes.start_process(pid)?;
            Ok((pid, input, output))
        })();
        let (pid, input, output) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        self.live.insert(
            pid,
            Instance {
                service: definition.service_id.clone(),
                child,
                input,
                output,
                buffer: Vec::new(),
                ready: false,
                session: session.clone(),
                stopping: false,
                frame_limit: FRAME_LIMIT.min(definition.ipc.max_message_bytes as usize),
            },
        );
        Ok(pid)
    }
    fn request_stop(&mut self, id: &ServiceId, process: ProcessId) -> Result<(), String> {
        let instance = self.instance(id, process)?;
        if !instance.stopping {
            // Single frame is smaller than PIPE_BUF and the descriptor is nonblocking.
            match instance.input.write(b"{\"op\":\"stop\"}\n") {
                Ok(14) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                _ => return Err("control pipe unavailable".into()),
            }
            instance.stopping = true;
        }
        Ok(())
    }
    fn terminate(&mut self, id: &ServiceId, process: ProcessId) -> Result<(), String> {
        self.instance(id, process)?
            .child
            .kill()
            .map_err(|_| "termination failed".into())
    }
    fn poll(&mut self, id: &ServiceId, process: ProcessId) -> Result<ProcessObservation, String> {
        let instance = self.instance(id, process)?;
        let mut logs = Vec::new();
        let mut invalid = false;
        for _ in 0..16 {
            let mut chunk = [0; 1024];
            match instance.output.read(&mut chunk) {
                Ok(0) => break,
                Ok(length) => {
                    instance.buffer.extend_from_slice(&chunk[..length]);
                    while let Some(end) = instance.buffer.iter().position(|b| *b == b'\n') {
                        if end > instance.frame_limit {
                            invalid = true;
                            break;
                        }
                        let frame: Vec<_> = instance.buffer.drain(..=end).collect();
                        if instance.stopping {
                            continue;
                        }
                        if instance.session.context().is_err() {
                            invalid = true;
                            break;
                        }
                        match serde_json::from_slice::<Value>(&frame) {
                            Ok(value) if value["op"] == "ready" => instance.ready = true,
                            Ok(value) if value["op"] == "log" => {
                                if let Some(text) =
                                    value["message"].as_str().filter(|s| s.len() <= 1024)
                                {
                                    logs.push(text.escape_default().to_string());
                                } else {
                                    invalid = true;
                                }
                            }
                            _ => invalid = true,
                        }
                    }
                    if instance.buffer.len() > instance.frame_limit || invalid {
                        invalid = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    invalid = true;
                    break;
                }
            }
        }
        if invalid {
            let _ = instance.child.kill();
        }
        let exit = instance
            .child
            .try_wait()
            .map_err(|_| "process poll failed")?;
        let ready = instance.ready;
        for log in logs {
            if self.logs.len() == MAX_LOGS {
                self.logs.pop_front();
            }
            self.logs.push_back((id.clone(), log));
        }
        if let Some(exit) = exit {
            let code = exit.code().unwrap_or(128);
            self.processes.stop_process(process, code)?;
            self.processes
                .reap_isolated_process(&mut self.objects, process)?;
            self.live.remove(&process);
            return Ok(ProcessObservation::Exited(code));
        }
        Ok(if ready {
            ProcessObservation::Ready
        } else {
            ProcessObservation::Running
        })
    }
}
impl Drop for HostedRunner {
    fn drop(&mut self) {
        for instance in self.live.values_mut() {
            let _ = instance.child.kill();
            let _ = instance.child.wait();
        }
    }
}
fn nonblocking(fd: i32) -> Result<(), String> {
    // Owned live pipe descriptor, flags preserve the existing access mode.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err("pipe setup failed".into());
        }
    }
    Ok(())
}
fn memfile(bytes: &[u8]) -> Result<File, String> {
    let fd = unsafe {
        libc::memfd_create(
            c"hyber-service".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err("payload allocation failed".into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|_| "payload staging failed")?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "payload rewind failed")?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err("payload sealing failed".into());
    }
    Ok(file)
}
fn seccomp_filter() -> Vec<u8> {
    // x86_64 only; reject alternate ABI before syscall number dispatch.
    let mut instructions: Vec<(u16, u8, u8, u32)> = vec![
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xc000003e),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x35, 0, 1, 0x40000000),
        (0x06, 0, 0, 0x80000000),
    ];
    for syscall in [
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_ptrace,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_bpf,
        libc::SYS_io_uring_setup,
        libc::SYS_userfaultfd,
    ] {
        instructions.extend([
            (0x15, 0, 1, syscall as u32),
            (0x06, 0, 0, 0x50000 | libc::EPERM as u32),
        ]);
    }
    // libc falls back from clone3 to clone; only thread creation is allowed.
    instructions.extend([
        (0x15, 0, 1, libc::SYS_clone3 as u32),
        (0x06, 0, 0, 0x50000 | libc::ENOSYS as u32),
        (0x15, 0, 4, libc::SYS_clone as u32),
        (0x20, 0, 0, 16),
        (0x45, 1, 0, libc::CLONE_THREAD as u32),
        (0x06, 0, 0, 0x50000 | libc::EPERM as u32),
        (0x06, 0, 0, 0x7fff0000),
        (0x06, 0, 0, 0x7fff0000),
    ]);
    let mut bytes = Vec::new();
    for (code, jt, jf, k) in instructions {
        bytes.extend(code.to_ne_bytes());
        bytes.push(jt);
        bytes.push(jf);
        bytes.extend(k.to_ne_bytes());
    }
    bytes
}
