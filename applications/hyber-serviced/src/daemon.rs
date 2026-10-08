use hyber_auth::{SessionGuard, SessionKind};
use hyber_core::SecurityManager;
use hyber_fs::{FileDevice, Volume};
use hyber_package::HyberFsPackageStore;
use hyber_package_format::{PackageId, SignedPackage};
use hyber_service::{
    definition::load_lua_definition,
    supervisor::{AuthenticatedServiceAuthority, ServiceSupervisor},
};
use hyber_service_contract::{ServiceId, ServiceIdentity};
use hyber_service_host::HostedRunner;
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::{Duration, Instant},
};

pub fn run(args: &[String]) -> Result<(), String> {
    if args.first().is_some_and(|a| a == "ctl") && (args.len() == 4 || args.len() == 5) {
        let password = hyber_auth::prompt_password("Password: ").map_err(|e| e.to_string())?;
        println!(
            "{}",
            hyber_service_host::client::request(
                Path::new(&args[1]),
                &args[2],
                &password,
                &args[3],
                args.get(4).map(String::as_str),
            )?
        );
        return Ok(());
    }
    if args.len() < 8 || args[0] != "serve" {
        return Err("usage: hyber-serviced serve <auth-image> <auth-blocks> <admin> <package-image> <package-blocks> <socket> <package=user>...\n       hyber-serviced ctl <socket> <user> <status|start|stop|restart|enable|disable|logs|shutdown> [service-id]".into());
    }
    if args.len() - 7 > 64 {
        return Err("hosted supervisor supports at most 64 activated services".into());
    }
    let blocks = |value: &str| {
        value
            .parse::<u64>()
            .map_err(|_| "invalid block count".to_string())
    };
    let admin = hyber_auth::hosted_login(
        &args[1],
        blocks(&args[2])?,
        &args[3],
        SessionKind::Interactive,
    )
    .map_err(|e| e.to_string())?;
    let context = admin.context().map_err(|e| e.to_string())?;
    SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")?;
    let accounts = admin.administrative_accounts().map_err(|e| e.to_string())?;
    let volume = Volume::mount(
        FileDevice::open_read_only(&args[4], blocks(&args[5])?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if !volume.recovery_warnings().is_empty() {
        return Err("package image needs recovery review".into());
    }
    let (packages, trust) = HyberFsPackageStore
        .load(&volume)
        .map_err(|e| e.to_string())?;
    let mut supervisor = ServiceSupervisor::default();
    let mut runner = HostedRunner::new(std::env::current_exe().map_err(|e| e.to_string())?)?;
    let mut entries = Vec::new();
    let mut selected = BTreeSet::new();
    for mapping in &args[7..] {
        let (package, username) = mapping.split_once('=').ok_or("expected package=user")?;
        if !selected.insert(package) {
            return Err("duplicate package activation".into());
        }
        let account = accounts
            .user_by_name(username)
            .ok_or("unknown service identity")?;
        let installed = packages
            .registry
            .active(&PackageId(package.into()))
            .ok_or("package not installed")?;
        let artifact =
            SignedPackage::decode(&installed.record.artifact).map_err(|e| e.to_string())?;
        trust.verify(&artifact).map_err(|e| e.to_string())?;
        let declaration = artifact
            .input
            .files
            .iter()
            .find(|f| f.path == "service.lua")
            .ok_or("package has no service.lua")?;
        let definition = load_lua_definition(
            std::str::from_utf8(&declaration.bytes).map_err(|_| "invalid service source")?,
            ServiceIdentity {
                user_id: account.id,
                group_id: account.primary_group,
            },
            &accounts,
            &installed.grant,
        )?;
        let payload = artifact
            .input
            .files
            .iter()
            .find(|f| f.path == installed.grant.manifest.entrypoint)
            .ok_or("package payload missing")?;
        runner.insert_payload(definition.service_id.clone(), payload.bytes.clone())?;
        entries.push((definition, installed.grant.clone()));
    }
    supervisor
        .register_batch(&context, &accounts, entries)
        .map_err(|e| e.to_string())?;
    let path = Path::new(&args[6]);
    let parent = path
        .parent()
        .ok_or("socket requires a private parent directory")?;
    let metadata = parent.metadata().map_err(|_| "socket parent missing")?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err("socket parent must be owned by the host user with mode 0700".into());
    }
    let listener = UnixListener::bind(path).map_err(|_| "cannot create fresh control socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let _socket = SocketCleanup(args[6].clone());
    let mut authority =
        AuthenticatedServiceAuthority::new(admin.clone(), 3600).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut shutting_down = false;
    println!("Hyber service supervisor ready");
    loop {
        let actor = match admin.context() {
            Ok(actor) => actor,
            Err(_) => {
                return Err("supervisor authority expired or changed; services stopped".into())
            }
        };
        if !shutting_down {
            if let Err(error) = supervisor.drive(
                &actor,
                started.elapsed().as_secs(),
                &mut runner,
                &mut authority,
            ) {
                eprintln!("supervisor: {error}");
            }
        } else {
            let ids: Vec<_> = supervisor.services().map(|(id, _)| id.clone()).collect();
            // Stop leaves first. Repeated passes make progress after exit acknowledgement.
            for id in ids {
                let _ = supervisor.stop(&actor, &id, &mut runner);
            }
            let _ = supervisor.drive(
                &actor,
                started.elapsed().as_secs(),
                &mut runner,
                &mut authority,
            );
            if runner.live_count() == 0 {
                break;
            }
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                let response = control(
                    &mut stream,
                    &admin,
                    &mut supervisor,
                    &mut runner,
                    &mut shutting_down,
                );
                let response = match response {
                    Ok(result) => serde_json::json!({"ok":true,"result":result}),
                    Err(error) => serde_json::json!({"ok":false,"result":error}),
                };
                let _ = writeln!(stream, "{response}");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("control listener failed".into()),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = admin.logout();
    Ok(())
}
fn control(
    stream: &mut UnixStream,
    admin: &SessionGuard,
    supervisor: &mut ServiceSupervisor,
    runner: &mut HostedRunner,
    shutting_down: &mut bool,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    BufReader::new(stream)
        .take(8193)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "invalid request")?;
    if bytes.len() > 8192 || bytes.last() != Some(&b'\n') {
        return Err("invalid request".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "invalid request")?;
    let client = admin
        .authenticate_client(
            value["username"].as_str().ok_or("authentication failed")?,
            value["password"]
                .as_str()
                .ok_or("authentication failed")?
                .as_bytes(),
        )
        .map_err(|_| "authentication failed")?;
    let result = (|| {
        let context = client.context().map_err(|_| "authentication failed")?;
        SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")?;
        let command = value["command"].as_str().ok_or("missing command")?;
        if command == "logs" {
            let mut output = String::new();
            for (id, message) in runner.take_logs() {
                let line = format!("[{}] {}\n", id.0, message);
                if output.len() + line.len() > 16 * 1024 {
                    break;
                }
                output.push_str(&line);
            }
            return Ok(output);
        }
        if command == "status" {
            if let Some(id) = value["id"].as_str() {
                return supervisor
                    .status_text(&ServiceId(id.into()))
                    .map_err(|e| e.to_string());
            }
            return Ok(supervisor
                .services()
                .map(|(id, status)| format!("{} {:?}", id.0, status.state))
                .collect::<Vec<_>>()
                .join("\n"));
        }
        if command == "shutdown" {
            *shutting_down = true;
            return Ok("shutdown requested".into());
        }
        if *shutting_down {
            return Err("supervisor is shutting down".into());
        }
        let id = ServiceId(value["id"].as_str().ok_or("service id required")?.into());
        match command {
            "start" => supervisor.request_start(&context, &id),
            "stop" => supervisor.stop(&context, &id, runner),
            "restart" => supervisor.restart(&context, &id, runner),
            "enable" => supervisor.enable(&context, &id),
            "disable" => supervisor.disable(&context, &id),
            _ => return Err("unknown service command".into()),
        }
        .map_err(|e| e.to_string())?;
        Ok("request accepted".into())
    })();
    let _ = client.logout();
    result
}
struct SocketCleanup(String);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
