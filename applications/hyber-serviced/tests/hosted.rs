use hyber_auth::{AuthService, SessionGuard, SessionKind, SystemClock};
use hyber_core::SecurityContext;
use hyber_identity::AccountState;
use hyber_manifest::*;
use hyber_service::supervisor::*;
use hyber_service_contract::*;
use hyber_service_host::HostedRunner;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn fixture(
    runtime: Runtime,
    bytes: Vec<u8>,
) -> (
    HostedRunner,
    ServiceDefinition,
    ApplicationGrant,
    SessionGuard,
) {
    let password = b"real service test root password";
    let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
    let admin = auth
        .login("root", password, SessionKind::Interactive, 600)
        .unwrap();
    let user = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("payload")?;
            accounts.create_user("payload", group, AccountState::Service)
        })
        .unwrap();
    auth.set_password(&admin, user, b"real service test credential")
        .unwrap();
    let group = auth.accounts().user(user).unwrap().primary_group;
    let token = auth.service_session(&admin, user, 600).unwrap();
    let session = SessionGuard::new(Arc::new(Mutex::new(auth)), token).unwrap();
    let capabilities = BTreeSet::from([CapabilityName("service.background".into())]);
    let manifest = Manifest {
        format_version: 1,
        app_id: ApplicationId("payload".into()),
        version: "1.0.0".into(),
        publisher: "test".into(),
        display_name: "Payload".into(),
        entrypoint: if runtime == Runtime::Lua {
            "main.lua"
        } else {
            "main"
        }
        .into(),
        runtime,
        requested_capabilities: capabilities.clone(),
        storage: StorageScopes::default(),
        execution: ExecutionMode::Service,
        network: NetworkPolicy::default(),
        resources: ResourceQuotas {
            memory_bytes: 2 * 1024 * 1024 * 1024,
            cpu_shares: 8,
            handles: 64,
            storage_bytes: 1024,
        },
    };
    let grant = GrantPolicy {
        capabilities: capabilities.clone(),
        allow_gui: false,
        allow_background: false,
        allow_service: true,
        max_resources: manifest.resources,
    }
    .approve(manifest)
    .unwrap();
    let definition = ServiceDefinition {
        format_version: 1,
        service_id: ServiceId("payload".into()),
        application_id: ApplicationId("payload".into()),
        identity: ServiceIdentity {
            user_id: user,
            group_id: group,
        },
        startup: StartupPolicy::Manual,
        restart: RestartPolicy::OnFailure,
        health_check: HealthCheck::IpcReadiness,
        dependencies: BTreeSet::new(),
        payload: if runtime == Runtime::Lua {
            ServicePayload::Lua {
                entrypoint: "main.lua".into(),
            }
        } else {
            ServicePayload::Go(GoPayloadContract {
                module: "main".into(),
                arguments: vec![],
                max_concurrency: 2,
                cooperative_cancellation: true,
            })
        },
        requested_capabilities: capabilities,
        socket_policy: SocketPolicy::default(),
        ipc: IpcContract {
            endpoints: BTreeSet::new(),
            max_message_bytes: 8192,
        },
    };
    let mut runner = HostedRunner::new(env!("CARGO_BIN_EXE_hyber-serviced").into()).unwrap();
    runner
        .insert_payload(definition.service_id.clone(), bytes)
        .unwrap();
    (runner, definition, grant, session)
}
fn context(session: &SessionGuard) -> SecurityContext {
    let mut context = session.context().unwrap();
    context.capabilities.clear();
    context.supplementary_groups.clear();
    context
}

fn approve_network(
    definition: &mut ServiceDefinition,
    grant: ApplicationGrant,
) -> ApplicationGrant {
    let mut manifest = grant.manifest;
    manifest
        .requested_capabilities
        .insert(CapabilityName("network.outbound".into()));
    manifest.network.outbound = true;
    manifest.network.domains.insert("localhost".into());
    definition
        .requested_capabilities
        .insert(CapabilityName("network.outbound".into()));
    definition.socket_policy.outbound = true;
    definition.socket_policy.domains.insert("localhost".into());
    GrantPolicy {
        capabilities: manifest.requested_capabilities.clone(),
        allow_gui: false,
        allow_background: false,
        allow_service: true,
        max_resources: manifest.resources,
    }
    .approve(manifest)
    .unwrap()
}

#[test]
fn blocked_network_read_does_not_block_service_stop() {
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = peer.local_addr().unwrap().port();
    let source = format!(
        "local s=hyber.network.connect('localhost',{port},'udp'); hyber.service.ready(); s:read(1)"
    );
    let (mut runner, mut definition, grant, session) = fixture(Runtime::Lua, source.into_bytes());
    let grant = approve_network(&mut definition, grant);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    let start = Instant::now();
    runner.request_stop(&definition.service_id, pid).unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(0))
    });
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "supervisor was blocked by socket read"
    );
}

#[test]
fn service_network_policy_denies_undeclared_destination() {
    let source = b"hyber.network.connect('denied.test',80,'tcp'); hyber.service.ready()".to_vec();
    let (mut runner, mut definition, grant, session) = fixture(Runtime::Lua, source);
    let grant = approve_network(&mut definition, grant);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(
        &mut runner,
        &definition,
        pid,
        |o| matches!(o, ProcessObservation::Exited(code) if code != 0),
    );
    assert_eq!(runner.live_count(), 0);
}
#[test]
fn service_resolver_denies_undeclared_destination() {
    let source = b"hyber.network.resolve('denied.test'); hyber.service.ready()".to_vec();
    let (mut runner, mut definition, grant, session) = fixture(Runtime::Lua, source);
    let grant = approve_network(&mut definition, grant);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(
        &mut runner,
        &definition,
        pid,
        |o| matches!(o, ProcessObservation::Exited(code) if code != 0),
    );
    assert_eq!(runner.live_count(), 0);
}

#[test]
fn service_socket_inspection_exposes_only_logical_metadata() {
    let source = b"local s=hyber.network.connect('localhost', 9, 'udp'); local i=s:inspect(); assert(i.object_id>0 and i.owner>0); assert(i.protocol=='udp' and i.state=='Connected'); assert(i.host=='localhost' and i.port==9); assert(i.bytes_sent==0 and i.bytes_received==0); assert(i.fd==nil and i.address==nil); s:close(); hyber.service.ready(); while hyber.service.wait(10) do end".to_vec();
    let (mut runner, mut definition, grant, session) = fixture(Runtime::Lua, source);
    let grant = approve_network(&mut definition, grant);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    runner.request_stop(&definition.service_id, pid).unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Exited(0)
    });
    assert_eq!(runner.live_count(), 0);
}

#[test]
fn service_cancel_and_supervisor_diagnostics_share_logical_state() {
    let source = b"local s=hyber.network.connect('localhost',9,'udp'); assert(s:wait('writable',0)); s:cancel(); s:cancel(); assert(s:inspect().state=='Closed'); hyber.service.ready(); while hyber.service.wait(10) do end; s:close()".to_vec();
    let (mut runner, mut definition, grant, session) = fixture(Runtime::Lua, source);
    let grant = approve_network(&mut definition, grant);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    assert!(runner.network_diagnostics(&session).is_err());
    let password = b"diagnostic authority test password";
    let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
    let token = auth
        .login("root", password, SessionKind::Interactive, 600)
        .unwrap();
    let admin = SessionGuard::new(Arc::new(Mutex::new(auth)), token).unwrap();
    let records = runner.network_diagnostics(&admin).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, definition.service_id);
    assert_eq!(records[0].1, pid);
    assert_eq!(records[0].3.state, hyber_network::SocketState::Closed);
    runner.request_stop(&definition.service_id, pid).unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(_))
    });
    assert!(runner.network_diagnostics(&admin).unwrap().is_empty());
}
fn await_observation(
    runner: &mut HostedRunner,
    definition: &ServiceDefinition,
    pid: hyber_core::ProcessId,
    expected: impl Fn(ProcessObservation) -> bool,
) -> ProcessObservation {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let observation = runner.poll(&definition.service_id, pid).unwrap();
        if expected(observation) {
            return observation;
        }
        assert!(
            !matches!(observation, ProcessObservation::Exited(_)),
            "payload exited before expected event: {observation:?}"
        );
        assert!(Instant::now() < deadline, "payload did not respond");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn real_lua_ready_graceful_stop_and_reap() {
    let bytes = b"assert(io == nil and os == nil and require == nil); hyber.log.info('Lua sandbox verified'); hyber.service.ready(); while hyber.service.wait(10) do end".to_vec();
    let (mut runner, definition, grant, session) = fixture(Runtime::Lua, bytes);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    assert!(runner
        .take_logs()
        .iter()
        .any(|(_, line)| line == "Lua sandbox verified"));
    runner.request_stop(&definition.service_id, pid).unwrap();
    assert_eq!(
        await_observation(&mut runner, &definition, pid, |o| matches!(
            o,
            ProcessObservation::Exited(_)
        )),
        ProcessObservation::Exited(0)
    );
    assert_eq!(runner.live_count(), 0);
}

#[test]
fn real_lua_network_is_brokered_without_host_socket_access() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("loopback accept failed: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    let source = format!("assert(io == nil and os == nil); local dns=hyber.network.resolve('localhost'); assert(dns.host=='localhost' and dns.answers>0 and dns.answers<=16 and dns.cache_seconds<=30); assert(hyber.network.resolve('localhost').cached); local s=hyber.network.connect('localhost', {port}, 'tcp'); assert(type(s)=='userdata'); assert(s:write('ping')==4); local reply=''; while #reply<4 do reply=reply .. s:read(4-#reply) end; assert(reply=='pong'); s:close(); s:close(); hyber.service.ready(); while hyber.service.wait(10) do end");
    let (mut runner, mut definition, grant, session) = fixture(Runtime::Lua, source.into_bytes());
    let mut manifest = grant.manifest.clone();
    manifest
        .requested_capabilities
        .insert(CapabilityName("network.outbound".into()));
    manifest.network.outbound = true;
    manifest.network.domains.insert("localhost".into());
    let grant = GrantPolicy {
        capabilities: manifest.requested_capabilities.clone(),
        allow_gui: false,
        allow_background: false,
        allow_service: true,
        max_resources: manifest.resources,
    }
    .approve(manifest)
    .unwrap();
    definition
        .requested_capabilities
        .insert(CapabilityName("network.outbound".into()));
    definition.socket_policy.outbound = true;
    definition.socket_policy.domains.insert("localhost".into());
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    runner.request_stop(&definition.service_id, pid).unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(0))
    });
    peer.join().unwrap();
    assert_eq!(runner.live_count(), 0);
}
#[test]
fn real_lua_infinite_loop_can_be_terminated() {
    let (mut runner, definition, grant, session) = fixture(
        Runtime::Lua,
        b"hyber.service.ready(); while true do end".to_vec(),
    );
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    runner.terminate(&definition.service_id, pid).unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(_))
    });
    assert_eq!(runner.live_count(), 0);
}

#[test]
fn real_lua_memory_limit_and_declared_frame_limit_are_enforced() {
    let source = b"local t = {}; while true do t[#t+1] = string.rep('x', 1024*1024) end".to_vec();
    let (mut runner, definition, grant, session) = fixture(Runtime::Lua, source);
    let mut manifest = grant.manifest;
    manifest.resources.memory_bytes = 64 * 1024 * 1024;
    let grant = GrantPolicy {
        capabilities: manifest.requested_capabilities.clone(),
        allow_gui: false,
        allow_background: false,
        allow_service: true,
        max_resources: manifest.resources,
    }
    .approve(manifest)
    .unwrap();
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    let exited = await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(_))
    });
    assert_ne!(exited, ProcessObservation::Exited(0));
    assert_eq!(runner.live_count(), 0);

    let (mut runner, mut definition, grant, session) = fixture(
        Runtime::Lua,
        b"hyber.log.info(string.rep('x', 1024)); while hyber.service.wait(20) do end".to_vec(),
    );
    definition.ipc.max_message_bytes = 64;
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    let exited = await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(_))
    });
    assert_ne!(exited, ProcessObservation::Exited(0));
    assert!(runner.take_logs().is_empty());
}

#[test]
fn real_payload_session_revocation_prevents_later_messages() {
    let (mut runner, definition, grant, session) = fixture(
        Runtime::Lua,
        b"hyber.service.ready(); while hyber.service.wait(10) do hyber.log.info('tick') end"
            .to_vec(),
    );
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    runner.take_logs();
    session.logout().unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        matches!(o, ProcessObservation::Exited(_))
    });
    assert!(runner.take_logs().is_empty());
}
#[test]
fn real_go_is_sandboxed_and_uses_the_same_lifecycle() {
    let directory =
        std::env::temp_dir().join(format!("hyber-go-service-test-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("payload");
    let status = std::process::Command::new("go")
        .args(["build", "-o"])
        .arg(&executable)
        .arg(".")
        .current_dir(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/go-service"
        ))
        .env("CGO_ENABLED", "0")
        .status()
        .expect("Go toolchain required for hosted acceptance");
    assert!(status.success());
    let bytes = std::fs::read(&executable).unwrap();
    std::fs::remove_file(&executable).unwrap();
    std::fs::remove_dir(&directory).unwrap();
    let (mut runner, definition, grant, session) = fixture(Runtime::Go, bytes);
    let pid = runner
        .start(&definition, &context(&session), &grant, &session)
        .unwrap();
    await_observation(&mut runner, &definition, pid, |o| {
        o == ProcessObservation::Ready
    });
    assert!(runner
        .take_logs()
        .iter()
        .any(|(_, line)| line == "Go sandbox verified"));
    runner.request_stop(&definition.service_id, pid).unwrap();
    assert_eq!(
        await_observation(&mut runner, &definition, pid, |o| matches!(
            o,
            ProcessObservation::Exited(_)
        )),
        ProcessObservation::Exited(0)
    );
}
