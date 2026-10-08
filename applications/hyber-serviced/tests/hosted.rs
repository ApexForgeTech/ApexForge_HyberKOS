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
    let (mut runner, definition, mut grant, session) = fixture(Runtime::Lua, source);
    grant.manifest.resources.memory_bytes = 64 * 1024 * 1024;
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
