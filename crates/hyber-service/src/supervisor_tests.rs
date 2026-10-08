use super::*;
use hyber_auth::{AuthService, SessionToken, SystemClock};
use hyber_identity::AccountState;
use hyber_manifest::*;
use hyber_service_contract::*;
use std::sync::{Arc, Mutex};

struct Authority {
    auth: Arc<Mutex<AuthService>>,
    admin: SessionToken,
}
impl ServiceSessionAuthority for Authority {
    fn open(&mut self, definition: &ServiceDefinition) -> Result<SessionGuard, String> {
        let token = self
            .auth
            .lock()
            .unwrap()
            .service_session(&self.admin, definition.identity.user_id, 600)
            .map_err(|e| e.to_string())?;
        SessionGuard::new(self.auth.clone(), token).map_err(|e| e.to_string())
    }
}
#[derive(Default)]
struct Runner {
    next: u64,
    processes: BTreeMap<ProcessId, ProcessObservation>,
    guards: Vec<SessionGuard>,
    fail_start: bool,
    fail_stop: bool,
    fail_poll: bool,
    terminated: Vec<ProcessId>,
}
impl ServiceRunner for Runner {
    fn terminate(&mut self, _: &ServiceId, process: ProcessId) -> Result<(), String> {
        self.terminated.push(process);
        Ok(())
    }
    fn start(
        &mut self,
        definition: &ServiceDefinition,
        context: &SecurityContext,
        grant: &ApplicationGrant,
        session: &SessionGuard,
    ) -> Result<ProcessId, String> {
        assert_eq!(context.user_id, definition.identity.user_id);
        assert!(context.capabilities.is_empty());
        assert!(context.supplementary_groups.is_empty());
        definition.validate_against(grant).unwrap();
        self.guards.push(session.clone());
        if self.fail_start {
            return Err("private host path /secret".into());
        }
        self.next += 1;
        let pid = ProcessId(self.next);
        self.processes.insert(pid, ProcessObservation::Running);
        Ok(pid)
    }
    fn request_stop(&mut self, _: &ServiceId, _: ProcessId) -> Result<(), String> {
        if self.fail_stop {
            Err("private stop details".into())
        } else {
            Ok(())
        }
    }
    fn poll(&mut self, _: &ServiceId, process: ProcessId) -> Result<ProcessObservation, String> {
        if self.fail_poll {
            Err("private poll details".into())
        } else {
            Ok(self.processes[&process])
        }
    }
}
fn setup() -> (
    ServiceSupervisor,
    Authority,
    Runner,
    ServiceDefinition,
    ApplicationGrant,
) {
    let password = b"supervisor root test password";
    let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
    let admin = auth
        .login("root", password, SessionKind::Interactive, 600)
        .unwrap();
    let uid = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("worker")?;
            accounts.create_user("worker", group, AccountState::Service)
        })
        .unwrap();
    auth.set_password(&admin, uid, b"supervisor worker password")
        .unwrap();
    let group = auth.accounts().user(uid).unwrap().primary_group;
    let capabilities = BTreeSet::from([CapabilityName("service.background".into())]);
    let manifest = Manifest {
        format_version: 1,
        app_id: ApplicationId("worker".into()),
        version: "1.0.0".into(),
        publisher: "hyber".into(),
        display_name: "Worker".into(),
        entrypoint: "main.lua".into(),
        runtime: Runtime::Lua,
        requested_capabilities: capabilities.clone(),
        storage: StorageScopes::default(),
        execution: ExecutionMode::Service,
        network: NetworkPolicy::default(),
        resources: ResourceQuotas {
            memory_bytes: 1024,
            cpu_shares: 1,
            handles: 4,
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
        service_id: ServiceId("worker".into()),
        application_id: ApplicationId("worker".into()),
        identity: ServiceIdentity {
            user_id: uid,
            group_id: group,
        },
        startup: StartupPolicy::Automatic,
        restart: RestartPolicy::OnFailure,
        health_check: HealthCheck::IpcReadiness,
        dependencies: BTreeSet::new(),
        payload: ServicePayload::Lua {
            entrypoint: "main.lua".into(),
        },
        requested_capabilities: capabilities,
        socket_policy: SocketPolicy::default(),
        ipc: IpcContract {
            endpoints: BTreeSet::from(["worker".into()]),
            max_message_bytes: 1024,
        },
    };
    let mut supervisor = ServiceSupervisor::default();
    supervisor
        .register(
            &SecurityContext::root(),
            auth.accounts(),
            definition.clone(),
            grant.clone(),
        )
        .unwrap();
    (
        supervisor,
        Authority {
            auth: Arc::new(Mutex::new(auth)),
            admin,
        },
        Runner::default(),
        definition,
        grant,
    )
}

#[test]
fn stop_requires_exit_and_rejects_stale_events_after_restart() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    let root = SecurityContext::root();
    let id = &definition.service_id;
    supervisor
        .start(&root, id, &mut runner, &mut authority)
        .unwrap();
    let first = supervisor.status(id).unwrap().process_id.unwrap();
    supervisor.mark_ready(id, first).unwrap();
    supervisor.restart(&root, id, &mut runner).unwrap();
    assert_eq!(
        supervisor.status(id).unwrap().state,
        SupervisorState::Stopping
    );
    assert!(runner.guards[0].context().is_err());
    supervisor
        .drive(&root, 1, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.next, 1);
    runner
        .processes
        .insert(first, ProcessObservation::Exited(9));
    supervisor
        .drive(&root, 2, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.next, 2);
    let before = supervisor.status(id).unwrap().clone();
    assert!(supervisor.report_exit(id, first, 1, 3).is_err());
    assert!(supervisor.mark_ready(id, first).is_err());
    assert_eq!(supervisor.status(id), Some(&before));
}

#[test]
fn failed_stop_and_unknown_poll_do_not_discard_live_process() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    let root = SecurityContext::root();
    let id = &definition.service_id;
    supervisor
        .start(&root, id, &mut runner, &mut authority)
        .unwrap();
    let before = supervisor.status(id).unwrap().clone();
    runner.fail_stop = true;
    assert_eq!(
        supervisor.stop(&root, id, &mut runner),
        Err(SupervisorError::Runner(
            "service stop request failed".into()
        ))
    );
    assert_eq!(supervisor.status(id), Some(&before));
    assert!(runner.guards[0].context().is_ok());
    runner.fail_poll = true;
    supervisor
        .drive(&root, 1, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(supervisor.status(id).unwrap().process_id, before.process_id);
    assert_eq!(runner.next, 1);
}

#[test]
fn crash_budget_backoff_clock_and_manual_stop_are_enforced() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    let root = SecurityContext::root();
    let id = &definition.service_id;
    let mut now = 0;
    supervisor
        .start(&root, id, &mut runner, &mut authority)
        .unwrap();
    for _ in 0..MAX_RESTARTS {
        let process = supervisor.status(id).unwrap().process_id.unwrap();
        supervisor.report_exit(id, process, 1, now).unwrap();
        assert!(runner.guards.last().unwrap().context().is_err());
        let deadline = supervisor.status(id).unwrap().next_restart_at.unwrap();
        assert!(supervisor
            .start(&root, id, &mut runner, &mut authority)
            .is_err());
        now = deadline;
        supervisor
            .drive(&root, now, &mut runner, &mut authority)
            .unwrap();
    }
    let process = supervisor.status(id).unwrap().process_id.unwrap();
    supervisor.report_exit(id, process, 1, now).unwrap();
    assert_eq!(
        supervisor.status(id).unwrap().state,
        SupervisorState::Failed
    );
    assert!(supervisor.advance_clock(now - 1).is_err());
    supervisor.stop(&root, id, &mut runner).unwrap();
    supervisor
        .drive(&root, now + 1, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(
        supervisor.status(id).unwrap().state,
        SupervisorState::Stopped
    );
}

#[test]
fn dependency_readiness_endpoint_collision_and_revocation_fail_closed() {
    let (mut supervisor, mut authority, mut runner, mut child, grant) = setup();
    let root = SecurityContext::root();
    let parent = child.service_id.clone();
    child.service_id = ServiceId("child".into());
    child.dependencies.insert(parent.clone());
    assert!(supervisor
        .register(
            &root,
            authority.auth.lock().unwrap().accounts(),
            child.clone(),
            grant.clone()
        )
        .is_err());
    assert!(supervisor.status(&child.service_id).is_none());
    child.ipc.endpoints.clear();
    supervisor
        .register(
            &root,
            authority.auth.lock().unwrap().accounts(),
            child.clone(),
            grant,
        )
        .unwrap();
    supervisor
        .drive(&root, 0, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.next, 1);
    assert_eq!(
        supervisor.status(&child.service_id).unwrap().state,
        SupervisorState::WaitingDependencies
    );
    supervisor.mark_ready(&parent, ProcessId(1)).unwrap();
    supervisor
        .drive(&root, 1, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.next, 2);
    assert_eq!(
        supervisor.stop(&root, &parent, &mut runner),
        Err(SupervisorError::DependenciesNotReady)
    );
    runner.guards[1].logout().unwrap();
    assert_eq!(
        supervisor.dispatch_context(&child.service_id),
        Err(SupervisorError::Authorization)
    );
    supervisor
        .drive(&root, 2, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(
        supervisor.status(&child.service_id).unwrap().state,
        SupervisorState::Stopping
    );
}

#[test]
fn failed_start_revokes_guard_and_sanitizes_error() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    runner.fail_start = true;
    assert!(supervisor
        .start(
            &SecurityContext::root(),
            &definition.service_id,
            &mut runner,
            &mut authority
        )
        .is_err());
    let status = supervisor.status(&definition.service_id).unwrap();
    assert_eq!(status.state, SupervisorState::Backoff);
    assert_eq!(status.diagnostic.as_deref(), Some("service start failed"));
    assert!(runner.guards[0].context().is_err());
}

#[test]
fn batch_registration_is_atomic_and_boot_starts_manual_dependencies() {
    let (old, mut authority, mut runner, mut parent, grant) = setup();
    drop(old);
    parent.startup = StartupPolicy::Manual;
    parent.health_check = HealthCheck::None;
    let mut child = parent.clone();
    child.service_id = ServiceId("child".into());
    child.startup = StartupPolicy::Automatic;
    child.dependencies.insert(parent.service_id.clone());
    let root = SecurityContext::root();
    let mut supervisor = ServiceSupervisor::default();
    {
        let auth = authority.auth.lock().unwrap();
        assert!(supervisor
            .register_batch(
                &root,
                auth.accounts(),
                [
                    (child.clone(), grant.clone()),
                    (parent.clone(), grant.clone())
                ]
            )
            .is_err());
        assert!(supervisor.status(&parent.service_id).is_none());
        child.ipc.endpoints.clear();
        supervisor
            .register_batch(
                &root,
                auth.accounts(),
                [(child.clone(), grant.clone()), (parent.clone(), grant)],
            )
            .unwrap();
    }
    supervisor
        .drive(&root, 0, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.next, 2);
    let parent_pid = supervisor
        .status(&parent.service_id)
        .unwrap()
        .process_id
        .unwrap();
    supervisor
        .report_exit(&parent.service_id, parent_pid, 0, 1)
        .unwrap();
    supervisor
        .drive(&root, 2, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(
        runner.next, 2,
        "successful exit must not trigger an implicit restart"
    );
}

#[test]
fn caller_logout_does_not_revoke_service_but_supervisor_drop_does() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    supervisor
        .start(
            &SecurityContext::root(),
            &definition.service_id,
            &mut runner,
            &mut authority,
        )
        .unwrap();
    authority
        .auth
        .lock()
        .unwrap()
        .logout(&authority.admin)
        .unwrap();
    assert!(supervisor.dispatch_context(&definition.service_id).is_ok());
    drop(supervisor);
    assert!(runner.guards[0].context().is_err());
}

#[test]
fn unauthorized_lifecycle_and_disabled_start_do_not_launch() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    let mut unprivileged = SecurityContext::root();
    unprivileged.user_id = definition.identity.user_id;
    unprivileged.group_id = definition.identity.group_id;
    unprivileged.capabilities.clear();
    let id = &definition.service_id;
    assert_eq!(
        supervisor.start(&unprivileged, id, &mut runner, &mut authority),
        Err(SupervisorError::Authorization)
    );
    assert_eq!(
        supervisor.disable(&unprivileged, id),
        Err(SupervisorError::Authorization)
    );
    supervisor.disable(&SecurityContext::root(), id).unwrap();
    assert!(supervisor
        .start(&SecurityContext::root(), id, &mut runner, &mut authority)
        .is_err());
    assert_eq!(runner.next, 0);
    supervisor.enable(&SecurityContext::root(), id).unwrap();
    supervisor
        .start(&SecurityContext::root(), id, &mut runner, &mut authority)
        .unwrap();
}

#[test]
fn lua_definition_is_bounded_strict_and_uses_external_identity_and_grant() {
    let (_, authority, _, definition, grant) = setup();
    let source = r#"return {
        format_version = 1, service_id = "worker", application_id = "worker",
        startup = "automatic", restart = "on-failure", health_check = "ipc-readiness",
        entrypoint = "main.lua", requested_capabilities = {"service.background"},
        ipc_endpoints = {"worker"}, max_message_bytes = 1024
    }"#;
    let auth = authority.auth.lock().unwrap();
    let load = |text: &str| {
        crate::definition::load_lua_definition(text, definition.identity, auth.accounts(), &grant)
    };
    assert_eq!(load(source).unwrap(), definition);
    for invalid in [
        "while true do end",
        "return os.execute('id')",
        "return { start = function() end }",
        "return require('io')",
        "return setmetatable({}, {})",
        "return string.rep('x', 1000000000)",
    ] {
        assert!(load(invalid).is_err());
    }
    assert!(load(&source.replace("{\"worker\"}", "{[2] = \"worker\"}")).is_err());
    assert!(load(&source.replace("{\"worker\"}", "{\"worker\", \"worker\"}")).is_err());
    assert!(load(&source.replace("format_version = 1", "format_version = '1'")).is_err());
    assert!(load(&source.replace(
        "max_message_bytes = 1024",
        "max_message_bytes = 1024, unknown = true"
    ))
    .is_err());
}

#[test]
fn go_declaration_validates_runtime_arguments_and_concurrency() {
    let (_, authority, _, definition, grant) = setup();
    let mut manifest = grant.manifest.clone();
    manifest.runtime = Runtime::Go;
    manifest.entrypoint = "main".into();
    let mut policy = GrantPolicy::deny_all();
    policy.allow_service = true;
    policy.capabilities = manifest.requested_capabilities.clone();
    let grant = policy.approve(manifest).unwrap();
    let source = r#"return {
        format_version=1, service_id='worker', application_id='worker',
        startup='automatic', restart='on-failure', health_check='ipc-readiness',
        entrypoint='main', requested_capabilities={'service.background'},
        max_message_bytes=1024, max_concurrency=2, arguments={'one','two'}
    }"#;
    let auth = authority.auth.lock().unwrap();
    let load = |text: &str| {
        crate::definition::load_lua_definition(text, definition.identity, auth.accounts(), &grant)
    };
    let ServicePayload::Go(payload) = load(source).unwrap().payload else {
        panic!("wrong runtime")
    };
    assert_eq!(payload.arguments, ["one", "two"]);
    assert_eq!(payload.max_concurrency, 2);
    for invalid in [
        source.replace("max_concurrency=2", "max_concurrency=0"),
        source.replace("{'one','two'}", "{[2]='two'}"),
        source.replace("{'one','two'}", "{one='two'}"),
        source.replace("{'one','two'}", "{function() end}"),
    ] {
        assert!(load(&invalid).is_err());
    }
}

#[test]
fn checked_in_service_examples_match_the_activation_contract() {
    let (_, authority, _, definition, _) = setup();
    let auth = authority.auth.lock().unwrap();
    for (manifest, source) in [
        (
            include_str!("../../../examples/lua-service/hyber.toml"),
            include_str!("../../../examples/lua-service/service.lua"),
        ),
        (
            include_str!("../../../examples/go-service/hyber.toml"),
            include_str!("../../../examples/go-service/service.lua"),
        ),
    ] {
        let manifest = Manifest::parse_toml(manifest).unwrap();
        let mut policy = GrantPolicy::deny_all();
        policy.allow_service = true;
        policy.max_resources.memory_bytes = 2 * 1024 * 1024 * 1024;
        policy
            .capabilities
            .insert(CapabilityName("service.background".into()));
        let grant = policy.approve(manifest).unwrap();
        crate::definition::load_lua_definition(
            source,
            definition.identity,
            auth.accounts(),
            &grant,
        )
        .unwrap();
    }
}

#[test]
fn projection_is_read_only_and_revalidates_running_sessions() {
    use crate::projection::SupervisorProvider;
    use hyber_core::ObjectId;
    use hyber_vfs::Provider;
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    supervisor
        .start(
            &SecurityContext::root(),
            &definition.service_id,
            &mut runner,
            &mut authority,
        )
        .unwrap();
    let shared = Arc::new(Mutex::new(supervisor));
    let objects = BTreeMap::from([(definition.service_id.clone(), ObjectId(2))]);
    assert!(SupervisorProvider::new(shared.clone(), ObjectId(2), objects.clone()).is_err());
    let mut provider = SupervisorProvider::new(shared, ObjectId(1), objects).unwrap();
    assert_eq!(
        provider.enumerate(ObjectId(1)).unwrap().unwrap(),
        vec![("worker".into(), ObjectId(2))]
    );
    assert!(provider.enumerate(ObjectId(2)).is_err());
    let mut bytes = [0; 1024];
    let n = provider.read(ObjectId(2), 0, &mut bytes).unwrap();
    assert!(std::str::from_utf8(&bytes[..n])
        .unwrap()
        .contains("State: Running"));
    assert_eq!(provider.read(ObjectId(2), u64::MAX, &mut []).unwrap(), 0);
    assert!(provider.write(ObjectId(2), 0, b"stop").is_err());
    runner.guards[0].logout().unwrap();
    assert!(provider.read(ObjectId(2), 0, &mut bytes).is_err());
}

#[test]
fn authenticated_authority_issues_independent_service_guards() {
    let (_, authority, _, definition, _) = setup();
    let guard = SessionGuard::new(authority.auth.clone(), authority.admin.clone()).unwrap();
    let mut adapter = AuthenticatedServiceAuthority::new(guard.clone(), 600).unwrap();
    let service = adapter.open(&definition).unwrap();
    assert_eq!(service.kind().unwrap(), SessionKind::Service);
    assert_eq!(
        service.context().unwrap().user_id,
        definition.identity.user_id
    );
    assert!(AuthenticatedServiceAuthority::new(service.clone(), 600).is_err());
    guard.logout().unwrap();
    assert!(service.context().is_ok());
    assert!(adapter.open(&definition).is_err());
    service.logout().unwrap();
}

#[test]
fn readiness_timeout_escalates_shutdown_but_never_invents_exit() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    let root = SecurityContext::root();
    let id = &definition.service_id;
    supervisor
        .start(&root, id, &mut runner, &mut authority)
        .unwrap();
    let pid = supervisor.status(id).unwrap().process_id.unwrap();
    supervisor.advance_clock(READINESS_TIMEOUT_TICKS).unwrap();
    assert!(supervisor.mark_ready(id, pid).is_err());
    supervisor
        .drive(&root, READINESS_TIMEOUT_TICKS, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(
        supervisor.status(id).unwrap().state,
        SupervisorState::Stopping
    );
    assert!(runner.guards[0].context().is_err());
    let deadline = READINESS_TIMEOUT_TICKS + STOP_TIMEOUT_TICKS;
    supervisor
        .drive(&root, deadline, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.terminated, vec![pid]);
    assert_eq!(supervisor.status(id).unwrap().process_id, Some(pid));
    supervisor
        .drive(&root, deadline + 1, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.terminated, vec![pid]);
    runner.processes.insert(pid, ProcessObservation::Exited(0));
    supervisor
        .drive(&root, deadline + 2, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(
        supervisor.status(id).unwrap().state,
        SupervisorState::Backoff
    );
    let retry = supervisor.status(id).unwrap().next_restart_at.unwrap();
    supervisor
        .drive(&root, retry, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(runner.next, 2);
}

#[test]
fn invalidated_session_is_stopped_even_when_poll_fails() {
    let (mut supervisor, mut authority, mut runner, definition, _) = setup();
    let root = SecurityContext::root();
    supervisor
        .start(&root, &definition.service_id, &mut runner, &mut authority)
        .unwrap();
    runner.guards[0].logout().unwrap();
    runner.fail_poll = true;
    supervisor
        .drive(&root, 1, &mut runner, &mut authority)
        .unwrap();
    assert_eq!(
        supervisor.status(&definition.service_id).unwrap().state,
        SupervisorState::Stopping
    );
    assert_eq!(runner.next, 1);
}
