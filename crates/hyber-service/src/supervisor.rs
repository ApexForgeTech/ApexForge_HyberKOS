//! Phase 18 Rust supervisor.  Definitions are validated before registration;
//! this module owns only lifecycle, dependency readiness, and restart policy.

use hyber_auth::{SessionGuard, SessionKind};
use hyber_core::{ProcessId, SecurityContext, SecurityManager};
use hyber_identity::AccountRegistry;
use hyber_manifest::ApplicationGrant;
use hyber_service_contract::{RestartPolicy, ServiceCatalog, ServiceDefinition, ServiceId};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RESTARTS: u32 = 5;
pub const MAX_BACKOFF_TICKS: u64 = 60;
pub const READINESS_TIMEOUT_TICKS: u64 = 30;
pub const STOP_TIMEOUT_TICKS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Registered,
    WaitingDependencies,
    Starting,
    Running,
    Stopping,
    Stopped,
    Backoff,
    Failed,
    Disabled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub state: SupervisorState,
    pub process_id: Option<ProcessId>,
    pub ready: bool,
    pub restart_count: u32,
    pub next_restart_at: Option<u64>,
    pub last_exit: Option<i32>,
    pub diagnostic: Option<String>,
    pub readiness_deadline: Option<u64>,
    pub stop_deadline: Option<u64>,
}
impl ServiceStatus {
    fn registered() -> Self {
        Self {
            state: SupervisorState::Registered,
            process_id: None,
            ready: false,
            restart_count: 0,
            next_restart_at: None,
            last_exit: None,
            diagnostic: None,
            readiness_deadline: None,
            stop_deadline: None,
        }
    }
}

pub trait ServiceRunner {
    fn start(
        &mut self,
        definition: &ServiceDefinition,
        context: &SecurityContext,
        grant: &ApplicationGrant,
        session: &SessionGuard,
    ) -> Result<ProcessId, String>;
    fn request_stop(&mut self, id: &ServiceId, process: ProcessId) -> Result<(), String>;
    /// An error means the outcome is unknown, not that the process has exited.
    fn poll(&mut self, id: &ServiceId, process: ProcessId) -> Result<ProcessObservation, String>;
    /// Forced termination is still a request: poll must acknowledge exit/reap.
    fn terminate(&mut self, _id: &ServiceId, _process: ProcessId) -> Result<(), String> {
        Err("forced termination is unsupported by this runner".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessObservation {
    Running,
    Ready,
    Exited(i32),
}

/// Trusted authority adapter. Every launch needs a fresh, independent service
/// session; caller sessions must never be reused here.
pub trait ServiceSessionAuthority {
    fn open(&mut self, definition: &ServiceDefinition) -> Result<SessionGuard, String>;
}

/// The hosting daemon retains its own administrative session. Interactive
/// client guards are not retained by this adapter or by running services.
pub struct AuthenticatedServiceAuthority {
    administrator: SessionGuard,
    lifetime_seconds: u64,
}
impl AuthenticatedServiceAuthority {
    pub fn new(
        administrator: SessionGuard,
        lifetime_seconds: u64,
    ) -> Result<Self, SupervisorError> {
        admin(
            &administrator
                .context()
                .map_err(|_| SupervisorError::Authorization)?,
        )?;
        if lifetime_seconds == 0 {
            return Err(SupervisorError::InvalidState);
        }
        Ok(Self {
            administrator,
            lifetime_seconds,
        })
    }
}
impl ServiceSessionAuthority for AuthenticatedServiceAuthority {
    fn open(&mut self, definition: &ServiceDefinition) -> Result<SessionGuard, String> {
        self.administrator
            .service_session(definition.identity.user_id, self.lifetime_seconds)
            .map_err(|_| "service session issuance denied".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    Authorization,
    UnknownService,
    InvalidState,
    DependenciesNotReady,
    Runner(String),
    Contract(String),
}
impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authorization => f.write_str("service administration denied"),
            Self::UnknownService => f.write_str("service not registered"),
            Self::InvalidState => f.write_str("invalid service lifecycle transition"),
            Self::DependenciesNotReady => f.write_str("service dependencies are not ready"),
            Self::Runner(e) | Self::Contract(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for SupervisorError {}

#[derive(Default)]
pub struct ServiceSupervisor {
    catalog: ServiceCatalog,
    grants: BTreeMap<ServiceId, ApplicationGrant>,
    status: BTreeMap<ServiceId, ServiceStatus>,
    now: u64,
    sessions: BTreeMap<ServiceId, SessionGuard>,
    restart_requested: BTreeSet<ServiceId>,
    desired: BTreeSet<ServiceId>,
    readiness_failed: BTreeSet<ServiceId>,
}
impl ServiceSupervisor {
    pub fn register(
        &mut self,
        actor: &SecurityContext,
        accounts: &AccountRegistry,
        definition: ServiceDefinition,
        grant: ApplicationGrant,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        for (_, registered) in self.catalog.definitions() {
            if !registered
                .ipc
                .endpoints
                .is_disjoint(&definition.ipc.endpoints)
            {
                return Err(SupervisorError::Contract(
                    "IPC endpoint already reserved".into(),
                ));
            }
        }
        self.catalog
            .register(accounts, definition.clone(), &grant)
            .map_err(|e| SupervisorError::Contract(e.to_string()))?;
        self.grants.insert(definition.service_id.clone(), grant);
        self.status
            .insert(definition.service_id, ServiceStatus::registered());
        Ok(())
    }
    pub fn status(&self, id: &ServiceId) -> Option<&ServiceStatus> {
        self.status.get(id)
    }
    pub fn services(&self) -> impl Iterator<Item = (&ServiceId, &ServiceStatus)> {
        self.status.iter()
    }
    pub fn status_text(&self, id: &ServiceId) -> Result<String, SupervisorError> {
        let status = self.status.get(id).ok_or(SupervisorError::UnknownService)?;
        if status.state == SupervisorState::Running {
            self.dispatch_context(id)?;
        }
        let definition = self
            .catalog
            .get(id)
            .ok_or(SupervisorError::UnknownService)?;
        let mut text = format!("Service: {}\nApplication: {}\nState: {:?}\nProcess: {}\nReady: {}\nRestarts: {}\nNext restart: {:?}\nLast exit: {:?}\nDiagnostic: {}\n",
            id.0, definition.application_id.0, status.state,
            status.process_id.map(|p| p.0.to_string()).unwrap_or_else(|| "-".into()),
            status.ready, status.restart_count, status.next_restart_at, status.last_exit,
            status.diagnostic.as_deref().unwrap_or("-"));
        for dependency in &definition.dependencies {
            let state = &self.status[dependency];
            text.push_str(&format!(
                "Dependency: {} {:?} ready={}\n",
                dependency.0, state.state, state.ready
            ));
        }
        Ok(text)
    }
    /// Publish no registrations unless the entire batch and its endpoint
    /// reservations validate successfully.
    pub fn register_batch(
        &mut self,
        actor: &SecurityContext,
        accounts: &AccountRegistry,
        entries: impl IntoIterator<Item = (ServiceDefinition, ApplicationGrant)>,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        let entries: Vec<_> = entries
            .into_iter()
            .take(hyber_service_contract::MAX_SERVICES + 1)
            .collect();
        let mut catalog = self.catalog.clone();
        catalog
            .register_batch(accounts, entries.clone())
            .map_err(|e| SupervisorError::Contract(e.to_string()))?;
        let mut endpoints = BTreeSet::new();
        for (_, definition) in catalog.definitions() {
            for endpoint in &definition.ipc.endpoints {
                if !endpoints.insert(endpoint) {
                    return Err(SupervisorError::Contract(
                        "IPC endpoint already reserved".into(),
                    ));
                }
            }
        }
        self.catalog = catalog;
        for (definition, grant) in entries {
            self.grants.insert(definition.service_id.clone(), grant);
            self.status
                .insert(definition.service_id, ServiceStatus::registered());
        }
        Ok(())
    }
    pub fn start(
        &mut self,
        actor: &SecurityContext,
        id: &ServiceId,
        runner: &mut dyn ServiceRunner,
        authority: &mut dyn ServiceSessionAuthority,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        let definition = self
            .catalog
            .get(id)
            .ok_or(SupervisorError::UnknownService)?
            .clone();
        let current = self
            .status
            .get(id)
            .ok_or(SupervisorError::UnknownService)?
            .state;
        if current == SupervisorState::Running {
            self.dispatch_context(id)?;
            return Ok(());
        }
        if current == SupervisorState::Backoff && !self.restart_due(id, self.now) {
            return Err(SupervisorError::InvalidState);
        }
        if matches!(
            current,
            SupervisorState::Disabled | SupervisorState::Starting | SupervisorState::Stopping
        ) {
            return Err(SupervisorError::InvalidState);
        }
        if !definition.dependencies.iter().all(|dep| {
            self.status
                .get(dep)
                .is_some_and(|s| s.state == SupervisorState::Running && s.ready)
                && self.dispatch_context(dep).is_ok()
        }) {
            self.status.get_mut(id).unwrap().state = SupervisorState::WaitingDependencies;
            self.desired.insert(id.clone());
            return Err(SupervisorError::DependenciesNotReady);
        }
        let session = match authority.open(&definition) {
            Ok(session) => session,
            Err(_) => {
                self.fail(id, "service session issuance denied".into(), -1);
                self.desired.remove(id);
                return Err(SupervisorError::Authorization);
            }
        };
        let checked = (|| {
            if session.kind().map_err(|_| SupervisorError::Authorization)? != SessionKind::Service {
                return Err(SupervisorError::Authorization);
            }
            let mut context = session
                .context()
                .map_err(|_| SupervisorError::Authorization)?;
            if context.user_id != definition.identity.user_id
                || (context.group_id != definition.identity.group_id
                    && !context
                        .supplementary_groups
                        .contains(&definition.identity.group_id))
            {
                return Err(SupervisorError::Authorization);
            }
            context.group_id = definition.identity.group_id;
            context.capabilities.clear();
            context.supplementary_groups.clear();
            Ok(context)
        })();
        let context = match checked {
            Ok(context) => context,
            Err(error) => {
                let _ = session.logout();
                self.fail(id, "service session validation failed".into(), -1);
                self.desired.remove(id);
                return Err(error);
            }
        };
        let status = self.status.get_mut(id).unwrap();
        status.state = SupervisorState::Starting;
        status.diagnostic = None;
        match runner.start(&definition, &context, &self.grants[id], &session) {
            Ok(process) => {
                self.desired.remove(id);
                self.restart_requested.remove(id);
                self.sessions.insert(id.clone(), session);
                let status = self.status.get_mut(id).unwrap();
                status.process_id = Some(process);
                status.next_restart_at = None;
                status.state = SupervisorState::Running;
                status.ready = matches!(
                    definition.health_check,
                    hyber_service_contract::HealthCheck::None
                );
                status.readiness_deadline = if status.ready {
                    None
                } else {
                    Some(self.now.saturating_add(READINESS_TIMEOUT_TICKS))
                };
                Ok(())
            }
            Err(_) => {
                let _ = session.logout();
                self.fail(id, "service start failed".into(), -1);
                self.schedule_retry(id);
                Err(SupervisorError::Runner("service start failed".into()))
            }
        }
    }
    /// Trusted runner event, tied to the exact process instance, not a public
    /// application authorization API.
    pub fn mark_ready(
        &mut self,
        id: &ServiceId,
        process: ProcessId,
    ) -> Result<(), SupervisorError> {
        self.dispatch_context(id)?;
        let status = self
            .status
            .get_mut(id)
            .ok_or(SupervisorError::UnknownService)?;
        if status.state != SupervisorState::Running
            || status.process_id != Some(process)
            || status
                .readiness_deadline
                .is_some_and(|deadline| self.now >= deadline)
        {
            return Err(SupervisorError::InvalidState);
        }
        status.ready = true;
        status.readiness_deadline = None;
        Ok(())
    }
    pub fn stop(
        &mut self,
        actor: &SecurityContext,
        id: &ServiceId,
        runner: &mut dyn ServiceRunner,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        if self.catalog.definitions().any(|(other, definition)| {
            other != id
                && definition.dependencies.contains(id)
                && self
                    .status
                    .get(other)
                    .is_some_and(|s| s.process_id.is_some())
        }) {
            return Err(SupervisorError::DependenciesNotReady);
        }
        let status = self
            .status
            .get_mut(id)
            .ok_or(SupervisorError::UnknownService)?;
        if matches!(
            status.state,
            SupervisorState::Stopped
                | SupervisorState::Registered
                | SupervisorState::Backoff
                | SupervisorState::WaitingDependencies
                | SupervisorState::Failed
        ) {
            status.state = SupervisorState::Stopped;
            status.next_restart_at = None;
            status.ready = false;
            self.restart_requested.remove(id);
            self.desired.remove(id);
            self.readiness_failed.remove(id);
            return Ok(());
        }
        let process = status.process_id.ok_or(SupervisorError::InvalidState)?;
        if status.state == SupervisorState::Stopping {
            self.restart_requested.remove(id);
            self.readiness_failed.remove(id);
            return Ok(());
        }
        let stop_result = runner
            .request_stop(id, process)
            .map_err(|_| SupervisorError::Runner("service stop request failed".into()));
        self.restart_requested.remove(id);
        self.desired.remove(id);
        self.readiness_failed.remove(id);
        // A stop request is not proof that the process exited.
        status.state = SupervisorState::Stopping;
        status.ready = false;
        status.next_restart_at = None;
        status.readiness_deadline = None;
        status.stop_deadline = Some(self.now.saturating_add(STOP_TIMEOUT_TICKS));
        if let Some(session) = self.sessions.remove(id) {
            let _ = session.logout();
        }
        stop_result
    }
    pub fn disable(
        &mut self,
        actor: &SecurityContext,
        id: &ServiceId,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        let status = self
            .status
            .get_mut(id)
            .ok_or(SupervisorError::UnknownService)?;
        if status.process_id.is_some() {
            return Err(SupervisorError::InvalidState);
        }
        status.state = SupervisorState::Disabled;
        self.restart_requested.remove(id);
        self.desired.remove(id);
        status.ready = false;
        status.next_restart_at = None;
        Ok(())
    }
    pub fn report_exit(
        &mut self,
        id: &ServiceId,
        process: ProcessId,
        exit: i32,
        now: u64,
    ) -> Result<(), SupervisorError> {
        if now < self.now {
            return Err(SupervisorError::InvalidState);
        }
        if self
            .status
            .get(id)
            .ok_or(SupervisorError::UnknownService)?
            .process_id
            != Some(process)
        {
            return Err(SupervisorError::InvalidState);
        }
        let state = self
            .status
            .get(id)
            .ok_or(SupervisorError::UnknownService)?
            .state;
        if !matches!(state, SupervisorState::Running | SupervisorState::Stopping) {
            return Err(SupervisorError::InvalidState);
        }
        self.now = now;
        self.fail(id, format!("process exited with {exit}"), exit);
        let status = self.status.get_mut(id).unwrap();
        let readiness_failed = self.readiness_failed.remove(id);
        if !readiness_failed && (exit == 0 || state == SupervisorState::Stopping) {
            status.state = SupervisorState::Stopped;
            return Ok(());
        }
        self.schedule_retry(id);
        Ok(())
    }
    fn schedule_retry(&mut self, id: &ServiceId) {
        let policy = self.catalog.get(id).unwrap().restart;
        let status = self.status.get_mut(id).unwrap();
        if policy == RestartPolicy::OnFailure && status.restart_count < MAX_RESTARTS {
            status.restart_count += 1;
            status.state = SupervisorState::Backoff;
            status.next_restart_at = self
                .now
                .checked_add((1_u64 << status.restart_count.min(5)).min(MAX_BACKOFF_TICKS));
            if status.next_restart_at.is_none() {
                status.state = SupervisorState::Failed;
            }
        }
    }
    pub fn restart_due(&self, id: &ServiceId, now: u64) -> bool {
        self.status.get(id).is_some_and(|s| {
            s.state == SupervisorState::Backoff && s.next_restart_at.is_some_and(|at| now >= at)
        })
    }
    /// Advance the trusted monotonic clock; callers drive this from their event loop.
    pub fn advance_clock(&mut self, now: u64) -> Result<(), SupervisorError> {
        if now < self.now {
            return Err(SupervisorError::InvalidState);
        }
        self.now = now;
        Ok(())
    }
    pub fn enable(
        &mut self,
        actor: &SecurityContext,
        id: &ServiceId,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        let status = self
            .status
            .get_mut(id)
            .ok_or(SupervisorError::UnknownService)?;
        if status.state != SupervisorState::Disabled {
            return Err(SupervisorError::InvalidState);
        }
        *status = ServiceStatus::registered();
        Ok(())
    }
    fn fail(&mut self, id: &ServiceId, diagnostic: String, exit: i32) {
        if let Some(session) = self.sessions.remove(id) {
            let _ = session.logout();
        }
        if let Some(status) = self.status.get_mut(id) {
            status.state = SupervisorState::Failed;
            status.process_id = None;
            status.ready = false;
            status.next_restart_at = None;
            status.readiness_deadline = None;
            status.stop_deadline = None;
            status.last_exit = Some(exit);
            status.diagnostic = Some(diagnostic.chars().take(512).collect());
        }
    }

    /// Revalidate on every protected dispatch. Only the declared service group
    /// is retained; account administration capabilities are never inherited.
    pub fn dispatch_context(&self, id: &ServiceId) -> Result<SecurityContext, SupervisorError> {
        let context = self.session_context(id)?;
        let mut pending: Vec<_> = self
            .catalog
            .get(id)
            .ok_or(SupervisorError::UnknownService)?
            .dependencies
            .iter()
            .collect();
        let mut checked = BTreeSet::new();
        while let Some(dependency) = pending.pop() {
            if !checked.insert(dependency) {
                continue;
            }
            self.session_context(dependency)?;
            if !self.status[dependency].ready {
                return Err(SupervisorError::DependenciesNotReady);
            }
            pending.extend(
                self.catalog
                    .get(dependency)
                    .ok_or(SupervisorError::UnknownService)?
                    .dependencies
                    .iter(),
            );
        }
        Ok(context)
    }

    fn session_context(&self, id: &ServiceId) -> Result<SecurityContext, SupervisorError> {
        let status = self.status.get(id).ok_or(SupervisorError::UnknownService)?;
        if status.state != SupervisorState::Running {
            return Err(SupervisorError::InvalidState);
        }
        let session = self
            .sessions
            .get(id)
            .ok_or(SupervisorError::Authorization)?;
        let mut context = session
            .context()
            .map_err(|_| SupervisorError::Authorization)?;
        let identity = self
            .catalog
            .get(id)
            .ok_or(SupervisorError::UnknownService)?
            .identity;
        if context.user_id != identity.user_id
            || (context.group_id != identity.group_id
                && !context.supplementary_groups.contains(&identity.group_id))
        {
            return Err(SupervisorError::Authorization);
        }
        context.group_id = identity.group_id;
        context.capabilities.clear();
        context.supplementary_groups.clear();
        Ok(context)
    }

    pub fn restart(
        &mut self,
        actor: &SecurityContext,
        id: &ServiceId,
        runner: &mut dyn ServiceRunner,
    ) -> Result<(), SupervisorError> {
        self.stop(actor, id, runner)?;
        self.restart_requested.insert(id.clone());
        Ok(())
    }

    /// Nonblocking trusted control-loop iteration. A failed poll retains the
    /// process identity; only an explicit exit observation permits replacement.
    pub fn drive(
        &mut self,
        actor: &SecurityContext,
        now: u64,
        runner: &mut dyn ServiceRunner,
        authority: &mut dyn ServiceSessionAuthority,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        self.advance_clock(now)?;
        let mut first_error = None;
        let automatic: Vec<_> = self
            .catalog
            .definitions()
            .filter(|(id, definition)| {
                definition.startup == hyber_service_contract::StartupPolicy::Automatic
                    && self.status[*id].state == SupervisorState::Registered
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in automatic {
            if let Err(error) = self.request_start(actor, &id) {
                self.fail(&id, "automatic startup dependency unavailable".into(), -1);
                first_error.get_or_insert(error);
            }
        }
        let order: Vec<_> = self
            .catalog
            .launch_order()
            .map_err(|e| SupervisorError::Contract(e.to_string()))?
            .into_iter()
            .map(|d| d.service_id.clone())
            .collect();
        for id in order.iter().rev() {
            let Some(process) = self.status[id].process_id else {
                continue;
            };
            let observation = runner.poll(id, process);
            if !matches!(observation, Ok(ProcessObservation::Exited(_))) {
                if self.status[id].state == SupervisorState::Running {
                    let expired = self.status[id]
                        .readiness_deadline
                        .is_some_and(|deadline| now >= deadline);
                    let revoked = self.dispatch_context(id).is_err();
                    if expired || revoked {
                        if let Err(error) = self.stop(actor, id, runner) {
                            first_error.get_or_insert(error);
                        }
                        // Failed delivery may still have entered Stopping.
                        // Preserve the timeout failure's retry policy in that case.
                        if self.status[id].state == SupervisorState::Stopping {
                            if expired && !revoked {
                                self.readiness_failed.insert(id.clone());
                            }
                            self.status.get_mut(id).unwrap().diagnostic = Some(if revoked {
                                "service session or dependency unavailable".into()
                            } else {
                                "service readiness timed out".into()
                            });
                        }
                    }
                }
                if self.status[id].state == SupervisorState::Stopping
                    && self.status[id]
                        .stop_deadline
                        .is_some_and(|deadline| now >= deadline)
                {
                    let status = self.status.get_mut(id).unwrap();
                    status.stop_deadline = None;
                    status.diagnostic = Some(match runner.terminate(id, process) {
                        Ok(()) => "forced termination requested; awaiting exit".into(),
                        Err(_) => "forced termination failed; process outcome unknown".into(),
                    });
                }
            }
            match observation {
                Ok(ProcessObservation::Exited(code)) => {
                    self.report_exit(id, process, code, now)?;
                }
                Ok(observation) => {
                    if self.status[id].state == SupervisorState::Running
                        && observation == ProcessObservation::Ready
                        && self.dispatch_context(id).is_ok()
                    {
                        self.mark_ready(id, process)?;
                    }
                }
                Err(_) => {
                    self.status.get_mut(id).unwrap().diagnostic =
                        Some("service poll failed; process outcome unknown".into());
                }
            }
        }
        for id in order {
            let status = &self.status[&id];
            if (self.desired.contains(&id)
                && matches!(
                    status.state,
                    SupervisorState::Registered
                        | SupervisorState::WaitingDependencies
                        | SupervisorState::Stopped
                ))
                || self.restart_due(&id, now)
                || (status.state == SupervisorState::Stopped
                    && self.restart_requested.contains(&id))
            {
                match self.start(actor, &id, runner, authority) {
                    Ok(()) => {
                        self.restart_requested.remove(&id);
                        self.desired.remove(&id);
                    }
                    Err(SupervisorError::DependenciesNotReady) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    /// Queue the full dependency closure; no payload is launched by this call.
    pub fn request_start(
        &mut self,
        actor: &SecurityContext,
        id: &ServiceId,
    ) -> Result<(), SupervisorError> {
        admin(actor)?;
        let mut pending = vec![id.clone()];
        let mut desired = BTreeSet::new();
        while let Some(id) = pending.pop() {
            let definition = self
                .catalog
                .get(&id)
                .ok_or(SupervisorError::UnknownService)?;
            if self.status[&id].state == SupervisorState::Disabled {
                return Err(SupervisorError::InvalidState);
            }
            if desired.insert(id) {
                pending.extend(definition.dependencies.iter().cloned());
            }
        }
        // An explicit administrative retry starts a fresh retry budget. Merely
        // queueing a Failed service previously left it permanently unstartable.
        for id in &desired {
            if self.status[id].state == SupervisorState::Failed {
                *self.status.get_mut(id).unwrap() = ServiceStatus::registered();
            }
        }
        self.desired.extend(
            desired
                .into_iter()
                .filter(|id| self.status[id].state != SupervisorState::Running),
        );
        Ok(())
    }
}
impl Drop for ServiceSupervisor {
    fn drop(&mut self) {
        // Losing the authority must fail closed even if a runner retains guards.
        // This does not claim to reap processes: hosted shutdown must drain them.
        for session in self.sessions.values() {
            let _ = session.logout();
        }
    }
}
fn admin(context: &SecurityContext) -> Result<(), SupervisorError> {
    SecurityManager::check_capability(context, "CAP_SYS_ADMIN")
        .map_err(|_| SupervisorError::Authorization)
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;
