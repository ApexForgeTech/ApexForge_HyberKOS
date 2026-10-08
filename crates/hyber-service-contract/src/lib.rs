//! Special_7 service and networking boundary contracts.
//!
//! This crate deliberately does not start processes or open sockets.  It
//! validates the data a future Rust supervisor and network implementation must
//! consume, so Lua and Go cannot become an alternate authority boundary.

use hyber_core::{GroupId, UserId};
use hyber_identity::{AccountRegistry, AccountState};
use hyber_manifest::{ApplicationGrant, ApplicationId, CapabilityName, ExecutionMode, Runtime};
use std::collections::{BTreeMap, BTreeSet};

pub const SERVICE_FORMAT_VERSION: u32 = 1;
pub const MAX_DEPENDENCIES: usize = 64;
pub const MAX_SERVICES: usize = 1024;
pub const MAX_DEPENDENCY_DEPTH: usize = 128;
pub const MAX_IPC_ENDPOINTS: usize = 32;
pub const MAX_IPC_MESSAGE_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupPolicy {
    Manual,
    Automatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    OnFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthCheck {
    None,
    IpcReadiness,
}

/// The future supervisor receives a concrete Hyber identity, never host UID/GID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub user_id: UserId,
    pub group_id: GroupId,
}

/// Contract for a Go payload.  The supervisor chooses the runtime adapter; this
/// is intentionally not a host command line or a host socket permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoPayloadContract {
    pub module: String,
    pub arguments: Vec<String>,
    pub max_concurrency: u16,
    pub cooperative_cancellation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePayload {
    Lua { entrypoint: String },
    Go(GoPayloadContract),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcContract {
    pub endpoints: BTreeSet<String>,
    pub max_message_bytes: u32,
}

/// Network intent is only a policy declaration.  It grants no direct socket
/// capability and cannot expose a host adapter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocketPolicy {
    pub outbound: bool,
    pub inbound: bool,
    pub domains: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDefinition {
    pub format_version: u32,
    pub service_id: ServiceId,
    pub application_id: ApplicationId,
    pub identity: ServiceIdentity,
    pub startup: StartupPolicy,
    pub restart: RestartPolicy,
    pub health_check: HealthCheck,
    pub dependencies: BTreeSet<ServiceId>,
    pub payload: ServicePayload,
    pub requested_capabilities: BTreeSet<CapabilityName>,
    pub socket_policy: SocketPolicy,
    pub ipc: IpcContract,
}

/// Stable subset produced by a restricted Lua service-definition binding.
/// Functions and arbitrary Lua userdata never cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaServiceTable {
    pub format_version: u32,
    pub service_id: String,
    pub application_id: String,
    pub startup: String,
    pub restart: String,
    pub health_check: String,
    pub dependencies: BTreeSet<String>,
    pub entrypoint: String,
    pub requested_capabilities: BTreeSet<String>,
    pub socket_outbound: bool,
    pub socket_inbound: bool,
    pub socket_domains: BTreeSet<String>,
    pub ipc_endpoints: BTreeSet<String>,
    pub max_message_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    Invalid(&'static str),
    Denied(&'static str),
    DuplicateService,
    MissingDependency(ServiceId),
    DependencyCycle,
}
impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid service contract: {reason}"),
            Self::Denied(reason) => write!(f, "service contract denied: {reason}"),
            Self::DuplicateService => f.write_str("service is already registered"),
            Self::MissingDependency(id) => write!(f, "missing service dependency: {}", id.0),
            Self::DependencyCycle => f.write_str("service dependency cycle"),
        }
    }
}
impl std::error::Error for ContractError {}

impl ServiceDefinition {
    pub fn from_lua_table(
        table: LuaServiceTable,
        identity: ServiceIdentity,
    ) -> Result<Self, ContractError> {
        let startup = match table.startup.as_str() {
            "manual" => StartupPolicy::Manual,
            "automatic" => StartupPolicy::Automatic,
            _ => return Err(ContractError::Invalid("invalid Lua startup policy")),
        };
        let restart = match table.restart.as_str() {
            "never" => RestartPolicy::Never,
            "on-failure" => RestartPolicy::OnFailure,
            _ => return Err(ContractError::Invalid("invalid Lua restart policy")),
        };
        let health_check = match table.health_check.as_str() {
            "none" => HealthCheck::None,
            "ipc-readiness" => HealthCheck::IpcReadiness,
            _ => return Err(ContractError::Invalid("invalid Lua health check")),
        };
        Ok(Self {
            format_version: table.format_version,
            service_id: ServiceId(table.service_id),
            application_id: ApplicationId(table.application_id),
            identity,
            startup,
            restart,
            health_check,
            dependencies: table.dependencies.into_iter().map(ServiceId).collect(),
            payload: ServicePayload::Lua {
                entrypoint: table.entrypoint,
            },
            requested_capabilities: table
                .requested_capabilities
                .into_iter()
                .map(CapabilityName)
                .collect(),
            socket_policy: SocketPolicy {
                outbound: table.socket_outbound,
                inbound: table.socket_inbound,
                domains: table.socket_domains,
            },
            ipc: IpcContract {
                endpoints: table.ipc_endpoints,
                max_message_bytes: table.max_message_bytes,
            },
        })
    }

    /// Validates both the schema and the approved application grant.  A service
    /// cannot request a capability that its application did not request *and*
    /// receive from trusted policy.
    pub fn validate_against(&self, grant: &ApplicationGrant) -> Result<(), ContractError> {
        if self.format_version != SERVICE_FORMAT_VERSION {
            return Err(ContractError::Invalid("unsupported service format version"));
        }
        validate_id(&self.service_id.0, "service id")?;
        if self.application_id != grant.manifest.app_id {
            return Err(ContractError::Denied(
                "service application does not match grant",
            ));
        }
        if grant.manifest.execution != ExecutionMode::Service
            || !grant.capability_granted("service.background")
        {
            return Err(ContractError::Denied(
                "application is not an approved service",
            ));
        }
        if !self
            .requested_capabilities
            .contains(&CapabilityName("service.background".into()))
        {
            return Err(ContractError::Denied(
                "service must explicitly declare service.background",
            ));
        }
        if self.dependencies.len() > MAX_DEPENDENCIES {
            return Err(ContractError::Invalid("too many dependencies"));
        }
        if self.dependencies.contains(&self.service_id) {
            return Err(ContractError::Invalid("service cannot depend on itself"));
        }
        for dependency in &self.dependencies {
            validate_id(&dependency.0, "dependency id")?;
        }
        for capability in &self.requested_capabilities {
            if !grant.capability_granted(&capability.0) {
                return Err(ContractError::Denied("service capability was not granted"));
            }
        }
        match &self.payload {
            ServicePayload::Lua { entrypoint } => {
                if grant.manifest.runtime != Runtime::Lua {
                    return Err(ContractError::Denied(
                        "Lua payload requires Lua application",
                    ));
                }
                validate_relative_entrypoint(entrypoint, ".lua")?;
                if entrypoint != &grant.manifest.entrypoint {
                    return Err(ContractError::Denied(
                        "service payload differs from application entrypoint",
                    ));
                }
            }
            ServicePayload::Go(payload) => {
                if grant.manifest.runtime != Runtime::Go {
                    return Err(ContractError::Denied("Go payload requires Go application"));
                }
                validate_go_payload(payload)?;
                if payload.module != grant.manifest.entrypoint {
                    return Err(ContractError::Denied(
                        "service payload differs from application entrypoint",
                    ));
                }
            }
        }
        validate_ipc(&self.ipc)?;
        validate_socket_policy(&self.socket_policy, grant, &self.requested_capabilities)?;
        Ok(())
    }

    /// Resolves the declared owner through the common Hyber identity registry.
    /// A service must use an enabled service account that is a member of its
    /// declared group; host identities and numeric look-alikes are rejected.
    pub fn validate_identity(&self, accounts: &AccountRegistry) -> Result<(), ContractError> {
        let user = accounts
            .user(self.identity.user_id)
            .ok_or(ContractError::Denied("service user does not exist"))?;
        let group = accounts
            .group(self.identity.group_id)
            .ok_or(ContractError::Denied("service group does not exist"))?;
        if user.state != AccountState::Service {
            return Err(ContractError::Denied("service requires a service account"));
        }
        let member_by_user =
            user.primary_group == group.id || user.supplementary_groups.contains(&group.id);
        if !member_by_user || !group.members.contains(&user.id) {
            return Err(ContractError::Denied(
                "service account is not a member of its group",
            ));
        }
        Ok(())
    }
}

/// Registry/graph verifier for the future Rust supervisor.  Registration is
/// pure validation: it neither starts a process nor creates a socket.
#[derive(Debug, Clone, Default)]
pub struct ServiceCatalog {
    services: BTreeMap<ServiceId, ServiceDefinition>,
}
impl ServiceCatalog {
    pub fn register(
        &mut self,
        accounts: &AccountRegistry,
        definition: ServiceDefinition,
        grant: &ApplicationGrant,
    ) -> Result<(), ContractError> {
        if self.services.len() >= MAX_SERVICES {
            return Err(ContractError::Invalid("service catalog capacity exceeded"));
        }
        definition.validate_against(grant)?;
        definition.validate_identity(accounts)?;
        if self.services.contains_key(&definition.service_id) {
            return Err(ContractError::DuplicateService);
        }
        let id = definition.service_id.clone();
        self.services.insert(id.clone(), definition);
        if let Err(error) = self.validate_graph() {
            self.services.remove(&id);
            return Err(error);
        }
        Ok(())
    }
    pub fn get(&self, id: &ServiceId) -> Option<&ServiceDefinition> {
        self.services.get(id)
    }
    /// Deterministic, read-only catalog view for the Rust supervisor.
    pub fn definitions(&self) -> impl Iterator<Item = (&ServiceId, &ServiceDefinition)> {
        self.services.iter()
    }
    /// Atomically validates a mutually-dependent declaration set. This is used
    /// when a future loader reads all Lua service definitions at once, and is
    /// the path that can distinguish a cycle from a merely missing dependency.
    pub fn register_batch(
        &mut self,
        accounts: &AccountRegistry,
        entries: impl IntoIterator<Item = (ServiceDefinition, ApplicationGrant)>,
    ) -> Result<(), ContractError> {
        let entries: Vec<_> = entries.into_iter().take(MAX_SERVICES + 1).collect();
        if entries.len() + self.services.len() > MAX_SERVICES {
            return Err(ContractError::Invalid("service catalog capacity exceeded"));
        }
        for (definition, grant) in &entries {
            definition.validate_against(grant)?;
            definition.validate_identity(accounts)?;
            if self.services.contains_key(&definition.service_id) {
                return Err(ContractError::DuplicateService);
            }
        }
        let original = self.services.clone();
        for (definition, _) in entries {
            if self.services.contains_key(&definition.service_id) {
                self.services = original;
                return Err(ContractError::DuplicateService);
            }
            self.services
                .insert(definition.service_id.clone(), definition);
        }
        if let Err(error) = self.validate_graph() {
            self.services = original;
            return Err(error);
        }
        Ok(())
    }
    pub fn launch_order(&self) -> Result<Vec<&ServiceDefinition>, ContractError> {
        self.validate_graph()?;
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        for id in self.services.keys() {
            self.visit(id, &mut visited, &mut BTreeSet::new(), &mut order)?;
        }
        Ok(order)
    }
    fn validate_graph(&self) -> Result<(), ContractError> {
        for definition in self.services.values() {
            for dependency in &definition.dependencies {
                if !self.services.contains_key(dependency) {
                    return Err(ContractError::MissingDependency(dependency.clone()));
                }
            }
        }
        let mut visited = BTreeSet::new();
        for id in self.services.keys() {
            self.visit(id, &mut visited, &mut BTreeSet::new(), &mut Vec::new())?;
        }
        Ok(())
    }
    fn visit<'a>(
        &'a self,
        id: &ServiceId,
        visited: &mut BTreeSet<ServiceId>,
        active: &mut BTreeSet<ServiceId>,
        order: &mut Vec<&'a ServiceDefinition>,
    ) -> Result<(), ContractError> {
        if visited.contains(id) {
            return Ok(());
        }
        if active.len() >= MAX_DEPENDENCY_DEPTH {
            return Err(ContractError::Invalid("service dependency depth exceeded"));
        }
        if !active.insert(id.clone()) {
            return Err(ContractError::DependencyCycle);
        }
        let definition = self.services.get(id).expect("validated service id");
        for dependency in &definition.dependencies {
            self.visit(dependency, visited, active, order)?;
        }
        active.remove(id);
        visited.insert(id.clone());
        order.push(definition);
        Ok(())
    }
}

fn validate_id(value: &str, label: &'static str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 64
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(ContractError::Invalid(label))
    } else {
        Ok(())
    }
}
fn validate_relative_entrypoint(value: &str, extension: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || !value.ends_with(extension)
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | "..") || part.contains('\\'))
    {
        Err(ContractError::Invalid("invalid payload entrypoint"))
    } else {
        Ok(())
    }
}
fn validate_go_payload(payload: &GoPayloadContract) -> Result<(), ContractError> {
    validate_id(&payload.module, "Go module")?;
    if payload.max_concurrency == 0 || !payload.cooperative_cancellation {
        return Err(ContractError::Invalid("invalid Go lifecycle contract"));
    }
    if payload.arguments.len() > 64 || payload.arguments.iter().any(|arg| arg.len() > 1024) {
        return Err(ContractError::Invalid("invalid Go arguments"));
    }
    Ok(())
}
fn validate_ipc(ipc: &IpcContract) -> Result<(), ContractError> {
    if ipc.endpoints.len() > MAX_IPC_ENDPOINTS
        || ipc.max_message_bytes == 0
        || ipc.max_message_bytes > MAX_IPC_MESSAGE_BYTES
    {
        return Err(ContractError::Invalid("invalid IPC contract"));
    }
    for endpoint in &ipc.endpoints {
        validate_id(endpoint, "IPC endpoint")?;
    }
    Ok(())
}
fn validate_socket_policy(
    socket: &SocketPolicy,
    grant: &ApplicationGrant,
    requested: &BTreeSet<CapabilityName>,
) -> Result<(), ContractError> {
    let outbound = CapabilityName("network.outbound".into());
    let inbound = CapabilityName("network.inbound".into());
    if socket.outbound != grant.manifest.network.outbound
        || socket.inbound != grant.manifest.network.inbound
        || socket.domains != grant.manifest.network.domains
    {
        return Err(ContractError::Denied(
            "socket policy differs from application grant",
        ));
    }
    if socket.outbound && (!requested.contains(&outbound) || !grant.capability_granted(&outbound.0))
    {
        return Err(ContractError::Denied(
            "outbound socket capability was not granted",
        ));
    }
    if socket.inbound && (!requested.contains(&inbound) || !grant.capability_granted(&inbound.0)) {
        return Err(ContractError::Denied(
            "inbound socket capability was not granted",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_manifest::{GrantPolicy, Manifest, NetworkPolicy, ResourceQuotas, StorageScopes};

    fn accounts() -> (AccountRegistry, ServiceIdentity) {
        let mut accounts = AccountRegistry::new();
        let group = accounts.create_group("services").unwrap();
        let user = accounts
            .create_user("dns-service", group, AccountState::Service)
            .unwrap();
        (
            accounts,
            ServiceIdentity {
                user_id: user,
                group_id: group,
            },
        )
    }

    fn grant(runtime: Runtime) -> ApplicationGrant {
        let capabilities: BTreeSet<CapabilityName> = ["service.background", "network.outbound"]
            .into_iter()
            .map(|value| CapabilityName(value.into()))
            .collect();
        let manifest = Manifest {
            format_version: 1,
            app_id: ApplicationId("dns-service".into()),
            version: "1.0.0".into(),
            publisher: "hyber".into(),
            display_name: "DNS service".into(),
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
            network: NetworkPolicy {
                outbound: true,
                inbound: false,
                domains: BTreeSet::new(),
            },
            resources: ResourceQuotas {
                memory_bytes: 1024,
                cpu_shares: 1,
                handles: 1,
                storage_bytes: 1024,
            },
        };
        GrantPolicy {
            capabilities,
            allow_gui: false,
            allow_background: false,
            allow_service: true,
            max_resources: manifest.resources,
        }
        .approve(manifest)
        .unwrap()
    }
    fn definition(id: &str, dependencies: &[&str], identity: ServiceIdentity) -> ServiceDefinition {
        ServiceDefinition {
            format_version: 1,
            service_id: ServiceId(id.into()),
            application_id: ApplicationId("dns-service".into()),
            identity,
            startup: StartupPolicy::Automatic,
            restart: RestartPolicy::OnFailure,
            health_check: HealthCheck::IpcReadiness,
            dependencies: dependencies
                .iter()
                .map(|id| ServiceId((*id).into()))
                .collect(),
            payload: ServicePayload::Lua {
                entrypoint: "main.lua".into(),
            },
            requested_capabilities: [
                CapabilityName("service.background".into()),
                CapabilityName("network.outbound".into()),
            ]
            .into_iter()
            .collect(),
            socket_policy: SocketPolicy {
                outbound: true,
                inbound: false,
                domains: BTreeSet::new(),
            },
            ipc: IpcContract {
                endpoints: ["dns".into()].into_iter().collect(),
                max_message_bytes: 1024,
            },
        }
    }
    #[test]
    fn approved_service_contract_has_deterministic_dependency_order() {
        let grant = grant(Runtime::Lua);
        let (accounts, identity) = accounts();
        let mut catalog = ServiceCatalog::default();
        let dependency = definition("network", &[], identity);
        catalog.register(&accounts, dependency, &grant).unwrap();
        let service = definition("dns", &["network"], identity);
        catalog.register(&accounts, service, &grant).unwrap();
        assert_eq!(
            catalog
                .launch_order()
                .unwrap()
                .iter()
                .map(|definition| definition.service_id.0.as_str())
                .collect::<Vec<_>>(),
            ["network", "dns"]
        );
    }
    #[test]
    fn oversized_and_deep_catalog_batches_fail_without_partial_registration() {
        let grant = grant(Runtime::Lua);
        let (accounts, identity) = accounts();
        let mut catalog = ServiceCatalog::default();
        let deep: Vec<_> = (0..=MAX_DEPENDENCY_DEPTH)
            .map(|index| {
                let mut entry = definition(&format!("svc{index:04}"), &[], identity);
                if index < MAX_DEPENDENCY_DEPTH {
                    entry
                        .dependencies
                        .insert(ServiceId(format!("svc{:04}", index + 1)));
                }
                (entry, grant.clone())
            })
            .collect();
        assert!(catalog.register_batch(&accounts, deep).is_err());
        assert_eq!(catalog.definitions().count(), 0);
        assert!(catalog
            .register_batch(
                &accounts,
                std::iter::repeat_n((definition("svc", &[], identity), grant), MAX_SERVICES + 1)
            )
            .is_err());
        assert_eq!(catalog.definitions().count(), 0);
    }
    #[test]
    fn rejects_missing_dependency_and_unapproved_socket_policy() {
        let grant = grant(Runtime::Lua);
        let (accounts, identity) = accounts();
        let mut catalog = ServiceCatalog::default();
        assert!(matches!(
            catalog.register(&accounts, definition("dns", &["network"], identity), &grant),
            Err(ContractError::MissingDependency(_))
        ));
        let mut invalid = definition("network", &[], identity);
        invalid.socket_policy.inbound = true;
        assert!(invalid.validate_against(&grant).is_err());
    }
    #[test]
    fn go_contract_requires_cooperative_cancellation_and_go_runtime() {
        let (_, identity) = accounts();
        let mut definition = definition("go-dns", &[], identity);
        definition.payload = ServicePayload::Go(GoPayloadContract {
            module: "dnsd".into(),
            arguments: vec![],
            max_concurrency: 8,
            cooperative_cancellation: true,
        });
        assert!(definition.validate_against(&grant(Runtime::Lua)).is_err());
        let mut go_definition = definition;
        go_definition.payload = ServicePayload::Go(GoPayloadContract {
            module: "dnsd".into(),
            arguments: vec![],
            max_concurrency: 8,
            cooperative_cancellation: false,
        });
        assert!(go_definition.validate_against(&grant(Runtime::Go)).is_err());
    }

    #[test]
    fn batch_registration_rejects_dependency_cycles_atomically() {
        let grant = grant(Runtime::Lua);
        let (accounts, identity) = accounts();
        let mut catalog = ServiceCatalog::default();
        let first = definition("one", &["two"], identity);
        let second = definition("two", &["one"], identity);
        assert!(matches!(
            catalog.register_batch(&accounts, [(first, grant.clone()), (second, grant)]),
            Err(ContractError::DependencyCycle)
        ));
        assert!(catalog.get(&ServiceId("one".into())).is_none());
    }
}
