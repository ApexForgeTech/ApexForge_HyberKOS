//! Special_6 application manifests, grants, and storage sandboxes.
//!
//! TOML is an untrusted request. A trusted policy must approve it before an
//! application receives a sandbox; manifests never grant themselves authority.

use hyber_core::Path;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const FORMAT_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApplicationId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityName(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    Lua,
    Go,
    Native,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    Gui,
    Background,
    Service,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeAccess {
    #[default]
    None,
    Read,
    ReadWrite,
}
impl ScopeAccess {
    pub const fn permits(self, write: bool) -> bool {
        matches!(self, Self::ReadWrite) || (!write && matches!(self, Self::Read))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageScopes {
    pub config: ScopeAccess,
    pub data: ScopeAccess,
    pub state: ScopeAccess,
    pub cache: ScopeAccess,
    pub temporary: ScopeAccess,
    pub runtime: ScopeAccess,
}
impl Default for StorageScopes {
    fn default() -> Self {
        Self {
            config: ScopeAccess::None,
            data: ScopeAccess::None,
            state: ScopeAccess::None,
            cache: ScopeAccess::None,
            temporary: ScopeAccess::None,
            runtime: ScopeAccess::None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkPolicy {
    pub outbound: bool,
    pub inbound: bool,
    pub domains: BTreeSet<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceQuotas {
    pub memory_bytes: u64,
    pub cpu_shares: u32,
    pub handles: u32,
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub app_id: ApplicationId,
    pub version: String,
    pub publisher: String,
    pub display_name: String,
    pub entrypoint: String,
    pub runtime: Runtime,
    #[serde(default)]
    pub requested_capabilities: BTreeSet<CapabilityName>,
    #[serde(default)]
    pub storage: StorageScopes,
    pub execution: ExecutionMode,
    #[serde(default)]
    pub network: NetworkPolicy,
    pub resources: ResourceQuotas,
}
impl Manifest {
    pub fn parse_toml(text: &str) -> Result<Self, ManifestError> {
        if text.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Invalid("manifest exceeds 64 KiB"));
        }
        let manifest: Self =
            toml::from_str(text).map_err(|_| ManifestError::Invalid("invalid manifest TOML"))?;
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.format_version != FORMAT_VERSION {
            return Err(ManifestError::UnsupportedVersion);
        }
        validate_id(&self.app_id.0, "application id")?;
        validate_id(&self.publisher, "publisher")?;
        if self.display_name.is_empty()
            || self.display_name.len() > 128
            || self.display_name.chars().any(char::is_control)
        {
            return Err(ManifestError::Invalid("invalid display name"));
        }
        parse_version(&self.version)?;
        validate_entrypoint(&self.entrypoint, self.runtime)?;
        let q = self.resources;
        if q.memory_bytes == 0
            || q.memory_bytes > (1 << 40)
            || q.cpu_shares == 0
            || q.cpu_shares > 10_000
            || q.handles == 0
            || q.handles > 65_536
            || q.storage_bytes == 0
            || q.storage_bytes > (1 << 40)
        {
            return Err(ManifestError::Invalid("invalid resource quota"));
        }
        for cap in &self.requested_capabilities {
            validate_capability(&cap.0)?;
        }
        if !self.network.outbound
            && (!self.network.domains.is_empty()
                || self
                    .requested_capabilities
                    .contains(&CapabilityName("network.outbound".into())))
        {
            return Err(ManifestError::Invalid(
                "outbound network capability requires network.outbound",
            ));
        }
        if self.network.inbound
            && !self
                .requested_capabilities
                .contains(&CapabilityName("network.inbound".into()))
        {
            return Err(ManifestError::Invalid(
                "inbound network policy requires network.inbound capability",
            ));
        }
        for domain in &self.network.domains {
            validate_domain(domain)?;
        }
        if matches!(self.execution, ExecutionMode::Service)
            && !self
                .requested_capabilities
                .contains(&CapabilityName("service.background".into()))
        {
            return Err(ManifestError::Invalid(
                "service execution requires service.background capability",
            ));
        }
        if matches!(self.execution, ExecutionMode::Gui)
            && !self
                .requested_capabilities
                .contains(&CapabilityName("gui.window".into()))
        {
            return Err(ManifestError::Invalid(
                "GUI execution requires gui.window capability",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Invalid(&'static str),
    UnsupportedVersion,
    Denied(String),
    AlreadyInstalled,
    NotInstalled,
    NoRollback,
}
impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) => f.write_str(s),
            Self::UnsupportedVersion => f.write_str("unsupported manifest version"),
            Self::Denied(s) => write!(f, "manifest grant denied: {s}"),
            Self::AlreadyInstalled => f.write_str("application version already installed"),
            Self::NotInstalled => f.write_str("application is not installed"),
            Self::NoRollback => f.write_str("no previous application version"),
        }
    }
}
impl std::error::Error for ManifestError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPolicy {
    pub capabilities: BTreeSet<CapabilityName>,
    pub allow_gui: bool,
    pub allow_background: bool,
    pub allow_service: bool,
    pub max_resources: ResourceQuotas,
}
impl GrantPolicy {
    pub fn deny_all() -> Self {
        Self {
            capabilities: BTreeSet::new(),
            allow_gui: false,
            allow_background: true,
            allow_service: false,
            max_resources: ResourceQuotas {
                memory_bytes: 256 * 1024 * 1024,
                cpu_shares: 1_000,
                handles: 256,
                storage_bytes: 256 * 1024 * 1024,
            },
        }
    }
    pub fn approve(&self, manifest: Manifest) -> Result<ApplicationGrant, ManifestError> {
        manifest.validate()?;
        if !manifest
            .requested_capabilities
            .is_subset(&self.capabilities)
        {
            return Err(ManifestError::Denied(
                "requested capability is not approved".into(),
            ));
        }
        let mode_ok = match manifest.execution {
            ExecutionMode::Gui => self.allow_gui,
            ExecutionMode::Background => self.allow_background,
            ExecutionMode::Service => self.allow_service,
        };
        if !mode_ok {
            return Err(ManifestError::Denied(
                "execution policy is not approved".into(),
            ));
        }
        let q = manifest.resources;
        let max = self.max_resources;
        if q.memory_bytes > max.memory_bytes
            || q.cpu_shares > max.cpu_shares
            || q.handles > max.handles
            || q.storage_bytes > max.storage_bytes
        {
            return Err(ManifestError::Denied(
                "requested resource quota exceeds policy".into(),
            ));
        }
        Ok(ApplicationGrant {
            manifest,
            granted_capabilities: self.capabilities.clone(),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationGrant {
    pub manifest: Manifest,
    granted_capabilities: BTreeSet<CapabilityName>,
}
impl ApplicationGrant {
    pub fn capability_granted(&self, capability: &str) -> bool {
        let cap = CapabilityName(capability.into());
        self.manifest.requested_capabilities.contains(&cap)
            && self.granted_capabilities.contains(&cap)
    }

    /// Capabilities actually granted to this application.  This is deliberately
    /// the intersection of the request and trusted policy, never the policy's
    /// complete capability set.
    pub fn granted_capabilities(&self) -> impl Iterator<Item = &CapabilityName> {
        self.manifest
            .requested_capabilities
            .iter()
            .filter(|capability| self.granted_capabilities.contains(*capability))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRoots {
    pub config: Path,
    pub data: Path,
    pub state: Path,
    pub cache: Path,
    pub temporary: Path,
    pub runtime: Path,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Config,
    Data,
    State,
    Cache,
    Temporary,
    Runtime,
}
#[derive(Debug, Clone)]
pub struct ApplicationSandbox {
    grant: ApplicationGrant,
    roots: StorageRoots,
}
impl ApplicationSandbox {
    pub fn new(grant: ApplicationGrant, roots: StorageRoots) -> Result<Self, ManifestError> {
        let roots_to_validate = [
            &roots.config,
            &roots.data,
            &roots.state,
            &roots.cache,
            &roots.temporary,
            &roots.runtime,
        ];
        for root in roots_to_validate {
            if !root.is_absolute || root.components.is_empty() || *root != root.normalize() {
                return Err(ManifestError::Invalid(
                    "storage root must be absolute, normalized, and non-root",
                ));
            }
        }
        for (index, root) in roots_to_validate.iter().enumerate() {
            for other in roots_to_validate.iter().skip(index + 1) {
                let root = root.normalize();
                let other = other.normalize();
                if root.components.starts_with(&other.components)
                    || other.components.starts_with(&root.components)
                {
                    return Err(ManifestError::Invalid(
                        "application storage roots must be disjoint",
                    ));
                }
            }
        }
        Ok(Self { grant, roots })
    }
    pub fn grant(&self) -> &ApplicationGrant {
        &self.grant
    }
    pub fn root(&self, class: StorageClass) -> Result<&Path, ManifestError> {
        let (root, scope) = self.root_and_scope(class);
        if scope == ScopeAccess::None {
            Err(ManifestError::Denied("storage scope is not granted".into()))
        } else {
            Ok(root)
        }
    }
    pub fn authorize(&self, path: &Path, write: bool) -> Result<StorageClass, ManifestError> {
        if !path.is_absolute {
            return Err(ManifestError::Denied(
                "application paths must be absolute Hyber paths".into(),
            ));
        }
        let path = path.normalize();
        for class in [
            StorageClass::Config,
            StorageClass::Data,
            StorageClass::State,
            StorageClass::Cache,
            StorageClass::Temporary,
            StorageClass::Runtime,
        ] {
            let (root, scope) = self.root_and_scope(class);
            let root = root.normalize();
            if path.components.starts_with(&root.components) {
                return if scope.permits(write) {
                    Ok(class)
                } else {
                    Err(ManifestError::Denied(
                        "storage scope does not grant this operation".into(),
                    ))
                };
            }
        }
        Err(ManifestError::Denied(
            "path escapes application storage roots".into(),
        ))
    }
    pub fn capability(&self, name: &str) -> bool {
        self.grant.capability_granted(name)
    }
    pub fn storage_limit(&self) -> u64 {
        self.grant.manifest.resources.storage_bytes
    }
    pub fn roots(&self) -> [&Path; 6] {
        [
            &self.roots.config,
            &self.roots.data,
            &self.roots.state,
            &self.roots.cache,
            &self.roots.temporary,
            &self.roots.runtime,
        ]
    }
    fn root_and_scope(&self, class: StorageClass) -> (&Path, ScopeAccess) {
        match class {
            StorageClass::Config => (&self.roots.config, self.grant.manifest.storage.config),
            StorageClass::Data => (&self.roots.data, self.grant.manifest.storage.data),
            StorageClass::State => (&self.roots.state, self.grant.manifest.storage.state),
            StorageClass::Cache => (&self.roots.cache, self.grant.manifest.storage.cache),
            StorageClass::Temporary => {
                (&self.roots.temporary, self.grant.manifest.storage.temporary)
            }
            StorageClass::Runtime => (&self.roots.runtime, self.grant.manifest.storage.runtime),
        }
    }
}

#[derive(Debug, Default)]
pub struct ManifestRegistry {
    versions: BTreeMap<ApplicationId, Vec<ApplicationGrant>>,
}
impl ManifestRegistry {
    pub fn install(&mut self, grant: ApplicationGrant) -> Result<(), ManifestError> {
        let id = grant.manifest.app_id.clone();
        let versions = self.versions.entry(id).or_default();
        if versions
            .iter()
            .any(|old| old.manifest.version == grant.manifest.version)
        {
            return Err(ManifestError::AlreadyInstalled);
        }
        if let Some(current) = versions.last() {
            if version_key(&grant.manifest.version)? <= version_key(&current.manifest.version)? {
                return Err(ManifestError::Denied(
                    "upgrade version must increase".into(),
                ));
            }
        }
        versions.push(grant);
        Ok(())
    }
    pub fn active(&self, id: &ApplicationId) -> Option<&ApplicationGrant> {
        self.versions.get(id).and_then(|v| v.last())
    }
    pub fn rollback(&mut self, id: &ApplicationId) -> Result<&ApplicationGrant, ManifestError> {
        let versions = self
            .versions
            .get_mut(id)
            .ok_or(ManifestError::NotInstalled)?;
        if versions.len() < 2 {
            return Err(ManifestError::NoRollback);
        }
        versions.pop();
        Ok(versions.last().expect("length checked"))
    }
}

fn validate_id(value: &str, label: &'static str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 64
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        Err(ManifestError::Invalid(label))
    } else {
        Ok(())
    }
}
fn validate_capability(value: &str) -> Result<(), ManifestError> {
    if matches!(
        value,
        "process.spawn"
            | "service.background"
            | "gui.window"
            | "network.outbound"
            | "network.inbound"
            | "shared-data.read"
            | "shared-data.write"
    ) {
        Ok(())
    } else {
        Err(ManifestError::Invalid("unknown application capability"))
    }
}
fn validate_domain(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        Err(ManifestError::Invalid("invalid network domain"))
    } else {
        Ok(())
    }
}
fn validate_entrypoint(value: &str, runtime: Runtime) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | "..") || part.contains('\\'))
        || runtime == Runtime::Lua && !value.ends_with(".lua")
    {
        Err(ManifestError::Invalid("invalid entrypoint"))
    } else {
        Ok(())
    }
}
fn parse_version(value: &str) -> Result<(u64, u64, u64), ManifestError> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(ManifestError::Invalid("version must be major.minor.patch"));
    }
    let parsed: Result<Vec<u64>, _> = parts
        .iter()
        .map(|part| {
            if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
                Err(())
            } else {
                part.parse().map_err(|_| ())
            }
        })
        .collect();
    let parsed = parsed.map_err(|_| ManifestError::Invalid("version must be major.minor.patch"))?;
    Ok((parsed[0], parsed[1], parsed[2]))
}
fn version_key(value: &str) -> Result<(u64, u64, u64), ManifestError> {
    parse_version(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Manifest {
        Manifest {
            format_version: 1,
            app_id: ApplicationId("editor".into()),
            version: "1.0.0".into(),
            publisher: "example".into(),
            display_name: "Editor".into(),
            entrypoint: "main.lua".into(),
            runtime: Runtime::Lua,
            requested_capabilities: BTreeSet::new(),
            storage: StorageScopes {
                data: ScopeAccess::ReadWrite,
                ..StorageScopes::default()
            },
            execution: ExecutionMode::Background,
            network: NetworkPolicy::default(),
            resources: ResourceQuotas {
                memory_bytes: 1024,
                cpu_shares: 1,
                handles: 1,
                storage_bytes: 1024,
            },
        }
    }
    fn roots() -> StorageRoots {
        StorageRoots {
            config: Path::parse("/users/a/.config/editor"),
            data: Path::parse("/users/a/.local/share/editor"),
            state: Path::parse("/users/a/.local/state/editor"),
            cache: Path::parse("/users/a/.cache/editor"),
            temporary: Path::parse("/temporary/users/1/editor"),
            runtime: Path::parse("/runtime/users/1/editor"),
        }
    }
    #[test]
    fn rejects_escapes_unknown_caps_and_self_grants() {
        let mut m = manifest();
        m.entrypoint = "../main.lua".into();
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.requested_capabilities
            .insert(CapabilityName("kernel.takeover".into()));
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.requested_capabilities
            .insert(CapabilityName("process.spawn".into()));
        assert!(GrantPolicy::deny_all().approve(m).is_err());
    }
    #[test]
    fn sandbox_cannot_escape_or_cross_scope() {
        let grant = GrantPolicy::deny_all().approve(manifest()).unwrap();
        let sandbox = ApplicationSandbox::new(grant, roots()).unwrap();
        assert!(sandbox
            .authorize(&Path::parse("/users/a/.local/share/editor/a"), true)
            .is_ok());
        assert!(sandbox
            .authorize(&Path::parse("/users/a/.local/share/other/a"), true)
            .is_err());
        assert!(sandbox
            .authorize(&Path::parse("/users/a/.config/editor/a"), false)
            .is_err());
        assert!(sandbox
            .authorize(&Path::parse("users/a/.local/share/editor/a"), true)
            .is_err());
    }
    #[test]
    fn sandbox_rejects_overlapping_storage_roots() {
        let grant = GrantPolicy::deny_all().approve(manifest()).unwrap();
        let mut invalid_roots = roots();
        invalid_roots.cache = Path::parse("/users/a/.local/share/editor/cache");
        assert!(ApplicationSandbox::new(grant, invalid_roots).is_err());
    }
    #[test]
    fn registry_requires_increasing_versions_and_rolls_back() {
        let policy = GrantPolicy::deny_all();
        let mut first = manifest();
        first.version = "1.0.0".into();
        let mut second = manifest();
        second.version = "1.1.0".into();
        let mut registry = ManifestRegistry::default();
        registry.install(policy.approve(first).unwrap()).unwrap();
        registry.install(policy.approve(second).unwrap()).unwrap();
        assert_eq!(
            registry
                .rollback(&ApplicationId("editor".into()))
                .unwrap()
                .manifest
                .version,
            "1.0.0"
        );
    }
}
