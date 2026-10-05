//! Trusted, deterministic Phase 17 package repository and installer core.
//!
//! The core is intentionally storage-agnostic: it validates signed artifacts,
//! resolves a repository snapshot, and atomically changes an in-memory durable
//! registry model. A provider adapter persists that model only after this layer
//! produces a committed transaction; no host path or host identity is part of
//! package authority.

use ed25519_dalek::VerifyingKey;
use hyber_core::{SecurityContext, SecurityManager, UserId};
use hyber_manifest::{ApplicationGrant, CapabilityName, GrantPolicy, Manifest};
use hyber_package_format::{
    artifact_digest, Dependency, PackageFormatError, PackageId, PackageKey, PackageVersion,
    SignedPackage, VersionRequirement,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_PLAN_PACKAGES: usize = 1_024;
pub const MAX_RESOLUTION_DEPTH: usize = 128;
const REGISTRY_MAGIC: [u8; 8] = *b"HYBPKR1\0";
const REGISTRY_VERSION: u32 = 1;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Trusted,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub key_id: String,
    pub publisher: String,
    /// Optional package-ID prefix; a key with `Some("example.")` cannot sign
    /// `other.app`. Prefixes are logical identifiers, never filesystem paths.
    pub package_prefix: Option<String>,
    pub state: KeyState,
    pub verifying_key: VerifyingKey,
}

#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    keys: BTreeMap<String, TrustedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord {
    pub key: PackageKey,
    pub application_id: String,
    pub publisher: String,
    pub key_id: String,
    pub digest: [u8; 32],
    pub dependencies: Vec<Dependency>,
    pub artifact: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Repository {
    by_digest: BTreeMap<[u8; 32], PackageRecord>,
    by_key: BTreeMap<PackageId, BTreeMap<PackageVersion, [u8; 32]>>,
}

/// Hosted local repository layout. Artifact filenames are only SHA-256
/// digests; neither package IDs nor package-provided paths affect host paths.
#[derive(Debug, Clone)]
pub struct LocalRepository {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionPlan {
    /// Dependencies precede dependents and every key has a fixed artifact
    /// digest from the snapshot used during resolution.
    pub ordered: Vec<PackageRecord>,
}

#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub record: PackageRecord,
    pub grant: ApplicationGrant,
    pub installed_by: UserId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Idle,
    Planned,
    Verified,
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone)]
pub struct PackageRegistry {
    generations: u64,
    installed: BTreeMap<PackageId, Vec<InstalledPackage>>,
    application_owners: BTreeMap<String, PackageId>,
    transaction: TransactionState,
}

impl Default for PackageRegistry {
    fn default() -> Self {
        Self {
            generations: 0,
            installed: BTreeMap::new(),
            application_owners: BTreeMap::new(),
            transaction: TransactionState::Idle,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PackageManager {
    pub repository: Repository,
    pub registry: PackageRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    Format(String),
    InvalidTrust(&'static str),
    UnknownKey,
    DisabledKey,
    RevokedKey,
    Signature,
    PublisherMismatch,
    KeyScopeDenied,
    ArtifactConflict,
    MissingDependency(PackageId),
    DependencyConflict(PackageId),
    DependencyCycle,
    ResolutionLimit,
    Authorization(String),
    Grant(String),
    AlreadyInstalled,
    DowngradeDenied,
    ApplicationOwnershipConflict,
    NotInstalled,
    NoRollback,
    ReverseDependency(PackageId),
    BusyTransaction,
    GenerationOverflow,
}

impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(reason) => write!(f, "invalid package format: {reason}"),
            Self::InvalidTrust(reason) => write!(f, "invalid package trust policy: {reason}"),
            Self::UnknownKey => f.write_str("package signing key is not trusted"),
            Self::DisabledKey => f.write_str("package signing key is disabled"),
            Self::RevokedKey => f.write_str("package signing key is revoked"),
            Self::Signature => f.write_str("package signature verification failed"),
            Self::PublisherMismatch => f.write_str("package publisher does not match signing key"),
            Self::KeyScopeDenied => f.write_str("signing key is not authorized for this package"),
            Self::ArtifactConflict => f.write_str("package key already maps to different artifact"),
            Self::MissingDependency(id) => write!(f, "missing package dependency: {}", id.0),
            Self::DependencyConflict(id) => write!(f, "package dependency conflict: {}", id.0),
            Self::DependencyCycle => f.write_str("package dependency cycle"),
            Self::ResolutionLimit => f.write_str("package dependency resolution limit exceeded"),
            Self::Authorization(reason) => write!(f, "package administration denied: {reason}"),
            Self::Grant(reason) => write!(f, "application grant denied: {reason}"),
            Self::AlreadyInstalled => f.write_str("package version is already installed"),
            Self::DowngradeDenied => f.write_str("package update must increase version"),
            Self::ApplicationOwnershipConflict => {
                f.write_str("application id belongs to another package")
            }
            Self::NotInstalled => f.write_str("package is not installed"),
            Self::NoRollback => f.write_str("no prior installed package version"),
            Self::ReverseDependency(id) => write!(f, "package is required by {}", id.0),
            Self::BusyTransaction => f.write_str("package transaction is already in progress"),
            Self::GenerationOverflow => f.write_str("package registry generation overflow"),
        }
    }
}
impl std::error::Error for PackageError {}

impl From<PackageFormatError> for PackageError {
    fn from(error: PackageFormatError) -> Self {
        match error {
            PackageFormatError::BadSignature => Self::Signature,
            other => Self::Format(other.to_string()),
        }
    }
}

impl TrustStore {
    pub fn add(&mut self, actor: &SecurityContext, key: TrustedKey) -> Result<(), PackageError> {
        require_admin(actor)?;
        validate_trusted_key(&key)?;
        if self.keys.contains_key(&key.key_id) {
            return Err(PackageError::InvalidTrust("duplicate key id"));
        }
        self.keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    pub fn set_state(
        &mut self,
        actor: &SecurityContext,
        key_id: &str,
        state: KeyState,
    ) -> Result<(), PackageError> {
        require_admin(actor)?;
        self.keys
            .get_mut(key_id)
            .ok_or(PackageError::UnknownKey)?
            .state = state;
        Ok(())
    }

    pub fn verify(&self, package: &SignedPackage) -> Result<(), PackageError> {
        let key = self
            .keys
            .get(&package.key_id)
            .ok_or(PackageError::UnknownKey)?;
        match key.state {
            KeyState::Trusted => (),
            KeyState::Disabled => return Err(PackageError::DisabledKey),
            KeyState::Revoked => return Err(PackageError::RevokedKey),
        }
        if package.input.metadata.publisher != key.publisher {
            return Err(PackageError::PublisherMismatch);
        }
        if key
            .package_prefix
            .as_ref()
            .is_some_and(|prefix| !package.input.metadata.key.id.0.starts_with(prefix))
        {
            return Err(PackageError::KeyScopeDenied);
        }
        package.verify(&key.verifying_key).map_err(Into::into)
    }
}

impl Repository {
    /// Import verifies first and only then makes the artifact index-visible.
    /// Re-importing identical bytes is idempotent; changing a key/version's
    /// artifact is rejected rather than silently replacing history.
    pub fn import(
        &mut self,
        trust: &TrustStore,
        artifact: &[u8],
    ) -> Result<PackageRecord, PackageError> {
        let package = SignedPackage::decode(artifact)?;
        trust.verify(&package)?;
        let digest = artifact_digest(artifact);
        if let Some(existing) = self.by_digest.get(&digest) {
            return Ok(existing.clone());
        }
        let record = PackageRecord {
            key: package.input.metadata.key.clone(),
            application_id: package.input.metadata.application_id.clone(),
            publisher: package.input.metadata.publisher.clone(),
            key_id: package.key_id,
            digest,
            dependencies: package.input.metadata.dependencies.clone(),
            artifact: artifact.to_vec(),
        };
        let versions = self.by_key.entry(record.key.id.clone()).or_default();
        if let Some(old_digest) = versions.get(&record.key.version) {
            if old_digest != &digest {
                return Err(PackageError::ArtifactConflict);
            }
        }
        versions.insert(record.key.version, digest);
        self.by_digest.insert(digest, record.clone());
        Ok(record)
    }

    pub fn candidate(&self, key: &PackageKey) -> Option<&PackageRecord> {
        self.by_key
            .get(&key.id)
            .and_then(|versions| versions.get(&key.version))
            .and_then(|digest| self.by_digest.get(digest))
    }

    pub fn candidates(&self, id: &PackageId) -> Vec<&PackageRecord> {
        self.by_key
            .get(id)
            .into_iter()
            .flat_map(|versions| versions.values().rev())
            .filter_map(|digest| self.by_digest.get(digest))
            .collect()
    }

    pub fn resolve(&self, requested: &[Dependency]) -> Result<ResolutionPlan, PackageError> {
        if requested.is_empty() || requested.len() > MAX_PLAN_PACKAGES {
            return Err(PackageError::ResolutionLimit);
        }
        let mut requirements = BTreeMap::<PackageId, Vec<VersionRequirement>>::new();
        for dependency in requested {
            requirements
                .entry(dependency.package.clone())
                .or_default()
                .push(dependency.requirement.clone());
        }
        let selected = resolve_selected(self, requirements, BTreeMap::new(), 0)?;
        let mut ordered = Vec::with_capacity(selected.len());
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for id in selected.keys() {
            order_dependencies(
                self,
                &selected,
                id,
                &mut visiting,
                &mut visited,
                &mut ordered,
            )?;
        }
        Ok(ResolutionPlan { ordered })
    }
}

impl LocalRepository {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PackageError> {
        let root = root.into();
        if root.exists() {
            let metadata = fs::symlink_metadata(&root).map_err(|error| {
                PackageError::Format(format!("cannot inspect repository root: {error}"))
            })?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(PackageError::Format(
                    "repository root must be a real directory".into(),
                ));
            }
        } else {
            fs::create_dir(&root).map_err(|error| {
                PackageError::Format(format!("cannot create repository root: {error}"))
            })?;
        }
        for name in ["packages", "index", "keys", "staging"] {
            let path = root.join(name);
            if path.exists() {
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    PackageError::Format(format!("cannot inspect repository directory: {error}"))
                })?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(PackageError::Format(
                        "repository component must be a real directory".into(),
                    ));
                }
            } else {
                fs::create_dir(&path).map_err(|error| {
                    PackageError::Format(format!("cannot create repository directory: {error}"))
                })?;
            }
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn import(
        &self,
        repository: &mut Repository,
        trust: &TrustStore,
        artifact: &[u8],
    ) -> Result<PackageRecord, PackageError> {
        let record = repository.import(trust, artifact)?;
        let destination = self
            .root
            .join("packages")
            .join(format!("{}.hybp", hex_digest(record.digest)));
        if destination.exists() {
            let existing = fs::read(&destination).map_err(|error| {
                PackageError::Format(format!("cannot read existing repository artifact: {error}"))
            })?;
            if existing == artifact {
                return Ok(record);
            }
            return Err(PackageError::ArtifactConflict);
        }
        publish_bytes(artifact, &destination, false)?;
        Ok(record)
    }

    /// Rebuild an in-memory repository from a deterministic listing. Every
    /// artifact is revalidated; unknown files or links are rejected rather than
    /// treated as harmless repository metadata.
    pub fn load(&self, trust: &TrustStore) -> Result<Repository, PackageError> {
        let package_dir = self.root.join("packages");
        let mut entries = fs::read_dir(&package_dir)
            .map_err(|error| {
                PackageError::Format(format!("cannot read repository packages: {error}"))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                PackageError::Format(format!("cannot enumerate repository packages: {error}"))
            })?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut repository = Repository::default();
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                PackageError::Format(format!("cannot inspect repository artifact: {error}"))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(PackageError::Format(
                    "repository contains a non-regular artifact".into(),
                ));
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                PackageError::Format("repository artifact name is not UTF-8".into())
            })?;
            if !name.ends_with(".hybp")
                || name.len() != 64 + 5
                || !name[..64].bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(PackageError::Format(
                    "repository artifact name is invalid".into(),
                ));
            }
            let bytes = fs::read(&path).map_err(|error| {
                PackageError::Format(format!("cannot read repository artifact: {error}"))
            })?;
            let record = repository.import(trust, &bytes)?;
            if name[..64] != hex_digest(record.digest) {
                return Err(PackageError::Format(
                    "repository artifact filename digest mismatch".into(),
                ));
            }
        }
        Ok(repository)
    }
}

impl PackageRegistry {
    pub fn generation(&self) -> u64 {
        self.generations
    }
    pub fn transaction_state(&self) -> TransactionState {
        self.transaction
    }
    pub fn active(&self, id: &PackageId) -> Option<&InstalledPackage> {
        self.installed.get(id).and_then(|versions| versions.last())
    }
    pub fn installed(&self) -> impl Iterator<Item = (&PackageId, &InstalledPackage)> {
        self.installed
            .iter()
            .filter_map(|(id, versions)| versions.last().map(|version| (id, version)))
    }

    /// Canonical durable state for a registry. Artifact bytes remain addressed
    /// by digest in the repository; this snapshot records only approved grants,
    /// ownership, versions, and activation order. It contains no private keys.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, PackageError> {
        if self.transaction != TransactionState::Idle {
            return Err(PackageError::BusyTransaction);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REGISTRY_MAGIC);
        put_u32(&mut bytes, REGISTRY_VERSION);
        put_u64(&mut bytes, self.generations);
        put_u32(
            &mut bytes,
            u32::try_from(self.installed.len()).map_err(|_| PackageError::ResolutionLimit)?,
        );
        for (id, versions) in &self.installed {
            put_string(&mut bytes, &id.0)?;
            put_u32(
                &mut bytes,
                u32::try_from(versions.len()).map_err(|_| PackageError::ResolutionLimit)?,
            );
            for installed in versions {
                put_version(&mut bytes, installed.record.key.version);
                bytes.extend_from_slice(&installed.record.digest);
                put_u32(&mut bytes, installed.installed_by.0);
                let capabilities = installed.grant.granted_capability_set();
                put_u32(
                    &mut bytes,
                    u32::try_from(capabilities.len()).map_err(|_| PackageError::ResolutionLimit)?,
                );
                for capability in capabilities {
                    put_string(&mut bytes, &capability.0)?;
                }
            }
        }
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(PackageError::ResolutionLimit);
        }
        Ok(bytes)
    }

    /// Reconstruct a registry only from repository-addressed artifacts. Every
    /// active artifact is reverified against current trust, so a revoked key
    /// cannot survive a restart as an active package.
    pub fn decode_snapshot(
        bytes: &[u8],
        repository: &Repository,
        trust: &TrustStore,
    ) -> Result<Self, PackageError> {
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(PackageError::Format(
                "package registry exceeds size limit".into(),
            ));
        }
        let mut reader = RegistryReader::new(bytes);
        if reader.take(8)? != REGISTRY_MAGIC {
            return Err(PackageError::Format(
                "invalid package registry magic".into(),
            ));
        }
        if reader.u32()? != REGISTRY_VERSION {
            return Err(PackageError::Format(
                "unsupported package registry version".into(),
            ));
        }
        let generations = reader.u64()?;
        let package_count = reader.count(MAX_PLAN_PACKAGES)?;
        let mut registry = Self {
            generations,
            ..Self::default()
        };
        for _ in 0..package_count {
            let id = PackageId(reader.string(128)?);
            let count = reader.count(MAX_PLAN_PACKAGES)?;
            if count == 0 {
                return Err(PackageError::Format(
                    "package registry has empty version set".into(),
                ));
            }
            let mut prior = None;
            let mut versions = Vec::with_capacity(count);
            for index in 0..count {
                let version = reader.version()?;
                if prior.is_some_and(|old| version <= old) {
                    return Err(PackageError::Format(
                        "package registry versions are unordered".into(),
                    ));
                }
                prior = Some(version);
                let mut digest = [0; 32];
                digest.copy_from_slice(reader.take(32)?);
                let installed_by = UserId(reader.u32()?);
                let capability_count = reader.count(256)?;
                let mut capabilities = BTreeSet::new();
                for _ in 0..capability_count {
                    let capability = CapabilityName(reader.string(128)?);
                    if !capabilities.insert(capability) {
                        return Err(PackageError::Format(
                            "duplicate persisted capability".into(),
                        ));
                    }
                }
                let key = PackageKey {
                    id: id.clone(),
                    version,
                };
                let record = repository
                    .candidate(&key)
                    .filter(|record| record.digest == digest)
                    .ok_or(PackageError::NotInstalled)?
                    .clone();
                let artifact = SignedPackage::decode(&record.artifact)?;
                if index + 1 == count {
                    trust.verify(&artifact)?;
                }
                let manifest = Manifest::parse_toml(&artifact.input.application_manifest)
                    .map_err(|error| PackageError::Grant(error.to_string()))?;
                let grant = ApplicationGrant::from_approved_capabilities(manifest, capabilities)
                    .map_err(|error| PackageError::Grant(error.to_string()))?;
                versions.push(InstalledPackage {
                    record,
                    grant,
                    installed_by,
                });
            }
            if registry.installed.insert(id, versions).is_some() {
                return Err(PackageError::Format(
                    "duplicate package registry key".into(),
                ));
            }
        }
        if !reader.finished() {
            return Err(PackageError::Format(
                "trailing package registry bytes".into(),
            ));
        }
        registry.rebuild_and_validate_owners()?;
        Ok(registry)
    }

    fn rebuild_and_validate_owners(&mut self) -> Result<(), PackageError> {
        self.application_owners.clear();
        let owners: Vec<_> = self
            .installed()
            .map(|(id, installed)| (id.clone(), installed.record.application_id.clone()))
            .collect();
        for (id, app_id) in owners {
            if self.application_owners.insert(app_id, id).is_some() {
                return Err(PackageError::ApplicationOwnershipConflict);
            }
        }
        for (id, installed) in self.installed() {
            for dependency in &installed.record.dependencies {
                let active = self
                    .active(&dependency.package)
                    .ok_or_else(|| PackageError::MissingDependency(dependency.package.clone()))?;
                if !dependency.requirement.matches(active.record.key.version) {
                    return Err(PackageError::DependencyConflict(id.clone()));
                }
            }
        }
        Ok(())
    }
}

impl PackageManager {
    pub fn resolve(&self, requested: &[Dependency]) -> Result<ResolutionPlan, PackageError> {
        self.repository.resolve(requested)
    }

    /// Plan, grant, and publish together. Every failure occurs against a clone,
    /// leaving the visible registry at its last committed generation.
    pub fn install(
        &mut self,
        actor: &SecurityContext,
        trust: &TrustStore,
        policy: &GrantPolicy,
        requested: &[Dependency],
    ) -> Result<ResolutionPlan, PackageError> {
        require_admin(actor)?;
        if self.registry.transaction != TransactionState::Idle {
            return Err(PackageError::BusyTransaction);
        }
        self.registry.transaction = TransactionState::Planned;
        let plan = match self.repository.resolve(requested) {
            Ok(plan) => plan,
            Err(error) => {
                self.registry.transaction = TransactionState::RolledBack;
                self.registry.transaction = TransactionState::Idle;
                return Err(error);
            }
        };
        self.registry.transaction = TransactionState::Verified;
        let mut next = self.registry.clone();
        next.transaction = TransactionState::Prepared;
        let operation = (|| {
            for record in &plan.ordered {
                let artifact = SignedPackage::decode(&record.artifact)?;
                // Repository import is not a permanent authorization grant:
                // a key can be revoked between import and activation.
                trust.verify(&artifact)?;
                if artifact_digest(&record.artifact) != record.digest
                    || artifact.input.metadata.key != record.key
                {
                    return Err(PackageError::Format(
                        "repository artifact/index mismatch".into(),
                    ));
                }
                let manifest = Manifest::parse_toml(&artifact.input.application_manifest)
                    .map_err(|error| PackageError::Grant(error.to_string()))?;
                let grant = policy
                    .approve(manifest)
                    .map_err(|error| PackageError::Grant(error.to_string()))?;
                install_one(&mut next, record.clone(), grant, actor.user_id)?;
            }
            next.generations = next
                .generations
                .checked_add(1)
                .ok_or(PackageError::GenerationOverflow)?;
            Ok(())
        })();
        match operation {
            Ok(()) => {
                next.transaction = TransactionState::Committed;
                self.registry = next;
                self.registry.transaction = TransactionState::Idle;
                Ok(plan)
            }
            Err(error) => {
                self.registry.transaction = TransactionState::RolledBack;
                self.registry.transaction = TransactionState::Idle;
                Err(error)
            }
        }
    }

    pub fn rollback(
        &mut self,
        actor: &SecurityContext,
        trust: &TrustStore,
        id: &PackageId,
    ) -> Result<&InstalledPackage, PackageError> {
        require_admin(actor)?;
        if self.registry.transaction != TransactionState::Idle {
            return Err(PackageError::BusyTransaction);
        }
        let current = self.registry.active(id).ok_or(PackageError::NotInstalled)?;
        let previous = self
            .registry
            .installed
            .get(id)
            .and_then(|versions| versions.get(versions.len().checked_sub(2)?))
            .ok_or(PackageError::NoRollback)?;
        // A revoked/disabled signing key must not become active merely because
        // an old package was retained for rollback.
        let rollback_artifact = SignedPackage::decode(&previous.record.artifact)?;
        trust.verify(&rollback_artifact)?;
        if current.record.application_id != previous.record.application_id {
            return Err(PackageError::ApplicationOwnershipConflict);
        }
        let mut next = self.registry.clone();
        let versions = next
            .installed
            .get_mut(id)
            .ok_or(PackageError::NotInstalled)?;
        if versions.len() < 2 {
            return Err(PackageError::NoRollback);
        }
        versions.pop();
        next.generations = next
            .generations
            .checked_add(1)
            .ok_or(PackageError::GenerationOverflow)?;
        self.registry = next;
        Ok(self
            .registry
            .active(id)
            .expect("rollback retains prior version"))
    }

    pub fn remove(&mut self, actor: &SecurityContext, id: &PackageId) -> Result<(), PackageError> {
        require_admin(actor)?;
        if self.registry.transaction != TransactionState::Idle {
            return Err(PackageError::BusyTransaction);
        }
        let removed = self
            .registry
            .active(id)
            .ok_or(PackageError::NotInstalled)?
            .clone();
        for (other_id, installed) in self.registry.installed() {
            if other_id != id
                && installed
                    .record
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.package == *id)
            {
                return Err(PackageError::ReverseDependency(other_id.clone()));
            }
        }
        let mut next = self.registry.clone();
        next.installed.remove(id);
        if next.application_owners.get(&removed.record.application_id) == Some(id) {
            next.application_owners
                .remove(&removed.record.application_id);
        }
        next.generations = next
            .generations
            .checked_add(1)
            .ok_or(PackageError::GenerationOverflow)?;
        self.registry = next;
        Ok(())
    }

    /// An in-progress state is never accepted as visible registry data. A
    /// persistent adapter calls this after reopening its last committed copy.
    pub fn recover(&mut self) {
        if self.registry.transaction != TransactionState::Idle {
            self.registry.transaction = TransactionState::Idle;
        }
    }
}

/// Build a deterministic signed artifact from a staging tree. This is the only
/// Phase 17 component that reads host files, and host paths stop at this
/// boundary: the resulting artifact contains validated relative package paths.
pub fn build_from_staging(
    staging: &Path,
    key_id: impl Into<String>,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<SignedPackage, PackageError> {
    let metadata = fs::symlink_metadata(staging).map_err(|error| {
        PackageError::Format(format!("cannot inspect staging directory: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PackageError::Format(
            "staging root must be a real directory".into(),
        ));
    }
    let application_manifest = fs::read_to_string(staging.join("hyber.toml"))
        .map_err(|error| PackageError::Format(format!("cannot read hyber.toml: {error}")))?;
    let package_manifest = fs::read_to_string(staging.join("package.toml"))
        .map_err(|error| PackageError::Format(format!("cannot read package.toml: {error}")))?;
    let metadata =
        hyber_package_format::PackageMetadata::from_toml(&package_manifest, &application_manifest)?;
    let mut files = Vec::new();
    collect_staging_files(staging, staging, &mut files)?;
    // package.toml controls construction and is not application content.
    files.retain(|file| file.path != "package.toml");
    let package = SignedPackage::sign(
        hyber_package_format::PackageInput {
            metadata,
            application_manifest,
            files,
        },
        key_id,
        signing_key,
    )?;
    // Force encoding now so all final size limits are enforced before a caller
    // considers the package successfully built.
    let _ = package.encode()?;
    Ok(package)
}

/// Write an already validated artifact without replacing an existing target
/// unless the caller explicitly requests it. The temporary file is created in
/// the target directory, flushed, and only then renamed into place.
pub fn write_artifact(
    artifact: &SignedPackage,
    destination: &Path,
    force: bool,
) -> Result<(), PackageError> {
    let bytes = artifact.encode()?;
    publish_bytes(&bytes, destination, force)
}

fn publish_bytes(bytes: &[u8], destination: &Path, force: bool) -> Result<(), PackageError> {
    if destination.exists() && !force {
        return Err(PackageError::Format(
            "artifact destination already exists".into(),
        ));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| PackageError::Format("artifact destination has no parent".into()))?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|error| {
        PackageError::Format(format!("cannot inspect artifact parent: {error}"))
    })?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err(PackageError::Format(
            "artifact parent must be a real directory".into(),
        ));
    }
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| PackageError::Format("invalid artifact destination name".into()))?;
    let temporary = parent.join(format!(".{name}.hyber-pkg-{}.tmp", std::process::id()));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                PackageError::Format(format!("cannot create artifact temporary file: {error}"))
            })?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| PackageError::Format(format!("cannot write artifact: {error}")))?;
        if force {
            // On the hosted Linux backend rename replaces the destination
            // atomically; never unlink it first.
            fs::rename(&temporary, destination).map_err(|error| {
                PackageError::Format(format!("cannot publish artifact: {error}"))
            })?;
        } else {
            // A hard link is an atomic no-replace publication primitive on the
            // same filesystem. It closes the exists/rename race above.
            fs::hard_link(&temporary, destination).map_err(|error| {
                PackageError::Format(format!(
                    "artifact destination already exists or cannot be linked: {error}"
                ))
            })?;
            fs::remove_file(&temporary).map_err(|error| {
                PackageError::Format(format!("cannot finalize artifact publication: {error}"))
            })?;
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                PackageError::Format(format!("cannot sync artifact directory: {error}"))
            })
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

fn collect_staging_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<hyber_package_format::PackageFile>,
) -> Result<(), PackageError> {
    if files.len() >= hyber_package_format::MAX_FILES {
        return Err(PackageError::Format("too many staging files".into()));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|error| PackageError::Format(format!("cannot read staging directory: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            PackageError::Format(format!("cannot enumerate staging directory: {error}"))
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            PackageError::Format(format!("cannot inspect staging entry: {error}"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(PackageError::Format(
                "staging symlinks are forbidden".into(),
            ));
        }
        if metadata.is_dir() {
            collect_staging_files(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(PackageError::Format(
                "staging special files are forbidden".into(),
            ));
        }
        if metadata.len() > hyber_package_format::MAX_FILE_BYTES as u64 {
            return Err(PackageError::Format(
                "staging file exceeds size limit".into(),
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PackageError::Format("staging path escaped root".into()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| PackageError::Format("staging path is not UTF-8".into()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        files.push(hyber_package_format::PackageFile {
            path: relative,
            bytes: fs::read(&path).map_err(|error| {
                PackageError::Format(format!("cannot read staging file: {error}"))
            })?,
        });
    }
    Ok(())
}

fn resolve_selected(
    repository: &Repository,
    requirements: BTreeMap<PackageId, Vec<VersionRequirement>>,
    selected: BTreeMap<PackageId, PackageRecord>,
    depth: usize,
) -> Result<BTreeMap<PackageId, PackageRecord>, PackageError> {
    if depth > MAX_RESOLUTION_DEPTH || requirements.len() > MAX_PLAN_PACKAGES {
        return Err(PackageError::ResolutionLimit);
    }
    for (id, record) in &selected {
        if !requirements.get(id).is_some_and(|constraints| {
            constraints
                .iter()
                .all(|constraint| constraint.matches(record.key.version))
        }) {
            return Err(PackageError::DependencyConflict(id.clone()));
        }
    }
    let Some((id, constraints)) = requirements
        .iter()
        .find(|(id, _)| !selected.contains_key(*id))
    else {
        return Ok(selected);
    };
    let candidates = repository.candidates(id);
    if candidates.is_empty() {
        return Err(PackageError::MissingDependency(id.clone()));
    }
    for candidate in candidates {
        if !constraints
            .iter()
            .all(|constraint| constraint.matches(candidate.key.version))
        {
            continue;
        }
        let mut next_requirements = requirements.clone();
        for dependency in &candidate.dependencies {
            next_requirements
                .entry(dependency.package.clone())
                .or_default()
                .push(dependency.requirement.clone());
        }
        let mut next_selected = selected.clone();
        next_selected.insert(id.clone(), candidate.clone());
        if let Ok(solution) =
            resolve_selected(repository, next_requirements, next_selected, depth + 1)
        {
            return Ok(solution);
        }
    }
    Err(PackageError::DependencyConflict(id.clone()))
}

fn order_dependencies(
    repository: &Repository,
    selected: &BTreeMap<PackageId, PackageRecord>,
    id: &PackageId,
    visiting: &mut BTreeSet<PackageId>,
    visited: &mut BTreeSet<PackageId>,
    ordered: &mut Vec<PackageRecord>,
) -> Result<(), PackageError> {
    if visited.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id.clone()) {
        return Err(PackageError::DependencyCycle);
    }
    let record = selected
        .get(id)
        .ok_or_else(|| PackageError::MissingDependency(id.clone()))?;
    for dependency in &record.dependencies {
        let dependency_record = selected
            .get(&dependency.package)
            .ok_or_else(|| PackageError::MissingDependency(dependency.package.clone()))?;
        if !dependency
            .requirement
            .matches(dependency_record.key.version)
            || repository.candidate(&dependency_record.key).is_none()
        {
            return Err(PackageError::DependencyConflict(dependency.package.clone()));
        }
        order_dependencies(
            repository,
            selected,
            &dependency.package,
            visiting,
            visited,
            ordered,
        )?;
    }
    visiting.remove(id);
    visited.insert(id.clone());
    ordered.push(record.clone());
    Ok(())
}

fn install_one(
    registry: &mut PackageRegistry,
    record: PackageRecord,
    grant: ApplicationGrant,
    installed_by: UserId,
) -> Result<(), PackageError> {
    if let Some(owner) = registry.application_owners.get(&record.application_id) {
        if owner != &record.key.id {
            return Err(PackageError::ApplicationOwnershipConflict);
        }
    }
    let versions = registry.installed.entry(record.key.id.clone()).or_default();
    if versions
        .iter()
        .any(|installed| installed.record.key.version == record.key.version)
    {
        return Err(PackageError::AlreadyInstalled);
    }
    if let Some(active) = versions.last() {
        if record.key.version <= active.record.key.version {
            return Err(PackageError::DowngradeDenied);
        }
    }
    registry
        .application_owners
        .insert(record.application_id.clone(), record.key.id.clone());
    versions.push(InstalledPackage {
        record,
        grant,
        installed_by,
    });
    Ok(())
}

fn require_admin(context: &SecurityContext) -> Result<(), PackageError> {
    SecurityManager::check_capability(context, "CAP_SYS_ADMIN").map_err(PackageError::Authorization)
}

fn validate_trusted_key(key: &TrustedKey) -> Result<(), PackageError> {
    if key.key_id.is_empty()
        || key.key_id.len() > 128
        || !key
            .key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(PackageError::InvalidTrust("invalid key id"));
    }
    if key.publisher.is_empty()
        || key.publisher.len() > 128
        || !key
            .publisher
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PackageError::InvalidTrust("invalid publisher"));
    }
    if let Some(prefix) = &key.package_prefix {
        if prefix.is_empty()
            || prefix.len() > 128
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PackageError::InvalidTrust("invalid package scope"));
        }
    }
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), PackageError> {
    if value.is_empty() || value.len() > 128 {
        return Err(PackageError::Format(
            "invalid package registry string".into(),
        ));
    }
    put_u32(
        out,
        u32::try_from(value.len())
            .map_err(|_| PackageError::Format("package registry string too long".into()))?,
    );
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_version(out: &mut Vec<u8>, version: PackageVersion) {
    put_u64(out, version.major);
    put_u64(out, version.minor);
    put_u64(out, version.patch);
}

struct RegistryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RegistryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], PackageError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| PackageError::Format("package registry length overflow".into()))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| PackageError::Format("truncated package registry".into()))?;
        self.offset = end;
        Ok(result)
    }
    fn u32(&mut self) -> Result<u32, PackageError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed-size slice"),
        ))
    }
    fn u64(&mut self) -> Result<u64, PackageError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed-size slice"),
        ))
    }
    fn count(&mut self, limit: usize) -> Result<usize, PackageError> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| PackageError::Format("package registry count overflow".into()))?;
        if count > limit {
            return Err(PackageError::Format(
                "package registry count exceeds limit".into(),
            ));
        }
        Ok(count)
    }
    fn string(&mut self, limit: usize) -> Result<String, PackageError> {
        let count = self.count(limit)?;
        let text = String::from_utf8(self.take(count)?.to_vec())
            .map_err(|_| PackageError::Format("package registry string is not UTF-8".into()))?;
        if text.is_empty() {
            return Err(PackageError::Format("package registry empty string".into()));
        }
        Ok(text)
    }
    fn version(&mut self) -> Result<PackageVersion, PackageError> {
        Ok(PackageVersion {
            major: self.u64()?,
            minor: self.u64()?,
            patch: self.u64()?,
        })
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hyber_package_format::{PackageFile, PackageInput, PackageMetadata};

    fn manifest(app: &str, version: &str) -> String {
        format!("format_version = 1\napp_id = \"{app}\"\nversion = \"{version}\"\npublisher = \"example\"\ndisplay_name = \"{app}\"\nentrypoint = \"main.lua\"\nruntime = \"lua\"\nexecution = \"background\"\n\n[storage]\ndata = \"read-write\"\n\n[resources]\nmemory_bytes = 1024\ncpu_shares = 1\nhandles = 1\nstorage_bytes = 1024\n")
    }
    fn artifact(
        id: &str,
        version: &str,
        dependencies: Vec<Dependency>,
        key: &SigningKey,
    ) -> Vec<u8> {
        SignedPackage::sign(
            PackageInput {
                metadata: PackageMetadata {
                    key: PackageKey {
                        id: PackageId(id.into()),
                        version: PackageVersion::parse(version).unwrap(),
                    },
                    application_id: id.into(),
                    publisher: "example".into(),
                    dependencies,
                },
                application_manifest: manifest(id, version),
                files: vec![
                    PackageFile {
                        path: "hyber.toml".into(),
                        bytes: manifest(id, version).into_bytes(),
                    },
                    PackageFile {
                        path: "main.lua".into(),
                        bytes: b"return true".to_vec(),
                    },
                ],
            },
            "example.dev",
            key,
        )
        .unwrap()
        .encode()
        .unwrap()
    }
    fn trust(key: &SigningKey) -> TrustStore {
        let mut trust = TrustStore::default();
        trust
            .add(
                &SecurityContext::root(),
                TrustedKey {
                    key_id: "example.dev".into(),
                    publisher: "example".into(),
                    package_prefix: None,
                    state: KeyState::Trusted,
                    verifying_key: key.verifying_key(),
                },
            )
            .unwrap();
        trust
    }
    #[test]
    fn trusted_import_resolves_dependencies_and_installs_atomically() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let trust = trust(&key);
        let mut manager = PackageManager::default();
        manager
            .repository
            .import(&trust, &artifact("base", "1.0.0", vec![], &key))
            .unwrap();
        manager
            .repository
            .import(
                &trust,
                &artifact(
                    "editor",
                    "1.0.0",
                    vec![Dependency {
                        package: PackageId("base".into()),
                        requirement: VersionRequirement::AtLeast(
                            PackageVersion::parse("1.0.0").unwrap(),
                        ),
                    }],
                    &key,
                ),
            )
            .unwrap();
        let plan = manager
            .install(
                &SecurityContext::root(),
                &trust,
                &GrantPolicy::deny_all(),
                &[Dependency {
                    package: PackageId("editor".into()),
                    requirement: VersionRequirement::Exact(PackageVersion::parse("1.0.0").unwrap()),
                }],
            )
            .unwrap();
        assert_eq!(
            plan.ordered
                .iter()
                .map(|record| record.key.id.0.as_str())
                .collect::<Vec<_>>(),
            ["base", "editor"]
        );
        assert!(manager
            .registry
            .active(&PackageId("editor".into()))
            .is_some());
        assert_eq!(manager.registry.generation(), 1);
    }
    #[test]
    fn trust_scope_tampering_and_reverse_dependencies_fail_closed() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let mut revoked_trust = trust(&key);
        revoked_trust
            .set_state(&SecurityContext::root(), "example.dev", KeyState::Revoked)
            .unwrap();
        let mut repository = Repository::default();
        assert!(matches!(
            repository.import(&revoked_trust, &artifact("base", "1.0.0", vec![], &key)),
            Err(PackageError::RevokedKey)
        ));
        let trust = trust(&key);
        let mut manager = PackageManager::default();
        manager
            .repository
            .import(&trust, &artifact("base", "1.0.0", vec![], &key))
            .unwrap();
        manager
            .repository
            .import(
                &trust,
                &artifact(
                    "editor",
                    "1.0.0",
                    vec![Dependency {
                        package: PackageId("base".into()),
                        requirement: VersionRequirement::Exact(
                            PackageVersion::parse("1.0.0").unwrap(),
                        ),
                    }],
                    &key,
                ),
            )
            .unwrap();
        manager
            .install(
                &SecurityContext::root(),
                &trust,
                &GrantPolicy::deny_all(),
                &[Dependency {
                    package: PackageId("editor".into()),
                    requirement: VersionRequirement::Exact(PackageVersion::parse("1.0.0").unwrap()),
                }],
            )
            .unwrap();
        assert!(matches!(
            manager.remove(&SecurityContext::root(), &PackageId("base".into())),
            Err(PackageError::ReverseDependency(_))
        ));
    }

    #[test]
    fn registry_snapshot_restores_only_repository_backed_trusted_packages() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let trust = trust(&key);
        let mut manager = PackageManager::default();
        manager
            .repository
            .import(&trust, &artifact("demo", "1.0.0", vec![], &key))
            .unwrap();
        manager
            .install(
                &SecurityContext::root(),
                &trust,
                &GrantPolicy::deny_all(),
                &[Dependency {
                    package: PackageId("demo".into()),
                    requirement: VersionRequirement::Exact(PackageVersion::parse("1.0.0").unwrap()),
                }],
            )
            .unwrap();
        let snapshot = manager.registry.encode_snapshot().unwrap();
        let restored =
            PackageRegistry::decode_snapshot(&snapshot, &manager.repository, &trust).unwrap();
        assert_eq!(restored.generation(), manager.registry.generation());
        assert!(restored.active(&PackageId("demo".into())).is_some());
        let mut corrupt = snapshot;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(PackageRegistry::decode_snapshot(&corrupt, &manager.repository, &trust).is_err());
    }

    #[test]
    fn staging_builder_sorts_payload_and_keeps_packaging_control_file_out() {
        let directory = std::env::temp_dir().join(format!(
            "hyber-package-builder-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        if directory.exists() {
            std::fs::remove_dir_all(&directory).unwrap();
        }
        std::fs::create_dir(&directory).unwrap();
        std::fs::create_dir(directory.join("assets")).unwrap();
        std::fs::write(directory.join("hyber.toml"), manifest("demo", "1.0.0")).unwrap();
        std::fs::write(
            directory.join("package.toml"),
            "format_version = 1\npackage_id = \"demo\"\n",
        )
        .unwrap();
        std::fs::write(directory.join("main.lua"), "return true\n").unwrap();
        std::fs::write(directory.join("assets/a.txt"), "asset\n").unwrap();
        let key = SigningKey::from_bytes(&[6; 32]);
        let package = build_from_staging(&directory, "example.dev", &key).unwrap();
        package.verify(&key.verifying_key()).unwrap();
        assert!(package
            .input
            .files
            .iter()
            .any(|file| file.path == "hyber.toml"));
        assert!(!package
            .input
            .files
            .iter()
            .any(|file| file.path == "package.toml"));
        let artifact = directory.join("demo.hybp");
        write_artifact(&package, &artifact, false).unwrap();
        assert!(write_artifact(&package, &artifact, false).is_err());
        let local = LocalRepository::open(directory.join("repository")).unwrap();
        let trust = trust(&key);
        let bytes = std::fs::read(&artifact).unwrap();
        let mut repository = Repository::default();
        local.import(&mut repository, &trust, &bytes).unwrap();
        // A repeated import of byte-identical artifact content is idempotent.
        local.import(&mut repository, &trust, &bytes).unwrap();
        assert!(local
            .load(&trust)
            .unwrap()
            .candidate(&PackageKey {
                id: PackageId("demo".into()),
                version: PackageVersion::parse("1.0.0").unwrap(),
            })
            .is_some());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
