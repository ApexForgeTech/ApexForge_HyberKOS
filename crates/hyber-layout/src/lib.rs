//! Special_3 — canonical user, application, runtime, and temporary layout.
//!
//! This crate contains policy, not a host-filesystem adapter.  All operations
//! use Hyber VFS/Object/Namespace abstractions so the same rules apply to an
//! in-memory test namespace, HostFS, and a future HyberFS provider.

use hyber_core::{GroupId, ObjectType, Path, SecurityContext, UserId};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::VFS;

const MAX_CLEANUP_DEPTH: usize = 64;
const MAX_CLEANUP_OBJECTS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Config,
    Data,
    State,
    Cache,
    Temporary,
    Runtime,
}

impl StorageClass {
    pub const fn is_disposable(self) -> bool {
        matches!(self, Self::Cache | Self::Temporary | Self::Runtime)
    }
}

/// Explicit per-class byte limits.  Providers that perform writes use
/// `check_quota` before accepting a new allocation; this policy does not infer
/// limits from host filesystem capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    pub config: u64,
    pub data: u64,
    pub state: u64,
    pub cache: u64,
    pub temporary: u64,
    pub runtime: u64,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            config: 64 * 1024 * 1024,
            data: 1024 * 1024 * 1024,
            state: 256 * 1024 * 1024,
            cache: 512 * 1024 * 1024,
            temporary: 256 * 1024 * 1024,
            runtime: 64 * 1024 * 1024,
        }
    }
}

impl Quotas {
    pub const fn limit(self, class: StorageClass) -> u64 {
        match class {
            StorageClass::Config => self.config,
            StorageClass::Data => self.data,
            StorageClass::State => self.state,
            StorageClass::Cache => self.cache,
            StorageClass::Temporary => self.temporary,
            StorageClass::Runtime => self.runtime,
        }
    }

    pub fn check_quota(
        self,
        class: StorageClass,
        used: u64,
        additional: u64,
    ) -> Result<(), String> {
        let total = used
            .checked_add(additional)
            .ok_or("storage quota arithmetic overflow")?;
        if total > self.limit(class) {
            return Err(format!("{:?} quota exceeded", class));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLayout {
    pub user_id: UserId,
    pub group_id: GroupId,
    pub username: String,
    pub home: Path,
}

impl UserLayout {
    pub fn new(
        user_id: UserId,
        group_id: GroupId,
        username: impl Into<String>,
        home: impl AsRef<str>,
    ) -> Result<Self, String> {
        let username = username.into();
        validate_component(&username, "username")?;
        let home = Path::parse(home.as_ref()).normalize();
        let expected = Path::parse(&format!("/users/{username}"));
        if home != expected {
            return Err("user home must be exactly /users/<username>".into());
        }
        Ok(Self {
            user_id,
            group_id,
            username,
            home,
        })
    }

    pub fn root() -> Self {
        Self::new(UserId(0), GroupId(0), "root", "/users/root")
            .expect("reserved root layout is valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLayout {
    pub user: UserLayout,
    pub app_id: String,
    pub config: Path,
    pub data: Path,
    pub state: Path,
    pub cache: Path,
    pub temporary: Path,
    pub runtime: Path,
}

impl AppLayout {
    pub fn new(user: UserLayout, app_id: impl Into<String>) -> Result<Self, String> {
        let app_id = app_id.into();
        validate_component(&app_id, "application id")?;
        let home = user.home.to_string();
        Ok(Self {
            config: Path::parse(&format!("{home}/.config/{app_id}")),
            data: Path::parse(&format!("{home}/.local/share/{app_id}")),
            state: Path::parse(&format!("{home}/.local/state/{app_id}")),
            cache: Path::parse(&format!("{home}/.cache/{app_id}")),
            temporary: Path::parse(&format!("/temporary/users/{}/{app_id}", user.user_id.0)),
            runtime: Path::parse(&format!("/runtime/users/{}/{app_id}", user.user_id.0)),
            user,
            app_id,
        })
    }

    pub fn path(&self, class: StorageClass) -> &Path {
        match class {
            StorageClass::Config => &self.config,
            StorageClass::Data => &self.data,
            StorageClass::State => &self.state,
            StorageClass::Cache => &self.cache,
            StorageClass::Temporary => &self.temporary,
            StorageClass::Runtime => &self.runtime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReport {
    pub class: StorageClass,
    pub path: Path,
    pub removed_objects: usize,
}

#[derive(Debug, Clone)]
pub struct LayoutManager {
    quotas: Quotas,
}

impl Default for LayoutManager {
    fn default() -> Self {
        Self::new(Quotas::default())
    }
}

impl LayoutManager {
    pub const fn new(quotas: Quotas) -> Self {
        Self { quotas }
    }

    pub const fn quotas(&self) -> Quotas {
        self.quotas
    }

    /// Create the stable global roots.  `/runtime` and `/temporary` are
    /// roots only; their contents are deliberately never treated as durable
    /// user data.
    pub fn initialize_system(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        system: &SecurityContext,
    ) -> Result<(), String> {
        require_system(system)?;
        for path in [
            "/apps",
            "/data",
            "/data/services",
            "/data/shared",
            "/data/logs",
            "/users",
            "/runtime",
            "/runtime/users",
            "/runtime/services",
            "/runtime/sockets",
            "/temporary",
            "/temporary/users",
            "/temporary/system",
        ] {
            self.ensure_directory(
                vfs,
                namespace,
                objects,
                system,
                &Path::parse(path),
                UserId(0),
                GroupId(0),
                0o755,
            )?;
        }
        Ok(())
    }

    /// Provision every home, live-runtime, and temporary root for a validated
    /// identity.  Existing objects are checked rather than silently adopted.
    pub fn provision_user(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        system: &SecurityContext,
        user: &UserLayout,
    ) -> Result<(), String> {
        self.initialize_system(vfs, namespace, objects, system)?;
        for path in [
            user.home.clone(),
            append(&user.home, "Documents")?,
            append(&user.home, "Downloads")?,
            append(&user.home, ".config")?,
            append(&user.home, ".local")?,
            append(&append(&user.home, ".local")?, "share")?,
            append(&append(&user.home, ".local")?, "state")?,
            append(&user.home, ".cache")?,
            append(&append(&user.home, ".local")?, "bin")?,
            Path::parse(&format!("/runtime/users/{}", user.user_id.0)),
            Path::parse(&format!("/temporary/users/{}", user.user_id.0)),
        ] {
            self.ensure_directory(
                vfs,
                namespace,
                objects,
                system,
                &path,
                user.user_id,
                user.group_id,
                0o700,
            )?;
        }
        Ok(())
    }

    /// Create the application-specific leaves after the user's private roots
    /// exist. A caller may only create directories for their own identity;
    /// system setup uses `provision_user` first.
    pub fn ensure_application(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        caller: &SecurityContext,
        app: &AppLayout,
    ) -> Result<(), String> {
        if caller.user_id != app.user.user_id && caller.user_id != UserId(0) {
            return Err("application layout belongs to another user".into());
        }
        for class in [
            StorageClass::Config,
            StorageClass::Data,
            StorageClass::State,
            StorageClass::Cache,
            StorageClass::Temporary,
            StorageClass::Runtime,
        ] {
            self.ensure_directory(
                vfs,
                namespace,
                objects,
                caller,
                app.path(class),
                app.user.user_id,
                app.user.group_id,
                0o700,
            )?;
        }
        Ok(())
    }

    /// A service never stores persistent state under a human user's home.
    #[allow(
        clippy::too_many_arguments,
        reason = "VFS mutation requires each manager and explicit service ownership"
    )]
    pub fn provision_service(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        system: &SecurityContext,
        service_id: &str,
        owner: UserId,
        group: GroupId,
    ) -> Result<(Path, Path), String> {
        require_system(system)?;
        validate_component(service_id, "service id")?;
        self.initialize_system(vfs, namespace, objects, system)?;
        let data = Path::parse(&format!("/data/services/{service_id}"));
        let runtime = Path::parse(&format!("/runtime/services/{service_id}"));
        for path in [&data, &runtime] {
            self.ensure_directory(vfs, namespace, objects, system, path, owner, group, 0o700)?;
        }
        Ok((data, runtime))
    }

    /// Shared namespaces are created only by the dedicated administrative
    /// capability.  Their mode remains private to the authority; future ACL or
    /// group grants can widen it without changing the canonical path model.
    pub fn provision_shared_namespace(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        caller: &SecurityContext,
        system: &SecurityContext,
        name: &str,
    ) -> Result<Path, String> {
        hyber_core::SecurityManager::check_capability(caller, "CAP_SHARED_DATA_ADMIN")?;
        require_system(system)?;
        validate_component(name, "shared namespace")?;
        let path = Path::parse(&format!("/data/shared/{name}"));
        self.ensure_directory(
            vfs,
            namespace,
            objects,
            system,
            &path,
            UserId(0),
            GroupId(0),
            0o700,
        )?;
        Ok(path)
    }

    /// Safely clear only disposable state belonging to this user.  The method
    /// never accepts an arbitrary target path, never follows a host path, and
    /// reports the exact number of removed Hyber objects.
    pub fn cleanup_user_disposable(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        system: &SecurityContext,
        user: &UserLayout,
        class: StorageClass,
    ) -> Result<CleanupReport, String> {
        require_system(system)?;
        if !class.is_disposable() {
            return Err("only cache, temporary, and runtime state may be cleaned".into());
        }
        let target = match class {
            StorageClass::Cache => append(&user.home, ".cache")?,
            StorageClass::Temporary => Path::parse(&format!("/temporary/users/{}", user.user_id.0)),
            StorageClass::Runtime => Path::parse(&format!("/runtime/users/{}", user.user_id.0)),
            _ => unreachable!(),
        };
        let mut removed = 0;
        self.clear_children(vfs, namespace, objects, system, &target, 0, &mut removed)?;
        Ok(CleanupReport {
            class,
            path: target,
            removed_objects: removed,
        })
    }

    pub fn usage(
        &self,
        vfs: &VFS,
        namespace: &NamespaceManager,
        objects: &ObjectManager,
        system: &SecurityContext,
        path: &Path,
    ) -> Result<u64, String> {
        require_system(system)?;
        self.usage_inner(vfs, namespace, objects, system, &path.normalize(), 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_directory(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        actor: &SecurityContext,
        path: &Path,
        owner: UserId,
        group: GroupId,
        mode: u32,
    ) -> Result<(), String> {
        let path = path.normalize();
        if !path.is_absolute || path.components.is_empty() {
            return Err("layout directories must be non-root absolute paths".into());
        }
        let mut components = Vec::new();
        for component in &path.components {
            components.push(component.clone());
            let current = Path {
                components: components.clone(),
                is_absolute: true,
            };
            let id = match namespace.resolve(&current, namespace.root()) {
                Ok(id) => id,
                Err(_) => {
                    let (parent, name) = current.parent_and_name().ok_or("invalid layout path")?;
                    vfs.create(
                        namespace,
                        objects,
                        actor,
                        &parent,
                        &name,
                        ObjectType::Directory,
                    )?
                }
            };
            let object = objects.lookup(id).ok_or("layout object missing")?;
            if object.object_type != ObjectType::Directory {
                return Err(format!("layout path is not a directory: {current}"));
            }
            // Intermediate shared roots remain system-owned. The final target
            // receives the requested ownership and restrictive mode.
            if current == path {
                let (existing_owner, existing_group, existing_mode) = {
                    let existing = objects.lookup(id).ok_or("layout object missing")?;
                    (existing.owner, existing.group, existing.permissions)
                };
                if actor.user_id == owner && existing_owner != owner {
                    return Err("existing layout directory belongs to another user".into());
                }
                if existing_owner != owner {
                    objects.chown(id, actor, owner)?;
                }
                if existing_group != group {
                    objects.chgrp(id, actor, group)?;
                }
                if existing_mode != mode {
                    objects.chmod(id, actor, mode)?;
                }
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "bounded cleanup carries explicit VFS state and traversal limits"
    )]
    fn clear_children(
        &self,
        vfs: &mut VFS,
        namespace: &mut NamespaceManager,
        objects: &mut ObjectManager,
        system: &SecurityContext,
        directory: &Path,
        depth: usize,
        removed: &mut usize,
    ) -> Result<(), String> {
        if depth > MAX_CLEANUP_DEPTH || *removed >= MAX_CLEANUP_OBJECTS {
            return Err("cleanup safety limit reached".into());
        }
        let entries = vfs.enumerate_secure(namespace, objects, system, directory)?;
        for (name, id) in entries {
            let child = append(directory, &name)?;
            if objects
                .lookup(id)
                .is_some_and(|object| object.object_type == ObjectType::Directory)
            {
                self.clear_children(vfs, namespace, objects, system, &child, depth + 1, removed)?;
            }
            vfs.remove(namespace, objects, system, directory, &name)?;
            *removed = removed.checked_add(1).ok_or("cleanup count overflow")?;
        }
        Ok(())
    }

    fn usage_inner(
        &self,
        vfs: &VFS,
        namespace: &NamespaceManager,
        objects: &ObjectManager,
        system: &SecurityContext,
        path: &Path,
        depth: usize,
    ) -> Result<u64, String> {
        if depth > MAX_CLEANUP_DEPTH {
            return Err("usage traversal depth exceeded".into());
        }
        let id = namespace.resolve(path, namespace.root())?;
        let object = objects.lookup(id).ok_or("usage object missing")?;
        if object.object_type != ObjectType::Directory {
            return Ok(object.size);
        }
        let mut total = 0u64;
        for (name, _) in vfs.enumerate_secure(namespace, objects, system, path)? {
            total = total
                .checked_add(self.usage_inner(
                    vfs,
                    namespace,
                    objects,
                    system,
                    &append(path, &name)?,
                    depth + 1,
                )?)
                .ok_or("usage arithmetic overflow")?;
        }
        Ok(total)
    }
}

fn require_system(context: &SecurityContext) -> Result<(), String> {
    hyber_core::SecurityManager::check_capability(context, "CAP_SYS_ADMIN")
}

fn validate_component(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("invalid {what}"));
    }
    Ok(())
}

fn append(parent: &Path, component: &str) -> Result<Path, String> {
    validate_component(component, "path component")?;
    if !parent.is_absolute {
        return Err("layout parent must be absolute".into());
    }
    let mut components = parent.components.clone();
    components.push(hyber_core::PathComponent::new(component));
    Ok(Path {
        components,
        is_absolute: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_memfs::MemFSProvider;

    fn fixture() -> (VFS, NamespaceManager, ObjectManager, SecurityContext) {
        let mut objects = ObjectManager::new();
        let namespace = NamespaceManager::new(&mut objects);
        let mut vfs = VFS::new();
        vfs.register_provider("mem".into(), Box::new(MemFSProvider::new()));
        vfs.mount(Path::parse("/"), "mem".into());
        (vfs, namespace, objects, SecurityContext::root())
    }

    #[test]
    fn provisioning_creates_private_roots_and_isolates_users() {
        let (mut vfs, mut namespace, mut objects, root) = fixture();
        let manager = LayoutManager::default();
        let alice = UserLayout::new(UserId(1000), GroupId(1000), "alice", "/users/alice").unwrap();
        let bob = UserLayout::new(UserId(1001), GroupId(1001), "bob", "/users/bob").unwrap();
        manager
            .provision_user(&mut vfs, &mut namespace, &mut objects, &root, &alice)
            .unwrap();
        manager
            .provision_user(&mut vfs, &mut namespace, &mut objects, &root, &bob)
            .unwrap();
        let alice_home = namespace.resolve(&alice.home, namespace.root()).unwrap();
        assert_eq!(objects.lookup(alice_home).unwrap().owner, UserId(1000));
        assert_eq!(objects.lookup(alice_home).unwrap().permissions, 0o700);
        let bob_context = SecurityContext {
            user_id: UserId(1001),
            group_id: GroupId(1001),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        assert!(VFS::check_traversal(
            &namespace,
            &objects,
            &bob_context,
            &append(&alice.home, "Documents").unwrap(),
            true
        )
        .is_err());
        let app = AppLayout::new(alice.clone(), "editor").unwrap();
        let alice_context = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        manager
            .ensure_application(&mut vfs, &mut namespace, &mut objects, &alice_context, &app)
            .unwrap();
        assert!(namespace.resolve(&app.runtime, namespace.root()).is_ok());
    }

    #[test]
    fn cleanup_is_scoped_to_disposable_data_and_reports_work() {
        let (mut vfs, mut namespace, mut objects, root) = fixture();
        let manager = LayoutManager::default();
        let user = UserLayout::new(UserId(1000), GroupId(1000), "alice", "/users/alice").unwrap();
        manager
            .provision_user(&mut vfs, &mut namespace, &mut objects, &root, &user)
            .unwrap();
        let app = AppLayout::new(user.clone(), "editor").unwrap();
        let context = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        manager
            .ensure_application(&mut vfs, &mut namespace, &mut objects, &context, &app)
            .unwrap();
        let (parent, _) = app.temporary.parent_and_name().unwrap();
        let file = vfs
            .create(
                &mut namespace,
                &mut objects,
                &context,
                &parent,
                "scratch",
                ObjectType::File,
            )
            .unwrap();
        objects.lookup_mut(file).unwrap().size = 10;
        let report = manager
            .cleanup_user_disposable(
                &mut vfs,
                &mut namespace,
                &mut objects,
                &root,
                &user,
                StorageClass::Temporary,
            )
            .unwrap();
        assert_eq!(report.removed_objects, 2); // app dir plus scratch
        assert!(namespace.resolve(&app.temporary, namespace.root()).is_err());
        assert!(manager
            .cleanup_user_disposable(
                &mut vfs,
                &mut namespace,
                &mut objects,
                &root,
                &user,
                StorageClass::Data
            )
            .is_err());
    }

    #[test]
    fn application_ids_paths_and_quotas_are_bounded() {
        let user = UserLayout::new(UserId(1000), GroupId(1000), "alice", "/users/alice").unwrap();
        assert!(AppLayout::new(user.clone(), "../escape").is_err());
        let app = AppLayout::new(user, "editor-2").unwrap();
        assert_eq!(app.config.to_string(), "/users/alice/.config/editor-2");
        let quotas = Quotas::default();
        assert!(quotas
            .check_quota(StorageClass::Runtime, quotas.runtime, 1)
            .is_err());
        assert!(quotas.check_quota(StorageClass::Data, 1, 2).is_ok());
    }

    #[test]
    fn shared_namespaces_require_capability_but_use_system_authority_for_mutation() {
        let (mut vfs, mut namespace, mut objects, root) = fixture();
        let manager = LayoutManager::default();
        manager
            .initialize_system(&mut vfs, &mut namespace, &mut objects, &root)
            .unwrap();
        let caller = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        assert!(manager
            .provision_shared_namespace(
                &mut vfs,
                &mut namespace,
                &mut objects,
                &caller,
                &root,
                "team",
            )
            .is_err());
        let mut permitted = caller;
        permitted.capabilities.push(hyber_core::Capability {
            name: "CAP_SHARED_DATA_ADMIN".into(),
        });
        let path = manager
            .provision_shared_namespace(
                &mut vfs,
                &mut namespace,
                &mut objects,
                &permitted,
                &root,
                "team",
            )
            .unwrap();
        let id = namespace.resolve(&path, namespace.root()).unwrap();
        assert_eq!(objects.lookup(id).unwrap().owner, UserId(0));
    }
}
