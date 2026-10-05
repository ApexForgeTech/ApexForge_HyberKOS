//! HyberKOS Virtual File System (VFS)
//! Phase 5 & 6 — VFS API, Provider Interface, Mount Model

use hyber_core::{HandleId, ObjectId, ObjectType, Path, ProcessId, Rights};
use hyber_handle::HandleManager;
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;

// ==========================================
// 6.3 — Provider Interface
// ==========================================
pub trait Provider {
    /// Persist an already validated metadata update before reporting success.
    /// Volatile providers intentionally retain only the ObjectManager copy.
    fn persist_metadata(&mut self, _object: &hyber_object::Object) -> Result<(), String> {
        Ok(())
    }

    /// Lookup an object by path within the provider
    fn lookup(&self, _path: &Path) -> Result<Option<ObjectId>, String> {
        Ok(None)
    }

    fn create(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String>;

    fn remove(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
    ) -> Result<(), String>;

    /// 7.6 Rename operantion.
    fn rename(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        old_parent_id: ObjectId,
        old_name: &str,
        new_parent_id: ObjectId,
        new_name: &str,
    ) -> Result<(), String>;

    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String>;
    fn write(&mut self, object_id: ObjectId, offset: u64, buffer: &[u8]) -> Result<usize, String>;
    fn enumerate(&self, dir_id: ObjectId) -> Result<Option<Vec<(String, ObjectId)>>, String>;
}

// ==========================================
// 6.4 — Mount Model
// ==========================================
#[derive(Debug, Clone)]
pub struct Mount {
    pub path: Path,
    pub provider_name: String,
}

#[derive(Debug, Default)]
pub struct MountTable {
    mounts: Vec<Mount>,
}

impl MountTable {
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    pub fn mount(&mut self, path: Path, provider_name: String) {
        self.mounts.push(Mount {
            path,
            provider_name,
        });
    }

    pub fn find_provider(&self, path: &Path) -> Option<String> {
        let mut best_match: Option<&Mount> = None;
        let mut best_match_len = 0;

        for mount in &self.mounts {
            let mount_str = mount.path.to_string();
            let path_str = path.to_string();
            let is_root = mount_str == "/";
            let is_boundary_match = path_str == mount_str
                || (path_str.starts_with(&mount_str) && mount_str.ends_with('/'))
                || (path_str.starts_with(&(mount_str.clone() + "/")));
            if (is_root || is_boundary_match) && mount_str.len() > best_match_len {
                best_match = Some(mount);
                best_match_len = mount_str.len();
            }
        }
        best_match.map(|m| m.provider_name.clone())
    }
}

// ==========================================
// 6.1 — VFS API
// ==========================================
pub struct VFS {
    providers: std::collections::HashMap<String, Box<dyn Provider>>,
    mount_table: MountTable,
    quota_roots: std::collections::HashMap<ObjectId, u64>,
    quota_members: std::collections::HashMap<ObjectId, ObjectId>,
}

impl VFS {
    pub fn new() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
            mount_table: MountTable::new(),
            quota_roots: Default::default(),
            quota_members: Default::default(),
        }
    }

    pub fn register_provider(&mut self, name: String, provider: Box<dyn Provider>) {
        self.providers.insert(name, provider);
    }

    pub fn mount(&mut self, path: Path, provider_name: String) {
        let path = path.normalize();
        self.mount_table.mount(path, provider_name);
    }

    pub fn lookup(&self, ns_mgr: &NamespaceManager, path: &Path) -> Result<ObjectId, String> {
        ns_mgr.resolve(&path.normalize(), ns_mgr.root())
    }

    /// Trusted layout authority installs aggregate, per-class limits. Rebuilt
    /// from the imported namespace on restart, never from host UID/GID values.
    pub fn set_quota(
        &mut self,
        ns: &NamespaceManager,
        root: ObjectId,
        limit: u64,
    ) -> Result<(), String> {
        let mut pending = vec![root];
        let mut members = std::collections::HashSet::new();
        while let Some(id) = pending.pop() {
            if !members.insert(id) {
                return Err("quota namespace cycle".into());
            }
            if self.quota_members.get(&id).is_some_and(|old| *old != root) {
                return Err("overlapping quota roots".into());
            }
            if let Some(entries) = ns.list_directory(id) {
                pending.extend(entries.into_iter().map(|node| node.object_id));
            }
        }
        for id in members {
            self.quota_members.insert(id, root);
        }
        self.quota_roots.insert(root, limit);
        Ok(())
    }

    /// Authorize using ObjectManager operations, persist, and restore the
    /// previous in-memory metadata if persistence fails. Providers must refuse
    /// further I/O if the durable outcome is uncertain.
    pub fn mutate_metadata<T>(
        &mut self,
        ns: &NamespaceManager,
        objects: &mut ObjectManager,
        context: &hyber_core::SecurityContext,
        path: &Path,
        change: impl FnOnce(&mut ObjectManager, ObjectId) -> Result<T, String>,
    ) -> Result<T, String> {
        Self::check_traversal(ns, objects, context, path, false)?;
        let id = self.lookup(ns, path)?;
        let old = objects.lookup(id).ok_or("metadata object missing")?.clone();
        let provider = self
            .mount_table
            .find_provider(&path.normalize())
            .ok_or("metadata provider missing")?;
        let provider = self
            .providers
            .get_mut(&provider)
            .ok_or("metadata provider missing")?;
        let result = change(objects, id).and_then(|value| {
            provider.persist_metadata(objects.lookup(id).ok_or("metadata object missing")?)?;
            Ok(value)
        });
        if result.is_err() {
            *objects.lookup_mut(id).ok_or("metadata object missing")? = old;
        }
        result
    }

    /// Check search permission on all ancestor directories. With include_target,
    /// also check the directory being created in, enumerated, or renamed in.
    pub fn check_traversal(
        ns_mgr: &NamespaceManager,
        obj_mgr: &ObjectManager,
        context: &hyber_core::SecurityContext,
        path: &Path,
        include_target: bool,
    ) -> Result<(), String> {
        let path = path.normalize();
        if !path.is_absolute {
            return Err("absolute path required".into());
        }
        let end = if include_target {
            path.components.len() + 1
        } else {
            path.components.len()
        };
        for count in 0..end {
            let ancestor = Path {
                is_absolute: true,
                components: path.components[..count].to_vec(),
            };
            let id = ns_mgr.resolve(&ancestor, ns_mgr.root())?;
            let object = obj_mgr.lookup(id).ok_or("ancestor missing")?;
            if object.object_type != ObjectType::Directory {
                return Err("ancestor is not a directory".into());
            }
            hyber_core::SecurityManager::check_access(
                context,
                object.owner,
                object.group,
                object.permissions,
                Rights {
                    execute: true,
                    ..Rights::empty()
                },
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // Manager ownership is explicit at this layer.
    pub fn open(
        &self,
        ns_mgr: &NamespaceManager,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        security_context: &hyber_core::SecurityContext,
        path: &Path,
        rights: Rights,
    ) -> Result<HandleId, String> {
        Self::check_traversal(ns_mgr, obj_mgr, security_context, path, false)?;
        let path = path.normalize();
        let provider_name = self
            .mount_table
            .find_provider(&path)
            .ok_or_else(|| format!("No provider mounted for path: {}", path))?;

        let object_id = ns_mgr.resolve(&path, ns_mgr.root())?;

        let obj = obj_mgr.lookup(object_id).ok_or("Object not found")?;
        hyber_core::SecurityManager::check_access(
            security_context,
            obj.owner,
            obj.group,
            obj.permissions,
            rights,
        )?;

        handle_mgr.open(obj_mgr, process_id, object_id, rights, provider_name)
    }

    pub fn close(
        &self,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        handle_id: HandleId,
    ) -> Result<(), String> {
        handle_mgr.close(obj_mgr, process_id, handle_id)
    }

    pub fn read(
        &self,
        handle_mgr: &mut HandleManager,
        process_id: ProcessId,
        handle_id: HandleId,
        buffer: &mut [u8],
    ) -> Result<usize, String> {
        let handle = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        handle_mgr.check_rights(process_id, handle_id, Rights::read_only())?;
        let object_id = handle.object_id;
        let offset = handle.offset;
        offset
            .checked_add(buffer.len() as u64)
            .ok_or("Read offset overflow")?;

        let provider = self
            .providers
            .get(&handle.provider_name)
            .ok_or_else(|| format!("Provider {} not found", handle.provider_name))?;

        let bytes_read = provider.read(object_id, offset, buffer)?;
        if bytes_read > buffer.len() {
            return Err("Provider returned invalid read length".into());
        }
        handle_mgr.update_offset(process_id, handle_id, bytes_read as u64)?;
        Ok(bytes_read)
    }

    /// Read through a handle while re-checking the caller against the current
    /// object metadata.  User-facing runtimes must use this rather than the
    /// legacy `read`, which exists for trusted kernel/provider internals.
    pub fn read_secure(
        &self,
        handle_mgr: &mut HandleManager,
        obj_mgr: &ObjectManager,
        process_id: ProcessId,
        security_context: &hyber_core::SecurityContext,
        handle_id: HandleId,
        buffer: &mut [u8],
    ) -> Result<usize, String> {
        let object_id = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?
            .object_id;
        let object = obj_mgr.lookup(object_id).ok_or("Object not found")?;
        if object.state != hyber_core::ObjectState::Live || object.references == 0 {
            return Err("Object is not live".into());
        }
        hyber_core::SecurityManager::check_access(
            security_context,
            object.owner,
            object.group,
            object.permissions,
            Rights::read_only(),
        )?;
        self.read(handle_mgr, process_id, handle_id, buffer)
    }

    pub fn write(
        &mut self,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        handle_id: HandleId,
        buffer: &[u8],
    ) -> Result<usize, String> {
        let handle = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        let write_rights = Rights {
            write: true,
            ..Rights::empty()
        };
        handle_mgr.check_rights(process_id, handle_id, write_rights)?;
        let object_id = handle.object_id;
        let offset = handle.offset;
        let provider_name = handle.provider_name.clone();
        offset
            .checked_add(buffer.len() as u64)
            .ok_or("Write offset overflow")?;
        let object = obj_mgr.lookup(object_id).ok_or("Object not found")?;
        if object.state != hyber_core::ObjectState::Live || object.references == 0 {
            return Err("Object is not live".into());
        }

        if buffer.is_empty() {
            return Ok(0);
        }
        if let Some(root) = self.quota_members.get(&object_id) {
            let used = self
                .quota_members
                .iter()
                .filter(|(_, r)| *r == root)
                .try_fold(0u64, |sum, (id, _)| {
                    sum.checked_add(obj_mgr.lookup(*id).map_or(0, |o| o.size))
                })
                .ok_or("quota usage overflow")?;
            let growth = (offset + buffer.len() as u64).saturating_sub(object.size);
            if growth > 0
                && used
                    .checked_add(growth)
                    .is_none_or(|size| size > self.quota_roots[root])
            {
                return Err("storage quota exceeded".into());
            }
        }
        let provider = self
            .providers
            .get_mut(&provider_name)
            .ok_or_else(|| format!("Provider {} not found", provider_name))?;

        let bytes_written = provider.write(object_id, offset, buffer)?;
        if bytes_written > buffer.len() {
            return Err("Provider returned invalid write length".into());
        }
        handle_mgr.update_offset(process_id, handle_id, bytes_written as u64)?;

        if let Some(obj) = obj_mgr.lookup_mut(object_id) {
            let new_size = offset + (bytes_written as u64);
            if new_size > obj.size {
                obj.size = new_size;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            obj.modified_at = obj.modified_at.max(obj.created_at).max(now);
            provider.persist_metadata(obj)?;
        }

        Ok(bytes_written)
    }

    /// Write through a handle while re-checking current object metadata.
    /// This closes the stale-handle permission gap after a chmod/ownership
    /// transition; handle rights alone are not a lasting authorization grant.
    pub fn write_secure(
        &mut self,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        security_context: &hyber_core::SecurityContext,
        handle_id: HandleId,
        buffer: &[u8],
    ) -> Result<usize, String> {
        let object_id = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?
            .object_id;
        let object = obj_mgr.lookup(object_id).ok_or("Object not found")?;
        hyber_core::SecurityManager::check_access(
            security_context,
            object.owner,
            object.group,
            object.permissions,
            Rights {
                write: true,
                ..Rights::empty()
            },
        )?;
        self.write(handle_mgr, obj_mgr, process_id, handle_id, buffer)
    }

    pub fn create(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        security_context: &hyber_core::SecurityContext,
        parent_path: &Path,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        Self::check_traversal(ns_mgr, obj_mgr, security_context, parent_path, true)?;
        let parent_path = parent_path.normalize();
        let provider_name = self
            .mount_table
            .find_provider(&parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", parent_path))?;

        let parent_id = ns_mgr.resolve(&parent_path, ns_mgr.root())?;

        let parent_obj = obj_mgr
            .lookup(parent_id)
            .ok_or("Parent directory not found")?;
        hyber_core::SecurityManager::check_access(
            security_context,
            parent_obj.owner,
            parent_obj.group,
            parent_obj.permissions,
            Rights {
                write: true,
                ..Rights::empty()
            },
        )?;

        let provider = self
            .providers
            .get_mut(&provider_name)
            .ok_or_else(|| format!("Provider {} not found", provider_name))?;

        let id = provider.create(obj_mgr, ns_mgr, parent_id, name, obj_type)?;
        let object = obj_mgr
            .lookup_mut(id)
            .ok_or("provider did not create object")?;
        object.owner = security_context.user_id;
        object.group = security_context.group_id;
        object.permissions = if obj_type == ObjectType::Directory {
            0o700
        } else {
            0o600
        };
        if let Err(error) = provider.persist_metadata(object) {
            // A failed durable create must not look successful to callers.
            let _ = provider.remove(obj_mgr, ns_mgr, parent_id, name);
            return Err(error);
        }
        if let Some(root) = self.quota_members.get(&parent_id).copied() {
            self.quota_members.insert(id, root);
        }
        Ok(id)
    }

    pub fn remove(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        security_context: &hyber_core::SecurityContext,
        parent_path: &Path,
        name: &str,
    ) -> Result<(), String> {
        Self::check_traversal(ns_mgr, obj_mgr, security_context, parent_path, true)?;
        let parent_path = parent_path.normalize();
        let provider_name = self
            .mount_table
            .find_provider(&parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", parent_path))?;
        let parent_id = ns_mgr.resolve(&parent_path, ns_mgr.root())?;
        let child = ns_mgr
            .lookup(parent_id, name)
            .ok_or("remove target missing")?;
        if self.quota_roots.contains_key(&child) {
            return Err("cannot remove a quota root".into());
        }
        let parent = obj_mgr
            .lookup(parent_id)
            .ok_or("Parent directory not found")?;
        hyber_core::SecurityManager::check_access(
            security_context,
            parent.owner,
            parent.group,
            parent.permissions,
            Rights {
                delete: true,
                write: true,
                ..Rights::empty()
            },
        )?;

        let provider = self
            .providers
            .get_mut(&provider_name)
            .ok_or_else(|| format!("Provider {} not found", provider_name))?;

        provider.remove(obj_mgr, ns_mgr, parent_id, name)?;
        self.quota_members.remove(&child);
        Ok(())
    }

    /// 7.6 Requirement:  rename in VFS level
    #[allow(clippy::too_many_arguments)] // Both source and destination namespace locations are required.
    pub fn rename(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        security_context: &hyber_core::SecurityContext,
        old_parent_path: &Path,
        old_name: &str,
        new_parent_path: &Path,
        new_name: &str,
    ) -> Result<(), String> {
        Self::check_traversal(ns_mgr, obj_mgr, security_context, old_parent_path, true)?;
        Self::check_traversal(ns_mgr, obj_mgr, security_context, new_parent_path, true)?;
        let old_parent_path = old_parent_path.normalize();
        let new_parent_path = new_parent_path.normalize();
        let provider_name = self
            .mount_table
            .find_provider(&old_parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", old_parent_path))?;
        let destination_provider = self
            .mount_table
            .find_provider(&new_parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", new_parent_path))?;
        if provider_name != destination_provider {
            return Err(
                "Cross-provider rename is not supported; copy then remove instead".to_string(),
            );
        }

        let old_parent_id = ns_mgr.resolve(&old_parent_path, ns_mgr.root())?;
        let new_parent_id = ns_mgr.resolve(&new_parent_path, ns_mgr.root())?;
        let child = ns_mgr
            .lookup(old_parent_id, old_name)
            .ok_or("rename target missing")?;
        let mut descendants = vec![child];
        while let Some(id) = descendants.pop() {
            if self.quota_roots.contains_key(&id) {
                return Err("cannot move a quota root or its ancestor".into());
            }
            if let Some(nodes) = ns_mgr.list_directory(id) {
                descendants.extend(nodes.into_iter().map(|n| n.object_id));
            }
        }
        if self.quota_roots.contains_key(&child)
            || self.quota_members.get(&old_parent_id) != self.quota_members.get(&new_parent_id)
        {
            return Err("rename across quota boundaries is unsupported; copy then remove".into());
        }
        for parent_id in [old_parent_id, new_parent_id] {
            let parent = obj_mgr
                .lookup(parent_id)
                .ok_or("Parent directory not found")?;
            hyber_core::SecurityManager::check_access(
                security_context,
                parent.owner,
                parent.group,
                parent.permissions,
                Rights {
                    rename: true,
                    write: true,
                    ..Rights::empty()
                },
            )?;
        }

        let provider = self
            .providers
            .get_mut(&provider_name)
            .ok_or_else(|| format!("Provider {} not found", provider_name))?;

        provider.rename(
            obj_mgr,
            ns_mgr,
            old_parent_id,
            old_name,
            new_parent_id,
            new_name,
        )
    }

    /// Enumerate a directory.
    ///
    /// Strategy (two-tier):
    /// 1. Ask the responsible provider first (by mount table lookup).
    ///    If it returns Ok(entries) — use them. This is the path for fully virtual
    ///    providers like ProcessProvider, DeviceProvider, ServiceProvider that own
    ///    their own data and have no NamespaceManager backing.
    /// 2. If the provider returns Err — fall back to NamespaceManager.
    ///    This is the path for HostFS and MemFS, where the namespace IS the source
    ///    of truth and the provider has nothing extra to add.
    fn enumerate(
        &self,
        ns_mgr: &NamespaceManager,
        path: &Path,
    ) -> Result<Vec<(String, ObjectId)>, String> {
        let path = path.normalize();
        let provider_name = self
            .mount_table
            .find_provider(&path)
            .ok_or_else(|| format!("No provider mounted for path: {}", path))?;

        let dir_id = ns_mgr.resolve(&path, ns_mgr.root())?;

        let provider = self
            .providers
            .get(&provider_name)
            .ok_or_else(|| format!("Provider '{}' not found", provider_name))?;

        match provider.enumerate(dir_id) {
            Ok(Some(entries)) => Ok(entries),
            Ok(None) => {
                // Provider explicitly defers directory listing to NamespaceManager.
                let nodes = ns_mgr
                    .list_directory(dir_id)
                    .ok_or_else(|| format!("Directory not found in namespace: {:?}", dir_id))?;
                Ok(nodes.into_iter().map(|n| (n.name, n.object_id)).collect())
            }
            Err(e) => Err(e),
        }
    }

    /// Enumerate a directory after checking the caller's read/enumerate
    /// rights. Integrations should use this entry point instead of the legacy
    /// provider-only helper above.
    pub fn enumerate_secure(
        &self,
        ns_mgr: &NamespaceManager,
        obj_mgr: &ObjectManager,
        security_context: &hyber_core::SecurityContext,
        path: &Path,
    ) -> Result<Vec<(String, ObjectId)>, String> {
        Self::check_traversal(ns_mgr, obj_mgr, security_context, path, true)?;
        let normalized = path.normalize();
        let dir_id = ns_mgr.resolve(&normalized, ns_mgr.root())?;
        let object = obj_mgr.lookup(dir_id).ok_or("Directory object not found")?;
        hyber_core::SecurityManager::check_access(
            security_context,
            object.owner,
            object.group,
            object.permissions,
            Rights {
                read: true,
                enumerate: true,
                ..Rights::empty()
            },
        )?;
        self.enumerate(ns_mgr, &normalized)
    }

    /// Get all active mount points for introspection
    pub fn list_mounts(&self) -> &[Mount] {
        &self.mount_table.mounts
    }

    /// mkdir: Create a directory (convenience wrapper around create)
    pub fn mkdir(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        security_context: &hyber_core::SecurityContext,
        parent_path: &Path,
        name: &str,
    ) -> Result<ObjectId, String> {
        self.create(
            ns_mgr,
            obj_mgr,
            security_context,
            parent_path,
            name,
            ObjectType::Directory,
        )
    }

    /// stat: Get metadata for an object at a path
    pub fn stat(
        &self,
        ns_mgr: &NamespaceManager,
        obj_mgr: &ObjectManager,
        security_context: &hyber_core::SecurityContext,
        path: &Path,
    ) -> Result<ObjectMetadata, String> {
        Self::check_traversal(ns_mgr, obj_mgr, security_context, path, false)?;
        let path = path.normalize();
        let object_id = ns_mgr.resolve(&path, ns_mgr.root())?;
        let obj = obj_mgr.lookup(object_id).ok_or("Object not found")?;
        hyber_core::SecurityManager::check_access(
            security_context,
            obj.owner,
            obj.group,
            obj.permissions,
            Rights::read_only(),
        )?;
        Ok(ObjectMetadata {
            object_id,
            object_type: obj.object_type,
            state: obj.state,
            size: obj.size,
            owner: obj.owner,
            group: obj.group,
            permissions: obj.permissions,
            created_at: obj.created_at,
            modified_at: obj.modified_at,
            references: obj.references,
        })
    }
}

/// Metadata returned by stat operation
#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    pub object_id: ObjectId,
    pub object_type: ObjectType,
    pub state: hyber_core::ObjectState,
    pub size: u64,
    pub owner: hyber_core::UserId,
    pub group: hyber_core::GroupId,
    pub permissions: u32,
    pub created_at: u64,
    pub modified_at: u64,
    pub references: u64,
}

impl Default for VFS {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{MountTable, Provider, VFS};
    use hyber_core::{ObjectId, ObjectType, Path, ProcessId, Rights};

    struct ReadProvider;
    impl Provider for ReadProvider {
        fn lookup(&self, _path: &Path) -> Result<Option<ObjectId>, String> {
            Ok(None)
        }
        fn create(
            &mut self,
            _: &mut hyber_object::ObjectManager,
            _: &mut hyber_namespace::NamespaceManager,
            _: ObjectId,
            _: &str,
            _: ObjectType,
        ) -> Result<ObjectId, String> {
            Err("unused".into())
        }
        fn remove(
            &mut self,
            _: &mut hyber_object::ObjectManager,
            _: &mut hyber_namespace::NamespaceManager,
            _: ObjectId,
            _: &str,
        ) -> Result<(), String> {
            Err("unused".into())
        }
        fn rename(
            &mut self,
            _: &mut hyber_object::ObjectManager,
            _: &mut hyber_namespace::NamespaceManager,
            _: ObjectId,
            _: &str,
            _: ObjectId,
            _: &str,
        ) -> Result<(), String> {
            Err("unused".into())
        }
        fn read(&self, _: ObjectId, _: u64, buffer: &mut [u8]) -> Result<usize, String> {
            if let Some(byte) = buffer.first_mut() {
                *byte = b'x';
                Ok(1)
            } else {
                Ok(0)
            }
        }
        fn write(&mut self, _: ObjectId, _: u64, _: &[u8]) -> Result<usize, String> {
            Err("unused".into())
        }
        fn enumerate(&self, _: ObjectId) -> Result<Option<Vec<(String, ObjectId)>>, String> {
            Ok(None)
        }
    }

    #[test]
    fn private_parent_cannot_be_bypassed_by_readable_child() {
        use hyber_core::{GroupId, ObjectType, SecurityContext, UserId};
        let mut objects = hyber_object::ObjectManager::new();
        let mut namespace = hyber_namespace::NamespaceManager::new(&mut objects);
        let parent = objects.create_object(ObjectType::Directory);
        objects.lookup_mut(parent).unwrap().permissions = 0o700;
        namespace
            .create_node(&objects, namespace.root(), "private", parent)
            .unwrap();
        namespace.initialize_directory(parent).unwrap();
        let child = objects.create_object(ObjectType::File);
        objects.lookup_mut(child).unwrap().permissions = 0o644;
        namespace
            .create_node(&objects, parent, "public", child)
            .unwrap();
        let mut user = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![GroupId(2000)],
            capabilities: vec![],
        };
        let path = Path::parse("/private/public");
        assert!(super::VFS::check_traversal(&namespace, &objects, &user, &path, false).is_err());
        objects.lookup_mut(parent).unwrap().group = GroupId(2000);
        objects.lookup_mut(parent).unwrap().permissions = 0o710;
        assert!(super::VFS::check_traversal(&namespace, &objects, &user, &path, false).is_ok());
        user.supplementary_groups.clear();
        assert!(super::VFS::check_traversal(&namespace, &objects, &user, &path, false).is_err());
    }

    #[test]
    fn provider_selection_obeys_component_boundaries() {
        let mut mounts = MountTable::new();
        mounts.mount(Path::parse("/"), "host".into());
        mounts.mount(Path::parse("/processes"), "proc".into());

        assert_eq!(
            mounts.find_provider(&Path::parse("/processes/1")),
            Some("proc".into())
        );
        assert_eq!(
            mounts.find_provider(&Path::parse("/processes-old")),
            Some("host".into())
        );
    }

    #[test]
    fn provider_selection_normalizes_before_routing() {
        let mut mounts = MountTable::new();
        mounts.mount(Path::parse("/"), "host".into());
        mounts.mount(Path::parse("/processes"), "proc".into());

        // VFS public operations normalize before consulting this table.  Keep
        // the routing invariant explicit here as well.
        assert_eq!(
            mounts.find_provider(&Path::parse("/temporary/../processes/1").normalize()),
            Some("proc".into())
        );
    }

    #[test]
    fn secure_read_rechecks_current_object_metadata() {
        use hyber_core::{GroupId, SecurityContext, UserId};
        let mut objects = hyber_object::ObjectManager::new();
        let mut namespace = hyber_namespace::NamespaceManager::new(&mut objects);
        let file = objects.create_object(ObjectType::File);
        objects.lookup_mut(file).unwrap().owner = UserId(1000);
        objects.lookup_mut(file).unwrap().group = GroupId(1000);
        objects.lookup_mut(file).unwrap().permissions = 0o600;
        namespace
            .create_node(&objects, namespace.root(), "owned", file)
            .unwrap();
        let context = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        let mut vfs = VFS::new();
        vfs.register_provider("read".into(), Box::new(ReadProvider));
        vfs.mount(Path::parse("/"), "read".into());
        let mut handles = hyber_handle::HandleManager::new();
        let handle = vfs
            .open(
                &namespace,
                &mut handles,
                &mut objects,
                ProcessId(1),
                &context,
                &Path::parse("/owned"),
                Rights::read_only(),
            )
            .unwrap();
        objects.lookup_mut(file).unwrap().owner = UserId(2000);
        let mut out = [0; 1];
        assert!(vfs
            .read_secure(
                &mut handles,
                &objects,
                ProcessId(1),
                &context,
                handle,
                &mut out,
            )
            .is_err());
    }
}
