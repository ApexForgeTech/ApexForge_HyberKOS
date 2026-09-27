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
    fn enumerate(&self, dir_id: ObjectId) -> Result<Vec<(String, ObjectId)>, String>;
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
}

impl VFS {
    pub fn new() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
            mount_table: MountTable::new(),
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
        ns_mgr.resolve(path, ns_mgr.root())
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
        let provider_name = self
            .mount_table
            .find_provider(path)
            .ok_or_else(|| format!("No provider mounted for path: {}", path))?;

        let object_id = ns_mgr.resolve(path, ns_mgr.root())?;

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

        let provider = self
            .providers
            .get(&handle.provider_name)
            .ok_or_else(|| format!("Provider {} not found", handle.provider_name))?;

        let bytes_read = provider.read(object_id, offset, buffer)?;
        handle_mgr.update_offset(process_id, handle_id, bytes_read as u64)?;
        Ok(bytes_read)
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

        let provider = self
            .providers
            .get_mut(&provider_name)
            .ok_or_else(|| format!("Provider {} not found", provider_name))?;

        let bytes_written = provider.write(object_id, offset, buffer)?;
        handle_mgr.update_offset(process_id, handle_id, bytes_written as u64)?;

        if let Some(obj) = obj_mgr.lookup_mut(object_id) {
            let new_size = offset + (bytes_written as u64);
            if new_size > obj.size {
                obj.size = new_size;
            }
            obj.modified_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }

        Ok(bytes_written)
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
        let provider_name = self
            .mount_table
            .find_provider(parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", parent_path))?;

        let parent_id = ns_mgr.resolve(parent_path, ns_mgr.root())?;

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

        provider.create(obj_mgr, ns_mgr, parent_id, name, obj_type)
    }

    pub fn remove(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        security_context: &hyber_core::SecurityContext,
        parent_path: &Path,
        name: &str,
    ) -> Result<(), String> {
        let provider_name = self
            .mount_table
            .find_provider(parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", parent_path))?;
        let parent_id = ns_mgr.resolve(parent_path, ns_mgr.root())?;
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

        provider.remove(obj_mgr, ns_mgr, parent_id, name)
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
        let provider_name = self
            .mount_table
            .find_provider(old_parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", old_parent_path))?;
        let destination_provider = self
            .mount_table
            .find_provider(new_parent_path)
            .ok_or_else(|| format!("No provider mounted for path: {}", new_parent_path))?;
        if provider_name != destination_provider {
            return Err(
                "Cross-provider rename is not supported; copy then remove instead".to_string(),
            );
        }

        let old_parent_id = ns_mgr.resolve(old_parent_path, ns_mgr.root())?;
        let new_parent_id = ns_mgr.resolve(new_parent_path, ns_mgr.root())?;
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
    pub fn enumerate(
        &self,
        ns_mgr: &NamespaceManager,
        path: &Path,
    ) -> Result<Vec<(String, ObjectId)>, String> {
        let provider_name = self
            .mount_table
            .find_provider(path)
            .ok_or_else(|| format!("No provider mounted for path: {}", path))?;

        let dir_id = ns_mgr.resolve(path, ns_mgr.root())?;

        let provider = self
            .providers
            .get(&provider_name)
            .ok_or_else(|| format!("Provider '{}' not found", provider_name))?;

        match provider.enumerate(dir_id) {
            Ok(entries) => Ok(entries),
            Err(_) => {
                // Provider defers directory listing to NamespaceManager.
                let nodes = ns_mgr
                    .list_directory(dir_id)
                    .ok_or_else(|| format!("Directory not found in namespace: {:?}", dir_id))?;
                Ok(nodes.into_iter().map(|n| (n.name, n.object_id)).collect())
            }
        }
    }

    /// Get all active mount points for introspection
    pub fn list_mounts(&self) -> &[Mount] {
        &self.mount_table.mounts
    }
}

impl Default for VFS {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::MountTable;
    use hyber_core::Path;

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
}
