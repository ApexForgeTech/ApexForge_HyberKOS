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
        self.mounts.push(Mount { path, provider_name });
    }

    pub fn find_provider(&self, path: &Path) -> Option<String> {
        let mut best_match: Option<&Mount> = None;
        let mut best_match_len = 0;

        for mount in &self.mounts {
            let mount_str = mount.path.to_string();
            let path_str = path.to_string();
            if path_str.starts_with(&mount_str) && mount_str.len() > best_match_len {
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
pub struct VFS<P: Provider> {
    provider: P,
    mount_table: MountTable,
}

impl<P: Provider> VFS<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mount_table: MountTable::new(),
        }
    }

    pub fn mount(&mut self, path: Path, provider_name: String) {
        self.mount_table.mount(path, provider_name);
    }

    pub fn lookup(&self, ns_mgr: &NamespaceManager, path: &Path) -> Result<ObjectId, String> {
        ns_mgr.resolve(path, ns_mgr.root())
    }

    pub fn open(
        &self,
        ns_mgr: &NamespaceManager,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        path: &Path,
        rights: Rights,
    ) -> Result<HandleId, String> {
        let object_id = ns_mgr.resolve(path, ns_mgr.root())?;
        handle_mgr.open(obj_mgr, process_id, object_id, rights)
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
        let bytes_read = self.provider.read(object_id, offset, buffer)?;
        handle_mgr.update_offset(process_id, handle_id, bytes_read as u64)?;
        Ok(bytes_read)
    }

    pub fn write(
        &mut self,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager, // Added to update metadata
        process_id: ProcessId,
        handle_id: HandleId,
        buffer: &[u8],
    ) -> Result<usize, String> {
        let handle = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        let write_rights = Rights { write: true, ..Rights::empty() };
        handle_mgr.check_rights(process_id, handle_id, write_rights)?;
        let object_id = handle.object_id;
        let offset = handle.offset;
        let bytes_written = self.provider.write(object_id, offset, buffer)?;
        handle_mgr.update_offset(process_id, handle_id, bytes_written as u64)?;
        
        // Update Core Metadata (Phase 8 completeness)
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
        parent_path: &Path,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        let parent_id = ns_mgr.resolve(parent_path, ns_mgr.root())?;
        self.provider.create(obj_mgr, ns_mgr, parent_id, name, obj_type)
    }

    pub fn remove(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        parent_path: &Path,
        name: &str,
    ) -> Result<(), String> {
        let parent_id = ns_mgr.resolve(parent_path, ns_mgr.root())?;
        self.provider.remove(obj_mgr, ns_mgr, parent_id, name)
    }

    /// 7.6 Requirement:  rename in VFS level
        pub fn rename(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager, // Added here too
        old_parent_path: &Path,
        old_name: &str,
        new_parent_path: &Path,
        new_name: &str,
    ) -> Result<(), String> {
        let old_parent_id = ns_mgr.resolve(old_parent_path, ns_mgr.root())?;
        let new_parent_id = ns_mgr.resolve(new_parent_path, ns_mgr.root())?;
        self.provider.rename(obj_mgr, ns_mgr, old_parent_id, old_name, new_parent_id, new_name)
    }

    pub fn enumerate(&self, ns_mgr: &NamespaceManager, path: &Path) -> Result<Vec<(String, ObjectId)>, String> {
        let dir_id = ns_mgr.resolve(path, ns_mgr.root())?;
        self.provider.enumerate(dir_id)
    }

    pub fn provider(&self) -> &P { &self.provider }
    pub fn provider_mut(&mut self) -> &mut P { &mut self.provider }

    /// Get all active mount points for introspection
    pub fn list_mounts(&self) -> &[Mount] {
        &self.mount_table.mounts
    }
}