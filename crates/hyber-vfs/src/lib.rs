//! HyberKOS Virtual File System (VFS)
//! Phase 5 — VFS API, Provider Interface, Mount Model

use std::collections::HashMap;
use hyber_core::{HandleId, ObjectId, ObjectType, Path, ProcessId, Rights};
use hyber_handle::{Handle, HandleManager};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;

// ==========================================
// 6.3 — Provider Interface
// ==========================================
/// Provider is the backend implementation that supplies/manages resources.
/// VFS does NOT know how the provider works, it only knows this interface.
pub trait Provider {
    /// Create a new object and link it to the namespace
    fn create(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String>;

    /// Remove an object and its namespace link
    fn remove(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
    ) -> Result<(), String>;

    /// Read data from an object into a buffer
    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String>;

    /// Write data from a buffer into an object
    fn write(&mut self, object_id: ObjectId, offset: u64, buffer: &[u8]) -> Result<usize, String>;

    /// Enumerate contents of a directory
    fn enumerate(&self, dir_id: ObjectId) -> Result<Vec<(String, ObjectId)>, String>;
}

// ==========================================
// 6.4 — Mount Model
// ==========================================
/// Mount represents a mapping from a namespace path to a Provider
#[derive(Debug, Clone)]
pub struct Mount {
    pub path: Path,
    pub provider_name: String,
}

/// Mount Table: Manages all mount points in the system
#[derive(Debug, Default)]
pub struct MountTable {
    mounts: Vec<Mount>,
}

impl MountTable {
    pub fn new() -> Self {
        Self {
            mounts: Vec::new(),
        }
    }

    /// Add a new mount point
    pub fn mount(&mut self, path: Path, provider_name: String) {
        self.mounts.push(Mount {
            path,
            provider_name,
        });
    }

    /// Find which provider handles a given path
    /// Returns the provider name for the longest matching mount point
    pub fn find_provider(&self, path: &Path) -> Option<String> {
        let mut best_match: Option<&Mount> = None;
        let mut best_match_len = 0;

        for mount in &self.mounts {
            // Check if the path starts with the mount point
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
/// VFS is the coordinator. It orchestrates Namespace, Handle, Object, and Provider.
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

    /// 6.4 — Mount a provider at a specific path
    pub fn mount(&mut self, path: Path, provider_name: String) {
        self.mount_table.mount(path, provider_name);
    }

    /// 6.1 — Lookup: Resolve a path to an ObjectId
    pub fn lookup(
        &self,
        ns_mgr: &NamespaceManager,
        path: &Path,
    ) -> Result<ObjectId, String> {
        ns_mgr.resolve(path, ns_mgr.root())
    }

    /// 6.1 — Open: Open a file/directory by path and return a HandleId
    pub fn open(
        &self,
        ns_mgr: &NamespaceManager,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        path: &Path,
        rights: Rights,
    ) -> Result<HandleId, String> {
        // 1. Resolve Path to ObjectId (Namespace Manager)
        let object_id = ns_mgr.resolve(path, ns_mgr.root())?;

        // 2. Create Handle and increment reference count (Handle Manager)
        handle_mgr.open(obj_mgr, process_id, object_id, rights)
    }

    /// 6.1 — Close: Close a handle and decrement reference count
    pub fn close(
        &self,
        handle_mgr: &mut HandleManager,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
        handle_id: HandleId,
    ) -> Result<(), String> {
        handle_mgr.close(obj_mgr, process_id, handle_id)
    }

    /// 6.1 — Read: Read data through a handle
    pub fn read(
        &self,
        handle_mgr: &mut HandleManager,
        process_id: ProcessId,
        handle_id: HandleId,
        buffer: &mut [u8],
    ) -> Result<usize, String> {
        // 1. Get handle to check rights and get object_id + offset
        let handle = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        // 2. Security Check: Must have READ rights
        handle_mgr.check_rights(process_id, handle_id, Rights::read_only())?;

        let object_id = handle.object_id;
        let offset = handle.offset;

        // 3. Delegate actual I/O to the Provider
        let bytes_read = self.provider.read(object_id, offset, buffer)?;

        // 4. Update handle offset
        handle_mgr.update_offset(process_id, handle_id, bytes_read as u64)?;

        Ok(bytes_read)
    }

    /// 6.1 — Write: Write data through a handle
    pub fn write(
        &mut self,
        handle_mgr: &mut HandleManager,
        process_id: ProcessId,
        handle_id: HandleId,
        buffer: &[u8],
    ) -> Result<usize, String> {
        // 1. Get handle
        let handle = handle_mgr
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        // 2. Security Check: Must have WRITE rights
        let write_rights = Rights {
            write: true,
            ..Rights::empty()
        };
        handle_mgr.check_rights(process_id, handle_id, write_rights)?;

        let object_id = handle.object_id;
        let offset = handle.offset;

        // 3. Delegate actual I/O to the Provider
        let bytes_written = self.provider.write(object_id, offset, buffer)?;

        // 4. Update handle offset
        handle_mgr.update_offset(process_id, handle_id, bytes_written as u64)?;

        Ok(bytes_written)
    }

    /// 6.1 — Create: Create a new file or directory
    pub fn create(
        &mut self,
        ns_mgr: &mut NamespaceManager,
        obj_mgr: &mut ObjectManager,
        parent_path: &Path,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        // 1. Resolve parent path
        let parent_id = ns_mgr.resolve(parent_path, ns_mgr.root())?;

        // 2. Delegate creation to Provider
        self.provider
            .create(obj_mgr, ns_mgr, parent_id, name, obj_type)
    }

    /// 6.1 — Remove: Remove a file or directory
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

    /// 6.1 — Enumerate: List contents of a directory
    pub fn enumerate(
        &self,
        ns_mgr: &NamespaceManager,
        path: &Path,
    ) -> Result<Vec<(String, ObjectId)>, String> {
        let dir_id = ns_mgr.resolve(path, ns_mgr.root())?;
        self.provider.enumerate(dir_id)
    }

    /// Get reference to the provider (for advanced operations)
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Get mutable reference to the provider
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
}

