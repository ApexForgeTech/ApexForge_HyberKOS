//! HyberKOS Memory File System (MemFS)
//! Phase 11 — Virtual /temporary Namespace
//!
//! MemFS is a fully in-memory, ephemeral file system.
//! All data written here lives in RAM and is lost on shutdown.
//! This backs the /temporary virtual directory (equivalent to tmpfs on Linux).
//!
//! Design principles:
//! - No Linux tmpfs or OS calls — pure Rust, pure Hyber.
//! - Reads and writes go through Hyber ObjectIds, not filenames.
//! - Supports files and directories.
//! - Consistent with the Provider interface.

use hyber_core::{ObjectId, ObjectType};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::Provider;
use std::collections::HashMap;

/// In-memory file storage entry
#[derive(Debug, Clone)]
struct MemEntry {
    /// The content bytes stored in RAM
    data: Vec<u8>,
    /// Whether this entry is a directory (no data, just a container)
    is_directory: bool,
}

impl MemEntry {
    fn new_file() -> Self {
        Self {
            data: Vec::new(),
            is_directory: false,
        }
    }
    fn new_directory() -> Self {
        Self {
            data: Vec::new(),
            is_directory: true,
        }
    }
}

/// MemFS Provider — backs the /temporary virtual namespace
///
/// All storage is in `entries: HashMap<ObjectId, MemEntry>`.
/// Namespace structure (names, parent-child relations) is handled
/// by NamespaceManager as with all other providers.
pub struct MemFSProvider {
    entries: HashMap<ObjectId, MemEntry>,
}

impl MemFSProvider {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Returns how many bytes are currently stored in MemFS
    pub fn total_bytes_used(&self) -> usize {
        self.entries.values().map(|e| e.data.len()).sum()
    }

    /// Returns total number of entries (files + directories)
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for MemFSProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for MemFSProvider {
    fn create(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        if obj_type != ObjectType::File && obj_type != ObjectType::Directory {
            return Err("MemFS only supports File and Directory creation".to_string());
        }

        // 1. Create Hyber object
        let obj_id = obj_mgr.create_object(obj_type);

        // 2. Register in namespace
        ns_mgr
            .create_node(obj_mgr, parent_id, name, obj_id)
            .map_err(|e| format!("Namespace error: {}", e))?;

        // 3. Initialize directory contents in namespace manager if needed
        if obj_type == ObjectType::Directory {
            ns_mgr
                .initialize_directory(obj_id)
                .map_err(|e| format!("MemFS init dir error: {}", e))?;
            self.entries.insert(obj_id, MemEntry::new_directory());
        } else {
            self.entries.insert(obj_id, MemEntry::new_file());
        }

        Ok(obj_id)
    }

    fn remove(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
    ) -> Result<(), String> {
        // 1. Find the object in the namespace
        let obj_id = ns_mgr
            .lookup(parent_id, name)
            .ok_or_else(|| format!("'{}' not found in MemFS", name))?;

        if obj_mgr
            .lookup(obj_id)
            .map(|o| o.object_type == ObjectType::Directory)
            .unwrap_or(false)
            && ns_mgr
                .list_directory(obj_id)
                .is_some_and(|entries| !entries.is_empty())
        {
            return Err("Cannot remove a non-empty directory".to_string());
        }

        // 2. Remove from namespace
        ns_mgr.remove_node(parent_id, name);

        // 3. Remove from our in-memory store
        self.entries.remove(&obj_id);

        // 4. Release and destroy the Hyber object
        obj_mgr.release(obj_id);
        obj_mgr.destroy(obj_id);

        Ok(())
    }

    fn rename(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        old_parent_id: ObjectId,
        old_name: &str,
        new_parent_id: ObjectId,
        new_name: &str,
    ) -> Result<(), String> {
        // The data stays in entries under the same ObjectId — only the namespace entry changes
        ns_mgr
            .rename_node(old_parent_id, old_name, new_parent_id, new_name)
            .map_err(|e| format!("MemFS rename error: {}", e))
    }

    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        let entry = self
            .entries
            .get(&object_id)
            .ok_or_else(|| format!("MemFS: ObjectId {:?} not found", object_id))?;

        if entry.is_directory {
            return Err("Cannot read a directory".to_string());
        }

        let offset = offset as usize;
        if offset >= entry.data.len() {
            return Ok(0); // EOF
        }

        let available = &entry.data[offset..];
        let len = buffer.len().min(available.len());
        buffer[..len].copy_from_slice(&available[..len]);
        Ok(len)
    }

    fn write(&mut self, object_id: ObjectId, offset: u64, buffer: &[u8]) -> Result<usize, String> {
        let entry = self
            .entries
            .get_mut(&object_id)
            .ok_or_else(|| format!("MemFS: ObjectId {:?} not found", object_id))?;

        if entry.is_directory {
            return Err("Cannot write to a directory".to_string());
        }

        let offset = offset as usize;

        // Grow the buffer if needed
        if offset + buffer.len() > entry.data.len() {
            entry.data.resize(offset + buffer.len(), 0);
        }

        entry.data[offset..offset + buffer.len()].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn enumerate(&self, dir_id: ObjectId) -> Result<Vec<(String, ObjectId)>, String> {
        // MemFS directory listing comes from NamespaceManager, not our entries map.
        // We signal this by returning an error — VFS will fall back to NamespaceManager.
        // The entry existing in our map confirms the dir exists in MemFS.
        let _ = self
            .entries
            .get(&dir_id)
            .ok_or_else(|| format!("MemFS dir {:?} not registered", dir_id))?;
        Err("MemFS defers directory listing to NamespaceManager".to_string())
    }
}
