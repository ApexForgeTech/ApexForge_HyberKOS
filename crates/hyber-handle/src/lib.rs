//! HyberKOS Handle Manager
//! Phase 4 — Handle Table, Open, Close, Rights, State
//!
//! FIX (Gap 2): INHERITABLE flag added to Handle. When a child process is
//!              created, only handles marked inheritable are cloned into its
//!              table.
//!
//! FIX (Gap 3): revoke_rights() added: lets the security manager or the object
//!              owner strip rights from any active handle at run-time.

use hyber_core::{HandleId, ObjectId, ProcessId, Rights};
use hyber_object::ObjectManager;
use std::collections::HashMap;

// ── 5.1 & 5.5 — Handle ───────────────────────────────────────────────────────

/// Flags that control handle behaviour across process boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleFlags {
    /// If true, this handle is copied to a child process on spawn.
    pub inheritable: bool,
}

impl HandleFlags {
    pub fn default_inheritable() -> Self {
        Self { inheritable: true }
    }

    pub fn not_inheritable() -> Self {
        Self { inheritable: false }
    }
}

impl Default for HandleFlags {
    fn default() -> Self {
        Self { inheritable: false }
    }
}

/// A process's access ticket to an Object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub handle_id: HandleId,
    pub object_id: ObjectId,
    pub rights: Rights,
    /// 5.5: Current read/write position (for File objects)
    pub offset: u64,
    pub provider_name: String,
    /// FIX Gap 2: Controls cross-process inheritance
    pub flags: HandleFlags,
}

// ── Handle Table (per-process) ────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleTable {
    handles: HashMap<HandleId, Handle>,
    next_handle_id: u64,
}

impl HandleTable {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_handle_id: 1,
        }
    }

    pub fn allocate_handle(
        &mut self,
        object_id: ObjectId,
        rights: Rights,
        provider_name: String,
        flags: HandleFlags,
    ) -> HandleId {
        let handle_id = HandleId(self.next_handle_id);
        self.next_handle_id += 1;

        let handle = Handle {
            handle_id,
            object_id,
            rights,
            offset: 0,
            provider_name,
            flags,
        };

        self.handles.insert(handle_id, handle);
        handle_id
    }

    pub fn remove_handle(&mut self, handle_id: HandleId) -> Option<ObjectId> {
        self.handles.remove(&handle_id).map(|h| h.object_id)
    }

    pub fn get_handle(&self, handle_id: HandleId) -> Option<&Handle> {
        self.handles.get(&handle_id)
    }

    pub fn get_handle_mut(&mut self, handle_id: HandleId) -> Option<&mut Handle> {
        self.handles.get_mut(&handle_id)
    }

    /// Clone only inheritable handles (used when spawning a child process).
    pub fn clone_inheritable(&self, new_table: &mut HandleTable) {
        for handle in self.handles.values() {
            if handle.flags.inheritable {
                // Re-allocate in child table preserving object_id and rights
                new_table.allocate_handle(
                    handle.object_id,
                    handle.rights,
                    handle.provider_name.clone(),
                    handle.flags,
                );
            }
        }
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Handle Manager (global) ───────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct HandleManager {
    process_tables: HashMap<ProcessId, HandleTable>,
}

impl HandleManager {
    pub fn new() -> Self {
        Self {
            process_tables: HashMap::new(),
        }
    }

    fn get_or_create_table(&mut self, process_id: ProcessId) -> &mut HandleTable {
        self.process_tables.entry(process_id).or_default()
    }

    /// Open a handle with default (non-inheritable) flags.
    pub fn open(
        &mut self,
        object_manager: &mut ObjectManager,
        process_id: ProcessId,
        object_id: ObjectId,
        rights: Rights,
        provider_name: String,
    ) -> Result<HandleId, String> {
        self.open_with_flags(
            object_manager,
            process_id,
            object_id,
            rights,
            provider_name,
            HandleFlags::default(),
        )
    }

    /// Open a handle with explicit flags (inheritable / not-inheritable).
    pub fn open_with_flags(
        &mut self,
        object_manager: &mut ObjectManager,
        process_id: ProcessId,
        object_id: ObjectId,
        rights: Rights,
        provider_name: String,
        flags: HandleFlags,
    ) -> Result<HandleId, String> {
        if !object_manager.retain(object_id) {
            return Err(format!(
                "Cannot open: Object {:?} is destroyed or does not exist",
                object_id
            ));
        }

        let table = self.get_or_create_table(process_id);
        let handle_id = table.allocate_handle(object_id, rights, provider_name, flags);

        Ok(handle_id)
    }

    pub fn close(
        &mut self,
        object_manager: &mut ObjectManager,
        process_id: ProcessId,
        handle_id: HandleId,
    ) -> Result<(), String> {
        let table = self.get_or_create_table(process_id);

        if let Some(object_id) = table.remove_handle(handle_id) {
            object_manager.release(object_id);
            Ok(())
        } else {
            Err(format!(
                "Cannot close: Handle {:?} not found in process {:?}",
                handle_id, process_id
            ))
        }
    }

    pub fn get_handle(&self, process_id: ProcessId, handle_id: HandleId) -> Option<&Handle> {
        self.process_tables.get(&process_id)?.get_handle(handle_id)
    }

    pub fn get_handle_mut(
        &mut self,
        process_id: ProcessId,
        handle_id: HandleId,
    ) -> Option<&mut Handle> {
        self.process_tables
            .get_mut(&process_id)?
            .get_handle_mut(handle_id)
    }

    /// 5.4 — Check if a handle has specific rights
    pub fn check_rights(
        &self,
        process_id: ProcessId,
        handle_id: HandleId,
        required: Rights,
    ) -> Result<(), String> {
        let handle = self
            .get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        if required.read && !handle.rights.read {
            return Err(format!(
                "Handle {:?} does not have READ permission",
                handle_id
            ));
        }
        if required.write && !handle.rights.write {
            return Err(format!(
                "Handle {:?} does not have WRITE permission",
                handle_id
            ));
        }
        if required.execute && !handle.rights.execute {
            return Err(format!(
                "Handle {:?} does not have EXECUTE permission",
                handle_id
            ));
        }

        Ok(())
    }

    /// FIX Gap 3 — Revoke specific rights from all handles on an object.
    ///
    /// When the security context of an Object changes (e.g., WRITE is removed),
    /// the SecurityManager calls this to strip the same rights from every open
    /// handle pointing at that object across all processes.
    pub fn revoke_rights(&mut self, object_id: ObjectId, rights_to_revoke: Rights) {
        for table in self.process_tables.values_mut() {
            for handle in table.handles.values_mut() {
                if handle.object_id == object_id {
                    if rights_to_revoke.read {
                        handle.rights.read = false;
                    }
                    if rights_to_revoke.write {
                        handle.rights.write = false;
                    }
                    if rights_to_revoke.execute {
                        handle.rights.execute = false;
                    }
                    if rights_to_revoke.delete {
                        handle.rights.delete = false;
                    }
                    if rights_to_revoke.rename {
                        handle.rights.rename = false;
                    }
                    if rights_to_revoke.enumerate {
                        handle.rights.enumerate = false;
                    }
                    if rights_to_revoke.connect {
                        handle.rights.connect = false;
                    }
                    if rights_to_revoke.wait {
                        handle.rights.wait = false;
                    }
                    if rights_to_revoke.signal {
                        handle.rights.signal = false;
                    }
                }
            }
        }
    }

    /// FIX Gap 2 — Inherit parent handles into a freshly-created child process.
    ///
    /// Only handles marked `flags.inheritable = true` are cloned.
    /// The child table gets brand-new HandleIds (so parent and child IDs do not
    /// collide), but the underlying ObjectId (and therefore the Object's strong
    /// reference count) is shared.
    pub fn inherit_into_child(
        &mut self,
        object_manager: &mut ObjectManager,
        parent_id: ProcessId,
        child_id: ProcessId,
    ) {
        // Collect inheritable handles from parent first to avoid borrow issues
        let inheritable: Vec<(ObjectId, Rights, String, HandleFlags)> = self
            .process_tables
            .get(&parent_id)
            .map(|t| {
                t.handles
                    .values()
                    .filter(|h| h.flags.inheritable)
                    .map(|h| (h.object_id, h.rights, h.provider_name.clone(), h.flags))
                    .collect()
            })
            .unwrap_or_default();

        for (obj_id, rights, provider, flags) in inheritable {
            // Bump the strong ref count so the child's table keeps the object alive
            object_manager.retain(obj_id);
            let child_table = self.get_or_create_table(child_id);
            child_table.allocate_handle(obj_id, rights, provider, flags);
        }
    }

    /// Helper: Update offset (for read/write operations)
    pub fn update_offset(
        &mut self,
        process_id: ProcessId,
        handle_id: HandleId,
        bytes_read: u64,
    ) -> Result<(), String> {
        let handle = self
            .get_handle_mut(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        handle.offset += bytes_read;
        Ok(())
    }

    /// List all handles for a given process (for shell introspection)
    pub fn list_handles(&self, process_id: ProcessId) -> Vec<&Handle> {
        match self.process_tables.get(&process_id) {
            Some(table) => table.handles.values().collect(),
            None => Vec::new(),
        }
    }

    /// Get all handle IDs for a given process (for cleanup)
    pub fn list_handle_ids(&self, process_id: ProcessId) -> Vec<HandleId> {
        match self.process_tables.get(&process_id) {
            Some(table) => table.handles.keys().cloned().collect(),
            None => Vec::new(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use hyber_core::{ObjectType, ProcessId, Rights};
    use hyber_object::ObjectManager;

    fn setup() -> (ObjectManager, HandleManager, ProcessId) {
        let mut obj_mgr = ObjectManager::new();
        let _ = obj_mgr.create_object(ObjectType::File); // id 1
        let handle_mgr = HandleManager::new();
        (obj_mgr, handle_mgr, ProcessId(1))
    }

    #[test]
    fn inherit_only_flagged_handles() {
        let (mut obj_mgr, mut hm, parent) = setup();
        let child = ProcessId(2);
        let file_id = hyber_core::ObjectId(1);

        // Open one inheritable and one non-inheritable handle in parent
        hm.open_with_flags(
            &mut obj_mgr,
            parent,
            file_id,
            Rights::read_only(),
            "hostfs".into(),
            HandleFlags::default_inheritable(),
        )
        .unwrap();
        hm.open_with_flags(
            &mut obj_mgr,
            parent,
            file_id,
            Rights::read_only(),
            "hostfs".into(),
            HandleFlags::not_inheritable(),
        )
        .unwrap();

        hm.inherit_into_child(&mut obj_mgr, parent, child);

        // Child should have exactly 1 handle
        assert_eq!(hm.list_handles(child).len(), 1);
    }

    #[test]
    fn revoke_strips_rights_from_all_processes() {
        let (mut obj_mgr, mut hm, p1) = setup();
        let p2 = ProcessId(2);
        let file_id = hyber_core::ObjectId(1);

        // Both processes open the same object with RW
        hm.open(&mut obj_mgr, p1, file_id, Rights::read_write(), "hostfs".into())
            .unwrap();
        // Re-retain for second process open
        obj_mgr.retain(file_id);
        hm.open(&mut obj_mgr, p2, file_id, Rights::read_write(), "hostfs".into())
            .unwrap();

        // Revoke WRITE from all handles on file_id
        hm.revoke_rights(file_id, Rights { write: true, ..Rights::empty() });

        // Neither process can write now
        for (pid, hid) in [(p1, HandleId(1)), (p2, HandleId(1))] {
            let h = hm.get_handle(pid, hid).unwrap();
            assert!(!h.rights.write, "Write should be revoked for {:?}", pid);
        }
    }
}
