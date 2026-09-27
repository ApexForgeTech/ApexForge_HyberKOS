//! HyberKOS Handle Manager
//! Phase 4 — Handle Table, Open, Close, Rights, State

use std::collections::HashMap;
use hyber_core::{
    HandleId,
    ObjectId,
    ProcessId,
    Rights,
};
use hyber_object::ObjectManager;

/// 5.1 & 5.5 — Handle: Represents a process's access to an Object
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub handle_id: HandleId,
    pub object_id: ObjectId,
    pub rights: Rights,
    pub offset: u64, // 5.5: Current read/write position (for File objects)
}

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

    pub fn allocate_handle(&mut self, object_id: ObjectId, rights: Rights) -> HandleId {
        let handle_id = HandleId(self.next_handle_id);
        self.next_handle_id += 1;

        let handle = Handle {
            handle_id,
            object_id,
            rights,
            offset: 0, // Initial offset is always 0
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
}

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
        self.process_tables
            .entry(process_id)
            .or_insert_with(HandleTable::new)
    }

    pub fn open(
        &mut self,
        object_manager: &mut ObjectManager,
        process_id: ProcessId,
        object_id: ObjectId,
        rights: Rights,
    ) -> Result<HandleId, String> {
        if !object_manager.retain(object_id) {
            return Err(format!("Cannot open: Object {:?} is destroyed or does not exist", object_id));
        }

        let table = self.get_or_create_table(process_id);
        let handle_id = table.allocate_handle(object_id, rights);

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
            Err(format!("Cannot close: Handle {:?} not found in process {:?}", handle_id, process_id))
        }
    }

    pub fn get_handle(&self, process_id: ProcessId, handle_id: HandleId) -> Option<&Handle> {
        self.process_tables.get(&process_id)?.get_handle(handle_id)
    }

    pub fn get_handle_mut(&mut self, process_id: ProcessId, handle_id: HandleId) -> Option<&mut Handle> {
        self.process_tables.get_mut(&process_id)?.get_handle_mut(handle_id)
    }

    /// 5.4 — Check if a handle has specific rights
    pub fn check_rights(&self, process_id: ProcessId, handle_id: HandleId, required: Rights) -> Result<(), String> {
        let handle = self.get_handle(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;

        // Check each required right
        if required.read && !handle.rights.read {
            return Err(format!("Handle {:?} does not have READ permission", handle_id));
        }
        if required.write && !handle.rights.write {
            return Err(format!("Handle {:?} does not have WRITE permission", handle_id));
        }
        if required.execute && !handle.rights.execute {
            return Err(format!("Handle {:?} does not have EXECUTE permission", handle_id));
        }

        Ok(())
    }

    /// Helper: Update offset (for read/write operations)
    pub fn update_offset(&mut self, process_id: ProcessId, handle_id: HandleId, bytes_read: u64) -> Result<(), String> {
        let handle = self.get_handle_mut(process_id, handle_id)
            .ok_or_else(|| format!("Handle {:?} not found", handle_id))?;
        
        handle.offset += bytes_read;
        Ok(())
    }
}

