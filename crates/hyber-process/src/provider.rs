use crate::manager::ProcessManager;
use hyber_core::{ObjectId, ObjectType};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::Provider;
use std::cell::RefCell;
use std::rc::Rc;

pub struct ProcessProvider {
    pub proc_mgr: Rc<RefCell<ProcessManager>>,
}

impl ProcessProvider {
    pub fn new(proc_mgr: Rc<RefCell<ProcessManager>>) -> Self {
        Self { proc_mgr }
    }
}

impl Provider for ProcessProvider {
    fn create(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _parent_id: ObjectId,
        _name: &str,
        _obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        Err("Cannot create files in /processes directly".to_string())
    }

    fn remove(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _parent_id: ObjectId,
        _name: &str,
    ) -> Result<(), String> {
        Err("Cannot remove files in /processes directly".to_string())
    }

    fn rename(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _old_parent_id: ObjectId,
        _old_name: &str,
        _new_parent_id: ObjectId,
        _new_name: &str,
    ) -> Result<(), String> {
        Err("Cannot rename in /processes".to_string())
    }

    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        let proc_mgr = self.proc_mgr.borrow();

        // Find the process by object_id
        let mut target_process = None;
        for proc in proc_mgr.list_processes() {
            if proc.object_id == object_id {
                target_process = Some(proc);
                break;
            }
        }

        let proc = target_process.ok_or("Process not found")?;

        // Create a simple string representation
        let info = format!(
            "Process ID: {}\nParent ID: {:?}\nState: {:?}\nUser ID: {}\nGroup ID: {}\n",
            proc.id.0,
            proc.parent_id,
            proc.state,
            proc.security_context.user_id.0,
            proc.security_context.group_id.0
        );
        let bytes = info.as_bytes();
        let offset = usize::try_from(offset).map_err(|_| "Offset is too large")?;
        if offset >= bytes.len() {
            return Ok(0);
        }
        let len = buffer.len().min(bytes.len() - offset);
        buffer[..len].copy_from_slice(&bytes[offset..offset + len]);
        Ok(len)
    }

    fn write(
        &mut self,
        _object_id: ObjectId,
        _offset: u64,
        _buffer: &[u8],
    ) -> Result<usize, String> {
        Err("Cannot write to process objects".to_string())
    }

    fn enumerate(&self, _dir_id: ObjectId) -> Result<Vec<(String, ObjectId)>, String> {
        let proc_mgr = self.proc_mgr.borrow();
        let mut entries = Vec::new();
        for proc in proc_mgr.list_processes() {
            entries.push((proc.id.0.to_string(), proc.object_id));
        }
        Ok(entries)
    }
}
