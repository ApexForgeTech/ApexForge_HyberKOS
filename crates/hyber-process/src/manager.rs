use std::collections::HashMap;
use hyber_core::{ProcessId, SecurityContext, ObjectType};
use hyber_object::ObjectManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Running,
    Stopped,
    Zombie,
}

pub struct Process {
    pub id: ProcessId,
    pub parent_id: Option<ProcessId>,
    pub state: ProcessState,
    pub security_context: SecurityContext,
    pub linux_pid: Option<u32>, // 11.3 - Linux Process Provider internal mapping
    pub object_id: hyber_core::ObjectId,
}

pub struct ProcessManager {
    processes: HashMap<ProcessId, Process>,
    next_id: u64,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_process(
        &mut self,
        obj_mgr: &mut ObjectManager,
        parent_id: Option<ProcessId>,
        security_context: SecurityContext,
        linux_pid: Option<u32>,
    ) -> ProcessId {
        let id = ProcessId(self.next_id);
        self.next_id += 1;

        let obj_id = obj_mgr.create_object(ObjectType::Process);
        
        // Setup ownership for the process object
        if let Some(obj) = obj_mgr.lookup_mut(obj_id) {
            obj.owner = security_context.user_id;
            obj.group = security_context.group_id;
            obj.permissions = 0o400; // Only readable by owner
        }

        let process = Process {
            id,
            parent_id,
            state: ProcessState::Created,
            security_context,
            linux_pid,
            object_id: obj_id,
        };

        self.processes.insert(id, process);
        id
    }

    pub fn get_process(&self, id: ProcessId) -> Option<&Process> {
        self.processes.get(&id)
    }

    pub fn get_process_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.processes.get_mut(&id)
    }

    pub fn start_process(&mut self, id: ProcessId) -> Result<(), String> {
        if let Some(p) = self.processes.get_mut(&id) {
            p.state = ProcessState::Running;
            Ok(())
        } else {
            Err("Process not found".to_string())
        }
    }

    pub fn stop_process(&mut self, id: ProcessId) -> Result<(), String> {
        if let Some(p) = self.processes.get_mut(&id) {
            p.state = ProcessState::Stopped;
            Ok(())
        } else {
            Err("Process not found".to_string())
        }
    }
    
    pub fn list_processes(&self) -> Vec<&Process> {
        self.processes.values().collect()
    }
}
