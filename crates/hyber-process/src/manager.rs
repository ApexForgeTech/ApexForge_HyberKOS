use hyber_core::{ObjectType, ProcessId, SecurityContext, ThreadId};
use hyber_object::ObjectManager;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Running,
    Stopped,
    Zombie,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Terminated,
}

/// 11.2 — Thread Object
pub struct Thread {
    pub id: ThreadId,
    pub process_id: ProcessId,
    pub state: ThreadState,
    pub object_id: hyber_core::ObjectId,
}

/// 11.1 — Process Object
pub struct Process {
    pub id: ProcessId,
    pub parent_id: Option<ProcessId>,
    pub state: ProcessState,
    pub security_context: SecurityContext,
    pub linux_pid: Option<u32>, // 11.3 - Linux Process Provider internal mapping
    pub object_id: hyber_core::ObjectId,
    pub threads: Vec<ThreadId>, // Process owns threads
    pub exit_code: Option<i32>,
}

pub struct ProcessManager {
    processes: HashMap<ProcessId, Process>,
    threads: HashMap<ThreadId, Thread>,
    next_pid: u64,
    next_tid: u64,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            threads: HashMap::new(),
            next_pid: 1,
            next_tid: 1,
        }
    }

    /// 11.5 — Process Operations: create
    pub fn create_process(
        &mut self,
        obj_mgr: &mut ObjectManager,
        parent_id: Option<ProcessId>,
        security_context: SecurityContext,
        linux_pid: Option<u32>,
    ) -> Result<ProcessId, String> {
        if let Some(parent) = parent_id {
            let parent_process = self.processes.get(&parent).ok_or("Parent process not found")?;
            if parent_process.state == ProcessState::Zombie {
                return Err("Cannot create a child of a terminated process".to_string());
            }
        }
        if self.next_pid == u64::MAX || self.next_tid == u64::MAX {
            return Err("Process or thread identifier space exhausted".to_string());
        }
        let id = ProcessId(self.next_pid);
        self.next_pid += 1;

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
            threads: Vec::new(),
            exit_code: None,
        };

        self.processes.insert(id, process);
        // Every process has a primary thread. A process with no thread cannot
        // satisfy the Phase 10 execution model.
        self.create_thread(obj_mgr, id)?;
        Ok(id)
    }

    /// 11.2 — Thread creation
    pub fn create_thread(
        &mut self,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
    ) -> Result<ThreadId, String> {
        if !self.processes.contains_key(&process_id) {
            return Err("Process not found".to_string());
        }

        let tid = ThreadId(self.next_tid);
        self.next_tid += 1;

        let obj_id = obj_mgr.create_object(ObjectType::Thread);
        let thread = Thread {
            id: tid,
            process_id,
            state: ThreadState::Ready,
            object_id: obj_id,
        };

        self.threads.insert(tid, thread);
        self.processes
            .get_mut(&process_id)
            .unwrap()
            .threads
            .push(tid);

        Ok(tid)
    }

    pub fn get_process(&self, id: ProcessId) -> Option<&Process> {
        self.processes.get(&id)
    }

    pub fn get_process_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.processes.get_mut(&id)
    }

    pub fn get_thread(&self, id: ThreadId) -> Option<&Thread> {
        self.threads.get(&id)
    }

    /// 11.5 — Process Operations: start
    pub fn start_process(&mut self, id: ProcessId) -> Result<(), String> {
        if let Some(p) = self.processes.get_mut(&id) {
            if p.state != ProcessState::Created {
                return Err(format!("Process {:?} cannot start from {:?}", id, p.state));
            }
            p.state = ProcessState::Running;
            // Also start all ready threads
            for tid in &p.threads {
                if let Some(t) = self.threads.get_mut(tid)
                    && t.state == ThreadState::Ready
                {
                    t.state = ThreadState::Running;
                }
            }
            Ok(())
        } else {
            Err("Process not found".to_string())
        }
    }

    /// 11.5 — Process Operations: stop (terminate)
    pub fn stop_process(&mut self, id: ProcessId, exit_code: i32) -> Result<(), String> {
        if let Some(p) = self.processes.get_mut(&id) {
            if p.state == ProcessState::Zombie {
                return Err("Process is already terminated".to_string());
            }
            p.state = ProcessState::Zombie;
            p.exit_code = Some(exit_code);
            // Terminate threads
            for tid in &p.threads {
                if let Some(t) = self.threads.get_mut(tid) {
                    t.state = ThreadState::Terminated;
                }
            }
            Ok(())
        } else {
            Err("Process not found".to_string())
        }
    }

    /// 11.5 — Process Operations: wait
    /// In a real system this would block. Here it returns the exit code if Zombie.
    pub fn wait_process(&self, id: ProcessId) -> Result<Option<i32>, String> {
        let p = self.processes.get(&id).ok_or("Process not found")?;
        if p.state == ProcessState::Zombie {
            Ok(p.exit_code)
        } else {
            Ok(None) // Still running
        }
    }

    /// 11.5 — Process Operations: signal
    pub fn signal_process(&mut self, id: ProcessId, _signal: u32) -> Result<(), String> {
        // Conceptually sends a signal to the process.
        let p = self.processes.get_mut(&id).ok_or("Process not found")?;
        if p.state != ProcessState::Running {
            return Err("Cannot signal a zombie process".to_string());
        }
        Ok(())
    }

    /// 11.5 — Process Operations: inspect (listing)
    pub fn list_processes(&self) -> Vec<&Process> {
        let mut v: Vec<&Process> = self.processes.values().collect();
        v.sort_by_key(|p| p.id);
        v
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}
