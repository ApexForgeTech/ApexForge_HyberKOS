//! HyberKOS Process Manager
//! Phase 10 — Process & Thread Model
//!
//! Handle inheritance is available through `create_process_with_handles()`;
//! the simpler `create_process()` is intentionally used when no handle table
//! is in scope.
//!
//! FIX (Gap 5): Minimal Pipe support added here so processes can communicate
//!              via stdin/stdout before Phase 19 IPC arrives.
//!              Pipe objects are backed by in-memory byte buffers.

use hyber_core::{ObjectId, ObjectType, ProcessId, SecurityContext, ThreadId};
use hyber_handle::HandleManager;
use hyber_object::ObjectManager;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Process / Thread States ───────────────────────────────────────────────────

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

// ── FIX Gap 5: Minimal in-process Pipe ───────────────────────────────────────

/// A simple in-memory byte pipe connecting a writer end to a reader end.
/// This satisfies the Phase 10 requirement for stdin/stdout between processes
/// without pulling in full Phase 19 IPC channels.
#[derive(Debug)]
pub struct Pipe {
    pub id: ObjectId,
    pub buffer: Arc<Mutex<Vec<u8>>>,
    pub closed: bool,
}

impl Pipe {
    pub fn new(id: ObjectId) -> Self {
        Self {
            id,
            buffer: Arc::new(Mutex::new(Vec::new())),
            closed: false,
        }
    }

    /// Write bytes into the pipe buffer.
    pub fn write(&self, data: &[u8]) -> Result<usize, String> {
        let mut buf = self
            .buffer
            .lock()
            .map_err(|_| "Pipe buffer lock poisoned")?;
        buf.extend_from_slice(data);
        Ok(data.len())
    }

    /// Read up to `out.len()` bytes from the pipe buffer.
    pub fn read(&self, out: &mut [u8]) -> Result<usize, String> {
        let mut buf = self
            .buffer
            .lock()
            .map_err(|_| "Pipe buffer lock poisoned")?;
        let len = out.len().min(buf.len());
        out[..len].copy_from_slice(&buf[..len]);
        buf.drain(..len);
        Ok(len)
    }

    /// Returns true if there are bytes waiting to be read.
    pub fn has_data(&self) -> bool {
        self.buffer.lock().map(|b| !b.is_empty()).unwrap_or(false)
    }
}

// ── 11.2 — Thread Object ─────────────────────────────────────────────────────
pub struct Thread {
    pub id: ThreadId,
    pub process_id: ProcessId,
    pub state: ThreadState,
    pub object_id: ObjectId,
}

// ── 11.1 — Process Object ────────────────────────────────────────────────────
pub struct Process {
    pub id: ProcessId,
    pub parent_id: Option<ProcessId>,
    pub state: ProcessState,
    pub security_context: SecurityContext,
    /// 11.3 - Linux Process Provider internal mapping
    pub linux_pid: Option<u32>,
    pub object_id: ObjectId,
    pub threads: Vec<ThreadId>,
    pub exit_code: Option<i32>,

    // FIX Gap 5: Optional stdio pipe pair (read-end, write-end) as ObjectIds
    pub stdin_pipe: Option<ObjectId>,
    pub stdout_pipe: Option<ObjectId>,
}

// ── Process Manager ───────────────────────────────────────────────────────────
pub struct ProcessManager {
    processes: HashMap<ProcessId, Process>,
    threads: HashMap<ThreadId, Thread>,
    /// FIX Gap 5: Registered pipes keyed by their ObjectId
    pipes: HashMap<ObjectId, Pipe>,
    next_pid: u64,
    next_tid: u64,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            threads: HashMap::new(),
            pipes: HashMap::new(),
            next_pid: 1,
            next_tid: 1,
        }
    }

    // ── 11.5 — Process Operations: create ────────────────────────────────────

    /// Create a new process.
    ///
    /// FIX Gap 2: If `handle_mgr` is supplied and the process has a parent,
    /// inheritable handles are automatically cloned from parent → child.
    pub fn create_process(
        &mut self,
        obj_mgr: &mut ObjectManager,
        parent_id: Option<ProcessId>,
        security_context: SecurityContext,
        linux_pid: Option<u32>,
    ) -> Result<ProcessId, String> {
        self.create_process_with_handles(obj_mgr, parent_id, security_context, linux_pid, None)
    }

    /// Extended variant: optionally accepts a HandleManager to wire up handle
    /// inheritance from the parent process.
    pub fn create_process_with_handles(
        &mut self,
        obj_mgr: &mut ObjectManager,
        parent_id: Option<ProcessId>,
        security_context: SecurityContext,
        linux_pid: Option<u32>,
        handle_mgr: Option<&mut HandleManager>,
    ) -> Result<ProcessId, String> {
        if let Some(parent) = parent_id {
            let parent_process = self
                .processes
                .get(&parent)
                .ok_or("Parent process not found")?;
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

        // Set ownership from the security context
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
            stdin_pipe: None,
            stdout_pipe: None,
        };

        self.processes.insert(id, process);

        // FIX Gap 2: Inherit parent handles into the child
        if let (Some(parent), Some(hm)) = (parent_id, handle_mgr)
            && let Err(error) = hm.inherit_into_child(obj_mgr, parent, id)
        {
            self.processes.remove(&id);
            obj_mgr.release(obj_id);
            obj_mgr.destroy(obj_id);
            return Err(error);
        }

        // Every process starts with a primary thread
        self.create_thread(obj_mgr, id)?;
        Ok(id)
    }

    // ── FIX Gap 5: Pipe creation ──────────────────────────────────────────────

    /// Create a pipe and wire it as the stdout of `writer_pid` and the stdin
    /// of `reader_pid`.  Returns the ObjectId of the pipe.
    pub fn create_pipe(
        &mut self,
        obj_mgr: &mut ObjectManager,
        writer_pid: ProcessId,
        reader_pid: ProcessId,
    ) -> Result<ObjectId, String> {
        if !self.processes.contains_key(&writer_pid) {
            return Err(format!("Writer process {:?} not found", writer_pid));
        }
        if !self.processes.contains_key(&reader_pid) {
            return Err(format!("Reader process {:?} not found", reader_pid));
        }

        let pipe_obj_id = obj_mgr.create_object(ObjectType::Pipe);
        let pipe = Pipe::new(pipe_obj_id);
        self.pipes.insert(pipe_obj_id, pipe);

        self.processes.get_mut(&writer_pid).unwrap().stdout_pipe = Some(pipe_obj_id);
        self.processes.get_mut(&reader_pid).unwrap().stdin_pipe = Some(pipe_obj_id);

        Ok(pipe_obj_id)
    }

    /// Write to the stdout pipe of a process (if one is connected).
    pub fn write_stdout(&self, pid: ProcessId, data: &[u8]) -> Result<usize, String> {
        let proc = self
            .processes
            .get(&pid)
            .ok_or_else(|| format!("Process {:?} not found", pid))?;
        let pipe_id = proc.stdout_pipe.ok_or("Process has no stdout pipe")?;
        let pipe = self.pipes.get(&pipe_id).ok_or("Pipe object not found")?;
        pipe.write(data)
    }

    /// Read from the stdin pipe of a process (if one is connected).
    pub fn read_stdin(&self, pid: ProcessId, out: &mut [u8]) -> Result<usize, String> {
        let proc = self
            .processes
            .get(&pid)
            .ok_or_else(|| format!("Process {:?} not found", pid))?;
        let pipe_id = proc.stdin_pipe.ok_or("Process has no stdin pipe")?;
        let pipe = self.pipes.get(&pipe_id).ok_or("Pipe object not found")?;
        pipe.read(out)
    }

    // ── 11.2 — Thread creation ────────────────────────────────────────────────

    pub fn create_thread(
        &mut self,
        obj_mgr: &mut ObjectManager,
        process_id: ProcessId,
    ) -> Result<ThreadId, String> {
        let process = self.processes.get(&process_id).ok_or("Process not found")?;
        if !matches!(process.state, ProcessState::Created | ProcessState::Running) {
            return Err("Cannot create a thread in a terminated process".into());
        }
        let owner = process.security_context.user_id;
        let group = process.security_context.group_id;

        let tid = ThreadId(self.next_tid);
        self.next_tid = self
            .next_tid
            .checked_add(1)
            .ok_or("Thread identifier space exhausted")?;

        let obj_id = obj_mgr.create_object(ObjectType::Thread);
        if let Some(object) = obj_mgr.lookup_mut(obj_id) {
            object.owner = owner;
            object.group = group;
            object.permissions = 0o400;
        }
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

    // ── Getters ───────────────────────────────────────────────────────────────

    pub fn get_process(&self, id: ProcessId) -> Option<&Process> {
        self.processes.get(&id)
    }

    pub fn get_process_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.processes.get_mut(&id)
    }

    pub fn get_thread(&self, id: ThreadId) -> Option<&Thread> {
        self.threads.get(&id)
    }

    pub fn get_pipe(&self, id: ObjectId) -> Option<&Pipe> {
        self.pipes.get(&id)
    }

    // ── 11.5 — Process Operations: start ─────────────────────────────────────

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

    // ── 11.5 — Process Operations: stop (terminate) ───────────────────────────

    pub fn stop_process(&mut self, id: ProcessId, exit_code: i32) -> Result<(), String> {
        if let Some(p) = self.processes.get_mut(&id) {
            if p.state == ProcessState::Zombie {
                return Err("Process is already terminated".to_string());
            }
            p.state = ProcessState::Zombie;
            p.exit_code = Some(exit_code);
            // Terminate all threads
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

    // ── 11.5 — Process Operations: wait ──────────────────────────────────────

    /// In a real system this would block. Here it returns the exit code if Zombie.
    pub fn wait_process(&self, id: ProcessId) -> Result<Option<i32>, String> {
        let p = self.processes.get(&id).ok_or("Process not found")?;
        if p.state == ProcessState::Zombie {
            Ok(p.exit_code)
        } else {
            Ok(None) // Still running
        }
    }

    /// Reap an isolated hosted child after its backend has acknowledged exit.
    /// Shared pipes and externally retained objects require their own cleanup
    /// owner and are deliberately refused by this narrow operation.
    pub fn reap_isolated_process(
        &mut self,
        objects: &mut ObjectManager,
        id: ProcessId,
    ) -> Result<(), String> {
        let process = self.processes.get(&id).ok_or("Process not found")?;
        if process.state != ProcessState::Zombie
            || process.stdin_pipe.is_some()
            || process.stdout_pipe.is_some()
        {
            return Err("Process cannot be reaped".into());
        }
        let mut object_ids = vec![process.object_id];
        for tid in &process.threads {
            object_ids.push(self.threads.get(tid).ok_or("Thread missing")?.object_id);
        }
        if object_ids
            .iter()
            .any(|object| objects.lookup(*object).is_none_or(|o| o.references != 1))
        {
            return Err("Process objects are still referenced".into());
        }
        let process = self.processes.remove(&id).unwrap();
        for tid in process.threads {
            self.threads.remove(&tid);
        }
        for object in object_ids {
            objects.release(object);
            objects.destroy(object);
        }
        Ok(())
    }

    // ── 11.5 — Process Operations: signal ────────────────────────────────────

    pub fn signal_process(&mut self, id: ProcessId, _signal: u32) -> Result<(), String> {
        let p = self.processes.get_mut(&id).ok_or("Process not found")?;
        if p.state != ProcessState::Running {
            return Err("Cannot signal a zombie process".to_string());
        }
        Ok(())
    }

    // ── 11.5 — Process Operations: inspect (listing) ─────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use hyber_core::{ObjectType, SecurityContext};
    use hyber_handle::{HandleFlags, HandleManager};
    use hyber_object::ObjectManager;

    #[test]
    fn isolated_reaping_requires_exit_and_exclusive_ownership() {
        let mut objects = ObjectManager::new();
        let mut manager = ProcessManager::new();
        let pid = manager
            .create_process(&mut objects, None, SecurityContext::root(), None)
            .unwrap();
        let object = manager.get_process(pid).unwrap().object_id;
        assert!(manager.reap_isolated_process(&mut objects, pid).is_err());
        manager.start_process(pid).unwrap();
        manager.stop_process(pid, 0).unwrap();
        objects.retain(object);
        assert!(manager.reap_isolated_process(&mut objects, pid).is_err());
        assert!(manager.get_process(pid).is_some());
        objects.release(object);
        manager.reap_isolated_process(&mut objects, pid).unwrap();
        assert!(manager.get_process(pid).is_none());
        assert!(objects.lookup(object).is_none());
        let next = manager
            .create_process(&mut objects, None, SecurityContext::root(), None)
            .unwrap();
        assert_ne!(next, pid);
    }

    #[test]
    fn thread_objects_use_process_identity_and_reject_post_exit_creation() {
        let mut objects = ObjectManager::new();
        let mut manager = ProcessManager::new();
        let mut context = SecurityContext::root();
        context.user_id = hyber_core::UserId(42);
        context.group_id = hyber_core::GroupId(43);
        context.capabilities.clear();
        let pid = manager
            .create_process(&mut objects, None, context.clone(), None)
            .unwrap();
        let tid = manager.get_process(pid).unwrap().threads[0];
        let object = objects
            .lookup(manager.get_thread(tid).unwrap().object_id)
            .unwrap();
        assert_eq!(
            (object.owner, object.group, object.permissions),
            (context.user_id, context.group_id, 0o400)
        );
        manager.start_process(pid).unwrap();
        manager.stop_process(pid, 0).unwrap();
        assert!(manager.create_thread(&mut objects, pid).is_err());
    }

    #[test]
    fn pipe_connects_two_processes() {
        let mut obj_mgr = ObjectManager::new();
        let mut proc_mgr = ProcessManager::new();

        let writer = proc_mgr
            .create_process(&mut obj_mgr, None, SecurityContext::root(), None)
            .unwrap();
        let reader = proc_mgr
            .create_process(&mut obj_mgr, None, SecurityContext::root(), None)
            .unwrap();

        proc_mgr.create_pipe(&mut obj_mgr, writer, reader).unwrap();

        proc_mgr.write_stdout(writer, b"hello pipe").unwrap();
        let mut buf = [0u8; 16];
        let n = proc_mgr.read_stdin(reader, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello pipe");
    }

    #[test]
    fn handle_inheritance_on_child_creation() {
        let mut obj_mgr = ObjectManager::new();
        let mut proc_mgr = ProcessManager::new();
        let mut handle_mgr = HandleManager::new();

        let parent = proc_mgr
            .create_process(&mut obj_mgr, None, SecurityContext::root(), None)
            .unwrap();

        // Give parent an inheritable file handle
        let file_id = obj_mgr.create_object(ObjectType::File);
        handle_mgr
            .open_with_flags(
                &mut obj_mgr,
                parent,
                file_id,
                hyber_core::Rights::read_only(),
                "hostfs".into(),
                HandleFlags::default_inheritable(),
            )
            .unwrap();

        // Create child — should inherit the handle
        let child = proc_mgr
            .create_process_with_handles(
                &mut obj_mgr,
                Some(parent),
                SecurityContext::root(),
                None,
                Some(&mut handle_mgr),
            )
            .unwrap();

        assert_eq!(handle_mgr.list_handles(child).len(), 1);
    }
}
