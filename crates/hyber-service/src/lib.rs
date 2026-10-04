//! HyberKOS Service Provider
//! Phase 11 — Virtual /services Namespace
//!
//! ServiceProvider backs the /services virtual directory.
//! Each registered service (background task / daemon-like entity)
//! appears as a virtual object under /services/<name>.
//! Services are HyberKOS-native; no Linux systemd/init is exposed.

use hyber_core::{ObjectId, ObjectType, ProcessId};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::Provider;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod session_tests;

/// The lifecycle state of a service
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is defined but not started
    Stopped,
    /// Service is actively running
    Running,
    /// Service encountered an error and halted
    Failed,
    /// Service was disabled (will not auto-start)
    Disabled,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::Stopped => write!(f, "stopped"),
            ServiceState::Running => write!(f, "running"),
            ServiceState::Failed => write!(f, "failed"),
            ServiceState::Disabled => write!(f, "disabled"),
        }
    }
}

/// A registered service entry
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    session: Option<hyber_auth::SessionGuard>,
    /// Unique numeric service ID
    pub id: u64,
    /// Human-readable service name (e.g. "logger", "netstack", "scheduler")
    pub name: String,
    /// Current state
    pub state: ServiceState,
    /// Short description
    pub description: String,
    /// Optional ProcessId if the service has a corresponding process
    pub process_id: Option<ProcessId>,
    /// ObjectId assigned to this service in the object model
    pub object_id: ObjectId,
}

/// Service Manager — owns service lifecycle
pub struct ServiceManager {
    services: HashMap<u64, ServiceEntry>,
    next_id: u64,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn register_service(
        &mut self,
        obj_mgr: &mut ObjectManager,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let object_id = obj_mgr.create_object(ObjectType::Service);
        let entry = ServiceEntry {
            session: None,
            id,
            name: name.into(),
            state: ServiceState::Stopped,
            description: description.into(),
            process_id: None,
            object_id,
        };
        self.services.insert(id, entry);
        id
    }

    pub fn start_service(&mut self, id: u64, process_id: Option<ProcessId>) -> Result<(), String> {
        let svc = self
            .services
            .get_mut(&id)
            .ok_or_else(|| format!("Service {} not found", id))?;
        if svc.state == ServiceState::Disabled {
            return Err(format!("Service '{}' is disabled", svc.name));
        }
        if svc.state == ServiceState::Running {
            return Err("service already running".into());
        }
        svc.state = ServiceState::Running;
        svc.process_id = process_id;
        Ok(())
    }

    pub fn stop_service(&mut self, id: u64) -> Result<(), String> {
        let svc = self
            .services
            .get_mut(&id)
            .ok_or_else(|| format!("Service {} not found", id))?;
        if let Some(session) = svc.session.take() {
            let _ = session.logout();
        }
        if svc.state != ServiceState::Disabled {
            svc.state = ServiceState::Stopped;
        }
        svc.process_id = None;
        Ok(())
    }

    pub fn mark_failed(&mut self, id: u64) -> Result<(), String> {
        let svc = self
            .services
            .get_mut(&id)
            .ok_or_else(|| format!("Service {} not found", id))?;
        if let Some(session) = svc.session.take() {
            let _ = session.logout();
        }
        svc.process_id = None;
        if svc.state != ServiceState::Disabled {
            svc.state = ServiceState::Failed;
        }
        Ok(())
    }

    pub fn disable_service(&mut self, id: u64) -> Result<(), String> {
        let svc = self
            .services
            .get_mut(&id)
            .ok_or_else(|| format!("Service {} not found", id))?;
        if let Some(session) = svc.session.take() {
            let _ = session.logout();
        }
        svc.state = ServiceState::Disabled;
        svc.process_id = None;
        Ok(())
    }

    pub fn list_services(&self) -> Vec<&ServiceEntry> {
        let mut v: Vec<&ServiceEntry> = self.services.values().collect();
        v.sort_by_key(|s| s.id);
        v
    }

    /// A service has its own session, independent of any GUI/client session.
    pub fn start_authenticated(
        &mut self,
        objects: &mut ObjectManager,
        id: u64,
        process_id: Option<ProcessId>,
        session: hyber_auth::SessionGuard,
    ) -> Result<(), String> {
        if session.kind().map_err(|e| e.to_string())? != hyber_auth::SessionKind::Service {
            return Err("service session required".into());
        }
        let context = session.context().map_err(|e| e.to_string())?;
        let object_id = self.services.get(&id).ok_or("service not found")?.object_id;
        if objects.lookup(object_id).is_none() {
            return Err("service object missing".into());
        }
        if self
            .services
            .get(&id)
            .is_some_and(|s| s.state == ServiceState::Running)
        {
            return Err("service already running".into());
        }
        self.start_service(id, process_id)?;
        let object = objects.lookup_mut(object_id).unwrap();
        object.owner = context.user_id;
        object.group = context.group_id;
        object.permissions = 0o400;
        self.services.get_mut(&id).unwrap().session = Some(session);
        Ok(())
    }

    /// Call at every authenticated service dispatch, never cache the result.
    pub fn session_context(&self, id: u64) -> Result<hyber_core::SecurityContext, String> {
        let service = self.services.get(&id).ok_or("service not found")?;
        if service.state != ServiceState::Running {
            return Err("service not running".into());
        }
        service
            .session
            .as_ref()
            .ok_or("service has no authenticated session")?
            .context()
            .map_err(|e| e.to_string())
    }

    pub fn get_service_by_name(&self, name: &str) -> Option<&ServiceEntry> {
        self.services.values().find(|s| s.name == name)
    }

    pub fn get_service_by_object(&self, oid: ObjectId) -> Option<&ServiceEntry> {
        self.services.values().find(|s| s.object_id == oid)
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// ServiceProvider — backs the /services virtual namespace
pub struct ServiceProvider {
    pub service_mgr: Arc<Mutex<ServiceManager>>,
}

impl ServiceProvider {
    pub fn new(service_mgr: Arc<Mutex<ServiceManager>>) -> Self {
        Self { service_mgr }
    }
}

impl Provider for ServiceProvider {
    fn create(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _parent_id: ObjectId,
        _name: &str,
        _obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        Err("/services is read-only. Register services through ServiceManager.".to_string())
    }

    fn remove(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _parent_id: ObjectId,
        _name: &str,
    ) -> Result<(), String> {
        Err("/services entries cannot be removed through the VFS directly.".to_string())
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
        Err("/services entries cannot be renamed.".to_string())
    }

    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        let mgr = self
            .service_mgr
            .lock()
            .map_err(|_| "ServiceManager lock poisoned")?;
        let svc = mgr
            .get_service_by_object(object_id)
            .ok_or("Service not found for this ObjectId")?;

        let info = format!(
            "Service: {}\nState: {}\nPID: {}\nDescription: {}\n",
            svc.name,
            svc.state,
            svc.process_id
                .map(|p| p.0.to_string())
                .unwrap_or_else(|| "-".to_string()),
            svc.description,
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
        Err("/services objects are read-only through VFS.".to_string())
    }

    fn enumerate(&self, _dir_id: ObjectId) -> Result<Option<Vec<(String, ObjectId)>>, String> {
        let mgr = self
            .service_mgr
            .lock()
            .map_err(|_| "ServiceManager lock poisoned")?;
        let entries = mgr
            .list_services()
            .into_iter()
            .map(|s| (s.name.clone(), s.object_id))
            .collect();
        Ok(Some(entries))
    }
}
