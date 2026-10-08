//! Read-only VFS projection. The caller owns creation and namespace linkage of
//! root/service objects and assigns their access-control metadata before mount.
use crate::supervisor::ServiceSupervisor;
use hyber_core::{ObjectId, ObjectType};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_service_contract::ServiceId;
use hyber_vfs::Provider;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// No lifecycle authority is obtained by opening a status projection.
pub fn check_projection_rights(rights: hyber_core::Rights) -> Result<(), String> {
    if rights.write
        || rights.execute
        || rights.delete
        || rights.rename
        || rights.connect
        || rights.wait
        || rights.signal
    {
        return Err("service projection supports only read/enumerate rights".into());
    }
    Ok(())
}

pub struct SupervisorProvider {
    supervisor: Arc<Mutex<ServiceSupervisor>>,
    root: ObjectId,
    objects: BTreeMap<ServiceId, ObjectId>,
}
impl SupervisorProvider {
    pub fn new(
        supervisor: Arc<Mutex<ServiceSupervisor>>,
        root: ObjectId,
        objects: BTreeMap<ServiceId, ObjectId>,
    ) -> Result<Self, String> {
        {
            let manager = supervisor.lock().map_err(|_| "supervisor unavailable")?;
            if !manager.services().map(|(id, _)| id).eq(objects.keys()) {
                return Err("projection must cover the registered catalog exactly".into());
            }
            let ids: BTreeSet<_> = objects.values().copied().collect();
            if ids.len() != objects.len() || ids.contains(&root) {
                return Err("duplicate projection object identity".into());
            }
        }
        Ok(Self {
            supervisor,
            root,
            objects,
        })
    }
}
impl Provider for SupervisorProvider {
    fn check_open(&self, object: ObjectId, rights: hyber_core::Rights) -> Result<(), String> {
        check_projection_rights(rights)?;
        if object == self.root {
            if rights.read {
                return Err("cannot read service directory as a file".into());
            }
        } else if !self.objects.values().any(|id| *id == object) || rights.enumerate {
            return Err("invalid service projection object or operation".into());
        }
        Ok(())
    }
    fn persist_metadata(&mut self, _: &hyber_object::Object) -> Result<(), String> {
        Err("service projection metadata is authority-owned".into())
    }
    fn create(
        &mut self,
        _: &mut ObjectManager,
        _: &mut NamespaceManager,
        _: ObjectId,
        _: &str,
        _: ObjectType,
    ) -> Result<ObjectId, String> {
        Err("services are read-only".into())
    }
    fn remove(
        &mut self,
        _: &mut ObjectManager,
        _: &mut NamespaceManager,
        _: ObjectId,
        _: &str,
    ) -> Result<(), String> {
        Err("services are read-only".into())
    }
    fn rename(
        &mut self,
        _: &mut ObjectManager,
        _: &mut NamespaceManager,
        _: ObjectId,
        _: &str,
        _: ObjectId,
        _: &str,
    ) -> Result<(), String> {
        Err("services are read-only".into())
    }
    fn write(&mut self, _: ObjectId, _: u64, _: &[u8]) -> Result<usize, String> {
        Err("services are read-only".into())
    }
    fn read(&self, object: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        let id = self
            .objects
            .iter()
            .find(|(_, value)| **value == object)
            .map(|(id, _)| id)
            .ok_or("unknown service object")?;
        let text = self
            .supervisor
            .lock()
            .map_err(|_| "supervisor unavailable")?
            .status_text(id)
            .map_err(|e| e.to_string())?;
        let offset = usize::try_from(offset).map_err(|_| "offset overflow")?;
        let bytes = text.as_bytes().get(offset..).unwrap_or_default();
        let length = buffer.len().min(bytes.len());
        buffer[..length].copy_from_slice(&bytes[..length]);
        Ok(length)
    }
    fn enumerate(&self, directory: ObjectId) -> Result<Option<Vec<(String, ObjectId)>>, String> {
        if directory != self.root {
            return Err("not the services directory".into());
        }
        let manager = self
            .supervisor
            .lock()
            .map_err(|_| "supervisor unavailable")?;
        if !manager.services().map(|(id, _)| id).eq(self.objects.keys()) {
            return Err("service catalog changed; rebuild the namespace projection".into());
        }
        Ok(Some(
            self.objects
                .iter()
                .map(|(id, object)| (id.0.clone(), *object))
                .collect(),
        ))
    }
}
