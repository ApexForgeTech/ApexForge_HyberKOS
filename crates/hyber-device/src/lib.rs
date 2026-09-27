//! HyberKOS Device Provider
//! Phase 11 — Virtual /devices Namespace
//! 
//! DeviceProvider backs the /devices virtual directory.
//! Each registered device appears as a virtual object.
//! No Linux device files are exposed directly — 
//! all device access is mediated through the Hyber object model.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use hyber_core::{ObjectId, ObjectType};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::Provider;

/// The category of a device
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceClass {
    /// Block storage (disk, partition, etc.)
    Block,
    /// Character / stream device (serial, tty, etc.)
    Character,
    /// Virtual device (null, zero, random, etc.)
    Virtual,
    /// Network interface
    Network,
}

/// A registered device in the HyberKOS device table
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    /// Hyber-internal device identifier
    pub id: u64,
    /// Human-readable device name (e.g. "null", "zero", "random", "disk0")
    pub name: String,
    /// Class/category of device
    pub class: DeviceClass,
    /// Whether the device is currently available
    pub online: bool,
    /// Short description for introspection
    pub description: String,
    /// ObjectId assigned when this device was registered
    pub object_id: ObjectId,
}

/// Device Manager — owns device lifecycle
pub struct DeviceManager {
    devices: HashMap<u64, DeviceEntry>,
    next_id: u64,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn register_device(
        &mut self,
        obj_mgr: &mut ObjectManager,
        name: impl Into<String>,
        class: DeviceClass,
        description: impl Into<String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let object_id = obj_mgr.create_object(ObjectType::Device);
        let entry = DeviceEntry {
            id,
            name: name.into(),
            class,
            online: true,
            description: description.into(),
            object_id,
        };
        self.devices.insert(id, entry);
        id
    }

    pub fn list_devices(&self) -> Vec<&DeviceEntry> {
        let mut v: Vec<&DeviceEntry> = self.devices.values().collect();
        v.sort_by_key(|d| d.id);
        v
    }

    pub fn get_device_by_name(&self, name: &str) -> Option<&DeviceEntry> {
        self.devices.values().find(|d| d.name == name)
    }

    pub fn get_device_by_object(&self, oid: ObjectId) -> Option<&DeviceEntry> {
        self.devices.values().find(|d| d.object_id == oid)
    }

    pub fn set_online(&mut self, id: u64, online: bool) {
        if let Some(d) = self.devices.get_mut(&id) {
            d.online = online;
        }
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// DeviceProvider — backs the /devices virtual namespace
pub struct DeviceProvider {
    pub device_mgr: Arc<Mutex<DeviceManager>>,
}

impl DeviceProvider {
    pub fn new(device_mgr: Arc<Mutex<DeviceManager>>) -> Self {
        Self { device_mgr }
    }
}

impl Provider for DeviceProvider {
    fn create(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _parent_id: ObjectId,
        _name: &str,
        _obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        Err("/devices is read-only. Register devices through DeviceManager.".to_string())
    }

    fn remove(
        &mut self,
        _obj_mgr: &mut ObjectManager,
        _ns_mgr: &mut NamespaceManager,
        _parent_id: ObjectId,
        _name: &str,
    ) -> Result<(), String> {
        Err("/devices entries cannot be removed through the VFS directly.".to_string())
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
        Err("/devices entries cannot be renamed.".to_string())
    }

    fn read(&self, object_id: ObjectId, _offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        let mgr = self.device_mgr.lock().map_err(|_| "DeviceManager lock poisoned")?;
        let dev = mgr
            .get_device_by_object(object_id)
            .ok_or("Device not found for this ObjectId")?;

        // Virtual "null" device: always returns zeros
        if dev.name == "null" {
            for b in buffer.iter_mut() { *b = 0; }
            return Ok(buffer.len());
        }

        // Virtual "zero" device: returns zeros
        if dev.name == "zero" {
            for b in buffer.iter_mut() { *b = 0; }
            return Ok(buffer.len());
        }

        // Virtual "random" device: returns pseudo-random bytes
        if dev.name == "random" {
            // Simple LCG-based pseudo-random (no external deps)
            let mut seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            for b in buffer.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *b = ((seed >> 33) & 0xFF) as u8;
            }
            return Ok(buffer.len());
        }

        // Generic device: return a human-readable info string
        let info = format!(
            "Device: {}\nClass: {:?}\nOnline: {}\nDescription: {}\n",
            dev.name, dev.class, dev.online, dev.description
        );
        let bytes = info.as_bytes();
        let len = buffer.len().min(bytes.len());
        buffer[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn write(&mut self, object_id: ObjectId, _offset: u64, buffer: &[u8]) -> Result<usize, String> {
        let mgr = self.device_mgr.lock().map_err(|_| "DeviceManager lock poisoned")?;
        let dev = mgr
            .get_device_by_object(object_id)
            .ok_or("Device not found for this ObjectId")?;

        // "null" device: accepts all writes, discards data (like /dev/null)
        if dev.name == "null" {
            return Ok(buffer.len());
        }

        Err(format!("Device '{}' does not support writes through VFS", dev.name))
    }

    fn enumerate(&self, _dir_id: ObjectId) -> Result<Vec<(String, ObjectId)>, String> {
        let mgr = self.device_mgr.lock().map_err(|_| "DeviceManager lock poisoned")?;
        let entries = mgr
            .list_devices()
            .into_iter()
            .map(|d| (d.name.clone(), d.object_id))
            .collect();
        Ok(entries)
    }
}
