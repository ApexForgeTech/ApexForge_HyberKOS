//! HyberKOS Object Manager
//! Phase 2 — Object Registry & Lifecycle
use std::collections::HashMap;
use hyber_core::{
    ObjectType,
    ObjectId,
    ObjectState,
    MetadataValue,
    UserId,
    GroupId,
};
use std::time::{SystemTime, UNIX_EPOCH};

//3.8 Object Traits
pub trait Readable {}
pub trait Writable {}
pub trait Seekable {}
pub trait Enumerable {}
pub trait Connectable {}
pub trait Waitable {}
pub trait Signalable {}

//Basic Object Structure
#[derive(Debug, Clone)]
pub struct Object {
    pub id: ObjectId,
    pub object_type: ObjectType,
    pub state: ObjectState,
    pub references: u64,

    // Core Metadata (Phase 8 & 9)
    pub owner: UserId,
    pub group: GroupId,
    pub permissions: u32,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub flags: u32,

    // Extended Metadata (Phase 8)
    pub extended_metadata: HashMap<String, MetadataValue>,
}

impl Object {
    pub fn new(id: ObjectId, object_type: ObjectType) -> Self {
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Default permissions based on ObjectType could be set here.
        // For now, we use a default mock value (e.g., 0o644 for files, 0o755 for dirs)
        let permissions = if object_type == ObjectType::Directory { 0o755 } else { 0o644 };

        Self {
            id,
            object_type,
            state: ObjectState::Live,
            references: 1, // Initial reference count is 1
            owner: UserId(0),      // Default owner (root)
            group: GroupId(0),      // Default group (root)
            permissions,
            size: 0,       // Default size
            created_at: now,
            modified_at: now,
            flags: 0, // Default flags
            extended_metadata: HashMap::new(),
        }
    }
}

/// Object Manager — owns the lifecycle of all Objects
pub struct ObjectManager {
    objects: HashMap<ObjectId, Object>,
    next_id: u64,
}

impl ObjectManager {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            next_id: 1, 
        }
    }

// Create a new object and return its ID
    pub fn create_object(&mut self, object_type: ObjectType) -> ObjectId {
        let id = ObjectId(self.next_id);
        self.next_id += 1;

        let object = Object::new(id, object_type);
        self.objects.insert(id, object);

        id
    }

    //Look up an object by its ID
   pub fn lookup(&self, id: ObjectId) -> Option<&Object> {
        self.objects.get(&id)
    }

   // Look up a mutable reference to an object by its ID
    pub fn lookup_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    //3.5 Object References
    pub fn retain(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.state == ObjectState::Live {
                obj.references += 1;
                return true;
            }
        }
        false
    }

    pub fn release(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.references > 0 {
                obj.references -= 1;
            }
            
            if obj.references == 0 {
                obj.state = ObjectState::Destroyed;
                return true; // Object is now destroyed
            }
        }
        false
    }

    // 3.6 Object Destruction
    pub fn destroy(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get(&id) {
            if obj.state == ObjectState::Destroyed || obj.references == 0 {
                self.objects.remove(&id);
                return true;
            }
        }
        false
    }

    // 9.3 Metadata API

    /// Get a specific extended metadata value
    pub fn get_metadata(&self, id: ObjectId, key: &str) -> Option<&MetadataValue> {
        self.objects.get(&id)?.extended_metadata.get(key)
    }

    /// Set a specific extended metadata value
    pub fn set_metadata(&mut self, id: ObjectId, key: &str, value: MetadataValue) -> Result<(), String> {
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        obj.extended_metadata.insert(key.to_string(), value);
        // Update modified_at timestamp when metadata changes
        obj.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(())
    }

    /// Remove a specific extended metadata value
    pub fn remove_metadata(&mut self, id: ObjectId, key: &str) -> Result<bool, String> {
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        let removed = obj.extended_metadata.remove(key).is_some();
        if removed {
            obj.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        Ok(removed)
    }

    /// List all extended metadata keys and values
    pub fn list_metadata(&self, id: ObjectId) -> Option<Vec<(String, MetadataValue)>> {
        self.objects.get(&id).map(|obj| {
            obj.extended_metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
    }
}
impl Default for ObjectManager {
        fn default() -> Self {
            Self::new()
        }
}
