//! HyberKOS Object Manager
//! Phase 2 — Object Registry & Lifecycle
use std::collections::HashMap;
use hyber_core::{
    ObjectType,
    ObjectId,
    ObjectState
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

    //3.7 Object Metadata
    pub created_at: u64,
    pub modified_at: u64,
    pub flags: u32, // Special flags for object behavior(For Example:2= Read-Only, 1=Hidden, System Object, etc.)
}

impl Object {
    pub fn new(id: ObjectId, object_type: ObjectType) -> Self {
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Self {
            id,
            object_type,
            state: ObjectState::Live,
            references: 1, // Initial reference count is 1
            created_at: now,
            modified_at: now,
            flags: 0, // Default flags
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


    
}
impl Default for ObjectManager {
        fn default() -> Self {
            Self::new()
        }
}
