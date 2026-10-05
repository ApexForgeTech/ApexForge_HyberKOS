//! HyberKOS Object Manager
//! Phase 2 — Object Registry & Lifecycle
//!
//! FIX (Gap 1): Strong/Weak reference model added to prevent circular-reference
//! memory leaks.  Only strong references keep an Object alive; weak references
//! can observe it without preventing destruction.

use hyber_core::{GroupId, MetadataValue, ObjectId, ObjectState, ObjectType, UserId};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── 3.8 Object Traits ────────────────────────────────────────────────────────
pub trait Readable {}
pub trait Writable {}
pub trait Seekable {}
pub trait Enumerable {}
pub trait Connectable {}
pub trait Waitable {}
pub trait Signalable {}

// ── Basic Object Structure ────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Object {
    pub id: ObjectId,
    pub object_type: ObjectType,
    pub state: ObjectState,

    /// Strong references — keep the object alive.
    /// Incremented by `retain()`, decremented by `release()`.
    pub references: u64,

    /// Weak references — may observe the object but do NOT keep it alive.
    /// Incremented by `retain_weak()`, decremented by `release_weak()`.
    /// An Object with references == 0 is destroyed regardless of weak_references.
    pub weak_references: u64,

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
            .unwrap_or_default()
            .as_secs();

        let permissions = if object_type == ObjectType::Directory {
            0o755
        } else {
            0o644
        };

        Self {
            id,
            object_type,
            state: ObjectState::Live,
            references: 1, // Initial strong reference count is 1
            weak_references: 0,
            owner: UserId(0),
            group: GroupId(0),
            permissions,
            size: 0,
            created_at: now,
            modified_at: now,
            flags: 0,
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
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("ObjectId space exhausted");

        let object = Object::new(id, object_type);
        self.objects.insert(id, object);

        id
    }

    // Look up an object by its ID
    pub fn lookup(&self, id: ObjectId) -> Option<&Object> {
        self.objects.get(&id)
    }

    // Look up a mutable reference to an object by its ID
    pub fn lookup_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    // ── 3.5 Strong Reference Operations ──────────────────────────────────────

    /// Increment the strong reference count of an object.
    /// Returns false if the object is already destroyed / does not exist.
    pub fn retain(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.state == ObjectState::Live && obj.references > 0 {
                let Some(next) = obj.references.checked_add(1) else {
                    return false;
                };
                obj.references = next;
                return true;
            }
        }
        false
    }

    /// Decrement the strong reference count.
    /// When it reaches 0 the object is marked Destroyed (but not removed from
    /// the registry yet — call `destroy()` to actually free it).
    /// Returns true when the object transitions to Destroyed.
    pub fn release(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.references == 0 {
                return false;
            }
            obj.references -= 1;

            if obj.references == 0 {
                obj.state = ObjectState::Destroyed;
                return true; // Object is now ready for destruction
            }
        }
        false
    }

    // ── FIX Gap 1: Weak Reference Operations ─────────────────────────────────

    /// Increment the weak reference count.
    /// Returns false if the object does not exist.
    pub fn retain_weak(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get_mut(&id) {
            let Some(next) = obj.weak_references.checked_add(1) else {
                return false;
            };
            obj.weak_references = next;
            return true;
        }
        false
    }

    /// Decrement the weak reference count.
    /// This never destroys the object — that is the role of `release()`.
    pub fn release_weak(&mut self, id: ObjectId) {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.weak_references > 0 {
                obj.weak_references -= 1;
            }
        }
    }

    /// Upgrade a weak reference to a strong reference.
    /// Returns the ObjectId if the object is still Live, or None if it has been
    /// destroyed (i.e., `references == 0`).
    pub fn upgrade_weak(&mut self, id: ObjectId) -> Option<ObjectId> {
        if let Some(obj) = self.objects.get_mut(&id) {
            if obj.state == ObjectState::Live && obj.references > 0 {
                obj.references = obj.references.checked_add(1)?;
                return Some(id);
            }
        }
        None
    }

    // ── 3.6 Object Destruction ────────────────────────────────────────────────

    /// Permanently remove a destroyed object from the registry.
    /// Only succeeds when both `references == 0` and state == Destroyed.
    /// Weak references are tolerated — they simply become dangling observations.
    pub fn destroy(&mut self, id: ObjectId) -> bool {
        if let Some(obj) = self.objects.get(&id) {
            if obj.state == ObjectState::Destroyed && obj.references == 0 {
                self.objects.remove(&id);
                return true;
            }
        }
        false
    }

    // ── 9.3 Metadata API ─────────────────────────────────────────────────────

    /// Change basic mode bits. Write access to content does not grant the
    /// ability to change its access policy: only the owner or an admin may.
    pub fn chmod(
        &mut self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        mode: u32,
    ) -> Result<(), String> {
        if mode & !0o777 != 0 {
            return Err("Only owner/group/other rwx bits are supported".into());
        }
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        if obj.state != ObjectState::Live {
            return Err("Object is not live".into());
        }
        if context.user_id != obj.owner {
            hyber_core::SecurityManager::check_capability(context, "CAP_SYS_ADMIN")?;
        }
        obj.permissions = mode;
        obj.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(())
    }

    /// A non-admin owner may assign only one of their own Hyber groups.
    /// Administrative callers must resolve the target against the registry.
    pub fn chgrp(
        &mut self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        group: GroupId,
    ) -> Result<(), String> {
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        if obj.state != ObjectState::Live {
            return Err("Object is not live".into());
        }
        let admin = hyber_core::SecurityManager::check_capability(context, "CAP_SYS_ADMIN").is_ok();
        if !admin
            && (context.user_id != obj.owner
                || (group != context.group_id && !context.supplementary_groups.contains(&group)))
        {
            return Err("Only the owner may select one of their groups".into());
        }
        obj.group = group;
        obj.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(())
    }

    /// Transfer object ownership.  Unlike `chgrp`, ownership changes are
    /// administrative operations: a normal owner must not be able to hand an
    /// object to another account and thereby bypass quota/audit policy.
    pub fn chown(
        &mut self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        owner: UserId,
    ) -> Result<(), String> {
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        if obj.state != ObjectState::Live {
            return Err("Object is not live".into());
        }
        hyber_core::SecurityManager::check_capability(context, "CAP_SYS_ADMIN")?;
        obj.owner = owner;
        obj.modified_at = now_secs();
        Ok(())
    }

    /// Get a specific extended metadata value
    pub fn get_metadata(&self, id: ObjectId, key: &str) -> Option<&MetadataValue> {
        let object = self.objects.get(&id)?;
        (object.state == ObjectState::Live)
            .then_some(object)
            .and_then(|object| object.extended_metadata.get(key))
    }

    /// Set a specific extended metadata value
    pub fn set_metadata(
        &mut self,
        id: ObjectId,
        key: &str,
        value: MetadataValue,
    ) -> Result<(), String> {
        Self::validate_metadata_key(key)?;
        Self::validate_metadata_value(&value, 0)?;
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        if obj.state != ObjectState::Live {
            return Err("Object is not live".into());
        }
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
        Self::validate_metadata_key(key)?;
        let obj = self.objects.get_mut(&id).ok_or("Object not found")?;
        if obj.state != ObjectState::Live {
            return Err("Object is not live".into());
        }
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
        self.objects
            .get(&id)
            .filter(|object| object.state == ObjectState::Live)
            .map(|obj| {
                obj.extended_metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
    }

    /// Read metadata through the common Hyber access policy.  The unguarded
    /// metadata helpers above remain for trusted manager/provider internals;
    /// shells and language runtimes must use these checked entry points.
    pub fn get_metadata_secure(
        &self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        key: &str,
    ) -> Result<Option<&MetadataValue>, String> {
        self.check_metadata_access(id, context, hyber_core::Rights::read_only())?;
        Ok(self.get_metadata(id, key))
    }

    pub fn list_metadata_secure(
        &self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
    ) -> Result<Vec<(String, MetadataValue)>, String> {
        self.check_metadata_access(id, context, hyber_core::Rights::read_only())?;
        Ok(self.list_metadata(id).unwrap_or_default())
    }

    pub fn set_metadata_secure(
        &mut self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        key: &str,
        value: MetadataValue,
    ) -> Result<(), String> {
        self.check_metadata_access(
            id,
            context,
            hyber_core::Rights {
                write: true,
                ..hyber_core::Rights::empty()
            },
        )?;
        self.set_metadata(id, key, value)
    }

    pub fn remove_metadata_secure(
        &mut self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        key: &str,
    ) -> Result<bool, String> {
        self.check_metadata_access(
            id,
            context,
            hyber_core::Rights {
                write: true,
                ..hyber_core::Rights::empty()
            },
        )?;
        self.remove_metadata(id, key)
    }

    fn check_metadata_access(
        &self,
        id: ObjectId,
        context: &hyber_core::SecurityContext,
        rights: hyber_core::Rights,
    ) -> Result<(), String> {
        let object = self.objects.get(&id).ok_or("Object not found")?;
        if object.state != ObjectState::Live {
            return Err("Object is not live".into());
        }
        hyber_core::SecurityManager::check_access(
            context,
            object.owner,
            object.group,
            object.permissions,
            rights,
        )
    }

    /// Validate persisted metadata using the same rules as runtime mutations.
    pub fn validate_metadata_entry(key: &str, value: &MetadataValue) -> Result<(), String> {
        Self::validate_metadata_key(key)?;
        Self::validate_metadata_value(value, 0)
    }

    fn validate_metadata_key(key: &str) -> Result<(), String> {
        let (namespace, name) = key
            .split_once('.')
            .ok_or("Metadata keys must use the 'namespace.name' form")?;
        if namespace.is_empty()
            || name.is_empty()
            || key.split('.').any(str::is_empty)
            || key.len() > 255
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err("Invalid metadata key".to_string());
        }
        Ok(())
    }

    fn validate_metadata_value(value: &MetadataValue, depth: usize) -> Result<(), String> {
        const MAX_VALUE_BYTES: usize = 64 * 1024;
        const MAX_LIST_DEPTH: usize = 16;
        const MAX_LIST_ITEMS: usize = 1024;

        match value {
            MetadataValue::String(value) if value.len() > MAX_VALUE_BYTES => {
                Err("Metadata string value is too large".into())
            }
            MetadataValue::Bytes(value) if value.len() > MAX_VALUE_BYTES => {
                Err("Metadata byte value is too large".into())
            }
            MetadataValue::List(values) => {
                if depth >= MAX_LIST_DEPTH {
                    return Err("Metadata list nesting is too deep".into());
                }
                if values.len() > MAX_LIST_ITEMS {
                    return Err("Metadata list has too many items".into());
                }
                for value in values {
                    Self::validate_metadata_value(value, depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Default for ObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use hyber_core::ObjectType;

    #[test]
    fn reference_overflow_and_inconsistent_destruction_are_rejected() {
        let mut mgr = ObjectManager::new();
        let id = mgr.create_object(ObjectType::File);
        mgr.lookup_mut(id).unwrap().references = u64::MAX;
        assert!(!mgr.retain(id));
        assert!(mgr.upgrade_weak(id).is_none());
        assert_eq!(mgr.lookup(id).unwrap().references, u64::MAX);
        mgr.lookup_mut(id).unwrap().state = ObjectState::Destroyed;
        assert!(!mgr.destroy(id));
        mgr.lookup_mut(id).unwrap().references = 1;
        assert!(mgr.release(id));
        assert!(!mgr.release(id));
        assert!(mgr.destroy(id));
    }

    #[test]
    fn permission_changes_require_ownership_and_group_membership() {
        let mut mgr = ObjectManager::new();
        let id = mgr.create_object(ObjectType::File);
        mgr.lookup_mut(id).unwrap().owner = UserId(1000);
        let mut user = hyber_core::SecurityContext {
            user_id: UserId(1001),
            group_id: GroupId(1001),
            supplementary_groups: vec![GroupId(2000)],
            capabilities: vec![],
        };
        assert!(mgr.chmod(id, &user, 0o777).is_err());
        assert!(mgr.chgrp(id, &user, GroupId(2000)).is_err());
        user.user_id = UserId(1000);
        assert!(mgr.chmod(id, &user, 0o4755).is_err());
        mgr.chmod(id, &user, 0o640).unwrap();
        assert!(mgr.chgrp(id, &user, GroupId(0)).is_err());
        mgr.chgrp(id, &user, GroupId(2000)).unwrap();
        assert_eq!(mgr.lookup(id).unwrap().permissions, 0o640);
        assert_eq!(mgr.lookup(id).unwrap().group, GroupId(2000));
        assert!(mgr.chown(id, &user, UserId(2001)).is_err());
        let mut admin = user.clone();
        admin.capabilities.push(hyber_core::Capability {
            name: "CAP_SYS_ADMIN".into(),
        });
        mgr.chown(id, &admin, UserId(2001)).unwrap();
        assert_eq!(mgr.lookup(id).unwrap().owner, UserId(2001));
        for key in [".name", "user.", "user..name"] {
            assert!(mgr
                .set_metadata(id, key, MetadataValue::Boolean(true))
                .is_err());
        }
    }

    #[test]
    fn metadata_is_bounded_and_checked_against_object_permissions() {
        let mut mgr = ObjectManager::new();
        let id = mgr.create_object(ObjectType::File);
        {
            let object = mgr.lookup_mut(id).unwrap();
            object.owner = UserId(1000);
            object.group = GroupId(1000);
            object.permissions = 0o600;
        }
        let owner = hyber_core::SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        let other = hyber_core::SecurityContext {
            user_id: UserId(1001),
            group_id: GroupId(1001),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        assert!(mgr
            .set_metadata_secure(
                id,
                &other,
                "user.label",
                MetadataValue::String("denied".into()),
            )
            .is_err());
        mgr.set_metadata_secure(
            id,
            &owner,
            "user.label",
            MetadataValue::String("allowed".into()),
        )
        .unwrap();
        assert_eq!(
            mgr.get_metadata_secure(id, &owner, "user.label").unwrap(),
            Some(&MetadataValue::String("allowed".into()))
        );
        assert!(mgr
            .set_metadata(
                id,
                "user.large",
                MetadataValue::Bytes(vec![0; 64 * 1024 + 1]),
            )
            .is_err());
    }

    #[test]
    fn strong_ref_lifecycle() {
        let mut mgr = ObjectManager::new();
        let id = mgr.create_object(ObjectType::File);
        // Initial ref count = 1
        assert_eq!(mgr.lookup(id).unwrap().references, 1);
        mgr.retain(id);
        assert_eq!(mgr.lookup(id).unwrap().references, 2);
        mgr.release(id);
        assert_eq!(mgr.lookup(id).unwrap().references, 1);
        mgr.release(id);
        // Object should be destroyed now
        assert_eq!(mgr.lookup(id).unwrap().state, ObjectState::Destroyed);
    }

    #[test]
    fn weak_ref_does_not_keep_object_alive() {
        let mut mgr = ObjectManager::new();
        let id = mgr.create_object(ObjectType::File);
        // Add a weak reference
        mgr.retain_weak(id);
        assert_eq!(mgr.lookup(id).unwrap().weak_references, 1);
        // Drop the strong reference
        mgr.release(id);
        // Object is Destroyed even though weak_references == 1
        assert_eq!(mgr.lookup(id).unwrap().state, ObjectState::Destroyed);
        // Upgrading a destroyed object must fail
        assert!(mgr.upgrade_weak(id).is_none());
    }

    #[test]
    fn upgrade_weak_succeeds_when_object_is_live() {
        let mut mgr = ObjectManager::new();
        let id = mgr.create_object(ObjectType::File);
        mgr.retain_weak(id);
        // Object still live (strong ref = 1)
        let upgraded = mgr.upgrade_weak(id);
        assert!(upgraded.is_some());
        assert_eq!(mgr.lookup(id).unwrap().references, 2);
    }
}
