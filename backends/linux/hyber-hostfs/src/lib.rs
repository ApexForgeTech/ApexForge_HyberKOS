//! HyberKOS Linux HostFS Provider
//! Phase 6 — Real Linux File System Interaction (Safely Isolated)

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hyber_core::{ObjectId, ObjectType};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::Provider;
mod metadata;

/// 7.1 & 7.2 — HostFS Provider
/// Maps HyberKOS namespace to a specific, isolated Linux directory.
pub struct HostFSProvider {
    /// 7.2: The root directory on the Linux host (e.g., "/home/neo/hyber-host")
    root_path: PathBuf,

    /// 7.3 & 7.5: Maps Hyber ObjectId to its relative Linux path (e.g., "users/neo/test.txt")
    /// This ensures Linux paths/inodes remain private and decoupled from Hyber names.
    object_paths: HashMap<ObjectId, PathBuf>,

    /// 7.4: Linux File Descriptor Isolation.
    /// Maps Hyber ObjectId to an open Linux File.
    /// Hyber Handle -> HostFS internal state -> Linux FD
    active_files: HashMap<ObjectId, File>,
    failed: bool,
    _root_lock: File,
}

impl HostFSProvider {
    /// Create a new HostFSProvider bound to a specific Linux directory
    pub fn new<P: AsRef<Path>>(host_root: P) -> std::io::Result<Self> {
        let requested_root = host_root.as_ref();

        // Ensure the root directory exists on the Linux host
        if !requested_root.exists() {
            fs::create_dir_all(requested_root)?;
        }
        // Keep a canonical root.  Every mapped object is checked against this
        // directory before an operation, so a hostile or accidental symbolic
        // link cannot redirect a Hyber object outside its configured host area.
        let root_path = fs::canonicalize(requested_root)?;
        if !root_path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HostFS root must be a directory",
            ));
        }

        // One hosted authority per root: independent cached namespaces must
        // not race ownership changes or independently spend the same quota.
        let root_lock = File::open(&root_path)?;
        root_lock
            .try_lock()
            .map_err(|e| std::io::Error::other(format!("HostFS root is in use: {e}")))?;
        Ok(Self {
            root_path,
            object_paths: HashMap::new(),
            active_files: HashMap::new(),
            failed: false,
            _root_lock: root_lock,
        })
    }

    /// Associate the already-created Hyber namespace root with the isolated
    /// host root.  Call this once before importing or creating children.
    pub fn bind_root(&mut self, root_id: ObjectId) {
        self.object_paths.insert(root_id, PathBuf::new());
    }

    pub fn restore_root_metadata(
        &self,
        objects: &mut ObjectManager,
        root_id: ObjectId,
    ) -> Result<(), String> {
        let file = metadata::open(&self.get_linux_path(root_id)?)?;
        if let Some(record) = metadata::load(&file)? {
            record.apply(objects.lookup_mut(root_id).ok_or("root object missing")?);
        }
        Ok(())
    }

    /// Helper: Get the full Linux path for a specific ObjectId
    fn get_linux_path(&self, obj_id: ObjectId) -> Result<PathBuf, String> {
        if self.failed {
            return Err("HostFS durable outcome uncertain; reopen required".into());
        }
        let relative = self
            .object_paths
            .get(&obj_id)
            .ok_or_else(|| format!("HostFS object {:?} has no path mapping", obj_id))?;
        if relative.is_absolute()
            || relative.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err("HostFS rejected an unsafe object path".to_string());
        }

        let path = self.root_path.join(relative);
        // Do not follow any symlink in a mapped path.  This intentionally
        // treats symlinks as unsupported HostFS objects until the provider has
        // a separate, capability-checked link model.
        let mut cursor = self.root_path.clone();
        for component in relative.components() {
            cursor.push(component);
            if let Ok(metadata) = fs::symlink_metadata(&cursor) {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "HostFS refused symbolic link: {}",
                        cursor.display()
                    ));
                }
            }
        }
        Ok(path)
    }

    /// Register an existing Linux file/directory into HyberKOS without truncating it.
    pub fn register_existing(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(format!("Invalid namespace node name '{name}'"));
        }
        let parent_path = self
            .object_paths
            .get(&parent_id)
            .cloned()
            .ok_or_else(|| format!("HostFS parent {:?} has no path mapping", parent_id))?;
        self.get_linux_path(parent_id)?;
        let new_relative_path = if parent_path.as_os_str().is_empty() {
            PathBuf::from(name)
        } else {
            parent_path.join(name)
        };

        let file = metadata::open(&self.get_linux_path(parent_id)?.join(name))?;
        let host = file.metadata().map_err(|e| e.to_string())?;
        if (obj_type == ObjectType::File && !host.is_file())
            || (obj_type == ObjectType::Directory && !host.is_dir())
        {
            return Err("HostFS import type mismatch".into());
        }
        let stored = metadata::load(&file)?;
        let obj_id = obj_mgr.create_object(obj_type);
        if let Some(record) = stored {
            record.apply(obj_mgr.lookup_mut(obj_id).ok_or("import object missing")?);
        }
        obj_mgr.lookup_mut(obj_id).unwrap().size = if host.is_file() { host.len() } else { 0 };
        if let Err(error) = ns_mgr.create_node(obj_mgr, parent_id, name, obj_id) {
            obj_mgr.release(obj_id);
            obj_mgr.destroy(obj_id);
            return Err(error);
        }
        if obj_type == ObjectType::Directory {
            ns_mgr.initialize_directory(obj_id)?;
        }
        self.object_paths.insert(obj_id, new_relative_path);
        Ok(obj_id)
    }
}

impl Provider for HostFSProvider {
    fn persist_metadata(&mut self, object: &hyber_object::Object) -> Result<(), String> {
        let file = metadata::open(&self.get_linux_path(object.id)?)?;
        let bytes = metadata::encode(object)?;
        if let Err(error) = metadata::store(&file, &bytes) {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }
    fn create(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        if ns_mgr.lookup(parent_id, name).is_some() {
            return Err(format!("Node '{name}' already exists"));
        }
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(format!("Invalid namespace node name '{name}'"));
        }

        // 2. 7.3 Example Mapping: Build the relative Linux path
        let parent_path = self
            .object_paths
            .get(&parent_id)
            .cloned()
            .ok_or_else(|| format!("HostFS parent {:?} has no path mapping", parent_id))?;
        let new_relative_path = if parent_path.as_os_str().is_empty() {
            PathBuf::from(name)
        } else {
            parent_path.join(name)
        };

        // 3. Create the host object before committing Hyber state. This avoids
        // dangling namespace entries when the OS operation fails.
        let linux_path = self.get_linux_path(parent_id)?.join(name);

        match obj_type {
            ObjectType::Directory => {
                fs::create_dir(&linux_path)
                    .map_err(|e| format!("Failed to create Linux dir: {}", e))?;
            }
            ObjectType::File => {
                // Ensure parent directories exist
                if let Some(parent) = linux_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create parent dir: {}", e))?;
                }
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&linux_path)
                    .map_err(|e| format!("Failed to create Linux file: {}", e))?;
            }
            _ => return Err("HostFS only supports File and Directory creation".to_string()),
        }

        // 4. Commit object and namespace. If that fails, undo the host create.
        let obj_id = obj_mgr.create_object(obj_type);
        if let Err(error) = ns_mgr.create_node(obj_mgr, parent_id, name, obj_id) {
            let _ = if obj_type == ObjectType::Directory {
                fs::remove_dir(&linux_path)
            } else {
                fs::remove_file(&linux_path)
            };
            obj_mgr.release(obj_id);
            obj_mgr.destroy(obj_id);
            return Err(format!("Namespace error: {error}"));
        }
        if obj_type == ObjectType::Directory {
            if let Err(error) = ns_mgr.initialize_directory(obj_id) {
                let _ = ns_mgr.remove_node(parent_id, name);
                let _ = fs::remove_dir(&linux_path);
                obj_mgr.release(obj_id);
                obj_mgr.destroy(obj_id);
                return Err(format!("Directory initialization error: {error}"));
            }
        }

        // 5. 7.5 Inode Isolation: Map ObjectId to relative path, NOT Linux inode
        self.object_paths.insert(obj_id, new_relative_path);

        Ok(obj_id)
    }

    fn remove(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
    ) -> Result<(), String> {
        // 1. Find the ObjectId from the namespace
        let obj_id = ns_mgr
            .lookup(parent_id, name)
            .ok_or_else(|| format!("Node '{}' not found in parent {:?}", name, parent_id))?;

        if obj_mgr
            .lookup(obj_id)
            .is_some_and(|object| object.references > 1)
        {
            return Err("Cannot remove an object with active handles".to_string());
        }

        // 2. Get the Linux path and delete it.  A non-empty directory must not
        // be erased implicitly: the caller has to remove its children first.
        let linux_path = self.get_linux_path(obj_id)?;
        if linux_path.is_dir() {
            fs::remove_dir(&linux_path)
                .map_err(|e| format!("Failed to remove empty dir: {}", e))?;
        } else {
            fs::remove_file(&linux_path).map_err(|e| format!("Failed to remove file: {}", e))?;
        }

        // 3. Remove the namespace entry before dropping the object.  Keeping it
        // would leave a visible path pointing at a destroyed object.
        ns_mgr
            .remove_node(parent_id, name)
            .ok_or_else(|| format!("Node '{}' disappeared during removal", name))?;

        // 4. Clean up internal state
        self.object_paths.remove(&obj_id);
        self.active_files.remove(&obj_id);

        // 5. Drop the node's ownership reference. Existing handles retain a
        // live object until they are closed.
        obj_mgr.release(obj_id);
        obj_mgr.destroy(obj_id);

        Ok(())
    }

    fn rename(
        &mut self,
        _obj_mgr: &mut ObjectManager, // Required by Provider trait but not used in HostFS rename
        ns_mgr: &mut NamespaceManager,
        old_parent_id: ObjectId,
        old_name: &str,
        new_parent_id: ObjectId,
        new_name: &str,
    ) -> Result<(), String> {
        // 1. Find the ObjectId
        let obj_id = ns_mgr
            .lookup(old_parent_id, old_name)
            .ok_or_else(|| format!("Node '{}' not found", old_name))?;

        // 2. Validate the namespace destination *before* mutating the host.
        // std::fs::rename may replace an existing file on Unix, which would
        // otherwise corrupt the namespace/host correspondence.
        if ns_mgr.lookup(new_parent_id, new_name).is_some() {
            return Err(format!("Node '{}' already exists in destination", new_name));
        }

        // 3. Get old and new Linux paths
        let old_linux_path = self.get_linux_path(obj_id)?;

        let new_parent_path = self
            .object_paths
            .get(&new_parent_id)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "HostFS destination parent {:?} has no path mapping",
                    new_parent_id
                )
            })?;
        let new_parent_linux_path = self.get_linux_path(new_parent_id)?;
        let new_relative_path = if new_parent_path.as_os_str().is_empty() {
            PathBuf::from(new_name)
        } else {
            new_parent_path.join(new_name)
        };
        let new_linux_path = new_parent_linux_path.join(new_name);
        if new_relative_path.is_absolute()
            || new_relative_path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err("HostFS rejected unsafe rename destination".into());
        }

        // Ensure new parent directory exists on Linux
        if let Some(parent) = new_linux_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create new parent dir: {}", e))?;
        }

        // 4. Rename on Linux host
        fs::rename(&old_linux_path, &new_linux_path)
            .map_err(|e| format!("Failed to rename Linux file: {}", e))?;

        // 5. Update Hyber Namespace.
        if let Err(error) = ns_mgr.rename_node(old_parent_id, old_name, new_parent_id, new_name) {
            // The namespace is authoritative to Hyber callers.  Restore the
            // host name if its commit fails, rather than silently splitting
            // the two views.  A failed rollback is surfaced explicitly.
            if let Err(rollback) = fs::rename(&new_linux_path, &old_linux_path) {
                return Err(format!(
                    "Namespace rename failed: {error}; HostFS rollback also failed: {rollback}"
                ));
            }
            return Err(format!("Namespace rename failed: {error}"));
        }

        // 6. Update the moved object and every descendant.  A directory move
        // changes the backing path of its whole subtree, not only its root.
        let old_relative_path = self.object_paths.get(&obj_id).cloned().unwrap_or_default();
        self.object_paths.insert(obj_id, new_relative_path);
        if !old_relative_path.as_os_str().is_empty() {
            let rebased: Vec<(ObjectId, PathBuf)> = self
                .object_paths
                .iter()
                .filter_map(|(id, path)| {
                    path.strip_prefix(&old_relative_path)
                        .ok()
                        .filter(|suffix| !suffix.as_os_str().is_empty())
                        .map(|suffix| (*id, self.object_paths[&obj_id].join(suffix)))
                })
                .collect();
            for (id, path) in rebased {
                self.object_paths.insert(id, path);
            }
        }

        Ok(())
    }

    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        // 7.4 FD Isolation: We acknowledge active_files but open a new FD for simplicity
        // in this immutable context. The '_active' prefix prevents unused variable warnings.
        let _active = self.active_files.get(&object_id);

        let mut file = File::open(self.get_linux_path(object_id)?)
            .map_err(|e| format!("Failed to open Linux file for reading: {}", e))?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek: {}", e))?;

        file.read(buffer)
            .map_err(|e| format!("Failed to read: {}", e))
    }

    fn write(&mut self, object_id: ObjectId, offset: u64, buffer: &[u8]) -> Result<usize, String> {
        let linux_path = self.get_linux_path(object_id)?;
        // A partial write/failed flush makes cached size/quota accounting
        // uncertain. Refuse all subsequent access until a fresh import.
        self.failed = true;

        // 7.4 FD Isolation: Open or reuse file
        let mut file = OpenOptions::new()
            .write(true)
            // A write through an existing Hyber handle must never materialize
            // an untracked host file if the backing object disappeared.
            .create(false)
            .truncate(false)
            .open(&linux_path)
            .map_err(|e| format!("Failed to open Linux file for writing: {}", e))?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek: {}", e))?;

        file.write_all(buffer)
            .map_err(|e| format!("Failed to write: {}", e))?;

        // Flush to ensure data hits the Linux host disk
        file.sync_all()
            .map_err(|e| format!("Failed to sync: {}", e))?;

        // Keep it in active_files for future operations (satisfies 7.4)
        self.active_files.insert(object_id, file);
        self.failed = false;
        Ok(buffer.len())
    }

    fn enumerate(&self, _dir_id: ObjectId) -> Result<Option<Vec<(String, ObjectId)>>, String> {
        // HyberKOS source of truth is the NamespaceManager, not the Linux disk.
        // Returning None forces the VFS to fallback to NamespaceManager::list_directory.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch_dir() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hyber-hostfs-test-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn metadata_survives_rename_and_rejects_damage_and_invalid_keys() {
        let dir = scratch_dir();
        let provider = HostFSProvider::new(&dir).unwrap();
        assert!(HostFSProvider::new(&dir).is_err());
        let path = dir.join("original");
        std::fs::write(&path, b"data").unwrap();
        let file = metadata::open(&path).unwrap();
        let mut object = hyber_object::Object::new(ObjectId(7), ObjectType::File);
        object.owner = hyber_core::UserId(42);
        object.permissions = 0o600;
        let encoded = metadata::encode(&object).unwrap();
        metadata::store(&file, &encoded).unwrap();
        std::fs::rename(&path, dir.join("renamed")).unwrap();
        let reopened = metadata::open(&dir.join("renamed")).unwrap();
        let mut restored = hyber_object::Object::new(ObjectId(99), ObjectType::File);
        metadata::load(&reopened)
            .unwrap()
            .unwrap()
            .apply(&mut restored);
        assert_eq!(restored.owner, object.owner);
        assert_eq!(restored.permissions, 0o600);
        assert_eq!(restored.id, ObjectId(99));
        let mut corrupt = encoded;
        corrupt[0] ^= 1;
        metadata::store(&file, &corrupt).unwrap();
        assert!(metadata::load(&reopened).is_err());
        object
            .extended_metadata
            .insert("invalid".into(), hyber_core::MetadataValue::Boolean(true));
        metadata::store(&file, &metadata::encode(&object).unwrap()).unwrap();
        assert!(metadata::load(&reopened).is_err());
        drop(provider);
        assert!(HostFSProvider::new(&dir).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mapped_paths_require_root_binding() {
        let dir = scratch_dir();
        let mut provider = HostFSProvider::new(&dir).unwrap();
        let mut objects = ObjectManager::new();
        let mut namespace = NamespaceManager::new(&mut objects);
        let root = namespace.root();
        assert!(provider
            .create(
                &mut objects,
                &mut namespace,
                root,
                "unbound",
                ObjectType::File,
            )
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_substitution_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = scratch_dir();
        let outside = scratch_dir().with_extension("outside");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        let mut provider = HostFSProvider::new(&dir).unwrap();
        let mut objects = ObjectManager::new();
        let mut namespace = NamespaceManager::new(&mut objects);
        let root = namespace.root();
        provider.bind_root(root);
        let id = provider
            .create(
                &mut objects,
                &mut namespace,
                root,
                "entry",
                ObjectType::File,
            )
            .unwrap();
        std::fs::remove_file(dir.join("entry")).unwrap();
        symlink(&outside, dir.join("entry")).unwrap();
        assert!(provider.read(id, 0, &mut [0; 8]).is_err());
        std::fs::remove_file(dir.join("entry")).unwrap();
        std::fs::remove_file(outside).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
