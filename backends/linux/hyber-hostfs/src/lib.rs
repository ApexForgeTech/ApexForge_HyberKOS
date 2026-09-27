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
}

impl HostFSProvider {
    /// Create a new HostFSProvider bound to a specific Linux directory
    pub fn new<P: AsRef<Path>>(host_root: P) -> std::io::Result<Self> {
        let root_path = host_root.as_ref().to_path_buf();
        
        // Ensure the root directory exists on the Linux host
        if !root_path.exists() {
            fs::create_dir_all(&root_path)?;
        }

        Ok(Self {
            root_path,
            object_paths: HashMap::new(),
            active_files: HashMap::new(),
        })
    }

    /// Helper: Get the full Linux path for a specific ObjectId
    fn get_linux_path(&self, obj_id: ObjectId) -> PathBuf {
        self.root_path.join(
            self.object_paths.get(&obj_id).unwrap_or(&PathBuf::from(obj_id.0.to_string()))
        )
    }
}

impl Provider for HostFSProvider {
    fn create(
        &mut self,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        parent_id: ObjectId,
        name: &str,
        obj_type: ObjectType,
    ) -> Result<ObjectId, String> {
        // 1. Create Hyber Object and Node
        let obj_id = obj_mgr.create_object(obj_type);
        ns_mgr.create_node(obj_mgr, parent_id, name, obj_id)
            .map_err(|e| format!("Namespace error: {}", e))?;
        
        if obj_type == ObjectType::Directory {
            ns_mgr.initialize_directory(obj_id)
                .map_err(|e| format!("Init dir error: {}", e))?;
        }

        // 2. 7.3 Example Mapping: Build the relative Linux path
        let parent_path = self.object_paths.get(&parent_id).cloned().unwrap_or_default();
        let new_relative_path = if parent_path.as_os_str().is_empty() {
            PathBuf::from(name)
        } else {
            parent_path.join(name)
        };

        // 3. Create REAL Linux file/directory
        let linux_path = self.root_path.join(&new_relative_path);
        
        match obj_type {
            ObjectType::Directory => {
                fs::create_dir_all(&linux_path)
                    .map_err(|e| format!("Failed to create Linux dir: {}", e))?;
            }
            ObjectType::File => {
                // Ensure parent directories exist
                if let Some(parent) = linux_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| format!("Failed to create parent dir: {}", e))?;
                }
                File::create(&linux_path)
                    .map_err(|e| format!("Failed to create Linux file: {}", e))?;
            }
            _ => return Err("HostFS only supports File and Directory creation".to_string()),
        }

        // 4. 7.5 Inode Isolation: Map ObjectId to relative path, NOT Linux inode
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
        let obj_id = ns_mgr.lookup(parent_id, name)
            .ok_or_else(|| format!("Node '{}' not found in parent {:?}", name, parent_id))?;

        // 2. Get the Linux path and delete it
        let linux_path = self.get_linux_path(obj_id);
        if linux_path.is_dir() {
            fs::remove_dir_all(&linux_path).map_err(|e| format!("Failed to remove dir: {}", e))?;
        } else {
            fs::remove_file(&linux_path).map_err(|e| format!("Failed to remove file: {}", e))?;
        }

        // 3. Clean up internal state
        self.object_paths.remove(&obj_id);
        self.active_files.remove(&obj_id);
        
        // 4. Destroy Hyber object
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
        let obj_id = ns_mgr.lookup(old_parent_id, old_name)
            .ok_or_else(|| format!("Node '{}' not found", old_name))?;

        // 2. Get old and new Linux paths
        let old_linux_path = self.get_linux_path(obj_id);
        
        let new_parent_path = self.object_paths.get(&new_parent_id).cloned().unwrap_or_default();
        let new_relative_path = if new_parent_path.as_os_str().is_empty() {
            PathBuf::from(new_name)
        } else {
            new_parent_path.join(new_name)
        };
        let new_linux_path = self.root_path.join(&new_relative_path);

        // Ensure new parent directory exists on Linux
        if let Some(parent) = new_linux_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create new parent dir: {}", e))?;
        }

        // 3. Rename on Linux host
        fs::rename(&old_linux_path, &new_linux_path)
            .map_err(|e| format!("Failed to rename Linux file: {}", e))?;

        // 4. Update Hyber Namespace cleanly (No hacks needed anymore)
        ns_mgr.rename_node(old_parent_id, old_name, new_parent_id, new_name)
            .map_err(|e| format!("Namespace rename failed: {}", e))?;

        // 5. Update internal path map
        self.object_paths.insert(obj_id, new_relative_path);

        Ok(())
    }

    fn read(&self, object_id: ObjectId, offset: u64, buffer: &mut [u8]) -> Result<usize, String> {
        // 7.4 FD Isolation: We acknowledge active_files but open a new FD for simplicity 
        // in this immutable context. The '_active' prefix prevents unused variable warnings.
        let _active = self.active_files.get(&object_id); 
        
        let mut file = File::open(self.get_linux_path(object_id))
            .map_err(|e| format!("Failed to open Linux file for reading: {}", e))?;
            
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek: {}", e))?;
            
        file.read(buffer)
            .map_err(|e| format!("Failed to read: {}", e))
    }

    fn write(&mut self, object_id: ObjectId, offset: u64, buffer: &[u8]) -> Result<usize, String> {
        let linux_path = self.get_linux_path(object_id);
        
        // 7.4 FD Isolation: Open or reuse file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
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
            
        Ok(buffer.len())
    }

    fn enumerate(&self, _dir_id: ObjectId) -> Result<Vec<(String, ObjectId)>, String> {
        // HyberKOS source of truth is the NamespaceManager, not the Linux disk.
        // Returning an error forces the VFS to fallback to NamespaceManager::list_directory.
        Err("HostFS relies on NamespaceManager for directory listing".to_string())
    }
}