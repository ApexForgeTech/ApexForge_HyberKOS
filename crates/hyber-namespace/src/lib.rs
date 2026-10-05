use hyber_core::{Node, ObjectId, ObjectState, ObjectType, Path};
use std::collections::HashMap;

use hyber_object::ObjectManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceManager {
    root: ObjectId,
    directory_contents: HashMap<ObjectId, HashMap<String, ObjectId>>, // Maps directory ObjectId to a mapping of names to ObjectIds
    parent_directories: HashMap<ObjectId, ObjectId>,
}

impl NamespaceManager {
    pub fn new(object_manager: &mut ObjectManager) -> Self {
        // Create a root directory object
        let root_id = object_manager.create_object(ObjectType::Directory);

        // Initialize empty contents for the root directory
        let mut directory_contents = HashMap::new();
        directory_contents.insert(root_id, HashMap::new());
        let mut parent_directories = HashMap::new();
        parent_directories.insert(root_id, root_id);

        Self {
            root: root_id,
            directory_contents,
            parent_directories,
        }
    }

    ///Gets root directory ObjectId
    pub fn root(&self) -> ObjectId {
        self.root
    }

    ///Create Node in the namespace
    pub fn create_node(
        &mut self,
        object_manager: &ObjectManager,
        parent: ObjectId,
        name: &str,
        object_id: ObjectId,
    ) -> Result<Node, String> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(format!("Invalid namespace node name '{name}'"));
        }

        // A node may only point to a live object.  Without this check dangling
        // namespace entries can be created trivially.
        if object_manager
            .lookup(object_id)
            .is_none_or(|o| o.state != ObjectState::Live || o.references == 0)
        {
            return Err(format!("Object {:?} does not exist", object_id));
        }
        // The current providers transfer the initial reference to one node.
        // Hard links require separate reference accounting and are deferred.
        if object_id == self.root
            || self
                .directory_contents
                .values()
                .any(|entries| entries.values().any(|id| *id == object_id))
        {
            return Err("Object already has a namespace node; hard links are unsupported".into());
        }
        if object_id == parent || self.is_descendant(parent, object_id) {
            return Err("Cannot create a namespace cycle".into());
        }

        // Validate: Parent must exist and be a Directory
        let parent_obj = object_manager
            .lookup(parent)
            .ok_or_else(|| format!("Parent directory {:?} does not exist", parent))?;

        if parent_obj.object_type != ObjectType::Directory
            || parent_obj.state != ObjectState::Live
            || parent_obj.references == 0
        {
            return Err(format!(
                "Parent {:?} is not a directory (type: {})",
                parent, parent_obj.object_type
            ));
        }

        // Validate: Parent must have an entry in directory_contents
        let parent_contents = self
            .directory_contents
            .get_mut(&parent)
            .ok_or_else(|| format!("Parent directory {:?} is not initialized", parent))?;

        // Validate: Name must not already exist in parent
        if parent_contents.contains_key(name) {
            return Err(format!(
                "Node '{}' already exists in parent directory {:?}",
                name, parent
            ));
        }

        // Create the node
        let node = Node::new(name, object_id);

        // Add to parent's contents
        parent_contents.insert(name.to_string(), object_id);
        if parent_obj.object_type == ObjectType::Directory
            && object_manager
                .lookup(object_id)
                .is_some_and(|object| object.object_type == ObjectType::Directory)
        {
            self.parent_directories.insert(object_id, parent);
        }

        Ok(node)
    }

    //4.4 Lookup Node in the namespace
    pub fn lookup_node(&self, parent: ObjectId, name: &str) -> Option<Node> {
        self.directory_contents
            .get(&parent)?
            .get(name)
            .map(|object_id| Node::new(name, *object_id))
    }

    pub fn lookup(&self, parent: ObjectId, name: &str) -> Option<ObjectId> {
        self.directory_contents.get(&parent)?.get(name).copied()
    }

    pub fn resolve(&self, path: &Path, start_dir: ObjectId) -> Result<ObjectId, String> {
        // Normalize the path and determine the starting directory
        let normalized_path = path.normalize();

        //If the path is absolute, start from the root("/"); otherwise, start from the provided directory
        let mut current_dir = if normalized_path.is_absolute {
            self.root
        } else {
            start_dir
        };

        //Iterate through each component of the path
        for component in &normalized_path.components {
            let name = &component.0;

            if name == "." {
                continue;
            }
            if name == ".." {
                current_dir = *self
                    .parent_directories
                    .get(&current_dir)
                    .ok_or_else(|| format!("Parent directory for {:?} is unknown", current_dir))?;
                continue;
            }

            //check if the current directory has an entry named as the current component
            let next_id = self.lookup(current_dir, name).ok_or_else(|| {
                format!(
                    "Path component '{}' not found in directory {:?}",
                    name, current_dir
                )
            })?;

            //Update the current directory to the next component's ObjectId
            current_dir = next_id;
        }
        Ok(current_dir)
    }

    pub fn remove_node(&mut self, parent_id: ObjectId, name: &str) -> Option<ObjectId> {
        let id = self.lookup(parent_id, name)?;
        if id == self.root
            || self
                .directory_contents
                .get(&id)
                .is_some_and(|entries| !entries.is_empty())
        {
            return None;
        }
        let contents = self.directory_contents.get_mut(&parent_id)?;
        let object_id = contents.remove(name)?;
        if object_id != self.root {
            self.parent_directories.remove(&object_id);
        }
        self.directory_contents.remove(&object_id);
        Some(object_id)
    }

    /// Renames a node from old parent/name to new parent/name cleanly
    pub fn rename_node(
        &mut self,
        old_parent_id: ObjectId,
        old_name: &str,
        new_parent_id: ObjectId,
        new_name: &str,
    ) -> Result<(), String> {
        if new_name.is_empty()
            || new_name == "."
            || new_name == ".."
            || new_name.contains(['/', '\0'])
        {
            return Err(format!("Invalid namespace node name '{new_name}'"));
        }

        if !self.directory_contents.contains_key(&new_parent_id) {
            return Err(format!(
                "New parent directory {:?} is not initialized",
                new_parent_id
            ));
        }

        // 1. Get the object ID
        let obj_id = self
            .lookup(old_parent_id, old_name)
            .ok_or_else(|| format!("Node '{}' not found in old parent", old_name))?;

        // A directory cannot be moved into itself or one of its descendants.
        // Otherwise resolution would create an unreachable namespace cycle.
        if obj_id == new_parent_id || self.is_descendant(new_parent_id, obj_id) {
            return Err("Cannot move a directory into itself or its descendant".to_string());
        }

        if old_parent_id == new_parent_id && old_name == new_name {
            return Ok(());
        }
        if self.lookup(new_parent_id, new_name).is_some() {
            return Err(format!("Node '{}' already exists in new parent", new_name));
        }
        // A move preserves the directory's contents and reference ownership.
        self.directory_contents
            .get_mut(&old_parent_id)
            .ok_or("source parent missing")?
            .remove(old_name);

        // 3. Add to new parent
        let new_parent_contents =
            self.directory_contents
                .get_mut(&new_parent_id)
                .ok_or_else(|| {
                    format!(
                        "New parent directory {:?} is not initialized",
                        new_parent_id
                    )
                })?;

        if new_parent_contents.contains_key(new_name) {
            // Rollback: put it back in the old parent if the new name already exists
            if let Some(old_contents) = self.directory_contents.get_mut(&old_parent_id) {
                old_contents.insert(old_name.to_string(), obj_id);
            }
            if self.directory_contents.contains_key(&obj_id) {
                self.parent_directories.insert(obj_id, old_parent_id);
            }
            return Err(format!("Node '{}' already exists in new parent", new_name));
        }

        new_parent_contents.insert(new_name.to_string(), obj_id);
        if self.directory_contents.contains_key(&obj_id) {
            self.parent_directories.insert(obj_id, new_parent_id);
        }
        Ok(())
    }

    fn is_descendant(&self, candidate: ObjectId, ancestor: ObjectId) -> bool {
        let mut current = candidate;
        let mut seen = std::collections::HashSet::new();
        while seen.insert(current) {
            if current == ancestor {
                return true;
            }
            let Some(parent) = self.parent_directories.get(&current) else {
                return false;
            };
            if *parent == current {
                return false;
            }
            current = *parent;
        }
        true
    }
    pub fn initialize_directory(&mut self, dir_id: ObjectId) -> Result<(), String> {
        if self.directory_contents.contains_key(&dir_id) {
            return Err(format!("Directory {:?} is already initialized", dir_id));
        }

        self.directory_contents.insert(dir_id, HashMap::new());
        Ok(())
    }

    pub fn list_directory(&self, dir_id: ObjectId) -> Option<Vec<Node>> {
        self.directory_contents.get(&dir_id).map(|contents| {
            contents
                .iter()
                .map(|(name, object_id)| Node::new(name.clone(), *object_id))
                .collect()
        })
    }
}

impl NamespaceManager {
    /// Create a sentinel/placeholder NamespaceManager that is intentionally empty.
    ///
    /// This is used by the shell's `run_lua_script` to temporarily swap out
    /// the real namespace manager via `std::mem::replace` while handing
    /// ownership to the Lua runtime.  The placeholder is NEVER used for
    /// actual namespace operations — it will be immediately replaced with
    /// the real one returned by `run_lua_script`.
    ///
    /// ObjectId(u64::MAX) is used as a sentinel root that will never match
    /// any real object created by ObjectManager (which starts at id 1).
    pub fn new_placeholder() -> Self {
        use hyber_core::ObjectId;
        let mut directory_contents = std::collections::HashMap::new();
        let sentinel = ObjectId(u64::MAX);
        directory_contents.insert(sentinel, std::collections::HashMap::new());
        let mut parent_directories = std::collections::HashMap::new();
        parent_directories.insert(sentinel, sentinel);
        Self {
            root: sentinel,
            directory_contents,
            parent_directories,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NamespaceManager;
    use hyber_core::ObjectType;
    use hyber_object::ObjectManager;

    #[test]
    fn node_ownership_and_directory_lifetime_are_consistent() {
        let mut objects = ObjectManager::new();
        let mut ns = NamespaceManager::new(&mut objects);
        let root = ns.root();
        let dir = objects.create_object(ObjectType::Directory);
        ns.create_node(&objects, root, "dir", dir).unwrap();
        ns.initialize_directory(dir).unwrap();
        let file = objects.create_object(ObjectType::File);
        ns.create_node(&objects, dir, "file", file).unwrap();
        assert!(ns.create_node(&objects, root, "alias", file).is_err());
        assert!(ns.create_node(&objects, dir, "cycle", root).is_err());
        assert!(ns.remove_node(root, "dir").is_none());
        ns.rename_node(root, "dir", root, "renamed").unwrap();
        assert_eq!(ns.lookup(dir, "file"), Some(file));
        assert_eq!(ns.remove_node(dir, "file"), Some(file));
        assert_eq!(ns.remove_node(root, "renamed"), Some(dir));
        assert!(ns.list_directory(dir).is_none());
        objects.release(file);
        assert!(ns.create_node(&objects, root, "dead", file).is_err());
    }

    #[test]
    fn node_names_and_targets_are_validated() {
        let mut objects = ObjectManager::new();
        let mut namespace = NamespaceManager::new(&mut objects);
        let root = namespace.root();
        let file = objects.create_object(ObjectType::File);

        assert!(namespace.create_node(&objects, root, "a/b", file).is_err());
        assert!(namespace.create_node(&objects, root, "..", file).is_err());
        assert!(namespace
            .create_node(&objects, root, "missing", hyber_core::ObjectId(999))
            .is_err());
        assert!(namespace.create_node(&objects, root, "valid", file).is_ok());
    }

    #[test]
    fn relative_parent_resolution_uses_namespace_parents() {
        let mut objects = ObjectManager::new();
        let mut namespace = NamespaceManager::new(&mut objects);
        let root = namespace.root();
        let dir = objects.create_object(ObjectType::Directory);
        namespace.create_node(&objects, root, "dir", dir).unwrap();
        namespace.initialize_directory(dir).unwrap();
        assert_eq!(
            namespace.resolve(&hyber_core::Path::parse(".."), dir),
            Ok(root)
        );
    }

    #[test]
    fn directory_cannot_move_into_descendant() {
        let mut objects = ObjectManager::new();
        let mut namespace = NamespaceManager::new(&mut objects);
        let root = namespace.root();
        let parent = objects.create_object(ObjectType::Directory);
        let child = objects.create_object(ObjectType::Directory);
        namespace
            .create_node(&objects, root, "parent", parent)
            .unwrap();
        namespace.initialize_directory(parent).unwrap();
        namespace
            .create_node(&objects, parent, "child", child)
            .unwrap();
        namespace.initialize_directory(child).unwrap();
        assert!(namespace
            .rename_node(root, "parent", child, "moved")
            .is_err());
    }
}
