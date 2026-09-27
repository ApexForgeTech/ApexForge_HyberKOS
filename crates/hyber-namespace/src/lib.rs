use hyber_core::{Node, ObjectId, ObjectType, Path};
use std::collections::HashMap;

use hyber_object::ObjectManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceManager {
    root: ObjectId,
    directory_contents: HashMap<ObjectId, HashMap<String, ObjectId>>, // Maps directory ObjectId to a mapping of names to ObjectIds
}

impl NamespaceManager {
    pub fn new(object_manager: &mut ObjectManager) -> Self {
        // Create a root directory object
        let root_id = object_manager.create_object(ObjectType::Directory);

        // Initialize empty contents for the root directory
        let mut directory_contents = HashMap::new();
        directory_contents.insert(root_id, HashMap::new());

        Self {
            root: root_id,
            directory_contents,
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
        if object_manager.lookup(object_id).is_none() {
            return Err(format!("Object {:?} does not exist", object_id));
        }

        // Validate: Parent must exist and be a Directory
        let parent_obj = object_manager
            .lookup(parent)
            .ok_or_else(|| format!("Parent directory {:?} does not exist", parent))?;

        if parent_obj.object_type != ObjectType::Directory {
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
                // The namespace deliberately has no parent pointers.  Callers
                // should normalize relative paths against their working path
                // before resolving; an unresolved parent is never silently
                // treated as the current directory.
                return Err("Cannot resolve an unanchored '..' path component".to_string());
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
        let contents = self.directory_contents.get_mut(&parent_id)?;
        contents.remove(name)
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

        // 2. Remove from old parent
        self.remove_node(old_parent_id, old_name);

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
            return Err(format!("Node '{}' already exists in new parent", new_name));
        }

        new_parent_contents.insert(new_name.to_string(), obj_id);
        Ok(())
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

impl Default for NamespaceManager {
    fn default() -> Self {
        // This is a placeholder - real initialization requires ObjectManager
        // Use NamespaceManager::new() instead
        panic!("Use NamespaceManager::new(object_manager) to create a NamespaceManager")
    }
}

#[cfg(test)]
mod tests {
    use super::NamespaceManager;
    use hyber_core::ObjectType;
    use hyber_object::ObjectManager;

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
}
