/* Object types for the Hyber kernel.
FILE
DIRECTORY
PROCESS
THREAD
SOCKET
PIPE
DEVICE
SERVICE
SHARED_MEMORY
PACKAGE
CHANNEL
 */
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    File,
    Directory,
    Process,
    Thread,
    Socket,
    Pipe,
    Device,
    Service,
    SharedMemory,
    Package,
    Channel,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectType::File => write!(f, "FILE"),
            ObjectType::Directory => write!(f, "DIRECTORY"),
            ObjectType::Process => write!(f, "PROCESS"),
            ObjectType::Thread => write!(f, "THREAD"),
            ObjectType::Socket => write!(f, "SOCKET"),
            ObjectType::Pipe => write!(f, "PIPE"),
            ObjectType::Device => write!(f, "DEVICE"),
            ObjectType::Service => write!(f, "SERVICE"),
            ObjectType::SharedMemory => write!(f, "SHARED_MEMORY"),
            ObjectType::Package => write!(f, "PACKAGE"),
            ObjectType::Channel => write!(f, "CHANNEL"),
        }
    }
}

//2.2 Object ID

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub u64);

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.0)
    }
}

// 2.3 Process ID

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessId(pub u64);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProcessId({})", self.0)
    }
}

// 2.4 Handle ID

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HandleId(pub u64);

impl fmt::Display for HandleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HandleId({})", self.0)
    }
}

// 2.4.1 User, Group, and Thread IDs (Phase 9 & 10)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(pub u32);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UID({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(pub u32);

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GID({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(pub u64);

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ThreadId({})", self.0)
    }
}
// 2.5 Node

/// A Node maps a name to an ObjectId inside a Directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub object_id: ObjectId,
}

impl Node {
    pub fn new(name: impl Into<String>, object_id: ObjectId) -> Self {
        Self {
            name: name.into(),
            object_id,
        }
    }
}

// 2.6 Path and PathComponent

/// A single component of a path (e.g. "users", "neo", "test.txt")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathComponent(pub String);

impl PathComponent {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for PathComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a full path in the Hyber namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub components: Vec<PathComponent>,
    pub is_absolute: bool,
}

impl Path {
    /// Create a path from a string like "/users/neo/test.txt"
    pub fn parse(s: &str) -> Self {
        let is_absolute = s.starts_with('/');
        let components = s
            .split('/')
            .filter(|c| !c.is_empty())
            .map(PathComponent::new)
            .collect();

        Self {
            components,
            is_absolute,
        }
    }

    pub fn normalize(&self) -> Self {
        let mut normalized_components = Vec::new();

        let is_absolute = self.is_absolute;

        for component in &self.components {
            match component.0.as_str() {
                "." => continue, // Skip current directory
                ".." => {
                    if normalized_components
                        .last()
                        .is_some_and(|c: &PathComponent| c.0 != "..")
                    {
                        normalized_components.pop(); // Go up one directory
                    } else if !is_absolute {
                        // A relative path must retain leading parents.  Dropping
                        // them changes the meaning when it is resolved from a
                        // non-root working directory.
                        normalized_components.push(component.clone());
                    }
                }
                _ => normalized_components.push(component.clone()),
            }
        }

        Self {
            components: normalized_components,
            is_absolute,
        }
    }
    pub fn parent_and_name(&self) -> Option<(Self, String)> {
        let mut comps = self.components.clone();
        let name = comps.pop()?.0;
        Some((
            Self {
                components: comps,
                is_absolute: self.is_absolute,
            },
            name,
        ))
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_absolute {
            write!(f, "/")?;
        }
        let parts: Vec<&str> = self.components.iter().map(|c| c.0.as_str()).collect();
        write!(f, "{}", parts.join("/"))
    }
}

// 2,7 Rights

//Access rights that can be granted to a handle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub delete: bool,
    pub rename: bool,
    pub enumerate: bool,
    pub connect: bool,
    pub wait: bool,
    pub signal: bool,
}

impl Rights {
    pub fn empty() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
            delete: false,
            rename: false,
            enumerate: false,
            connect: false,
            wait: false,
            signal: false,
        }
    }

    pub fn read_only() -> Self {
        Self {
            read: true,
            ..Self::empty()
        }
    }

    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            ..Self::empty()
        }
    }

    pub fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            delete: true,
            rename: true,
            enumerate: true,
            connect: true,
            wait: true,
            signal: true,
        }
    }
}

// 2.8 Object State

//Lifecycle state of an object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectState {
    /// The object is currently active and can be used.
    Live,
    /// The object is in the process of being destroyed and should not be used.
    Destroyed,
    /// The object is in the process of being closed and should not be used.
    Closing,
}

impl fmt::Display for ObjectState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectState::Live => write!(f, "LIVE"),
            ObjectState::Destroyed => write!(f, "DESTROYED"),
            ObjectState::Closing => write!(f, "CLOSING"),
        }
    }
}

// 2.9 Metadata Types
#[derive(Debug, Clone, PartialEq)]
pub enum MetadataValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
    Timestamp(u64),
    List(Vec<MetadataValue>),
}

impl fmt::Display for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataValue::String(s) => write!(f, "\"{}\"", s),
            MetadataValue::Integer(i) => write!(f, "{}", i),
            MetadataValue::Boolean(b) => write!(f, "{}", b),
            MetadataValue::Bytes(b) => write!(f, "<bytes: {} len>", b.len()),
            MetadataValue::Timestamp(t) => write!(f, "<timestamp: {}>", t),
            MetadataValue::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
        }
    }
}

// 2.10 Security Foundation (Phase 9)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityContext {
    pub user_id: UserId,
    pub group_id: GroupId,
    pub supplementary_groups: Vec<GroupId>,
    pub capabilities: Vec<Capability>,
}

impl SecurityContext {
    pub fn root() -> Self {
        Self {
            user_id: UserId(0),
            group_id: GroupId(0),
            supplementary_groups: Vec::new(),
            capabilities: vec![Capability {
                name: "CAP_SYS_ADMIN".to_string(),
            }],
        }
    }
}

pub struct SecurityManager;

impl SecurityManager {
    pub fn check_access(
        context: &SecurityContext,
        owner: UserId,
        group: GroupId,
        permissions: u32,
        requested_rights: Rights,
    ) -> Result<(), String> {
        // Root always has access
        if context.user_id.0 == 0 {
            return Ok(());
        }

        let allowed_read;
        let allowed_write;
        let allowed_execute;

        if context.user_id == owner {
            allowed_read = (permissions & 0o400) != 0;
            allowed_write = (permissions & 0o200) != 0;
            allowed_execute = (permissions & 0o100) != 0;
        } else if context.group_id == group || context.supplementary_groups.contains(&group) {
            allowed_read = (permissions & 0o040) != 0;
            allowed_write = (permissions & 0o020) != 0;
            allowed_execute = (permissions & 0o010) != 0;
        } else {
            allowed_read = (permissions & 0o004) != 0;
            allowed_write = (permissions & 0o002) != 0;
            allowed_execute = (permissions & 0o001) != 0;
        }

        if requested_rights.read && !allowed_read {
            return Err("Access denied: READ permission missing".to_string());
        }
        if requested_rights.write && !allowed_write {
            return Err("Access denied: WRITE permission missing".to_string());
        }
        if requested_rights.execute && !allowed_execute {
            return Err("Access denied: EXECUTE permission missing".to_string());
        }
        // POSIX-style metadata has no separate delete/rename bits: those
        // operations are governed by write permission on the parent directory.
        if (requested_rights.write || requested_rights.delete || requested_rights.rename)
            && !allowed_write
        {
            return Err("Access denied: WRITE permission missing".to_string());
        }
        if requested_rights.enumerate && !allowed_read {
            return Err("Access denied: READ permission missing".to_string());
        }
        // These rights do not have a safe owner/group/other encoding.  They
        // are object-capability operations and must never be granted merely
        // because an object is readable or writable.
        for (requested, capability, operation) in [
            (requested_rights.connect, "CAP_OBJECT_CONNECT", "CONNECT"),
            (requested_rights.wait, "CAP_OBJECT_WAIT", "WAIT"),
            (requested_rights.signal, "CAP_OBJECT_SIGNAL", "SIGNAL"),
        ] {
            if requested {
                Self::check_capability(context, capability)
                    .map_err(|_| format!("Access denied: {operation} capability missing"))?;
            }
        }

        Ok(())
    }

    pub fn check_capability(context: &SecurityContext, required: &str) -> Result<(), String> {
        if context.user_id.0 == 0 {
            return Ok(());
        }
        if context.capabilities.iter().any(|c| c.name == required) {
            Ok(())
        } else {
            Err(format!("Access denied: Missing capability '{}'", required))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplementary_group_permissions_do_not_override_owner_class() {
        let context = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![GroupId(2000)],
            capabilities: vec![],
        };
        assert!(SecurityManager::check_access(
            &context,
            UserId(12),
            GroupId(2000),
            0o040,
            Rights::read_only()
        )
        .is_ok());
        assert!(SecurityManager::check_access(
            &context,
            UserId(1000),
            GroupId(2000),
            0o040,
            Rights::read_only()
        )
        .is_err());
        assert!(SecurityManager::check_access(
            &context,
            UserId(12),
            GroupId(2001),
            0o040,
            Rights::read_only()
        )
        .is_err());
        assert_eq!(Path::parse("../../a").normalize().to_string(), "../../a");
    }

    #[test]
    fn object_specific_rights_require_explicit_capabilities() {
        let mut context = SecurityContext {
            user_id: UserId(1000),
            group_id: GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        let special = Rights {
            connect: true,
            wait: true,
            signal: true,
            ..Rights::empty()
        };
        assert!(SecurityManager::check_access(
            &context,
            UserId(1000),
            GroupId(1000),
            0o777,
            special,
        )
        .is_err());
        for name in ["CAP_OBJECT_CONNECT", "CAP_OBJECT_WAIT", "CAP_OBJECT_SIGNAL"] {
            context.capabilities.push(Capability { name: name.into() });
        }
        assert!(SecurityManager::check_access(
            &context,
            UserId(1000),
            GroupId(1000),
            0o777,
            special,
        )
        .is_ok());
    }

    #[test]
    fn relative_normalization_preserves_leading_parent() {
        let path = Path::parse("../users/./neo").normalize();
        assert_eq!(path.to_string(), "../users/neo");
    }

    #[test]
    fn absolute_normalization_cannot_escape_root() {
        let path = Path::parse("/users/../../temporary").normalize();
        assert_eq!(path.to_string(), "/temporary");
    }
}
