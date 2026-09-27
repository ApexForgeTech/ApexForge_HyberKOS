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
    Channel
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
    pub fn from_str(s: &str) -> Self {
        let is_absolute = s.starts_with('/');
        let components = s
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| PathComponent::new(c))
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
                    if !normalized_components.is_empty() {
                        normalized_components.pop(); // Go up one directory
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
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_absolute {
            write!(f, "/")?;
        }
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
    Channel
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
    pub fn from_str(s: &str) -> Self {
        let is_absolute = s.starts_with('/');
        let components = s
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| PathComponent::new(c))
            .collect();

        Self {
            components,
            is_absolute,
        }
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

impl Rights{
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
}   let parts: Vec<&str> = self.components.iter().map(|c| c.0.as_str()).collect();
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

impl Rights{
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