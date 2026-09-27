# ApexForge_HyberKOS

> **A modular, secure, language-neutral operating system architecture designed to begin on Linux and eventually become an independent operating system.**

---

## Table of Contents

1. [Project Identity](#1-project-identity)
2. [Vision](#2-vision)
3. [Mission](#3-mission)
4. [Why HyberKOS Exists](#4-why-hyberkos-exists)
5. [Core Principles](#5-core-principles)
6. [Goals](#6-goals)
7. [Non-Goals](#7-non-goals)
8. [The Fundamental Architecture](#8-the-fundamental-architecture)
9. [Core Terminology](#9-core-terminology)
10. [Object Model](#10-object-model)
11. [Object IDs](#11-object-ids)
12. [Nodes](#12-nodes)
13. [Paths](#13-paths)
14. [Files and Directories](#14-files-and-directories)
15. [Handles](#15-handles)
16. [Providers](#16-providers)
17. [VFS](#17-vfs)
18. [The Relationship Between Everything](#18-the-relationship-between-everything)
19. [Namespaces](#19-namespaces)
20. [The HyberKOS Root Namespace](#20-the-hyberkos-root-namespace)
21. [Filesystem Architecture](#21-filesystem-architecture)
22. [HyberFS](#22-hyberfs)
23. [HyberFS On-Disk Architecture](#23-hyberfs-on-disk-architecture)
24. [Metadata Architecture](#24-metadata-architecture)
25. [Persistent and Runtime Objects](#25-persistent-and-runtime-objects)
26. [Language Architecture](#26-language-architecture)
27. [Language-Neutral System Design](#27-language-neutral-system-design)
28. [Kernel Architecture](#28-kernel-architecture)
29. [Hyber Core](#29-hyber-core)
30. [Object Manager](#30-object-manager)
31. [Namespace and Node Manager](#31-namespace-and-node-manager)
32. [Handle and Capability Manager](#32-handle-and-capability-manager)
33. [Process and Thread Architecture](#33-process-and-thread-architecture)
34. [Memory Architecture](#34-memory-architecture)
35. [IPC Architecture](#35-ipc-architecture)
36. [Device Architecture](#36-device-architecture)
37. [Networking Architecture](#37-networking-architecture)
38. [Service Architecture](#38-service-architecture)
39. [Package Architecture](#39-package-architecture)
40. [Shell Architecture](#40-shell-architecture)
41. [GUI Architecture](#41-gui-architecture)
42. [Application Architecture](#42-application-architecture)
43. [Lua Runtime](#43-lua-runtime)
44. [C and C++](#44-c-and-c)
45. [Rust](#45-rust)
46. [Assembly](#46-assembly)
47. [Python](#47-python)
48. [Go](#48-go)
49. [Java and Kotlin](#49-java-and-kotlin)
50. [JavaScript, TypeScript and React](#50-javascript-typescript-and-react)
51. [Future HyberLang](#51-future-hyberlang)
52. [Compilation and Execution Model](#52-compilation-and-execution-model)
53. [Linux Host Architecture](#53-linux-host-architecture)
54. [Future Native Kernel Architecture](#54-future-native-kernel-architecture)
55. [Migration Strategy](#55-migration-strategy)
56. [Security Architecture](#56-security-architecture)
57. [Permissions and Access Control](#57-permissions-and-access-control)
58. [Storage and Data Integrity](#58-storage-and-data-integrity)
59. [Crash Consistency](#59-crash-consistency)
60. [Snapshots and Future Features](#60-snapshots-and-future-features)
61. [Repository Architecture](#61-repository-architecture)
62. [Development Environment](#62-development-environment)
63. [Example System Operations](#63-example-system-operations)
64. [Design Invariants](#64-design-invariants)
65. [Development Phases](#65-development-phases)
66. [Risks and Tradeoffs](#66-risks-and-tradeoffs)
67. [Future Extensions](#67-future-extensions)
68. [Final Architectural Model](#68-final-architectural-model)

---

# 1. Project Identity

## Name

**ApexForge_HyberKOS**

Short form:

**HyberKOS**

The project is an operating-system architecture and implementation effort under the ApexForge ecosystem.

The name represents two ideas:

* **ApexForge** — the engineering environment and project family.
* **HyberKOS** — the operating-system architecture itself.

The project is not intended to be merely another Linux distribution.

It is intended to become an independent operating-system architecture.

---

# 2. Vision

The long-term vision of ApexForge_HyberKOS is:

> Build an operating system whose fundamental abstractions belong to HyberKOS itself rather than being inherited from Linux or another existing operating system.

The first version may run **on top of Linux**.

That is a deliberate engineering strategy.

Linux provides:

* hardware access
* process execution
* memory management
* networking
* storage
* drivers
* scheduling
* security primitives

during the early development stages.

However, Linux must remain an implementation detail.

The architecture should eventually be capable of becoming:

```text
Hardware
   ↓
HyberKOS Kernel
   ↓
HyberKOS Core
   ↓
Hyber VFS
   ↓
HyberFS
   ↓
Applications
```

without requiring the entire userland to be redesigned.

---

# 3. Mission

The mission is to create a modular operating system with:

* its own object model
* its own namespace model
* its own Node abstraction
* its own Handle model
* its own VFS
* its own filesystem
* its own process model
* its own IPC architecture
* its own service architecture
* strong security boundaries
* language-neutral APIs
* modular providers
* native developer tooling
* long-term support for multiple programming languages

The system should be understandable from first principles.

A developer should be able to understand:

```text
Path
 ↓
Node
 ↓
Object
```

and:

```text
Process
 ↓
Handle
 ↓
Object
```

without needing to understand Linux internals.

---

# 4. Why HyberKOS Exists

Traditional application development often happens above a large existing operating system.

For example:

```text
Application
 ↓
Library
 ↓
Runtime
 ↓
System Call
 ↓
Kernel
 ↓
Hardware
```

The application is therefore strongly influenced by the operating system below it.

HyberKOS attempts to define its own stable conceptual layer.

For example:

```text
Application
 ↓
Hyber API
 ↓
Hyber Core
 ↓
Hyber Object Model
 ↓
Hyber VFS
 ↓
Provider
 ↓
Backend
```

The backend could initially be Linux.

Later it could be a native HyberKOS kernel.

This separation is one of the most important architectural goals.

---

# 5. Core Principles

## 5.1 Linux is a backend during the initial phase

Linux is not the identity of HyberKOS.

The initial system may use:

```text
Linux Backend
```

but Hyber applications should not depend directly on Linux APIs.

---

## 5.2 Object identity must belong to HyberKOS

HyberKOS Object IDs must not simply be Linux inode numbers.

Similarly:

```text
Hyber Process ID
```

must not simply become:

```text
Linux PID
```

Backend identifiers remain backend identifiers.

---

## 5.3 Path is not identity

A path is an address.

It is not the object itself.

For example:

```text
/users/neo/documents/test.txt
```

is a path.

The path resolves to a Node.

The Node references an Object.

---

## 5.4 Node is not Object

A Node is a namespace-visible entry.

An Object is the underlying system resource.

Therefore:

```text
Node
 ↓
Object
```

is intentional.

---

## 5.5 Handle is not Object

A Handle represents a process's access/reference to an Object.

Multiple processes can have different Handles referring to the same Object.

---

## 5.6 VFS is not Filesystem

VFS defines a common interface.

HyberFS is one concrete filesystem implementation.

---

## 5.7 Language neutrality

HyberKOS must not become:

> "an operating system written for Lua"

or:

> "an operating system written for Rust applications."

The system foundation is language-neutral.

---

## 5.8 Security by architecture

Security should not be added at the end.

Objects, handles, capabilities, namespaces, processes, services and IPC should all be designed with security boundaries from the beginning.

---

# 6. Goals

HyberKOS aims to provide:

* modularity
* portability
* security
* observability
* language neutrality
* custom filesystem support
* custom namespace semantics
* native process/object abstractions
* strong isolation
* predictable APIs
* developer friendliness
* self-hosting capability
* eventual native kernel operation

---

# 7. Non-Goals

HyberKOS is not initially intended to:

* replace Linux immediately
* support every programming language inside the kernel
* reproduce every Linux subsystem exactly
* become Linux-compatible at the architectural level
* copy `/`
* copy `C:\`
* expose Linux file descriptors as native Hyber Handles
* expose Linux PIDs as Hyber process IDs
* expose Linux inodes as Hyber Object IDs

Compatibility can be implemented later.

Compatibility should not define the core architecture.

---

# 8. The Fundamental Architecture

The conceptual system is:

```text
                         APPLICATIONS
                              │
                              ▼
                    HYBER APPLICATION API
                              │
                              ▼
                       HYBER RUNTIME
                              │
                              ▼
                         HYBER CORE
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        Object Manager   Process Manager   Security
              │
              ▼
        Namespace Manager
              │
              ▼
             VFS
              │
              ▼
          PROVIDERS
              │
        ┌─────┼───────────┐
        ▼     ▼           ▼
     HyberFS HostFS    Device/Virtual
                         Providers
```

The architecture is intentionally layered.

---

# 9. Core Terminology

The following concepts must remain distinct.

| Concept    | Meaning                                                |
| ---------- | ------------------------------------------------------ |
| Object     | The actual system-managed resource                     |
| Object ID  | Identity number of an Object                           |
| Node       | Namespace entry pointing to an Object                  |
| Path       | Human-readable address of a Node                       |
| File       | An Object of FILE type                                 |
| Directory  | An Object of DIRECTORY type                            |
| Handle     | Process-local access/reference to an Object            |
| Provider   | Backend implementation that supplies/manages resources |
| VFS        | Virtual interface for namespace/resource operations    |
| Filesystem | Concrete storage implementation                        |

---

# 10. Object Model

The Object is the fundamental resource abstraction of HyberKOS.

Examples:

```text
File Object
Directory Object
Process Object
Thread Object
Socket Object
Pipe Object
Device Object
Service Object
Shared Memory Object
Package Object
```

Conceptually:

```text
Object
├── File
├── Directory
├── Process
├── Thread
├── Socket
├── Pipe
├── Device
├── Service
└── ...
```

An Object may contain:

```text
Object
├── object_id
├── object_type
├── ownership
├── security
├── metadata
├── state
└── provider_reference
```

The exact fields depend on the Object type.

---

# 11. Object IDs

An Object ID uniquely identifies an Object within the relevant HyberKOS identity domain.

Example:

```text
Object #123
```

may represent:

```text
FILE
```

while:

```text
Object #456
```

may represent:

```text
PROCESS
```

Object ID is not the Object.

Simple analogy:

```text
Person = Object
Passport number = Object ID
```

Another analogy:

```text
Car = Object
Registration identity = Object ID
```

The identity is used to refer to the resource.

---

## Object ID vs Linux inode

Linux may use an inode number to identify a filesystem inode.

HyberKOS Object IDs are broader.

For example:

```text
Object #100 → File
Object #101 → Directory
Object #102 → Process
Object #103 → Socket
Object #104 → Device
```

Therefore:

```text
Hyber Object ID != Linux inode
```

The Linux backend may internally map:

```text
Hyber Object #100
        ↓
Linux inode 82731
```

but this mapping is private.

---

# 12. Nodes

Node is one of the most important concepts in HyberKOS.

## Definition

> A Node is a namespace-visible entry consisting primarily of a name and a reference to an Object.

Example:

```text
Node
├── name = "test.txt"
└── object_id = 123
```

This means:

> There is an entry named `test.txt` here, and that entry refers to Object #123.

---

## Node is NOT:

```text
Node != File
Node != Object
Node != Object ID
Node != Path
Node != Handle
```

Instead:

```text
Path
 ↓
Node
 ↓
Object
```

---

## Example

Suppose:

```text
/users/neo/test.txt
```

exists.

The system can conceptually resolve it as:

```text
/users/neo/test.txt
        ↓
Node("test.txt")
        ↓
Object #123
        ↓
FILE OBJECT
```

---

## Multiple Nodes can reference one Object

This allows hard-link-like semantics.

```text
Node("a.txt") ─────┐
                   │
                   ▼
                Object #123
                   ▲
                   │
Node("backup.txt") ┘
```

The two names can refer to the same underlying Object.

---

# 13. Paths

A Path is a human-readable namespace address.

Example:

```text
/users/neo/documents/report.txt
```

The path itself is not the file.

It is an instruction for namespace resolution.

Conceptually:

```text
Path
 ↓
Namespace traversal
 ↓
Node
 ↓
Object
```

---

## Example

```text
/users/neo/projects/hypercalc/main.py
```

may resolve as:

```text
/
 ↓
users
 ↓
neo
 ↓
projects
 ↓
hypercalc
 ↓
main.py
 ↓
Object #8001
```

Every component is resolved through the namespace.

---

# 14. Files and Directories

## File

A File is an Object whose type is:

```text
FILE
```

Example:

```text
Object #500
type = FILE
size = 1048576
```

The Node may be:

```text
Node:
name = "photo.jpg"
object_id = 500
```

---

## Directory

A Directory is also an Object.

Example:

```text
Object #100
type = DIRECTORY
```

Its contents are Nodes:

```text
Directory Object #100

"photo.jpg"  → Object #500
"test.txt"   → Object #501
"projects"   → Object #600
```

This is important:

> A directory contains namespace entries, not raw files themselves.

---

# 15. Handles

A Handle is a process-local reference/access entry for an Object.

Example:

```text
Process A
└── Handle Table
    └── Handle 7 → Object #123
```

Another process can have:

```text
Process B
└── Handle Table
    └── Handle 4 → Object #123
```

Both processes access the same Object.

---

## Handle example

```text
Process #20

Handle 0
    ↓
Object #10

Handle 1
    ↓
Object #11

Handle 7
    ↓
Object #123
```

The Handle can contain:

```text
handle_id
object_id
rights
flags
state
offset
```

depending on the Object type.

---

## Handles are process-local

For example:

```text
Process A:
Handle 7 → Object #123

Process B:
Handle 7 → Object #900
```

Both are valid.

Handle numbers do not need to be globally unique.

---

## Handle does NOT mean "don't reopen"

If Object #123 is already open:

```text
Process A → Object #123
```

another process can still open it:

```text
Process B → Object #123
```

The system may maintain:

```text
open_refs = 2
```

but that does not prevent additional opens.

The reference count is primarily useful for lifecycle/resource management.

---

# 16. Providers

A Provider is a backend implementation responsible for supplying or managing a class of resources.

Examples:

```text
HostFS Provider
HyberFS Provider
MemFS Provider
Process Provider
Device Provider
Service Provider
Network Provider
```

---

## HostFS Provider

During the Linux-hosted phase:

```text
Hyber VFS
   ↓
HostFS Provider
   ↓
Linux filesystem
```

The Provider translates Hyber operations into Linux operations.

---

## HyberFS Provider

Later:

```text
Hyber VFS
   ↓
HyberFS Provider
   ↓
HyberFS
   ↓
Disk
```

No Linux filesystem is required for persistent storage.

---

## Virtual Providers

Not every namespace needs disk storage.

For example:

```text
/processes
```

can be provided by:

```text
ProcessProvider
```

and:

```text
/devices
```

by:

```text
DeviceProvider
```

---

# 17. VFS

VFS means:

> Virtual File System

In HyberKOS, VFS is more than a traditional filesystem abstraction.

It provides a common namespace/resource interface.

Potential operations include:

```text
lookup
open
close
read
write
seek
create
delete
rename
mkdir
enumerate
mount
unmount
stat
set_metadata
get_metadata
```

---

## VFS does not store files

VFS is an abstraction.

For example:

```text
Application
    ↓
VFS
    ↓
Provider
    ↓
Backend
```

The backend might be:

```text
HyberFS
Linux host filesystem
Memory
Device
Process manager
Service manager
Network subsystem
```

---

# 18. The Relationship Between Everything

This is the core mental model.

## Namespace path

```text
PATH
  ↓
NODE
  ↓
OBJECT
```

Example:

```text
/users/neo/test.txt
       ↓
Node("test.txt")
       ↓
Object #123
       ↓
FILE
```

---

## Process access

```text
PROCESS
  ↓
HANDLE TABLE
  ↓
HANDLE
  ↓
OBJECT
```

Example:

```text
Process #20
    ↓
Handle 7
    ↓
Object #123
```

---

## Backend

```text
OBJECT
  ↓
OBJECT INTERFACE
  ↓
PROVIDER
  ↓
BACKEND
```

---

## Full model

```text
                    PATH
                     │
                     ▼
                 NAMESPACE
                     │
                     ▼
                    NODE
                     │
                     ▼
                   OBJECT
                     ▲
                     │
                   HANDLE
                     ▲
                     │
                  PROCESS


                   OBJECT
                     │
                     ▼
                INTERFACE
                     │
                     ▼
                 PROVIDER
                     │
                     ▼
                  BACKEND
```

This separation is fundamental.

---

# 19. Namespaces

HyberKOS treats namespaces as first-class system concepts.

A namespace is a structured collection of names and references.

Examples:

```text
Filesystem namespace
Process namespace
Device namespace
Service namespace
Network namespace
Package namespace
```

A namespace does not necessarily mean a disk directory.

---

# 20. The HyberKOS Root Namespace

HyberKOS uses:

```text
/
```

as the root of its global namespace.

However:

> `/` is not necessarily the physical root of a disk.

It is the root of the HyberKOS namespace.

This is a critical distinction.

---

## Proposed hierarchy

```text
/
├── system/
├── users/
├── apps/
├── data/
├── config/
├── packages/
├── services/
├── devices/
├── processes/
├── runtime/
├── temporary/
├── volumes/
└── developer/
```

Some entries may be persistent.

Others may be virtual.

---

# 21. Filesystem Architecture

HyberKOS separates:

```text
Namespace
```

from:

```text
Physical storage
```

For example:

```text
/
├── users/
├── processes/
├── devices/
└── services/
```

does not imply that all four are ordinary disk directories.

Instead:

```text
/users
   ↓
persistent filesystem provider

/processes
   ↓
ProcessProvider

/devices
   ↓
DeviceProvider

/services
   ↓
ServiceProvider
```

---

# 22. HyberFS

HyberFS is the planned native filesystem of HyberKOS.

The filesystem is designed around the Hyber object model.

The high-level structure is:

```text
HyberFS
│
├── Superblock
├── Object Store
├── Node / Directory Index
├── Metadata Store
├── Allocation Manager
├── Data Store
├── Journal
└── Optional Indexes
```

---

# 23. HyberFS On-Disk Architecture

## 23.1 Superblock

The Superblock contains global filesystem information.

Possible fields:

```text
magic
version
filesystem_uuid
block_size
total_blocks
feature_flags
object_store_location
metadata_location
data_store_location
journal_location
```

Example:

```text
HyberFS Superblock

magic = HYBERFS
version = 1
block_size = 4096
uuid = ...
features = JOURNAL | CHECKSUM
```

---

## 23.2 Object Store

Persistent Objects can be represented in the Object Store.

Example:

```text
Object #500

type = FILE
owner = neo
size = 12000
permissions = ...
timestamps = ...
metadata_ref = ...
data_ref = ...
```

---

## 23.3 Node / Directory Index

Directories contain mappings:

```text
name → Object ID
```

Example:

```text
Directory Object #100

"test.txt"   → #500
"photo.jpg"  → #501
"projects"   → #600
```

This is the persistent representation of namespace entries.

---

## 23.4 Data Store

The actual file content is stored here.

For example:

```text
Object #500
     ↓
Data Extents
     ↓
Block 1000
Block 1001
Block 1002
```

Large files should use extents rather than a naive one-block-per-pointer design.

---

## 23.5 Metadata Store

The Metadata Store contains:

### Core metadata

```text
object_id
object_type
owner
group
permissions
size
timestamps
flags
```

### Extended metadata

```text
file.mime
file.encoding
security.label
app.creator
user.*
```

---

## 23.6 Allocation Manager

The Allocation Manager tracks:

```text
free blocks
used blocks
extents
allocation groups
fragmentation
```

Potential future strategies:

* bitmaps
* extent trees
* allocation groups
* delayed allocation

---

## 23.7 Journal

The Journal exists to improve crash consistency.

Example operation:

```text
rename A → B
```

The system must avoid leaving the filesystem in a corrupt intermediate state if power is lost.

---

## 23.8 Future Copy-on-Write

A future HyberFS version may support:

```text
Copy-on-Write
Snapshots
Versioned metadata
Atomic snapshots
```

These should be considered extensions rather than requirements for the first prototype.

---

# 24. Metadata Architecture

Metadata is divided into three major categories.

## 24.1 Core Persistent Metadata

Examples:

```text
object_id
object_type
owner
permissions
size
timestamps
flags
storage references
```

---

## 24.2 Extensible Metadata

Examples:

```text
file.mime = "text/plain"
file.encoding = "utf-8"

security.label = "user-data"

app.creator = "hyber-editor"

user.favorite = true
```

The system should support namespaces for metadata.

---

## 24.3 Runtime Metadata

Examples:

```text
process.state
cpu_usage
thread.state
socket.state
```

Runtime state normally should not be persisted as ordinary filesystem metadata.

---

# 25. Persistent and Runtime Objects

HyberKOS distinguishes between persistent and runtime resources.

## Persistent Objects

Examples:

```text
File
Directory
Symlink
Package
Persistent Configuration
Persistent Database
```

These can be represented by HyberFS.

---

## Runtime Objects

Examples:

```text
Process
Thread
Socket
Pipe
IPC endpoint
Service instance
Device instance
```

These usually exist in memory/runtime.

They can nevertheless be exposed through virtual namespaces.

For example:

```text
/processes/123
```

could represent:

```text
Process Object #8000
```

without there being an actual disk file.

---

# 26. Language Architecture

HyberKOS is deliberately multi-language.

No single language should dominate the entire architecture.

---

## Language map

| Language        | Main Role                                                    |
| --------------- | ------------------------------------------------------------ |
| Rust            | Kernel/core/system infrastructure                            |
| C               | Low-level compatibility, firmware, drivers, system libraries |
| Assembly        | CPU-specific low-level code                                  |
| C++             | High-performance applications, GUI, complex native software  |
| Lua             | Initial embedded scripting/runtime                           |
| Python          | Automation, tooling, development utilities                   |
| Go              | Networking and standalone system services/tools              |
| Java            | JVM applications                                             |
| Kotlin          | JVM applications and modern application development          |
| JavaScript      | Application/UI ecosystem                                     |
| TypeScript      | Structured application/UI development                        |
| React           | GUI/application frontend                                     |
| HyberLang       | Future native language                                       |
| Other languages | Through Hyber API/ABI                                        |

---

# 27. Language-Neutral System Design

The core rule is:

> The operating system does not care which language an application was written in.

For example:

```text
Lua App
   ↓
Hyber API
```

and:

```text
Rust App
   ↓
Hyber API
```

and:

```text
C++ App
   ↓
Hyber API
```

should ultimately reach the same operating-system abstractions.

---

## Incorrect architecture

```text
Lua
 ↓
Linux
```

or:

```text
Python
 ↓
Linux
```

as the public architecture.

---

## Correct architecture

```text
Lua
 └──┐
Rust ├──→ Hyber API → Hyber Core
C++ ┤
Go  ┤
Python
JS/TS
Java/Kotlin
```

The API is the boundary.

---

# 28. Kernel Architecture

The future native kernel should be independent of user applications.

Initial target:

```text
Rust
C
Assembly
```

---

## Assembly

Used where direct CPU control is necessary:

* boot entry
* context switching
* interrupt entry
* CPU initialization
* architecture-specific instructions
* low-level synchronization
* special register manipulation

---

## Rust

Primary systems implementation language.

Potential components:

```text
memory manager
scheduler
object manager
IPC
VFS
security
process manager
drivers
```

Rust provides memory-safety advantages for large portions of the kernel.

---

## C

C remains useful for:

* hardware-facing components
* existing low-level libraries
* firmware interfaces
* interoperability
* architecture-specific components

---

# 29. Hyber Core

Hyber Core sits between the kernel/backend and higher-level components.

Conceptually:

```text
Kernel / Backend
       ↓
Hyber Core
       ↓
Object / Namespace / VFS / Security
```

The Core defines system semantics.

---

# 30. Object Manager

The Object Manager is responsible for system Objects.

Potential responsibilities:

```text
create_object
destroy_object
lookup_object
reference_object
release_object
get_object_type
get_object_metadata
```

Example:

```text
create_file()
      ↓
Object Manager
      ↓
Object #123
```

---

## Object types

Possible enumeration:

```text
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
```

Future types can be added.

---

# 31. Namespace and Node Manager

This component manages:

```text
names
nodes
parent-child relationships
namespace traversal
mount points
aliases
links
```

Example:

```text
/users/neo/test.txt
```

is resolved through the Namespace Manager.

Conceptually:

```text
lookup("/")
 ↓
lookup("users")
 ↓
lookup("neo")
 ↓
lookup("test.txt")
 ↓
Node
 ↓
Object
```

---

# 32. Handle and Capability Manager

Handles provide controlled access to Objects.

A Handle may include:

```text
object reference
rights
flags
state
```

Example:

```text
Handle 7
Object #123
Rights = READ | WRITE
```

---

## Capability-oriented design

Future HyberKOS may use capability-style security.

For example:

```text
Handle → Object + Rights
```

Instead of merely saying:

> "Process can access Object."

the system can say:

> "Process has this specific Handle with these specific rights."

Possible rights:

```text
READ
WRITE
EXECUTE
DELETE
RENAME
ENUMERATE
CONNECT
SIGNAL
WAIT
ADMIN
```

Different Object types can support different rights.

---

# 33. Process and Thread Architecture

A Process is an Object.

A Thread is also an Object.

Conceptually:

```text
Process Object
├── Thread Object
├── Thread Object
├── Address Space
├── Handle Table
├── Security Context
└── Process Metadata
```

---

## Process namespace

The system may expose:

```text
/processes/
```

through a ProcessProvider.

Example:

```text
/processes/100
/processes/101
/processes/102
```

These are namespace entries representing Process Objects.

They are not ordinary disk files.

---

# 34. Memory Architecture

The future kernel should manage:

```text
physical memory
virtual memory
address spaces
page tables
memory mappings
shared memory
memory protection
allocation
```

Applications should not directly depend on the physical memory implementation.

A Hyber memory API can later expose:

```text
allocate
map
unmap
protect
share
```

---

# 35. IPC Architecture

Inter-process communication is a core subsystem.

Possible mechanisms:

```text
pipes
channels
message queues
shared memory
sockets
events
signals
RPC
```

The Object model should make these resources first-class Objects.

For example:

```text
Pipe Object
Socket Object
Channel Object
SharedMemory Object
```

---

## Example

```text
Process A
   ↓
Handle 5
   ↓
Channel Object #900

Channel Object
   ↑
Handle 3
   ↑
Process B
```

---

# 36. Device Architecture

Devices should be represented through Objects.

Example:

```text
Device Object
├── type
├── capabilities
├── metadata
├── state
└── provider
```

Namespace:

```text
/devices/
├── storage/
├── network/
├── input/
├── display/
└── audio/
```

Example:

```text
/devices/storage/nvme0
```

might resolve to:

```text
Node
 ↓
Device Object
 ↓
NVMe Provider
 ↓
Kernel Driver
 ↓
Hardware
```

---

# 37. Networking Architecture

Networking should expose language-neutral APIs.

Potential components:

```text
Network Manager
Socket Manager
Interface Manager
Routing
DNS
Firewall
TLS
Network Providers
```

Example:

```text
Application
 ↓
Hyber Network API
 ↓
Socket Object
 ↓
Network Provider
 ↓
Kernel network subsystem
```

---

# 38. Service Architecture

Services are first-class system resources.

Examples:

```text
network
audio
display
storage
package-manager
logging
authentication
```

Namespace:

```text
/services/
```

Example:

```text
/services/network
```

may represent a Service Object.

---

## Service manager responsibilities

```text
start
stop
restart
status
dependencies
health
permissions
logs
```

---

# 39. Package Architecture

Applications should not merely be copied into random directories.

Packages should be first-class concepts.

Potential package metadata:

```text
package.id
package.name
package.version
package.dependencies
package.entrypoint
package.permissions
package.publisher
package.signature
```

Namespace:

```text
/packages/
├── installed/
├── cache/
├── repositories/
└── metadata/
```

Installed application resources may appear under:

```text
/apps/
```

---

# 40. Shell Architecture

HyberKOS should have a native shell.

Potential name:

```text
hyber-shell
```

The shell should interact with Hyber abstractions.

Example:

```text
ls /users/neo
```

internally:

```text
Shell
 ↓
Hyber API
 ↓
VFS
 ↓
Namespace Manager
 ↓
Directory Object
 ↓
Nodes
```

It should not require the shell to understand Linux `/proc`, Linux FDs, or Linux-specific paths.

---

# 41. GUI Architecture

GUI should be separate from the kernel.

Potential architecture:

```text
GUI Applications
       ↓
Hyber GUI API
       ↓
Window Manager / Display Server
       ↓
Hyber Core
       ↓
Kernel
```

Possible implementation languages:

```text
Rust
C++
TypeScript
JavaScript
```

React can be used for applications or UI layers where appropriate.

---

# 42. Application Architecture

An application can be:

* native binary
* interpreted program
* bytecode program
* script
* service
* GUI application

Examples:

```text
calculator
terminal
browser
editor
file manager
chess engine
network tool
OSINT tool
```

The OS should not care which language produced it.

---

# 43. Lua Runtime

Lua is the initial scripting language because it is:

* lightweight
* embeddable
* simple
* suitable for system scripting
* useful during early development

A possible implementation is:

```text
Hyber Lua Runtime
        ↓
Lua VM
        ↓
Hyber API bindings
        ↓
Hyber Core
```

---

## Example

A Lua application:

```lua
local file = hyber.open("/users/neo/test.txt")
local data = file:read()
print(data)
file:close()
```

The Lua layer should translate these calls into Hyber API operations.

Conceptually:

```text
Lua
 ↓
Lua binding
 ↓
Hyber API
 ↓
Handle
 ↓
Object
```

Lua must not become the architecture itself.

---

# 44. C and C++

## C

C is appropriate for:

* low-level libraries
* hardware interfaces
* compatibility layers
* firmware-related code
* legacy interoperability

---

## C++

C++ is appropriate for:

* GUI
* high-performance applications
* complex native software
* game engines
* scientific software
* applications requiring existing C++ ecosystems

---

## Example

```text
C++ Application
      ↓
Hyber C/C++ API
      ↓
Hyber ABI
      ↓
Hyber Core
```

---

# 45. Rust

Rust is expected to be the primary systems-development language.

Potential components:

```text
Hyber Core
Hyber VFS
Object Manager
Process Manager
Security
IPC
Network Services
System Tools
Drivers
```

Rust should also be available to application developers.

---

# 46. Assembly

Assembly is reserved for places where direct architecture control is necessary.

Examples:

```text
boot
interrupt stubs
context switching
CPU initialization
special instructions
atomic primitives
architecture-specific memory operations
```

Assembly should not be used for ordinary high-level system logic.

---

# 47. Python

Python is primarily intended for:

* development tools
* automation
* testing
* build scripts
* system administration utilities
* data processing
* AI tooling

Python applications can still access the Hyber API.

---

# 48. Go

Go is particularly suitable for:

* network services
* daemons
* standalone tools
* infrastructure utilities
* concurrent services

Example:

```text
Go Service
 ↓
Hyber API
 ↓
Service Manager
```

---

# 49. Java and Kotlin

Java and Kotlin applications can operate through a JVM runtime.

Architecture:

```text
Java/Kotlin
     ↓
JVM
     ↓
Hyber JVM integration
     ↓
Hyber API
```

The JVM itself is an application/runtime layer.

It is not part of the kernel.

---

# 50. JavaScript, TypeScript and React

These languages are suitable for:

* GUI applications
* developer tools
* web-oriented applications
* desktop-like interfaces
* frontend components

Example:

```text
React
 ↓
TypeScript
 ↓
Hyber UI Runtime
 ↓
Hyber API
```

The exact GUI technology is intentionally not permanently frozen.

---

# 51. Future HyberLang

HyberLang is a possible future native language.

The language should be designed after the OS architecture becomes mature.

Potential goals:

* direct Hyber API support
* strong typing
* systems programming
* safe memory model
* native binaries
* excellent tooling
* direct Object/Handle abstractions

However:

> HyberLang must not be required for HyberKOS to function.

The OS must already support other languages.

---

# 52. Compilation and Execution Model

A generic application pipeline:

```text
Source Code
    ↓
Compiler / Interpreter
    ↓
Native Binary / Bytecode / Script
    ↓
Hyber Runtime
    ↓
Hyber API
    ↓
Hyber Core
    ↓
Kernel
```

---

## Native example

```text
C/Rust/C++
     ↓
Compiler
     ↓
Hyber executable
     ↓
Process Object
     ↓
Handles
     ↓
Hyber Core
```

---

## Script example

```text
Lua
 ↓
Lua Runtime
 ↓
Hyber API
 ↓
Process Object
```

---

# 53. Linux Host Architecture

The first implementation will run on Linux.

Architecture:

```text
Linux
  ↓
Hyber Host Layer
  ↓
Hyber Core
  ↓
Hyber VFS
  ↓
Providers
  ↓
Applications
```

More precisely:

```text
Lua / Rust / C++ / Python / etc.
              ↓
          Hyber API
              ↓
          Hyber Core
              ↓
        Hyber Object Model
              ↓
             VFS
              ↓
        HostFS Provider
              ↓
        Linux system calls
              ↓
         Linux kernel
              ↓
           Hardware
```

---

# 54. Future Native Kernel Architecture

Eventually:

```text
Applications
     ↓
Hyber API
     ↓
Hyber Core
     ↓
Hyber VFS
     ↓
HyberFS Provider
     ↓
Hyber Kernel
     ↓
Drivers
     ↓
Hardware
```

The public architecture remains mostly unchanged.

Only the backend changes substantially.

---

# 55. Migration Strategy

The migration from Linux-hosted HyberKOS to native HyberKOS should happen gradually.

## Stage 1

```text
Linux
 ↓
Hyber Host
```

---

## Stage 2

Move more functionality into Hyber:

```text
Linux
 ↓
Hyber Kernel Abstraction
 ↓
Hyber Core
```

---

## Stage 3

Build a minimal native kernel:

```text
Boot
Memory
Interrupts
Scheduler
IPC
Object Manager
```

---

## Stage 4

Implement native VFS:

```text
Hyber Kernel
 ↓
Hyber VFS
```

---

## Stage 5

Implement HyberFS:

```text
Hyber VFS
 ↓
HyberFS
 ↓
Disk
```

---

## Stage 6

Move userland to the native environment.

---

## Stage 7

Reduce Linux dependency until:

```text
Linux
```

is no longer required.

---

# 56. Security Architecture

Security must exist at multiple layers.

```text
Hardware
 ↓
Kernel
 ↓
Object Security
 ↓
Handle Rights
 ↓
Process Isolation
 ↓
Namespace Isolation
 ↓
Service Security
 ↓
Application Permissions
```

---

## Security principles

* least privilege
* explicit permissions
* object-based access
* capability-style handles
* process isolation
* secure IPC
* signed packages
* secure boot support in future
* filesystem integrity
* audit logging

---

# 57. Permissions and Access Control

A File Object may have:

```text
owner
group
permissions
ACL
security label
```

Example:

```text
Object #500

owner = neo

READ   = yes
WRITE  = yes
EXECUTE = no
```

Handles can additionally restrict access.

Example:

```text
Handle 7
Object #500
Rights = READ
```

Even if the Object supports writing, the Handle may only grant:

```text
READ
```

This creates an additional security boundary.

---

# 58. Storage and Data Integrity

HyberFS should eventually support:

* block checksums
* metadata checksums
* data integrity verification
* journaling
* atomic operations
* corruption detection
* recovery
* snapshots
* optional encryption
* quotas
* sparse files
* extents
* compression

These features should be implemented incrementally.

---

# 59. Crash Consistency

Filesystem operations must be designed around failure.

Example:

```text
Create file
 ↓
Allocate Object
 ↓
Create Node
 ↓
Allocate data
 ↓
Write metadata
```

If power is lost halfway through, the filesystem must be able to recover.

Potential mechanisms:

```text
journal
transaction records
checksums
atomic metadata updates
orphan cleanup
recovery scan
```

---

# 60. Snapshots and Future Features

Future HyberFS may support:

```text
snapshot
restore
rollback
versioning
copy-on-write
deduplication
compression
transparent encryption
integrity trees
filesystem cloning
```

These should not complicate the first prototype unnecessarily.

The architecture should leave room for them.

---

# 61. Repository Architecture

The source repository should be modular.

Possible structure:

```text
ApexForge_HyberKOS/
│
├── README.md
├── VISION.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
│
├── docs/
│
├── crates/
│   ├── hyber-core/
│   ├── hyber-api/
│   ├── hyber-object/
│   ├── hyber-namespace/
│   ├── hyber-handle/
│   ├── hyber-vfs/
│   ├── hyber-process/
│   ├── hyber-ipc/
│   ├── hyber-security/
│   ├── hyber-net/
│   ├── hyber-device/
│   ├── hyber-service/
│   ├── hyber-package/
│   ├── hyber-runtime/
│   ├── hyber-lua/
│   └── hyber-shell/
│
├── fs/
│   └── hyberfs/
│
├── kernel/
│   ├── arch/
│   ├── memory/
│   ├── interrupts/
│   ├── scheduler/
│   └── drivers/
│
├── backends/
│   ├── linux/
│   └── native/
│
├── applications/
│   ├── terminal/
│   ├── file-manager/
│   ├── editor/
│   └── settings/
│
├── tools/
│
├── tests/
│
└── examples/
```

This structure is provisional.

The exact repository layout may evolve.

---

# 62. Development Environment

The Linux-hosted development environment should make it possible to build HyberKOS without requiring a native kernel.

For example:

```text
Linux
 └── ApexForge_HyberKOS
      ├── Hyber Core
      ├── Hyber VFS
      ├── HostFS
      └── Applications
```

Later, QEMU or another virtualization environment can be used for native-kernel testing.

---

# 63. Example System Operations

## 63.1 Opening a file

Application requests:

```text
open("/users/neo/test.txt", READ)
```

Flow:

```text
Application
 ↓
Hyber API
 ↓
VFS
 ↓
Namespace Manager
 ↓
Node("test.txt")
 ↓
Object #123
 ↓
Security check
 ↓
Handle Manager
 ↓
Handle 7
 ↓
Application
```

Result:

```text
Handle 7
```

The application uses Handle 7 for subsequent operations.

---

# 63.2 Reading the file

```text
read(7)
```

Flow:

```text
Handle 7
 ↓
Object #123
 ↓
FILE interface
 ↓
Provider
 ↓
Storage
```

---

# 63.3 Creating a file

Request:

```text
create("/users/neo/test.txt")
```

Flow:

```text
Path
 ↓
Parent Directory
 ↓
Namespace Manager
 ↓
Create File Object
 ↓
Object #900
 ↓
Create Node("test.txt")
 ↓
Directory updated
```

Result:

```text
Node("test.txt")
       ↓
Object #900
```

---

# 63.4 Launching an application

Suppose:

```text
/apps/editor
```

is an application.

Flow:

```text
Application Launcher
 ↓
Package/Application Object
 ↓
Executable
 ↓
Process Manager
 ↓
Process Object
 ↓
Thread Object
 ↓
Handle Table
 ↓
Application running
```

---

# 63.5 Accessing a process

User executes:

```text
list /processes
```

Flow:

```text
Shell
 ↓
VFS
 ↓
ProcessProvider
 ↓
Process Objects
 ↓
Nodes
 ↓
Output
```

No physical files are necessary.

---

# 63.6 Accessing a device

User executes:

```text
inspect /devices/network
```

Flow:

```text
Path
 ↓
Node
 ↓
Device Object
 ↓
Device Provider
 ↓
Driver
 ↓
Hardware
```

---

# 63.7 Starting a service

```text
service start network
```

Flow:

```text
Shell
 ↓
Service Manager
 ↓
Service Object
 ↓
Process Manager
 ↓
Process Object
 ↓
Network subsystem
```

---

# 63.8 Installing a package

Example:

```text
hyber install editor
```

Flow:

```text
Package Manager
 ↓
Repository
 ↓
Package verification
 ↓
Dependency resolution
 ↓
Package installation
 ↓
Application Object
 ↓
/apps/editor
```

Security checks occur before activation.

---

# 64. Design Invariants

These rules should remain stable unless the architecture is deliberately redesigned.

## Invariant 1

```text
Path != Node
```

---

## Invariant 2

```text
Node != Object
```

---

## Invariant 3

```text
Object ID != Object
```

---

## Invariant 4

```text
Handle != Object
```

---

## Invariant 5

```text
VFS != Filesystem
```

---

## Invariant 6

```text
Provider != Object
```

---

## Invariant 7

Linux identifiers must not become public Hyber identifiers.

Therefore:

```text
Hyber Object ID != Linux inode
Hyber Process ID != Linux PID
Hyber Handle != Linux FD
```

---

## Invariant 8

The public Hyber API must not require Linux-specific behavior.

---

## Invariant 9

Lua must remain an application/runtime layer.

---

## Invariant 10

The kernel should not need to understand every application programming language.

---

# 65. Development Phases

## Phase 0 — Architecture

Define:

```text
Object
Node
Path
Handle
Provider
VFS
Security
```

No premature kernel complexity.

---

## Phase 1 — Host Runtime

Implement:

```text
Hyber Core
Object Manager
Namespace Manager
VFS
HostFS Provider
Handle Manager
```

Run on Linux.

---

## Phase 2 — Hyber Shell

Build:

```text
hyber-shell
```

with basic commands:

```text
ls
cd
open
cat
mkdir
create
remove
move
copy
processes
devices
services
```

---

## Phase 3 — Lua Runtime

Implement:

```text
Hyber Lua
```

with APIs for:

```text
filesystem
processes
IPC
networking
services
metadata
```

---

## Phase 4 — HyberFS Prototype

Implement:

```text
Superblock
Object Store
Directory Index
Metadata
Allocation
Data Store
Journal
```

Initially on a disk image.

---

## Phase 5 — Native Kernel Prototype

Start:

```text
Boot
 ↓
CPU initialization
 ↓
Memory
 ↓
Interrupts
 ↓
Scheduler
 ↓
Processes
```

---

## Phase 6 — Native Object Model

Move:

```text
Object Manager
Handle Manager
IPC
```

into the native kernel/core architecture.

---

## Phase 7 — Native VFS

Implement Hyber VFS directly on the native kernel.

---

## Phase 8 — Native HyberFS

Remove dependence on Linux filesystems.

---

## Phase 9 — Userland

Port:

```text
Shell
Runtime
Package Manager
Services
Applications
```

---

## Phase 10 — Self-Hosting

HyberKOS should eventually be capable of building significant portions of itself.

Goal:

```text
HyberKOS
 ↓
Compiler
 ↓
HyberKOS
```

---

# 66. Risks and Tradeoffs

## Complexity

A custom operating system is extremely complex.

Therefore architecture must be modular.

---

## Performance

Abstraction layers can introduce overhead.

The system should therefore distinguish:

```text
Public abstraction
```

from:

```text
internal optimized implementation
```

An abstraction does not require inefficient implementation.

---

## Compatibility

Supporting many languages increases complexity.

The solution is a stable ABI/API.

---

## Filesystem complexity

HyberFS should not attempt every advanced feature immediately.

The first version should prioritize:

```text
correctness
integrity
simplicity
recoverability
```

over maximum performance.

---

## Kernel complexity

The kernel should remain small where possible.

Complex functionality can live in user-space services when the architecture permits.

---

# 67. Future Extensions

Potential future components include:

```text
Hyber Secure Boot
Hyber Cryptography Framework
Hyber Container System
Hyber Virtual Machines
Hyber Package Registry
Hyber Developer SDK
Hyber GUI Toolkit
Hyber Cloud Runtime
Hyber Distributed Objects
Hyber Network Namespace
Hyber Containers
Hyber Sandbox
Hyber AI Runtime
Hyber Observability Framework
Hyber System Tracing
Hyber Performance Profiler
Hyber Debugger
HyberFS Snapshots
HyberFS Encryption
HyberFS Compression
HyberFS Deduplication
```

---

# 68. Final Architectural Model

The final conceptual model of ApexForge_HyberKOS is:

```text
                         ┌───────────────────────┐
                         │     APPLICATIONS      │
                         │                       │
                         │ Lua / Rust / C / C++  │
                         │ Python / Go / JS / TS │
                         │ Java / Kotlin / etc.  │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │     HYBER API/ABI     │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │    RUNTIME LAYERS     │
                         │ Lua / JVM / JS / etc. │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │      HYBER CORE       │
                         └───────────┬───────────┘
                                     │
             ┌───────────────────────┼────────────────────────┐
             │                       │                        │
             ▼                       ▼                        ▼
      Object Manager          Process Manager          Security
             │                       │                        │
             └───────────────────────┼────────────────────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ NAMESPACE / NODE MGR  │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │      HYBER VFS        │
                         └───────────┬───────────┘
                                     │
                       ┌─────────────┼─────────────┐
                       │             │             │
                       ▼             ▼             ▼
                  HyberFS        HostFS       Virtual Providers
                       │             │             │
                       ▼             ▼             ▼
                     Disk         Linux       Runtime Resources
```

---

# Core Mental Model

The entire system can be remembered through three simple relationships.

## Namespace

```text
PATH
  ↓
NODE
  ↓
OBJECT
```

Example:

```text
/users/neo/test.txt
        ↓
   Node("test.txt")
        ↓
     Object #123
        ↓
       FILE
```

---

## Process access

```text
PROCESS
  ↓
HANDLE TABLE
  ↓
HANDLE
  ↓
OBJECT
```

Example:

```text
Process #50
     ↓
Handle 7
     ↓
Object #123
```

---

## Backend

```text
OBJECT
  ↓
INTERFACE
  ↓
PROVIDER
  ↓
BACKEND
```

Example:

```text
Object #123
     ↓
File Interface
     ↓
HostFS Provider
     ↓
Linux filesystem
```

Later:

```text
Object #123
     ↓
File Interface
     ↓
HyberFS Provider
     ↓
HyberFS
     ↓
Disk
```

---

# The Most Important Architectural Idea

ApexForge_HyberKOS is not fundamentally:

```text
"Linux with a different shell."
```

It is not:

```text
"Lua running on Linux."
```

It is not:

```text
"Another filesystem on Linux."
```

The actual long-term idea is:

```text
                    HYBERKOS
                       │
       ┌───────────────┼────────────────┐
       │               │                │
    Objects        Namespaces        Processes
       │               │                │
    Handles           Nodes          Handles
       │               │                │
       └───────────────┼────────────────┘
                       │
                    HYBER VFS
                       │
                   PROVIDERS
                       │
             ┌─────────┴─────────┐
             │                   │
          HyberFS             Backend
             │                   │
            Disk               Linux
```

Linux is the first backend.

HyberFS is the future native storage layer.

Hyber Core is the semantic center.

Objects are the fundamental resources.

Nodes connect names to Objects.

Paths locate Nodes.

Handles give processes controlled access to Objects.

Providers connect Hyber abstractions to implementations.

VFS provides the common interface.

Languages communicate through the Hyber API/ABI.

And eventually:

```text
Hardware
   ↓
HyberKOS Kernel
   ↓
HyberKOS Core
   ↓
Hyber VFS
   ↓
HyberFS
   ↓
Applications
```

becomes the complete native operating system.

---

# Architectural North Star

The final design principle of ApexForge_HyberKOS is:

> **Define the operating system in terms of HyberKOS concepts first, and define platform-specific implementations second.**

Therefore the project should always ask:

```text
"What does HyberKOS mean?"
```

before:

```text
"How does Linux do this?"
```

Linux is useful for implementation knowledge.

Linux must not dictate the identity of HyberKOS.

---

# Status of This Vision

The following are considered foundational architectural decisions:

* HyberKOS has its own Object model.
* Object IDs are separate from backend identifiers.
* Node represents a namespace entry referencing an Object.
* Path resolves through Nodes to Objects.
* Handles provide process-local access to Objects.
* Providers implement resource backends.
* VFS is separated from concrete filesystems.
* `/` is the root of the HyberKOS namespace.
* `/processes`, `/devices`, and `/services` can be virtual namespaces.
* HyberFS is the planned native filesystem.
* Linux is an initial backend rather than the final system identity.
* Rust, C, and Assembly form the low-level foundation.
* Lua is an initial scripting/runtime environment.
* C++, Python, Go, Java, Kotlin, JavaScript, TypeScript, React and other languages may be supported at appropriate layers.
* HyberLang may become a future native language.
* The public API/ABI must remain language-neutral.
* Native-kernel migration must not require redesigning the entire application architecture.

Some implementation details remain intentionally open.

They should be frozen only after prototypes, benchmarks, security analysis, and filesystem experiments validate them.

---

# End

**ApexForge_HyberKOS**

> *Build the abstractions first.
> Build the implementation second.
> Keep the architecture independent.
> Make the system understandable.
> Make the system yours.*
