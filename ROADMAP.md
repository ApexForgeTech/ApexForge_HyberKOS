# ApexForge_HyberKOS

# Detailed Development Roadmap

> **Status:** Development Roadmap
> **Project:** ApexForge_HyberKOS
> **Purpose:** Transform the HyberKOS architecture defined in `VISION.md` into a working operating-system platform.

---

# 0. How to Use This Roadmap

This roadmap is intentionally sequential.

Do **not** jump directly into:

* kernel development
* bootloader development
* filesystem optimization
* GUI
* networking
* multiple language runtimes
* drivers

before the foundational architecture has been validated.

The project should evolve through this general path:

```text
Architecture
    ↓
Repository
    ↓
Core abstractions
    ↓
Object system
    ↓
Namespace / Node system
    ↓
Handle system
    ↓
VFS
    ↓
Linux Host Backend
    ↓
Applications
    ↓
HyberFS
    ↓
Process / IPC / Services
    ↓
Native Kernel
    ↓
Native VFS
    ↓
Native HyberFS
    ↓
Self-hosting
```

The most important rule is:

> **Do not implement a future feature until the abstraction it depends on is sufficiently stable.**

---

# 1. Phase 0 — Project Foundation

## Objective

Create the repository, development environment, documentation structure, build system and engineering rules.

At the end of this phase:

```text
ApexForge_HyberKOS/
```

must exist as a clean, buildable project.

No operating-system functionality is required yet.

---

## 1.1 — Create the Repository

Create:

```text
ApexForge_HyberKOS/
```

Initialize Git.

Recommended initial files:

```text
README.md
VISION.md
ROADMAP.md
LICENSE
CONTRIBUTING.md
SECURITY.md
.gitignore
```

---

## 1.2 — Define Repository Structure

Create the initial structure:

```text
ApexForge_HyberKOS/
│
├── README.md
├── VISION.md
├── ROADMAP.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
│
├── docs/
│
├── crates/
│
├── kernel/
│
├── fs/
│
├── backends/
│
├── applications/
│
├── tools/
│
├── tests/
│
└── examples/
```

Do not fill everything immediately.

Create directories only when needed.

---

# 1.3 — Development Toolchain

Primary development environment:

```text
Linux
Rust
Cargo
Git
C compiler
CMake where necessary
NASM
LLVM/Clang
GCC
QEMU
GDB
objdump
readelf
```

Later:

```text
Python
Node.js
TypeScript
Lua
Go
JDK
Kotlin
```

Do not install every runtime before it is needed.

---

# 1.4 — Rust Workspace

Create a Cargo workspace.

Initial packages:

```text
crates/
├── hyber-core/
├── hyber-object/
├── hyber-namespace/
├── hyber-handle/
├── hyber-vfs/
└── hyber-api/
```

At this stage these can contain almost no logic.

The purpose is to establish boundaries.

---

# 1.5 — Documentation Rules

Create:

```text
docs/
├── architecture/
├── design/
├── filesystem/
├── kernel/
├── api/
├── security/
└── development/
```

Important architectural decisions should be documented.

Example:

```text
docs/design/object-model.md
docs/design/namespace-model.md
docs/design/handle-model.md
docs/filesystem/hyberfs-design.md
```

---

# 1.6 — Phase 0 Exit Criteria

Do not move forward until:

* Git repository exists.
* Rust workspace builds.
* Basic tests run.
* Documentation structure exists.
* `VISION.md` exists.
* `ROADMAP.md` exists.
* Repository builds from a clean checkout.

Target:

```text
cargo build
cargo test
```

both succeed.

---

# 2. Phase 1 — Formalize the HyberKOS Type System

## Objective

Before implementing behavior, define the fundamental types.

This is the first actual HyberKOS engineering phase.

---

# 2.1 — Define Object Types

Create:

```text
ObjectType
```

Possible initial values:

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

Do not implement every Object yet.

Start with:

```text
FILE
DIRECTORY
```

Then add runtime Objects gradually.

---

# 2.2 — Define Object ID

Create a type conceptually equivalent to:

```text
ObjectId
```

Do NOT simply use:

```text
u64
```

everywhere.

Create a strong type around it.

Conceptually:

```text
ObjectId(123)
```

rather than:

```text
123
```

This prevents accidentally confusing:

```text
ObjectId
ProcessId
HandleId
NodeId
```

---

# 2.3 — Define Process ID

Create:

```text
ProcessId
```

Even if the Linux backend internally uses Linux PIDs.

Never expose Linux PIDs directly.

---

# 2.4 — Define Handle ID

Create:

```text
HandleId
```

This is process-local.

Example:

```text
Process A
HandleId(7)

Process B
HandleId(7)
```

both may exist.

---

# 2.5 — Define Node

Create the initial Node structure.

Conceptually:

```text
Node {
    name
    object_id
}
```

Do not over-engineer it.

The first goal is:

```text
name → ObjectId
```

---

# 2.6 — Define Path

Create:

```text
Path
PathComponent
```

Support:

```text
/
/users
/users/neo
/users/neo/test.txt
```

Later add:

```text
.
..
relative paths
absolute paths
normalization
escaping
```

---

# 2.7 — Define Rights

Create:

```text
Rights
```

Initial values:

```text
READ
WRITE
EXECUTE
DELETE
RENAME
ENUMERATE
CONNECT
WAIT
SIGNAL
```

Do not implement complex capability security yet.

Only define the model.

---

# 2.8 — Define Object State

Objects may need lifecycle states.

For example:

```text
LIVE
CLOSING
DESTROYED
```

Runtime Objects can later have specialized states.

---

# 2.9 — Phase 1 Exit Criteria

You should now be able to represent:

```text
ObjectId
ProcessId
HandleId
Node
Path
ObjectType
Rights
```

without depending on Linux.

This is the first major architectural milestone.

---

# 3. Phase 2 — Object Manager

## Objective

Build the first actual HyberKOS subsystem.

The Object Manager owns the lifecycle of Objects.

---

# 3.1 — Object Registry

Create:

```text
ObjectManager
```

It should support:

```text
create
lookup
reference
release
destroy
```

---

# 3.2 — Object Storage

Initially use an in-memory structure.

Example:

```text
HashMap<ObjectId, Object>
```

Do not optimize prematurely.

---

# 3.3 — Object Creation

Implement:

```text
create_object(ObjectType)
```

Example:

```text
create_object(FILE)
```

returns:

```text
ObjectId(100)
```

---

# 3.4 — Object Lookup

Implement:

```text
get_object(ObjectId)
```

Example:

```text
ObjectId(100)
       ↓
ObjectManager
       ↓
File Object
```

---

# 3.5 — Object References

Implement reference tracking.

Example:

```text
Object #100
references = 3
```

Operations:

```text
retain()
release()
```

---

# 3.6 — Object Destruction

When an Object reaches its final reference:

```text
references = 0
```

the Object may become eligible for destruction.

Do not immediately assume every Object follows exactly the same lifecycle.

Filesystem persistence and runtime lifetime will later differ.

---

# 3.7 — Object Metadata

Implement minimal metadata:

```text
object_id
object_type
created_at
modified_at
flags
```

Later add:

```text
owner
permissions
ACL
size
storage_reference
extended_metadata
```

---

# 3.8 — Object Interfaces

Do not make every Object implement every operation.

Create conceptual interfaces.

Example:

```text
Readable
Writable
Seekable
Enumerable
Connectable
Waitable
Signalable
```

Example:

```text
File
 ├── Readable
 ├── Writable
 └── Seekable
```

Directory:

```text
Directory
 ├── Enumerable
 └── Lookupable
```

---

# 3.9 — Phase 2 Exit Criteria

You must be able to:

```text
Create Object
 ↓
Receive ObjectId
 ↓
Lookup Object
 ↓
Reference Object
 ↓
Release Object
 ↓
Destroy Object
```

without Linux.

---

# 4. Phase 3 — Namespace and Node Manager

## Objective

Create the system's namespace.

This phase transforms:

```text
Object
```

into something addressable.

---

# 4.1 — Namespace Root

Create:

```text
/
```

as the root namespace.

Create a root Directory Object.

Example:

```text
Object #1
type = DIRECTORY
```

---

# 4.2 — Node Storage

Implement:

```text
Directory Object
    ↓
Node Map
```

Example:

```text
"users" → Object #10
"apps"  → Object #20
"data"  → Object #30
```

---

# 4.3 — Create Node

Implement:

```text
create_node(parent, name, object_id)
```

Example:

```text
create_node(
    root,
    "users",
    ObjectId(10)
)
```

---

# 4.4 — Lookup Node

Implement:

```text
lookup(parent, "users")
```

Result:

```text
Node
name = users
object_id = 10
```

---

# 4.5 — Path Resolution

Implement:

```text
resolve("/users/neo/test.txt")
```

Flow:

```text
/
 ↓
users
 ↓
neo
 ↓
test.txt
```

Final result:

```text
ObjectId
```

---

# 4.6 — Relative Paths

Implement:

```text
.
..
```

Example:

```text
/users/neo/projects
```

then:

```text
../documents
```

resolves to:

```text
/users/neo/documents
```

---

# 4.7 — Path Normalization

Support:

```text
/users/neo/../neo/test.txt
```

normalizing to:

```text
/users/neo/test.txt
```

Handle repeated separators:

```text
/users//neo///test.txt
```

---

# 4.8 — Links

Implement later:

```text
hard link
symbolic link
```

Do not start with them.

First stabilize basic Node → Object mapping.

---

# 4.9 — Phase 3 Exit Criteria

You should be able to create:

```text
/
├── users/
├── apps/
└── data/
```

and resolve:

```text
/users/neo/test.txt
```

into:

```text
ObjectId
```

---

# 5. Phase 4 — Handle Manager

## Objective

Allow Processes to access Objects.

---

# 5.1 — Handle Table

Create:

```text
HandleTable
```

per process.

Example:

```text
Process #10
└── HandleTable
    ├── 0 → Object #1
    ├── 1 → Object #5
    └── 7 → Object #100
```

---

# 5.2 — Open

Implement:

```text
open(path, rights)
```

Flow:

```text
Path
 ↓
Node
 ↓
Object
 ↓
Security Check
 ↓
Handle
```

Example result:

```text
HandleId(7)
```

---

# 5.3 — Close

Implement:

```text
close(handle)
```

This should:

```text
remove handle
 ↓
release object reference
```

---

# 5.4 — Handle Rights

Example:

```text
Handle 7
Object #100
Rights = READ
```

A later:

```text
write(7)
```

must fail.

---

# 5.5 — Handle State

Potential fields:

```text
object_id
rights
flags
offset
```

Only add fields when required.

---

# 5.6 — Phase 4 Exit Criteria

A process should be able to:

```text
resolve path
 ↓
obtain Object
 ↓
create Handle
 ↓
read through Handle
 ↓
close Handle
```

---

# 6. Phase 5 — VFS

## Objective

Create the abstraction between applications and Providers.

---

# 6.1 — Define VFS API

Initial API:

```text
lookup
open
close
read
write
create
remove
rename
mkdir
enumerate
stat
```

---

# 6.2 — VFS Must Not Know Linux

Do not put:

```text
libc
Linux syscall
Linux FD
Linux inode
```

inside the public VFS API.

---

# 6.3 — Provider Interface

Define:

```text
Provider
```

Possible operations:

```text
lookup
create
remove
open
read
write
enumerate
```

---

# 6.4 — Mount Model

Define:

```text
Mount
```

Conceptually:

```text
Namespace Path
      ↓
Mount
      ↓
Provider
```

Example:

```text
/users
   ↓
HostFS Provider
```

---

# 6.5 — Phase 5 Exit Criteria

Applications can call:

```text
VFS.open()
VFS.read()
VFS.write()
```

without knowing which Provider implements the operation.

---

# 7. Phase 6 — Linux HostFS Provider

## Objective

Make HyberKOS actually interact with real Linux files.

This is the first point where Linux enters the implementation.

---

# 7.1 — HostFS Provider

Create:

```text
backends/linux/
```

and:

```text
HostFSProvider
```

---

# 7.2 — Root Mapping

Do NOT map:

```text
Hyber /
```

directly to:

```text
Linux /
```

Instead create a dedicated host directory.

For example:

```text
~/hyber-host/
```

or:

```text
/mnt/.../hyber-host/
```

The exact location can be configurable.

---

# 7.3 — Example Mapping

Hyber:

```text
/users/neo/test.txt
```

may internally map to:

```text
hyber-host/users/neo/test.txt
```

Linux details remain private.

---

# 7.4 — Linux File Descriptor Isolation

Linux FD:

```text
int fd
```

must not become:

```text
Hyber HandleId
```

Instead:

```text
Hyber Handle
    ↓
HostFS internal state
    ↓
Linux FD
```

---

# 7.5 — Linux Inode Isolation

Linux inode numbers must not become Object IDs.

Instead:

```text
ObjectId
    ↓
HostFS Object State
    ↓
Linux inode
```

---

# 7.6 — Phase 6 Exit Criteria

A real file can be:

```text
created
opened
read
written
renamed
deleted
```

through Hyber VFS.

---

# 8. Phase 7 — First Hyber Shell


## Objective

Create the first visible HyberKOS environment.

The shell provides two layers of commands:
1. **Standard Base Commands** — familiar POSIX-like commands for daily tasks.
2. **HyberKOS Native Commands** — unique commands that expose the Object Model, Handle Manager, and VFS Providers.

Under the hood, **no command uses Linux syscalls directly**. All commands operate through the HyberKOS VFS, Namespace, Handle, and Provider abstractions.

---

# 8.1 — Shell

Create:

```text
hyber-shell
```


Location:

```text
applications/hyber-shell/
```

The shell is a REPL (Read-Eval-Print Loop) that:
* Reads user input from `stdin`
* Parses commands and arguments
* Executes through HyberKOS abstractions
* Prints results to `stdout`
* Displays the prompt:

```text
hyber>
```

---

# 8.2 — Standard Base Commands (Familiarity Layer)

These commands behave like their Linux/Unix counterparts for user familiarity, but operate entirely through HyberKOS abstractions.

## Navigation & Context

```text
pwd
cd <path>
```

* `pwd` — Print current Hyber namespace path.
* `cd` — Change working directory. Supports `.`, `..`, absolute and relative paths.

## File & Directory Management

```text
ls [path]
mkdir <path>
touch <path>
rm <path>
mv <source> <dest>
cp <source> <dest>
```

* `ls` — List directory contents (names only). Flags: `-l`, `-a`.
* `mkdir` — Create a Directory Object and link it to the namespace. Flags: `-p`.
* `touch` — Create an empty File Object or update `modified_at` timestamp.
* `rm` — Remove a Node and destroy the Object if reference count reaches 0. Flags: `-r`.
* `mv` — Relocate a Node (rename or move to a different parent).
* `cp` — Copy file data through Handle-based read/write.

## Content Viewing

```text
cat <path>
```

* `cat` — Read a File Object through a Handle and print its contents.

---

# 8.3 — HyberKOS Native Commands (Introspection Layer)

These commands are unique to HyberKOS. They expose the Object Model, Handle Manager, and VFS Providers.

## Namespace & Object Introspection

```text
list [path]
look <path>
```

* `list` — The Hyber-aware `ls`. Shows:

```text
Name | ObjectId | Type | Refs | Size
```

Example:

```text
test.txt | Obj(104) | FILE | 1 | 4096
```

* `look` — Replaces `stat`/`inspect`. Dumps deep Object metadata:
  * Object ID, Type, State (Live/Closing/Destroyed)
  * Reference count
  * Created/Modified timestamps
  * Flags
  * Provider handling the Object
  * Flags: `-v` (verbose, includes extended metadata).

## Handle Management (Capability System)

```text
acquire <path> [mode]
release <handle_id>
handles
```

* `acquire` — Replaces `open`. Manually requests a Handle to an Object.
  * Modes: `r` (Read), `w` (Write), `rw` (Read/Write). Default: `r`.
  * Output:

```text
Acquired Handle #7 for Object #104
```

* `release` — Replaces `close`. Drops a Handle, decrementing the Object's reference count.
* `handles` — Displays the shell process's current Handle Table:

```text
HandleId | ObjectId | Rights | Offset
```

## VFS & Security Introspection

```text
mnts
rights <path>
```

* `mnts` — Replaces `mounts`/`providers`. Lists active VFS mount points:

```text
Namespace Path | Provider Name | Status
```

Example:

```text
/ | HostFSProvider | Active
```

* `rights` — Evaluates effective access rights for a path:

```text
READ: Yes | WRITE: No | EXECUTE: No
```

## System Control

```text
exit
```

* `exit` — Gracefully shuts down the shell.
* **Crucial Action:** Automatically iterates through the Handle Table and calls `release` on all open handles before terminating, preventing resource leaks.

---

# 8.4 — Process-Independent Shell

Initially the shell runs as a Linux process.

Later it becomes a native Hyber process.

The shell must not depend on Linux-specific APIs. It should only use:

```text
Hyber VFS
Hyber Namespace
Hyber Handle Manager
Hyber Object Manager
Hyber Providers
```

---

# 8.5 — Shell Path Handling

Commands operate on:

```text
Hyber paths
```

not Linux paths.

Example:

```text
ls /users/neo
```

NOT:

```text
ls /home/neo/hyber-host/users/neo
```

## Path Handling Rules

1. **Hyber Paths Only:** All commands accept Hyber namespace paths. They must never accept or expose Linux host paths.
2. **Relative Resolution:** If a path does not start with `/`, it is resolved relative to the shell's current `pwd` context.
3. **Normalization:** Paths like `/users/../users/./neo` are automatically normalized by the `NamespaceManager` before execution.

---

# 8.6 — Implementation Strategy

## REPL Loop

The shell runs a continuous:

```text
Read → Eval → Print → Loop
```

## Parser

A simple string tokenizer splits user input into:

```text
command
arguments
flags
```

## Execution

* Standard commands map to `VFS` and `NamespaceManager` helpers.
* Native commands map directly to `ObjectManager`, `HandleManager`, and `MountTable` queries.

## Backend Initialization

At startup, the shell:
1. Creates an `ObjectManager`.
2. Creates a `NamespaceManager` with root `/`.
3. Creates a `HandleManager`.
4. Initializes `HostFSProvider` at a safe, isolated directory (e.g., `~/hyber-host`).
5. Mounts the provider at `/`.
6. Enters the REPL loop.

---

# 8.7 — Phase 7 Exit Criteria

You should be able to start:

```text
hyber-shell
```

and interact with the Hyber namespace using both standard and native commands.

Example session:

```text
hyber> pwd
/
hyber> mkdir /users
hyber> mkdir /users/neo
hyber> touch /users/neo/test.txt
hyber> acquire /users/neo/test.txt rw
Acquired Handle #1 for Object #5
hyber> handles
HandleId | ObjectId | Rights | Offset
1        | Obj(5)   | RW     | 0
hyber> list /users/neo
Name       | ObjectId | Type | Refs | Size
test.txt   | Obj(5)   | FILE | 1    | 0
hyber> look /users/neo/test.txt
Object ID:   5
Type:        FILE
State:       LIVE
References:  1
Created:     2026-09-27 16:30:00
Modified:    2026-09-27 16:30:00
Provider:    HostFSProvider
hyber> mnts
Namespace Path | Provider Name    | Status
/              | HostFSProvider   | Active
hyber> release 1
Released Handle #1
hyber> exit
```

At this point the project becomes demonstrable.


---


# 9. Phase 8 — Metadata System

## Objective

Build the metadata model before building the native filesystem.

---

# 9.1 — Core Metadata

Implement:

```text
owner
group
permissions
size
timestamps
flags
```

---

# 9.2 — Extended Metadata

Design:

```text
namespace.key = value
```

Example:

```text
file.mime = text/plain
file.encoding = utf-8
app.creator = hyber-editor
user.favorite = true
```

---

# 9.3 — Metadata API

Implement:

```text
get_metadata
set_metadata
remove_metadata
list_metadata
```

---

# 9.4 — Metadata Validation

Prevent invalid metadata types.

Potential types:

```text
string
integer
boolean
bytes
timestamp
list
```

---

# 9.5 — Phase 8 Exit Criteria

Files can expose:

```text
core metadata
+
extended metadata
```

through the Hyber API.

---

# 10. Phase 9 — Security Foundation

## Objective

Make access control part of the architecture.

---

# 10.1 — Identity

Define:

```text
UserId
GroupId
```

Do not directly expose Linux UID/GID as Hyber identities.

---

# 10.2 — Permissions

Implement:

```text
READ
WRITE
EXECUTE
```

initially.

---

# 10.3 — Access Check

Every sensitive operation should eventually pass through:

```text
SecurityManager
```

Example:

```text
open()
 ↓
SecurityManager
 ↓
allowed / denied
```

---

# 10.4 — Handle Rights

Even after object access is approved:

```text
Handle
```

may restrict rights.

Example:

```text
Object allows:
READ + WRITE

Handle grants:
READ
```

---

# 10.5 — Capability Foundation

Design:

```text
Capability
```

without implementing the entire security architecture yet.

---

# 10.6 — Phase 9 Exit Criteria

At minimum:

```text
unauthorized read → denied
unauthorized write → denied
invalid handle → denied
invalid capability → denied
```

---

# 11. Phase 10 — Process Model

## Objective

Move from "shell running as a Linux process" toward a real Hyber process abstraction.

---

# 11.1 — Process Object

Implement:

```text
Process Object
```

with:

```text
ProcessId
state
parent
handle table
security context
```

---

# 11.2 — Thread Object

Implement:

```text
Thread Object
```

with:

```text
ThreadId
state
```

---

# 11.3 — Linux Process Provider

Initially:

```text
Hyber Process
 ↓
Linux Process
```

The mapping remains internal.

---

# 11.4 — Process Namespace

Expose:

```text
/processes
```

Example:

```text
/processes/1
/processes/2
/processes/3
```

---

# 11.5 — Process Operations

Implement conceptual operations:

```text
create
start
stop
wait
signal
inspect
```

---

# 11.6 — Phase 10 Exit Criteria

The system can represent running processes as Hyber Process Objects.

---

# 12. Phase 11 — Virtual Namespaces

## Objective

Implement the non-filesystem parts of the root namespace.

---

# 12.1 — `/processes`

Backed by:

```text
ProcessProvider
```

---

# 12.2 — `/devices`

Backed by:

```text
DeviceProvider
```

---

# 12.3 — `/services`

Backed by:

```text
ServiceProvider
```

---

# 12.4 — `/runtime`

Backed primarily by runtime providers.

---

# 12.5 — `/temporary`

Initially:

```text
MemFS
```

can be used.

---

# 12.6 — `/volumes`

Implement mountable storage concepts.

---

# 12.7 — Phase 11 Exit Criteria

The namespace should conceptually resemble:

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

with appropriate providers.

---

# 13. Phase 12 — Lua Runtime

## Objective

Introduce the first official scripting environment.

---

# 13.1 — Embed Lua

Integrate Lua through the selected Rust binding.

Keep Lua isolated in:

```text
hyber-lua/
```

---

# 13.2 — Hyber Lua API

Provide:

```text
hyber.fs
hyber.process
hyber.ipc
hyber.network
hyber.service
hyber.metadata
```

This is the planned Lua-facing surface, not a claim that every subsystem is
already implemented. In the current roadmap state, filesystem/process/object
metadata/security operations and early pipe primitives are available; full IPC,
network, and service APIs are introduced by their later phases and must not be
treated as Phase 12 completion requirements.

---

# 13.3 — File Example

A Lua program should be able to conceptually do:

```lua
local file = hyber.fs.open(
    "/users/neo/test.txt",
    "read"
)

local data = file:read()

print(data)

file:close()
```

---

# 13.4 — Lua Security

Lua applications must operate through Hyber permissions.

Lua should never receive unrestricted Linux access.

---

# 13.5 — Phase 12 Exit Criteria

A Lua program can:

```text
start
open Hyber Objects
use Handles
read/write files
use the currently available process and pipe primitives
exit
```

---

# 13.6. Phase 12.5 — Advanced Lua Integration

## Objective

Expose the currently implemented foundational abstractions (Phases 1–11) to
Lua, turning Lua into the primary user-space orchestrator rather than just a
simple script runner. This phase provides early process control, metadata,
security checks, and the available pipe primitives; the complete IPC model
remains reserved for Phase 19.

---

# 13.6.1 — Process Management in Lua

Expose process spawning and the currently available pipe primitives to Lua;
the complete IPC contract remains a later-phase responsibility:

```lua
local pid = hyber.proc.spawn("/apps/editor.lua")
hyber.proc.wait(pid)
```

---

# 13.6.2 — Advanced Metadata & Security

Allow Lua to modify extended metadata and evaluate security rules directly:

```lua
hyber.obj.meta_set(path, "sys.role", "string", "daemon")
local can_write = hyber.sec.check_access(path, "WRITE")
```

---

# 13.6.3 — Phase 12.5 Exit Criteria

Lua can control the implemented process model, permission checks, metadata,
and early pipe-based communication. It acts as the user-space orchestrator
without replacing the language-neutral kernel, object, VFS, or future full IPC
architecture.

---

# 14. Phase 13 — Hyber Application API

> **⚠️ IMPLEMENTATION NOTE (Deferred):**
> Phase 13 (C API / `libhyber` / multi-language SDK) is intentionally deferred to **after Phase 30 (GUI)**.
> The reason: a stable ABI/API cannot be frozen until the full kernel abstraction surface (kernel, native VFS, native process model) is mature.
> Prematurely publishing a C ABI would require breaking changes as the system evolves.
>
> **When to implement:** After Phase 30 (GUI), revisit Phase 13 and implement:
> - `libhyber` C shared library
> - `hyber.h` public C header
> - Rust idiomatic bindings (`hyber-rs`)
> - Python, Go, Java, Kotlin, JS/TS bindings
>
> **Phase 14A (Lua Foundation Developer Toolchain)** is implemented NOW
> (current version) and remains Lua-only until the deferred Phase 13 API/ABI is implemented.
> This current work is Phase 14A (Lua Foundation). After Phase 13, Phase 14B
> extends it for Lua applications and compiled/multi-language applications.

## Objective

Formalize the application model and API that every language will eventually
use. This phase is intentionally implemented only after the GUI has exposed
the real requirements for applications, windows, surfaces, events, handles,
IPC, services, and permissions.

---

# 14.1 — Stable Concepts

Define APIs for:

```text
Objects
Handles
Filesystem
Processes
IPC
Networking
Devices
Services
Metadata
Security
```

---

# 14.2 — C API

Create:

```text
libhyber
```

or an equivalent public C interface.

This becomes an important interoperability layer.

---

# 14.3 — Rust API

Create idiomatic Rust bindings.

---

# 14.4 — Language Bindings

Later:

```text
Lua
Python
Go
Java
Kotlin
JavaScript
TypeScript
C++
```

---

# 14.5 — ABI Design

Only after the API is sufficiently stable should the project define a more
formal ABI. GUI-specific contracts must be designed here, but GUI internals
must not be exposed as an accidental language-specific ABI.

Do not freeze the entire syscall ABI yet.

---

# 14.6 — Phase 13 Exit Criteria

At least:

```text
Rust
C
Lua
```

applications can use the same Hyber concepts.

---

# 15. Phase 14A — Lua Foundation Developer Toolchain (Current)

## Objective

Make HyberKOS pleasant to develop for.

## Scope and Status

Phase 14A is a Lua-only foundation toolchain. It runs scripts in an isolated
in-memory Hyber context and exposes inspection/debugging workflows; it is not a
stable application ABI, package manager, service manager, or GUI runtime.

The currently implemented command surface is:

```text
hyber run
hyber new
hyber inspect
hyber ns
hyber handles
hyber mount
hyber trace
```

`hyber build` and `hyber package` are intentionally not Phase 14A
requirements. Build/package workflows belong to later application and package
phases and must not be presented as completed commands until implemented.

---

# 15.1 — CLI Tool

Create:

```text
hyber
```

Example:

```text
hyber run app.lua
hyber new example
hyber inspect
hyber mount
```

---

# 15.2 — Application Manifest

Define:

```text
hyber.toml
```

Example:

```toml
name = "example"
version = "0.1.0"
entrypoint = "main.lua"
```

Later:

```text
permissions = [...]
dependencies = [...]
```

---

# 15.3 — Debugging

Create tools for:

```text
object inspection
handle inspection
namespace inspection
process inspection
provider inspection
```

---

# 15.4 — Tracing

Introduce:

```text
hyber trace
```

for system operations.

Example:

```text
PATH LOOKUP
 ↓
NODE
 ↓
OBJECT
 ↓
HANDLE
 ↓
READ
```

---

# 15.5 — Phase 14A Exit Criteria

A Lua developer can:

```text
scaffold an application
validate a hyber.toml manifest
run a Lua entrypoint
inspect objects, namespaces, handles, mounts, and resolution traces
debug the current in-memory context
```

Phase 14A is complete only for this foundation scope. The following remain
explicitly out of scope until later phases:

```text
stable cross-language ABI
portable manifest permission enforcement
package build/install/signing
long-running service supervision
GUI application lifecycle integration
```

The Lua toolchain must consume Hyber abstractions and must not define the
kernel, object model, VFS architecture, GUI architecture, or public ABI.

---

# 16. Phase 15 — HyberFS Design

## Objective

Define, document, and prototype a persistent HyberFS volume with deterministic
on-disk semantics. The result must be readable by a future implementation in a
different language or operating system; Rust is only the implementation
language of this prototype.

This phase is not the native kernel filesystem implementation. The native
block-device, kernel VFS boundary, and boot-time root filesystem are reserved
for Phases 21–25 after the native process, object, VFS, and device layers exist.

Phase 15 owns the on-disk format, formatting, user-space mount/unmount,
objects, nodes, directories, file data, metadata, allocation, and minimal
metadata journaling. It does not own native kernel integration, hardware
drivers, the public application ABI, full recovery policy, encryption,
compression, snapshots, deduplication, or network filesystems.

## Implementation Languages

The filesystem format and on-disk rules are language-neutral and must be
specified in documentation first. The executable Phase 15 prototype and its
tests should be written in Rust because it is memory-safe, portable, and
already matches the existing Hyber object/VFS code. Rust is the implementation
language here, not part of the public filesystem format or future application
ABI.

Lua may orchestrate demonstrations and test scenarios once the relevant Hyber
APIs exist, but Lua must not define the on-disk format or storage invariants.
C/C++ and assembly are not required for this user-space design/prototype;
low-level native storage work belongs to Phases 21–25.

## Recommended Rust Component Boundaries

Keep format encoding separate from storage behavior:

```text
hyberfs-format   → fixed-width on-disk records and validation
hyberfs          → volume, objects, directories, data, allocation, journal
hyberfs-tool     → format, inspect, check, mount, and test commands
hyberfs-tests    → integration, property, corruption, and reopen tests
```

The format layer must not perform I/O, and the volume layer must depend on an
abstract block-device interface. The first block device is a regular-file
backend; a future native block device can implement the same interface without
changing the on-disk format.

Before implementation, Object/Node/VFS semantics, object types and lifetime,
namespace lookup, permission vocabulary, and error/result conventions must be
documented. The prototype must use Hyber abstractions rather than Linux inode
numbers, file descriptors, paths, or process IDs in the on-disk format.

---

# 16.1 — Filesystem Specification

Write:

```text
docs/filesystem/hyberfs-spec.md
```

Define:

```text
block size
on-disk byte order
fixed-width integer sizes
alignment and reserved fields
format compatibility rules
superblock
Object IDs
Object records
Node records
directory format
name encoding and validation
metadata
allocation
journal
checksums
```

The specification is normative. Every field must define its type, width,
alignment, valid range, owner, and recovery behavior. Host-native struct
layout, pointers, Rust enum layout, and compiler ABI must never be written
directly to disk.

The format must define canonical naming rules: empty names, `.` and `..`, path
separators, invalid UTF-8, and duplicate names must have explicit behavior.
Malformed mandatory fields must fail validation; unknown optional fields may be
skipped.

---

# 16.2 — Disk Image

Create:

```text
hyberfs.img
```

for development. Formatting must validate image size, alignment, truncation,
and arithmetic overflow before writing. It must never overwrite an existing
image without an explicit force/confirmation mode.

Initially use:

```text
QEMU
```

or a Linux-hosted Rust disk-image tool. The image is a regular-file test
backend only; Linux filesystem semantics must not become HyberFS semantics.

---

# 16.3 — Superblock

Implement:

```text
magic
version
UUID
block size
filesystem size
feature flags
root object ID
object/data/allocation/journal region locations
clean/unclean state
format checksum
```

Mount must reject invalid magic, unsupported required versions, impossible or
overlapping regions, invalid block sizes, and checksum failures. Redundant
superblock copies, if used, require deterministic disagreement and selection
rules.

---

# 16.4 — Object Store

Implement persistent Objects.

Example:

```text
Object #100
type = DIRECTORY
```

Object records must define stable `ObjectId`, type, state, owner/group,
permissions or capability metadata, timestamps, logical size, and a generation
or record version. Object IDs must not be reused while live references,
directory entries, or journal transactions can refer to the old object.
Deletion removes namespace references first and reclaims storage only after the
object is no longer reachable or open under the documented rules.

---

# 16.5 — Directory Index

Implement:

```text
name → ObjectId
```

Directory operations must have deterministic lookup, insertion, replacement,
and removal behavior. Duplicate names, invalid names, missing-object targets,
and directory cycles must be rejected. `.` and `..` are resolution concepts,
not ordinary stored entries.

---

# 16.6 — Data Store

Implement file data storage.

Start simple.

Possible first implementation:

```text
direct extents
```

Then later:

```text
extent tree
```

Define logical offsets, physical ranges, holes, maximum file size,
partial-block writes, truncate, append, and end-of-file behavior. The initial
direct-extent format must reserve a documented extension path for larger files;
host pointers and host file offsets must never become persistent identifiers.

---

# 16.7 — Metadata Store

Persist:

```text
ownership
permissions
timestamps
size
flags
extended metadata
```

Metadata updates must validate type, length, ownership, timestamp units, and
bounded key/value sizes. Unknown optional metadata may be skipped, while
malformed mandatory metadata must fail validation or the operation.

---

# 16.8 — Allocation Manager

Implement:

```text
free block tracking
allocation
deallocation
```

The current Phase 15 prototype uses deterministic serialized-state slot
capacity accounting rather than pretending that file data already has a native
block bitmap. Its allocator must reject payloads that exceed the inactive slot
capacity and must leave the previous committed generation intact on failure.

A persistent per-data-block bitmap and extent allocator are required before
native block-device integration; they are not silently implied by the current
user-space snapshot representation.

Optimize later.

Reserved metadata, object, data, and journal regions must never overlap.
Detect double allocation, freeing reserved/out-of-range blocks, and arithmetic
overflow. Allocation changes must be part of the transaction model before an
operation is acknowledged.

---

# 16.9 — Journal

Implement a minimal metadata transaction boundary.

The version 2 prototype journals by invalidating and flushing the inactive
slot header, writing/flushing its full payload, then publishing/flushing the
checksummed generation header. The geometry superblock remains immutable.
This is an atomic snapshot journal boundary, not a block-level record log.

Each snapshot has a monotonic generation, bounded payload, checksum, and
deterministic newest-valid-slot selection. Interrupted writes must leave either
the previous or the new valid generation visible, never a partially decoded
state. Phase 16 validates this boundary with torn-write and flush-failure
injection. A native block-level record journal requires a future format change;
the current recovery engine reports invalid objects instead of destructive repair.

---

# 16.10 — Mount, Unmount, and Operations

Define the user-space lifecycle:

```text
format → validate → mount → operate → flush → clean unmount
```

Mount validates the superblock, region layout, root object, directory roots,
object records, and allocation boundaries before exposing the volume. A failed
mount exposes no partially initialized state. Unmount drains or rejects active
operations, flushes committed transactions, writes clean state, and releases
resources. Remount must reproduce the same logical namespace and file data.

Define behavior for:

```text
create, open, read, write, append, truncate
mkdir, lookup, enumerate, rename, unlink
metadata read/write
mount, sync, unmount
```

Every operation returns a typed result and distinguishes at least invalid input,
missing object, already exists, not-a-directory, is-a-directory, permission
denied, no space, corrupt format, unsupported feature, busy, and I/O failure.

# 16.11 — Invariants and Validation

The prototype must validate that:

```text
all referenced objects exist
each allocated block has at most one owner
reserved regions are never data allocations
directory entries target compatible object types
object sizes match data mappings
free-space accounting matches allocation records
the root object exists and is a directory
committed journal records are structurally valid
```

Provide both an in-process checker and a standalone inspection/check command.
Diagnostics must identify the object, block, or transaction violating an
invariant.

# 16.12 — Testing and Acceptance

Use Rust unit, integration, property, deterministic reopen, and corruption
tests. Cover valid and malformed images, invalid versions, empty/nested
directories, duplicate names, small and multi-block files, overwrite, append,
truncate, rename, unlink/reclamation, metadata persistence, out-of-space,
overflow, clean remount, and interrupted metadata transactions.

Property tests should generate operation sequences and compare the mounted
filesystem with a simple reference model. Tests must not depend on host
filesystem ordering.

# 16.13 — Phase 15 Exit Criteria

HyberFS can:

```text
format
mount
create directory
create file
write file
read file
rename file
delete file
unmount
remount
```

and preserve data. In addition, the normative specification, deterministic
format/version validation, object/directory/data/metadata invariants, slot
capacity accounting, atomic snapshot transactions, safe invalid-image failure,
and Rust unit/integration/property tests must all pass.

Phase 15 is complete only for this user-space format/prototype scope. Phase 16
may add aggressive crash injection, recovery repair, and broader checksums; an
incompatible format change requires a new version or documented migration.

---

# 17. Phase 16 — HyberFS Reliability

## Objective

Make the Phase 15 HyberFS design/prototype trustworthy before optimizing it or
porting it into the native kernel storage stack.

## Implementation Languages and Responsibilities

```text
Rust        → recovery engine, validators, fault-injection harness, hyberfsck
Lua         → optional test scenarios and trusted orchestration only
Go          → not required for filesystem correctness or recovery
C/C++/ASM   → not used in this user-space reliability phase
```

Recovery must remain independent of Lua and Go. A damaged or interrupted Lua
runtime must not prevent the filesystem checker from validating an image.

---

# 17.1 — Crash Testing

Test:

```text
power loss simulation
process crash
write interruption
rename interruption
metadata interruption
```

---

# 17.2 — Recovery

Implement:

```text
journal replay
orphan cleanup
metadata verification
allocation verification
```

---

# 17.3 — Checksums

Add:

```text
superblock checksum
metadata checksum
journal checksum
```

Later:

```text
data checksums
```

---

# 17.4 — Consistency Checker

Create:

```text
hyberfsck
```

Possible checks:

```text
Object references
Node references
allocation
directory structure
metadata
journal state
```

---

# 17.5 — Phase 16 Exit Criteria

The current Rust implementation includes a write/flush crash matrix, generation
and metadata checksums, bounded iterative graph validation, deterministic
reference-model/remount tests, and the read-only `hyberfsck` binary. Recovery
diagnostics identify damaged slots; a recovered older snapshot is not reported
as a clean image. Failed commits poison the mounted writer until remount.
Physical power-cut testing and native-device qualification remain separate
from these deterministic hosted tests.

The filesystem survives intentionally simulated failures without silently
corrupting its structure. The phase is complete only when:

```text
fault-injected slot writes are tested
newest-valid-generation recovery is tested
bad superblock/slot checksums are detected
truncated payloads are rejected safely
orphan/dangling/cyclic object graphs are reported
allocation and region invariants are checked
hyberfsck returns a deterministic result and non-zero failure status
recovery never invents or silently drops committed user data
```

---

# Special Integration Gate — Special_*

Phase 16 (HyberFS Reliability) is complete as a filesystem phase, but Phase 17
must not begin until the following mandatory special phases are complete. These
phases do not renumber or replace Phase 17. They connect reliable storage to
identity, sessions, shell behavior, Lua configuration, application data, and
the future service/network boundaries.

Every special phase preserves the rule that Lua orchestrates user-space policy
without becoming the kernel, process model, VFS, or public ABI.

---

# Special_1 — Identity, Users, and Groups

## Objective

Turn the existing `UserId`, `GroupId`, owner/group fields, permissions, and
capabilities into a coherent Hyber account model before package installation
and service ownership are introduced.

## Responsibilities

```text
User Object and Group Object
username/group-name validation
stable UserId/GroupId allocation
primary and supplementary memberships
account states: active, locked, disabled, service, guest
home-directory and service-account ownership
reserved identity policy for root/system users
```

IDs are Hyber identifiers, not host UIDs/GIDs. The model supports Linux-like
owner/group/other permissions and Windows-like named groups without copying
either operating system's internal ABI.

## Language Boundary

```text
Rust → account registry, validation, credential/session types, security checks
Lua  → capability-checked administrative workflows
Go   → not required for identity correctness
```

### Initial implementation boundary

The first implementation is the Rust crate `crates/hyber-identity`. It owns
the deterministic in-memory registry and its checksummed `HYBID01` snapshot:

```text
AccountRegistry
  ├─ UserAccount (state, home, primary/supplementary groups, capabilities)
  ├─ GroupAccount (deterministic member set)
  ├─ create/delete/membership/state/home/capability operations
  ├─ SecurityContext derivation
  └─ encode/decode + structural corruption validation
```

The snapshot is deliberately a byte payload rather than a host `/etc/passwd`
or `/etc/group` file. `hyber-auth` commits accounts, credential hashes, and
administrative audit entries together through the Phase 15/16 `replace_file`
and `sync` snapshot boundary. Raw registry methods are trusted internal APIs;
application administration must pass through the authenticated authority.
The identity crate does
not parse host accounts, store passwords, authenticate users, or silently
grant capabilities. Those are Special_2 responsibilities.

The registry rejects duplicate names/IDs, invalid names or homes, inconsistent
bidirectional memberships, invalid capability names, missing root invariants,
and truncated/checksum-invalid snapshots. Root's administrative capability is
explicitly stored and cannot be revoked; all other capabilities require an
explicit grant.

## Exit Criteria

```text
users/groups can be created, looked up, disabled, and listed
primary/supplementary membership is deterministic
SecurityContext uses the same owner/group checks everywhere
reserved IDs and duplicate names are rejected
home and service ownership are validated
account corruption is detected before session creation
```

## Required files and verification

```text
crates/hyber-identity/Cargo.toml
crates/hyber-identity/src/lib.rs
```

The crate must be included in the workspace and pass formatting, workspace
tests, clippy with warnings denied, and a round-trip/corruption test suite.
Special_1 is complete only when account mutations remain deterministic after
encode/decode and deletion removes every reverse group membership safely.
The implementation also validates unique home paths, reserved root state,
monotonic allocation counters, duplicate encoded memberships, and primary-group
transitions. Supplementary groups reach the common `SecurityContext` and its
owner/group/other checks. Creating physical home trees remains Special_3.

---

# Special_2 — Sessions, Authentication, and Credential Boundaries

## Objective

Create a user-space authentication/session boundary that produces a complete,
least-privilege Hyber `SecurityContext` without placing password or login
policy in the kernel, shell, Lua profile, or GUI.

## Responsibilities

```text
credential records and password-hash storage
authentication result and session ID
primary/supplementary groups and capability derivation
logout and session invalidation
locked/disabled/expired account policy
interactive, service, and non-interactive sessions
```

Passwords and tokens are never stored in plaintext. Authentication failures do
not reveal whether a username exists. A failed profile or shell cannot elevate
a session.

## Language Boundary

```text
Rust → credential/session types and security boundary
Lua  → trusted administrative workflows only
Go   → optional future auth/network payload, never authority
```

## Exit Criteria

```text
successful login yields a least-privilege SecurityContext
logout invalidates the session
locked/disabled users cannot create sessions
supplementary groups/capabilities are tested
credential data is protected and non-plaintext
shell/services/apps consume the same session context
```

## Implemented user-space boundary

`crates/hyber-auth` owns the account registry, credential records, session
digests, clock policy, and administrative audit. `AuthService::provision` is
trusted first-boot enrollment with an explicit root password; persisted stores
use `load`, never automatic reprovisioning. Passwords use salted Argon2id PHC
records with bounded parameters. Credential snapshots have a version, size
limit, SHA-256 damage checksum, and strict account/hash validation.

Session tokens contain 256 random bits and are redacted in diagnostics. Only
their digests are retained in the session table. Sessions are volatile and
must be recreated after restart. Interactive, non-interactive, and service
sessions have explicit account-state rules and bounded lifetimes. Account and
password expiry use a trusted clock; backwards clock movement revokes sessions.
Login failures use a common error and dummy password verification, with a
bounded authority-wide retry cooldown. This hosted cooldown is not a distributed
network rate limiter.

Administrative account changes are staged on a clone, validated, and audited.
Changes to an account revoke its active sessions; password changes revoke all
sessions for that account. Logout is immediately effective for every clone of
the same guard. `SessionGuard` derives current groups/capabilities for each
operation. The Rust boundary is trusted; arbitrary application-supplied
`SecurityContext` structs are not authentication proofs.

`AuthService::save` writes identities, hashes, and audit records in one HyberFS
snapshot with root-owned 0600 metadata. Mutations are in-memory until save
succeeds; administrative CLI success is printed only after durable save.
The dedicated hosted store is `/auth.store` inside an image kept outside the
application namespace. Damaged-slot recovery is refused for credentials.

## Consumers and tools

```text
hyber-auth-tool init <new-image> <blocks>
hyber-auth-tool user-add <image> <blocks> <username> [service|guest]
hyber-auth-tool passwd <image> <blocks> <username>
hyber-auth-tool lock|disable <image> <blocks> <username>
hyber-auth-tool unlock <image> <blocks> <username> <active|service|guest>
hyber-auth-tool check <image> <blocks>
hyber-shell --auth <image> <blocks> <username>
hyber run --auth <image> <blocks> <username> <script-or-project>
```

Passwords are terminal prompts, never command arguments. The hosted login
adapter detects persisted store changes and invalidates its old session.
It is a single-process authority adapter, not the future IPC login daemon.
Existing no-argument development shell/CLI modes remain trusted bootstrap
environments and must not be deployed as a multi-user login boundary.

Lua revalidates the session on Hyber operations and instruction hooks, removes
host I/O/process/module-loader globals, and cannot manufacture session tokens.
Authenticated shells reject numeric `su`; bootstrap numeric `su` requires an
administrative capability. Services use their own service session and validate
it at dispatch; closing a GUI or caller session does not stop that service.

Tests cover generic failure responses, retry cooldown, group/capability access,
expiry boundaries, clock rollback, password rotation, logout, locked accounts,
service independence, snapshot corruption, private metadata, and restart
invalidation. See `docs/security/identity-sessions.md` for the storage/trust
contract and integration limitations. Special_3 owns physical home provisioning;
the native login daemon and process termination policy remain later runtime work.

---

# Special_3 — Home, Runtime, Cache, and Application Data Layout

## Objective

Define standard locations so configuration, persistent data, cache, temporary
files, and live runtime state never get mixed together.

## Canonical Layout

```text
/apps/<app-id>/                         installed/read-only app files
/data/services/<service-id>/            service persistent data
/data/shared/<namespace>/               capability-controlled shared data
/data/logs/                             persistent logs
/runtime/users/<user-id>/               live sessions/runtime
/runtime/services/<service-id>/         live service state
/runtime/sockets/                       live IPC endpoints
/temporary/users/<user-id>/<app-id>/    disposable user-app data
/temporary/system/                      disposable system staging
/users/<user>/Documents/
/users/<user>/Downloads/
/users/<user>/.config/<app-id>/         configuration
/users/<user>/.local/share/<app-id>/    persistent app data
/users/<user>/.local/state/<app-id>/    recoverable app state
/users/<user>/.cache/<app-id>/          disposable cache
/users/<user>/.local/bin/               user executables
```

Applications use logical APIs (`app.config_dir()`, `app.data_dir()`,
`app.state_dir()`, `app.cache_dir()`, `app.temp_dir()`, and
`app.runtime_dir()`) rather than hardcoded host paths.

## Rules

```text
/apps is installation/read-only content
cache deletion cannot destroy the only user-data copy
/runtime and /temporary are not backup data
service data is owned by service identities
shared data requires explicit capability
quotas and cleanup policy are explicit per class
```

## Language Boundary

```text
Rust → path-provider, ownership, quotas, cleanup, VFS/security integration
Lua  → user-space app access through logical directory APIs
Go   → service/app consumers only, never storage-layout authority
```

## Exit Criteria

```text
new users receive correct home trees and ownership
apps receive isolated config/data/state/cache/temp/runtime paths
cross-user access is denied by default
runtime/temp cleanup is safe and observable
persistent paths survive remount; cache/temp are disposable
```

---

# Special_4 — Shell Input, History, and Navigation

## Objective

Make command input consistent across keyboard, GUI buttons, and future input
devices, including reliable history navigation.

## Responsibilities

```text
input buffer and cursor
Up/Down history navigation
GUI previous/next buttons using the same history controller
session and persistent history
history limits, deduplication, sensitive-command filtering
reverse search and clear operations
EOF, interrupt, cancel, and redraw behavior
```

Up/Down changes the input buffer only; it never executes a command. Execution
requires explicit submission. History is per user/session, permission
protected, bounded, and never stores passwords or declared secrets.

## Language Boundary

```text
Rust → shell parser, line editor, history controller, state machine
Lua  → aliases/functions/hooks through a restricted API
Go   → not required for interactive shell correctness
GUI  → calls the same shell controller, never a duplicate history engine
```

## Exit Criteria

```text
keyboard and GUI navigation are identical
history is isolated per user/session
reverse search and clear are deterministic
secret-like commands are filtered or explicitly confirmed
invalid commands cannot corrupt the input buffer
shell restart preserves only configured persistent history
```

---

# Special_5 — Lua Shell Profiles and Environment

## Objective

Provide a safe Bashrc/Zshrc-like configuration model without making Lua the
operating-system architecture.

## Profile Order

```text
/etc/hyber/profile.lua
/users/<user>/.hyber_profile.lua
/users/<user>/.hyber_login.lua       (login shells only)
/users/<user>/.hyberrc.lua           (interactive shells)
```

Profiles may define aliases, prompt functions, environment variables,
completion, key bindings, and shell hooks. They may not define the kernel
process model, bypass permissions, or access the host without capabilities.

Profile execution is sandboxed and capability-aware. A profile error logs a
warning and opens safe mode; it cannot prevent recovery or silently grant
privileges. Non-interactive scripts do not execute interactive profiles unless
explicitly requested.

## Language Boundary

```text
Rust → profile loader, ordering, limits, safe-mode fallback
Lua  → profile content, aliases, prompt, environment, user hooks
Go   → not required
```

## Exit Criteria

```text
login/non-login/interactive ordering is tested
system profile cannot be overridden to elevate privileges
profile failures are recoverable
environment changes are session-scoped
aliases and prompt customization use stable shell APIs
```

---

# Special_6 — Application Manifest, Sandbox, and Data Permissions

## Objective

Connect application identity to the data layout, user/group model, and
capability system before Phase 17 packages are installed.

## Manifest Scope

```text
application ID/version and entrypoint/runtime
requested capabilities
config/data/state/cache/temp/runtime scopes
publisher and user-facing name
service/background policy
network policy
resource quotas
```

Manifest permissions are requests, not grants. Rust validates and grants least
privilege; Lua can read the resulting context but cannot enlarge it. Go apps
receive the same manifest-derived context.

## Exit Criteria

```text
application IDs are unique and validated
paths cannot escape assigned data roots
requested capabilities require policy approval
manifest upgrades are versioned and reversible
GUI/background/service policy is explicit
package installation can consume this contract unchanged
```

---

# Special_7 — Service and Network Boundary Preparation

## Objective

Prepare the contracts that Phase 18 services and Phase 20 networking consume,
without prematurely implementing their complete supervisors or network stacks.

## Explicit Language Plan

```text
Rust → service lifecycle/control plane, Hyber objects, security, socket API
Lua  → declarative service definitions, startup policy, health checks, admin
Go   → service payloads and user-space network daemons/data plane
```

The service supervisor and security authority are not Lua or Go. Go services
are ordinary supervised Hyber applications. Lua cannot kill arbitrary
processes or open unrestricted sockets. Host adapters remain isolated and
temporary; native networking remains a later Rust-first phase.

## Exit Criteria

```text
service manifest schema is versioned
Rust supervisor boundary is defined
Lua definition validation rules are defined
Go daemon lifecycle and IPC contract is defined
capability/network policy is explicit
service/socket ownership maps to users/groups
Phase 18/20 can begin without redefining identity or data paths
```

---

# Special_8 — Cross-Layer Integration, Migration, and Gate Review

## Objective

Integrate reliable storage, identities, sessions, shell, Lua profiles,
application data, and service boundaries before package management begins.

## Required Integration Tests

```text
create user/group → login → create home tree → start shell
load profile → set prompt/alias → navigate persistent history
launch app → verify config/data/cache/temp/runtime isolation
deny cross-user and undeclared-capability access
restart session → verify only persistent classes survive
mount/remount HyberFS → verify accounts and app data
define Lua service → validate Rust supervision boundary
launch Go payload contract test → verify identity/capabilities
inject input event → verify shell/UI consumes one neutral event
```

No Phase 17 package format or installer may bypass these contracts. Any
incompatible storage, identity, manifest, shell, or capability change requires
an explicit migration/version decision. The gate is complete only when all
special-phase, workspace, corruption, and security tests pass.

---

# 18. Phase 17 — Package Manager

## Objective

Turn Lua applications, Go service payloads, and later language applications
into verifiable, installable packages on the Phase 15/16 storage foundation.
Installation consumes the `Special_1`–`Special_8` identity, session,
data-directory, manifest, capability, and service contracts; it does not
redefine them or freeze the future multi-language ABI.

---

# 18.1 — Package Format

Define:

```text
package metadata
application ID and runtime/language
files
permissions
capabilities and data scopes
dependencies
entrypoint
service/background policy
signature
```

---

# 18.2 — Package Object

Introduce:

```text
Package Object
```

---

# 18.3 — Repository

Create a local repository first.

Example:

```text
repository/
├── packages/
└── metadata/
```

---

# 18.4 — Installation

Implement:

```text
hyber install package
```

Flow:

```text
download
 ↓
verify
 ↓
resolve dependencies
 ↓
install
 ↓
register package
 ↓
register application
```

Installation must be atomic or recoverable: failed verification, dependency
resolution, or extraction must not leave a partially registered application.
Updates need rollback metadata, and removal must refuse to delete files still
owned by another installed package.

---

# 18.5 — Phase 17 Exit Criteria

A package can be:

```text
built
verified
installed
updated
removed
```

---

# 19. Phase 18 — Service Manager

## Objective

Create the user-space service architecture and lifecycle supervisor. The
service manager itself is a Rust system component because it owns Hyber
processes, objects, security contexts, dependencies, and restart policy. Lua
is the declarative/configuration and orchestration layer; it must not be the
supervisor, scheduler, process model, or service ABI. Go is used for selected
high-concurrency service implementations and network daemons, not for the
core supervisor.

Service roles are therefore explicit:

```text
Rust → service manager, lifecycle, dependency graph, security, supervision
Lua  → service definitions, init policy, automation, administrative commands
Go   → optional service payloads, proxies, network daemons, background workers
```

All three communicate through Hyber objects and the Phase 19 IPC contract;
Lua and Go never receive unrestricted host process or socket access.

---

# 19.1 — Service Object

Define:

```text
Service Object
```

---

# 19.2 — Service Definition (Lua-Driven)

Instead of static TOML/INI files, use Lua scripts to define and control services dynamically.

Example (`/services/network.lua`):

```lua
return {
    name = "network",
    startup = "automatic",
    dependencies = {"dns"},
    start = function()
        hyber.log.info("Starting network interface...")
        -- setup logic
    end,
    stop = function()
        hyber.log.info("Shutting down network...")
    end
}
```

The Lua file describes policy and callbacks; the Rust service manager validates
the schema, creates the process, applies capabilities, and invokes lifecycle
actions. A Go service is launched as an ordinary supervised application and
cannot bypass the same manifest or capability checks.

---

# 19.3 — Lifecycle

Implement:

```text
start
stop
restart
status
```

Define explicit service states, readiness/failure reporting, crash handling,
restart policy, and clean shutdown. A service is an independent user-space
process; closing a GUI window must not stop it unless an explicit policy or
administrative request says so.

---

# 19.4 — Dependencies

Example:

```text
network.service
    ↓
dns.service
```

---

# 19.5 — Security

Services should run with restricted permissions.

Service definitions must declare required capabilities, run under an explicit
security context, and be denied undeclared object, namespace, device, and
network access. Dependency ordering must not bypass these checks.

---

# 19.6 — Phase 18 Exit Criteria

The system can start and manage user-space services through Hyber abstractions.
The exit criteria require:

```text
Rust supervisor starts/stops/restarts/status-checks services
Lua definitions are schema-validated and cannot alter supervisor internals
Go service payloads run under the same process/security model
dependency cycles and missing dependencies are rejected
crash loops are rate-limited with explicit failure state
capabilities are least-privilege and auditable
GUI close does not implicitly terminate a service
service communication uses Hyber IPC primitives
```

---

# 20. Phase 19 — IPC

## Objective

Build real communication between Hyber processes.

---

# 20.1 — Pipes

Implement first.

```text
Pipe Object
```

---

# 20.2 — Channels

Implement:

```text
Channel Object
```

for structured messages.

---

# 20.3 — Shared Memory

Implement later:

```text
SharedMemory Object
```

---

# 20.4 — RPC

Build a basic request/response layer.

Example:

```text
Application
 ↓
RPC
 ↓
Service
```

---

# 20.5 — Phase 19 Exit Criteria

Two Hyber processes can:

```text
communicate
send data
receive data
request service operations
```

without direct Linux-specific communication.

---

# 21. Phase 20 — Networking

## Objective

Create Hyber-native user-space networking abstractions and a host-backed
networking implementation. This phase does not yet replace the kernel network
stack; that work belongs to Phase 27.

## Language Responsibilities

```text
Rust → Hyber NetworkInterface/Socket object model, security boundary, API
Go   → user-space networking data plane, clients, proxies, DNS/HTTP services,
       connection pools, concurrent background daemons
Lua  → configuration, service startup, policy, health checks, automation
```

Go networking is written from a clean Hyber-facing implementation boundary. It
may use a narrowly isolated host adapter in this phase, but host sockets must
never leak through the public Hyber object model. Lua does not implement TCP,
UDP, DNS, packet scheduling, or socket lifetime.

---

# 21.1 — Network Interfaces

Define:

```text
NetworkInterface Object
```

---

# 21.2 — Socket Object

Implement:

```text
Socket Object
```

---

# 21.3 — TCP/UDP

Initially map to Linux networking.

Later implement native networking.

The Phase 20 implementation is split into two explicit layers:

```text
Hyber Rust socket/object boundary
        ↓
Go user-space TCP/UDP clients and services
        ↓
isolated host-network adapter (temporary)
```

The Go layer must define timeouts, cancellation, bounded buffers, connection
limits, error mapping, and shutdown behavior. It must not define kernel
syscalls or freeze the final native networking ABI.

---

# 21.4 — DNS

Create:

```text
DNS Service
```

---

# 21.5 — Firewall

Design a Hyber security layer.

---

# 21.6 — Phase 20 Exit Criteria

A Hyber application can create a network connection without knowing Linux networking internals.

# 21.7 — Go Integration for Networking

Implement the user-space networking daemons in Go from the Hyber-facing
boundary:

```text
Go network daemon
 ↓
Hyber Network API / IPC
 ↓
Rust socket and security boundary
```

Start with DNS/client utilities, TCP/UDP clients, a bounded proxy, and a
health-check daemon. Each daemon must have explicit lifecycle, cancellation,
back-pressure, retry, timeout, logging, and capability requirements. Go is not
used for the native kernel network stack; Phase 27 defines that Rust-first
native implementation.

---

# 22. Phase 21 — Native Kernel Preparation

## Objective

Only now begin serious kernel development.

At this point the userland architecture already exists.

This dramatically reduces the risk of designing the kernel around incomplete abstractions.

---

# 22.1 — Kernel Repository

Create:

```text
kernel/
├── arch/
├── boot/
├── memory/
├── interrupts/
├── scheduler/
├── process/
├── ipc/
├── object/
├── security/
├── drivers/
└── syscall/
```

---

# 22.2 — Target Architecture

Start with:

```text
x86_64
```

because it is the primary development architecture.

Later:

```text
AArch64
RISC-V
```

may be supported.

---

# 22.3 — Boot (ASM / C / C++)

Implement using **Assembly** and **C/C++** (or bare-metal Rust):

```text
boot entry
CPU setup
stack
early console
```

These operations require the lowest-level hardware manipulation where Rust's memory safety model might be too restrictive.

---

# 22.4 — GDT / IDT (ASM)

Implement architecture-specific structures utilizing **Assembly** macros and instructions for precise CPU control.

---

# 22.5 — Interrupts

Implement:

```text
interrupt entry
exception handling
timer interrupt
```

---

# 22.6 — Physical Memory

Implement:

```text
physical frame allocator
```

---

# 22.7 — Virtual Memory

Implement:

```text
page tables
address spaces
mapping
unmapping
protection
```

---

# 22.8 — Kernel Heap

Implement:

```text
kernel allocator
```

---

# 22.9 — Scheduler

Implement:

```text
thread
context switch
run queue
timer scheduling
```

---

# 22.10 — Phase 21 Exit Criteria

The kernel can:

```text
boot
initialize CPU
initialize memory
handle interrupts
schedule at least one thread
```

---

# 23. Phase 22 — Native Process System

## Objective

Replace Linux process primitives.

---

# 23.1 — Native Thread

Implement native thread context.

---

# 23.2 — Native Process

Implement:

```text
Process Object
```

directly in the kernel/core.

---

# 23.3 — Address Space

Each process gets:

```text
AddressSpace
```

---

# 23.4 — Native Handle Table

Move Handle Manager into the native environment.

---

# 23.5 — Process Creation

Implement:

```text
create process
start process
exit process
wait process
```

---

# 23.6 — Phase 22 Exit Criteria

Hyber processes run without Linux process creation.

---

# 24. Phase 23 — Native Object Manager

## Objective

Move the Object model into the native kernel/core.

---

# 24.1 — Object Registry

Implement native Object registry.

---

# 24.2 — Object Lifetime

Implement:

```text
reference counting
ownership
destruction
```

---

# 24.3 — Object Types

Port:

```text
FILE
DIRECTORY
PROCESS
THREAD
PIPE
SOCKET
DEVICE
SERVICE
```

incrementally.

---

# 24.4 — Phase 23 Exit Criteria

Objects are no longer simulated through Linux resources.

---

# 25. Phase 24 — Native VFS

## Objective

Move VFS onto the native kernel.

---

# 25.1 — VFS Kernel Boundary

Define:

```text
syscall
 ↓
VFS
```

---

# 25.2 — Native Namespace Manager

Implement:

```text
lookup
create
delete
rename
```

---

# 25.3 — Native Handles

Connect:

```text
process
 ↓
handle
 ↓
object
```

---

# 25.4 — Phase 24 Exit Criteria

Native processes can perform:

```text
open
read
write
close
```

through Hyber VFS.

---

# 26. Phase 25 — Native HyberFS

## Objective

Run HyberFS directly on the native kernel.

---

# 26.1 — Block Device Interface

Define:

```text
BlockDevice Object
```

---

# 26.2 — Storage Driver

Initially support:

```text
virtio-blk
```

or another simple virtual disk interface.

---

# 26.3 — HyberFS Driver

Connect:

```text
VFS
 ↓
HyberFS Provider
 ↓
Block Device
 ↓
Storage Driver
```

---

# 26.4 — Root Filesystem

Boot into:

```text
/
```

provided by HyberFS.

---

# 26.5 — Phase 25 Exit Criteria

Native HyberKOS can:

```text
boot
mount HyberFS
create files
read files
execute applications
```

without Linux.

---

# 27. Phase 26 — Native Device Model

## Objective

Replace host devices with native drivers.

---

# 27.1 — Device Object

Implement:

```text
Device Object
```

---

# 27.2 — Driver Interface

Define:

```text
probe
initialize
read
write
control
shutdown
```

---

# 27.3 — Virtual Hardware First

Develop against QEMU.

Start with:

```text
serial
timer
virtio block
virtio network
```

---

# 27.4 — Real Hardware Later

Only after QEMU is stable.

Potential targets:

```text
NVMe
USB
keyboard
display
Wi-Fi
audio
```

---

# 27.5 — Phase 26 Exit Criteria

The kernel can interact with core hardware without Linux.

---

# 28. Phase 27 — Native Networking

## Objective

Replace Linux networking.

---

# 28.1 — Network Driver

Implement a virtual network device first.

---

# 28.2 — Network Stack

Implement:

```text
Ethernet
ARP
IPv4
IPv6
ICMP
UDP
TCP
```

incrementally.

---

# 28.3 — Socket Layer

Connect:

```text
Socket Object
```

to the native network stack.

---

# 28.4 — Phase 27 Exit Criteria

HyberKOS can communicate over a network without Linux.

---

# 29. Phase 28 — Native Services and Runtime

## Objective

Port the service and runtime ecosystem.

---

# 29.1 — Init System (init.lua)

Create the first native system manager driven entirely by Lua.

The kernel boots, mounts the VFS, and immediately executes `/system/init.lua` which orchestrates the rest of the OS startup.

---

# 29.2 — Service Manager

Move service lifecycle into native HyberKOS.

---

# 29.3 — Lua Runtime

Port Lua runtime to native HyberKOS.

---

# 29.4 — Shell

Port:

```text
hyber-shell
```

to native Hyber processes.

---

# 29.5 — Phase 28 Exit Criteria

A native system can boot into:

```text
Hyber Init
 ↓
Services
 ↓
Shell
 ↓
Applications
```

---

# 30. Phase 29 — Runtime and Language Preparation

## Objective

Prepare the runtime, embedding, tooling, and binding requirements for a future
polyglot ecosystem. Phase 29 may contain research prototypes and internal
adapters, but it must not publish or freeze `libhyber`, `hyber.h`, a stable
ABI, or official language SDKs. Those belong to the deferred Phase 13 gate
after Phase 30.

Recommended roles:

```text
C / C++             -> Hardware Drivers, GUI Compositors, Low-level performance
Rust                -> Kernel Core, VFS, Object Managers, Security
Lua                 -> Init system, Service Management, System Automation
Go                  -> Networking Stack, Microservices, Background Daemons
Java / Kotlin       -> Enterprise Applications, Android-like App Ecosystem
JavaScript / TS     -> Desktop Environment, Window Manager UI
Python              -> Data processing, Scripting, AI/ML Tooling
```

---

# 30.1 — C / C++ Preparation

Investigate:

```text
prototype C boundary
```

Document ABI requirements and experiment with internal adapters. Do not
publish `libhyber` or freeze the public C ABI here.

---

# 30.2 — Rust Preparation

Prototype:

```text
internal Rust adapter experiments
```

The official `hyber-rs` API is created only by Phase 13 after the GUI gate.

---

# 30.3 — Lua

Already implemented.

Will act as the primary user-space orchestrator and init system for HyberKOS;
it does not define the kernel architecture, object model, VFS architecture, or
public application ABI.

---

# 30.4 — Python Preparation

Research and prototype:

```text
Python → Hyber API
```

---

# 30.5 — Go (Golang) Preparation

Research and prototype:

```text
Go → Hyber API
```

Focus Go specifically on networking applications and highly concurrent background tasks.

---

# 30.6 — JVM (Java / Kotlin) Preparation

Research and prototype:

```text
Java/Kotlin
 ↓
JVM
 ↓
Hyber API
```

---

# 30.7 — JavaScript / TypeScript Preparation

Research and prototype:

```text
JS/TS
 ↓
Runtime (e.g. V8 / Bun / Deno)
 ↓
Hyber API
```

---

# 31. Phase 30 — GUI

> **📌 PHASE 13 GATE:**
> Complete the GUI and the underlying native abstractions first. Once Phase 30
> is complete, start the deferred Phase 13 implementation: `libhyber`,
> `hyber.h`, `hyber-rs`, the official language bindings, and the public ABI.
> Phase 14A remains the early Lua foundation; after Phase 13, implement Phase
> 14B as Lua Application Integration. Phase 30 itself does not freeze the ABI.

## Objective

Build a native graphical environment.

---

# 31.1 — Display Server

Implement:

```text
Display Manager
```

---

# 31.2 — Window Manager

Implement:

```text
Window Object
```

---

# 31.3 — Input

Implement:

```text
keyboard
mouse
touch
```

---

# 31.4 — GUI Toolkit (Backend)

Rust-first implementation:

```text
Rust
```

Use C or C++ only when a concrete platform, GPU, or specialized-rendering
requirement justifies the FFI boundary. C++ is not a mandatory GUI layer.
The backend provides hardware acceleration, compositing, and rendering
pipelines (for example Vulkan/OpenGL wrappers).

---

# 31.5 — React/TypeScript Desktop Layer

React/HTML/CSS/TypeScript are a user-facing presentation layer. They must not
own process scheduling, filesystem access, IPC, device access, or application
termination. The desktop layer may include the shell, taskbar, launcher,
settings, notifications, and application UI:

```text
React / HTML / CSS / TS
       ↓
Hyber GUI Runtime (runtime choice is replaceable)
       ↓
GUI IPC
       ↓
Rust-first Window Manager / Compositor
```

WebView, V8, or another JavaScript runtime is an implementation detail of the
GUI runtime, not a HyberKOS architectural dependency. A future native widget
runtime must remain possible without changing the application model.

## 31.5.1 — Process and Lifecycle Separation

The GUI must keep these concepts separate:

```text
Window     ≠     Application     ≠     Process     ≠     Service
```

Closing or crashing a renderer must not implicitly terminate the owning
application process or an independent background service. The system must
distinguish:

```text
close_window()
request_close_application()
terminate_process()
```

Window state and application/process state are managed by the OS/GUI
subsystem, not by React. A minimized, hidden, suspended, or closed window may
leave its application running according to an explicit application policy.

## 31.5.2 — Independent GUI and Application Processes

The minimum process topology is:

```text
GUI Runtime / Renderer
          │ GUI IPC
          ▼
Window Manager / Compositor
          │ Application IPC
          ▼
Application Process
          │ service IPC
          ▼
Independent Background Service (when required)
```

The topology must support these failure boundaries:

```text
renderer crash       → window/session recovery, application policy applies
window close         → close request, not automatic process kill
desktop restart      → services and eligible applications may survive
application crash    → its windows/resources are reclaimed, other apps survive
```

## 31.5.3 — System UI, Applications, and Capabilities

System UI (desktop, launcher, taskbar, notifications) and user applications
are separate clients with different capabilities. Applications request
capabilities such as window creation, input access, or screen capture through
Hyber security objects; they never receive unrestricted device or host access.

## 31.5.4 — Provisional Contracts Before Phase 13

GUI work before Phase 13 may use internal, versioned, provisional contracts for
windows, surfaces, events, and sessions. These contracts are implementation
interfaces only. Phase 13 later formalizes the language-neutral public
Application/GUI API and ABI after the GUI requirements are proven; GUI
internals must not leak into that ABI accidentally.

---

# 31.6 — Phase 30 Exit Criteria

HyberKOS can boot into a graphical environment, launch applications, and has
documented and exercised the native application/GUI concepts required to
implement the deferred Phase 13 API. At minimum, window/application/process
separation, close-vs-terminate semantics, renderer failure recovery, and
background-service independence are demonstrated. Phase 30 does not itself
freeze the public ABI.

---

# 31.7 — Phase 14B — Lua Application Integration (After Phase 13)

After Phase 13 defines the application and GUI contracts, adapt Lua to the
same public model:

```text
Lua
 ↓
Hyber Application API
 ↓
Hyber GUI API
 ↓
IPC and Hyber Services
```

Phase 14B is the final Lua application layer. It must consume the common
Application API rather than define the kernel, object model, VFS, GUI
architecture, or public ABI itself.

---

# 32. Phase 31 — Package Ecosystem

## Objective

Move from local package installation to an ecosystem.

---

# 32.1 — Package Repository

Create:

```text
Hyber Package Repository
```

---

# 32.2 — Signing

Implement package signatures.

---

# 32.3 — Dependency Resolution

Implement:

```text
dependency graph
version constraints
conflict detection
```

---

# 32.4 — Updates

Implement:

```text
update
rollback
```

---

# 32.5 — Phase 31 Exit Criteria

The operating system can maintain an application ecosystem.

---

# 33. Phase 32 — Advanced HyberFS

## Objective

Improve filesystem capabilities.

Potential features:

```text
snapshots
copy-on-write
compression
encryption
deduplication
quotas
checksums
integrity trees
cloning
```

Implement these individually.

Do not implement them all simultaneously.

---

# 34. Phase 33 — Observability

## Objective

Make the operating system understandable internally.

---

# 34.1 — Object Inspector

Example:

```text
hyber object inspect 123
```

---

# 34.2 — Handle Inspector

Example:

```text
hyber handle list process 10
```

---

# 34.3 — Namespace Inspector

Example:

```text
hyber namespace tree /
```

---

# 34.4 — Process Inspector

Example:

```text
hyber process inspect 10
```

---

# 34.5 — System Tracing

Example:

```text
hyber trace
```

Output:

```text
LOOKUP /users/neo/test.txt
NODE test.txt
OBJECT #123
HANDLE #7
READ 4096 bytes
```

---

# 35. Phase 34 — Testing and Verification

## Objective

Build confidence in every subsystem.

Testing categories:

```text
unit tests
integration tests
filesystem tests
kernel tests
ABI tests
security tests
fuzz tests
stress tests
crash tests
performance tests
```

---

# 35.1 — Object Tests

Test:

```text
creation
lookup
references
destruction
```

---

# 35.2 — Namespace Tests

Test:

```text
lookup
rename
delete
links
path normalization
```

---

# 35.3 — Handle Tests

Test:

```text
rights
close
invalid handles
multiple processes
```

---

# 35.4 — Filesystem Tests

Test:

```text
small files
large files
empty files
deep directories
many files
rename
delete
crash
recovery
```

---

# 35.5 — Security Tests

Test:

```text
unauthorized access
privilege escalation
capability misuse
invalid handles
IPC permissions
package permissions
```

---

# 36. Phase 35 — Performance Engineering

## Objective

Only after correctness is established.

Measure:

```text
path lookup
Object lookup
Handle lookup
read
write
IPC
process creation
context switching
filesystem throughput
filesystem latency
network latency
```

---

# 36.1 — Benchmark Framework

Create:

```text
benchmarks/
```

---

# 36.2 — Baselines

Compare:

```text
Hyber HostFS
HyberFS
Linux filesystem
```

where useful.

The goal is not to copy Linux performance blindly.

The goal is to understand the cost of Hyber abstractions.

---

# 37. Phase 36 — Self-Hosting

## Objective

The final major milestone.

HyberKOS begins building itself.

---

# 37.1 — Native Compiler Toolchain

Provide:

```text
C compiler
Rust compiler
assembler
linker
debugger
```

---

# 37.2 — Native Build System

HyberKOS builds:

```text
kernel
core
filesystem
services
applications
```

---

# 37.3 — Native Package Builder

HyberKOS packages its own components.

---

# 37.4 — Self-Rebuild

Target workflow:

```text
HyberKOS
 ↓
Compiler
 ↓
Build HyberKOS
 ↓
Install
 ↓
Boot new version
```

---

# 38. Phase 37 — HyberLang

## Objective

Only after the OS and API are mature.

Do not design HyberLang at the beginning.

---

# 38.1 — Language Specification

Define:

```text
syntax
types
memory model
ownership
concurrency
modules
errors
generics
FFI
```

---

# 38.2 — Compiler

Build:

```text
hyberc
```

---

# 38.3 — Standard Library

Create:

```text
hyber.std
hyber.fs
hyber.net
hyber.process
hyber.ipc
```

---

# 38.4 — Native Integration

HyberLang should communicate naturally with:

```text
Object
Handle
Process
VFS
IPC
```

---

# 39. Phase 38 — Hardware Expansion

Once the virtual hardware environment is stable, expand hardware support.

Priority:

```text
Serial
 ↓
Storage
 ↓
Keyboard
 ↓
Display
 ↓
Network
 ↓
USB
 ↓
NVMe
 ↓
Audio
 ↓
Wi-Fi
```

Real hardware should be added incrementally.

---

# 40. Phase 39 — Security Hardening

Perform a dedicated security pass.

---

## 40.1 — Kernel Security

Review:

```text
memory isolation
user/kernel separation
interrupt handling
syscalls
capabilities
```

---

## 40.2 — Object Security

Review:

```text
Object lifetime
Object ownership
Object access
Object references
```

---

## 40.3 — Handle Security

Review:

```text
handle forgery
rights escalation
use-after-close
stale handles
cross-process handle abuse
```

---

## 40.4 — Filesystem Security

Review:

```text
metadata
ACL
permissions
encryption
journal
recovery
```

---

## 40.5 — Package Security

Review:

```text
signatures
repositories
dependencies
updates
rollback
```

---

# 41. Phase 40 — Release Engineering

## Objective

Turn HyberKOS into a usable operating system distribution.

---

# 41.1 — Build Images

Generate:

```text
ISO
disk image
VM image
```

---

# 41.2 — Versioning

Define:

```text
major.minor.patch
```

or another formal scheme.

---

# 41.3 — Release Channels

Potential:

```text
development
nightly
beta
stable
```

---

# 41.4 — Installation

Create an installer.

---

# 41.5 — Recovery

Provide:

```text
recovery environment
filesystem checker
rollback
safe boot
```

---

# 42. Phase 41 — Stable HyberKOS

The system should now provide:

```text
Native Kernel
      ↓
Hyber Core
      ↓
Object Manager
      ↓
Namespace Manager
      ↓
Handle Manager
      ↓
VFS
      ↓
HyberFS
      ↓
Process Manager
      ↓
IPC
      ↓
Services
      ↓
Networking
      ↓
Package Manager
      ↓
Runtime Ecosystem
      ↓
Applications
```

---

# 43. What You Should Work on RIGHT NOW

Do not start the kernel.

Do not start HyberFS.

Do not start GUI.

Do not start networking.

Do not start drivers.

Your immediate sequence is:

```text
1. Create repository
        ↓
2. Create Rust workspace
        ↓
3. Define ObjectId
        ↓
4. Define ObjectType
        ↓
5. Define ProcessId
        ↓
6. Define HandleId
        ↓
7. Define Node
        ↓
8. Define Path
        ↓
9. Define Rights
        ↓
10. Implement ObjectManager
        ↓
11. Implement NamespaceManager
        ↓
12. Implement Path Resolution
        ↓
13. Implement HandleManager
        ↓
14. Implement VFS
        ↓
15. Implement HostFS Provider
        ↓
16. Build Hyber Shell
```

That is your **first development milestone**.

---

# 44. First Milestone — "Hyber Core Alpha"

The first meaningful version should look like:

```text
Linux
 │
 └── ApexForge_HyberKOS
       │
       ├── Hyber Core
       │
       ├── Object Manager
       │
       ├── Namespace Manager
       │
       ├── Handle Manager
       │
       ├── VFS
       │
       ├── HostFS Provider
       │
       └── Hyber Shell
```

And the user should be able to do:

```text
$ hyber
```

then:

```text
hyber> mkdir /users
hyber> mkdir /users/neo
hyber> touch /users/neo/test.txt
hyber> write /users/neo/test.txt "Hello HyberKOS"
hyber> cat /users/neo/test.txt
Hello HyberKOS
```

Internally:

```text
touch
 ↓
Path
 ↓
Node
 ↓
File Object
 ↓
ObjectId
 ↓
VFS
 ↓
HostFS Provider
 ↓
Linux filesystem
```

Then:

```text
cat
 ↓
Path
 ↓
Node
 ↓
Object
 ↓
Handle
 ↓
VFS
 ↓
HostFS Provider
 ↓
Linux
```

That is the first real proof that the architecture works.

---

# 45. Recommended Development Order

The entire project can be compressed into this dependency graph:

```text
                    ARCHITECTURE
                         │
                         ▼
                    TYPE SYSTEM
                         │
                         ▼
                   OBJECT MANAGER
                         │
                         ▼
                NAMESPACE / NODE MGR
                         │
                         ▼
                   HANDLE MANAGER
                         │
                         ▼
                        VFS
                         │
                         ▼
                  PROVIDER SYSTEM
                         │
                         ▼
                   HOSTFS / LINUX
                         │
                         ▼
                    HYBER SHELL
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
         Lua Runtime           Security
              │                     │
              └──────────┬──────────┘
                         ▼
                  PROCESS SYSTEM
                         │
                         ▼
                       IPC
                         │
                         ▼
                     SERVICES
                         │
                         ▼
                    PACKAGES
                         │
                         ▼
                     HYBERFS
                         │
                         ▼
                 NATIVE KERNEL
                         │
                         ▼
                  NATIVE OBJECTS
                         │
                         ▼
                    NATIVE VFS
                         │
                         ▼
                   NATIVE HYBERFS
                         │
                         ▼
                  NATIVE USERLAND
                         │
                         ▼
                   SELF-HOSTING
```

---

# 46. Golden Rules During Development

## Rule 1

Never allow Linux implementation details to leak into Hyber APIs.

---

## Rule 2

Never make:

```text
ObjectId = inode
```

---

## Rule 3

Never make:

```text
HandleId = Linux FD
```

---

## Rule 4

Never make:

```text
ProcessId = Linux PID
```

---

## Rule 5

Never make:

```text
Hyber / = Linux /
```

---

## Rule 6

Never make Lua the operating-system architecture.

---

## Rule 7

Never optimize before measuring.

---

## Rule 8

Never add a feature without defining its abstraction.

---

## Rule 9

Every subsystem needs tests.

---

## Rule 10

Every major architectural decision must be documented.

---

# 47. The Development Loop

For every subsystem use:

```text
DESIGN
  ↓
TYPE DEFINITIONS
  ↓
MINIMAL IMPLEMENTATION
  ↓
UNIT TESTS
  ↓
INTEGRATION TEST
  ↓
DOCUMENTATION
  ↓
BENCHMARK
  ↓
REVIEW
  ↓
NEXT SUBSYSTEM
```

Do not:

```text
CODE EVERYTHING
 ↓
TEST AT THE END
```

---

# 48. Final Roadmap at a Glance

```text
PHASE 0
Project Foundation

PHASE 1
HyberKOS Type System

PHASE 2
Object Manager

PHASE 3
Namespace + Node Manager

PHASE 4
Handle Manager

PHASE 5
VFS

PHASE 6
Linux HostFS Provider

PHASE 7
Hyber Shell

PHASE 8
Metadata

PHASE 9
Security Foundation

PHASE 10
Process Model

PHASE 11
Virtual Namespaces

PHASE 12
Lua Runtime

PHASE 12.5
Advanced Lua Integration

PHASE 13
Hyber Application API / ABI (deferred until after GUI)

PHASE 14A
Lua Foundation Developer Toolchain

PHASE 14B
Lua Application Integration (after Phase 13)

PHASE 15
HyberFS

PHASE 16
HyberFS Reliability

SPECIAL_1
Identity, Users, and Groups

SPECIAL_2
Sessions, Authentication, and Credential Boundaries

SPECIAL_3
Home, Runtime, Cache, and Application Data Layout

SPECIAL_4
Shell Input, History, and Navigation

SPECIAL_5
Lua Shell Profiles and Environment

SPECIAL_6
Application Manifest, Sandbox, and Data Permissions

SPECIAL_7
Service and Network Boundary Preparation

SPECIAL_8
Cross-Layer Integration, Migration, and Gate Review

PHASE 17
Package Manager

PHASE 18
Service Manager

PHASE 19
IPC

PHASE 20
Networking

PHASE 21
Native Kernel Preparation

PHASE 22
Native Process System

PHASE 23
Native Object Manager

PHASE 24
Native VFS

PHASE 25
Native HyberFS

PHASE 26
Native Device Model

PHASE 27
Native Networking

PHASE 28
Native Services + Runtime

PHASE 29
Runtime and Language Preparation

PHASE 30
GUI (Rust-first backend, React/TypeScript desktop)

PHASE 31
Package Ecosystem

PHASE 32
Advanced HyberFS

PHASE 33
Observability

PHASE 34
Testing + Verification

PHASE 35
Performance Engineering

PHASE 36
Self-Hosting

PHASE 37
HyberLang

PHASE 38
Hardware Expansion

PHASE 39
Security Hardening

PHASE 40
Release Engineering

PHASE 41
Stable HyberKOS
```

---

# 49. Immediate Starting Point

The first actual coding session should contain only:

```text
ApexForge_HyberKOS/
├── Cargo.toml
├── README.md
├── VISION.md
├── ROADMAP.md
│
└── crates/
    ├── hyber-core/
    ├── hyber-object/
    ├── hyber-namespace/
    ├── hyber-handle/
    ├── hyber-vfs/
    └── hyber-api/
```

Then implement, in exactly this order:

```text
ObjectId
    ↓
ObjectType
    ↓
Object
    ↓
ObjectManager
    ↓
Node
    ↓
Path
    ↓
Namespace
    ↓
HandleId
    ↓
Handle
    ↓
HandleTable
    ↓
VFS
```

Only after these work should the first Linux backend be written.

The first objective is therefore **not to build an operating system**.

The first objective is:

> **Build the smallest working HyberKOS world in which Path → Node → Object and Process → Handle → Object actually work.**

Once that foundation works, everything else can be built on top of it.

---

# Final Development Philosophy

ApexForge_HyberKOS should be built like a long-term systems project, not like a single giant application.

The development direction is:

```text
Understand
   ↓
Model
   ↓
Define
   ↓
Implement
   ↓
Test
   ↓
Observe
   ↓
Improve
```

The architecture should always remain visible.

At every point in development, it should be possible to answer:

```text
What is this?
Who owns it?
What Object represents it?
What Node exposes it?
What Path reaches it?
What Handle accesses it?
What Provider implements it?
What VFS operation reaches it?
What backend ultimately executes it?
```

If those questions can be answered clearly, HyberKOS remains architecturally coherent.

If they cannot, the subsystem should be redesigned before more code is added.

---

# End of Roadmap

**ApexForge_HyberKOS**

> **Architecture first.
> Abstractions second.
> Implementation third.
> Optimization fourth.
> Native kernel last.**
