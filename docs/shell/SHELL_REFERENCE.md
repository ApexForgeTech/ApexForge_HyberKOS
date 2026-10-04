# HyberKOS Shell — Command Reference

> **Phase 7–12.5 | hyber-shell v0.12.5**

This document covers all currently available commands in `hyber-shell`. The shell is the first user-space environment of HyberKOS. Every operation passes through the HyberKOS Object/Handle model — raw Linux system calls are never invoked directly.

---

## Getting Started

```bash
# Build the project
cd /home/<user>/Documents/ApexForge_HyberKOS
cargo build --bin hyber-shell

# Run the shell
cargo run --bin hyber-shell

# Or run the binary directly
./target/debug/hyber-shell
```

When the shell starts, it mounts `~/hyber-host/` as **HostFS** and creates the following virtual namespace:

```text
/
├── system/       ← HostFS  (OS internal files)
├── users/        ← HostFS  (user data)
├── apps/         ← HostFS  (installed applications)
├── data/         ← HostFS  (persistent data)
├── config/       ← HostFS  (configuration files)
├── packages/     ← HostFS  (package artifacts)
├── volumes/      ← HostFS  (mountable volumes)
├── developer/    ← HostFS  (development tools)
├── processes/    ← ProcessProvider  (live process tree)
├── devices/      ← DeviceProvider   (virtual devices)
├── services/     ← ServiceProvider  (system services)
├── runtime/      ← MemFS  (volatile runtime data)
└── temporary/    ← MemFS  (temporary scratch space)
```

The `/config` namespace remains a system-level compatibility area. Per-user
application data follows the special integration contract: configuration is
under `/users/<user>/.config/<app-id>`, persistent data under
`.local/share/<app-id>`, recoverable state under `.local/state/<app-id>`, cache
under `.cache/<app-id>`, temporary data under `/temporary/users/<user>/<app-id>`,
and live session data under `/runtime/users/<user>/`. These boundaries are
formalized by `Special_3` and enforced through logical application-directory
APIs rather than hardcoded host paths.

---

## Standard Operations

### `pwd` — Print Working Directory

```text
pwd
```

Prints the absolute path of the current working directory.

```text
hyber:/$ pwd
/
```

---

### `cd` — Change Directory

```text
cd <path>
cd ..
cd
```

| Argument | Description |
|----------|-------------|
| `<path>` | Relative or absolute path |
| `..` | Move to the parent directory |
| *(empty)* | Return to the root directory (`/`) |

```text
hyber:/$ cd /runtime
hyber:/runtime$ cd ..
hyber:/$
```

---

### `ls` — List Directory Contents

```text
ls [-l] [-a] [path]
```

| Flag | Description |
|------|-------------|
| `-l` | Long format — displays the Object type |
| `-a` | Show hidden files, including entries beginning with `.` |
| `path` | Path to list (default: current directory) |

```text
hyber:/$ ls /devices
null
random
zero

hyber:/$ ls -l /devices
null [DEVICE]
random [DEVICE]
zero [DEVICE]
```

---

### `tree` — Namespace Tree

```text
tree [path]
```

Recursively displays the namespace in tree format, with a maximum depth of 4 levels.

```text
hyber:/$ tree /
/
├── apps [DIRECTORY]
├── devices [DIRECTORY]
│   ├── null [DEVICE]
│   ├── random [DEVICE]
│   └── zero [DEVICE]
├── processes [DIRECTORY]
│   └── 1 [PROCESS]
├── runtime [DIRECTORY]
│   └── .keep [FILE]
├── services [DIRECTORY]
│   ├── logger [SERVICE]
│   ├── netstack [SERVICE]
│   └── scheduler [SERVICE]
└── temporary [DIRECTORY]
```

---

### `mkdir` — Create Directory

```text
mkdir [-p] <path>
```

| Flag | Description |
|------|-------------|
| `-p` | Create parent directories recursively |

```text
hyber:/$ mkdir /runtime/myapp
hyber:/$ mkdir -p /runtime/myapp/data/logs
```

---

### `touch` — Create File / Update Timestamp

```text
touch <path>
```

Creates the file if it does not exist. If it already exists, its `modified_at` timestamp is updated.

```text
hyber:/$ touch /runtime/myapp/config.txt
hyber:/$ touch /temporary/scratch.log
```

---

### `rm` — Remove

```text
rm [-r] <path>
```

| Flag | Description |
|------|-------------|
| `-r` | Recursive removal, required for non-empty directories |

```text
hyber:/$ rm /runtime/myapp/config.txt
hyber:/$ rm -r /runtime/myapp
```

> ⚠️ Virtual root namespace directories such as `/processes`, `/devices`, etc. cannot be removed.

---

### `mv` — Move / Rename

```text
mv <source> <dest>
```

Moves a file or directory to another path within the same Provider.

```text
hyber:/$ mv /runtime/old.txt /runtime/new.txt
hyber:/$ mv /runtime/config.txt /data/config.txt
```

---

### `cp` — Copy

```text
cp <source> <dest>
```

Reads a file and writes it as a new file. Directories are not copied.

```text
hyber:/$ cp /runtime/config.txt /temporary/config.bak
```

---

### `cat` — Print File Contents

```text
cat <path>
```

Opens the file, reads it through the VFS, and prints its contents to stdout.

```text
hyber:/$ cat /runtime/notes.txt
```

For virtual devices, `cat` reads one chunk and stops to prevent an infinite loop:

```text
hyber:/$ cat /devices/random
[Device output truncated]
```

---

# HyberKOS Native Commands

### `list` — List with Object Details

```text
list [path]
```

Unlike `ls`, `list` displays the ObjectId, type, reference count, and size for every entry.

```text
hyber:/$ list /devices
Name                 | ObjectId     | Type       | Refs  | Size
-----------------------------------------------------------------
null                 | ObjectId(5)  | DEVICE     | 1     | 0
random               | ObjectId(6)  | DEVICE     | 1     | 0
zero                 | ObjectId(7)  | DEVICE     | 1     | 0
```

---

### `look` — Deep Object Inspection

```text
look <path>
```

Displays all fields of an Object, including its ID, type, state, permissions, timestamps, provider, and extended metadata.

```text
hyber:/$ look /runtime/myapp/config.txt
Object ID:   ObjectId(42)
Type:        FILE
State:       LIVE
References:  1
Owner:       UID(0)
Group:       GID(0)
Permissions: 644
Size:        0
Created:     1791100000
Modified:    1791100000
Flags:       0
Provider:    runtime-memfs
```

---

### `acquire` — Acquire a Handle

```text
acquire <path> [mode]
```

| Mode | Description |
|------|-------------|
| `r` | Read-only (default) |
| `w` | Write-only |
| `rw` | Read + write |

```text
hyber:/$ acquire /runtime/config.txt rw
Acquired Handle #1 for Object #42
```

> Acquiring a handle increases the Object's strong reference count.

---

### `release` — Release a Handle

```text
release <handle_id>
```

```text
hyber:/$ release 1
Released Handle #1
```

---

### `handles` — List Open Handles

```text
handles
```

Displays the current process's handle table.

```text
hyber:/$ handles
HandleId   | ObjectId     | Rights     | Offset
--------------------------------------------------
HandleId(1) | ObjectId(42) | RW-        | 128
```

Rights:

- `R` = read
- `W` = write
- `X` = execute
- `-` = not granted

---

### `mnts` — Mount Points

```text
mnts
```

Displays all mount points registered with the VFS.

```text
hyber:/$ mnts
Namespace Path       | Provider Name        | Status
-------------------------------------------------------
/                    | hostfs               | Active
/processes           | procfs               | Active
/devices             | devfs                | Active
/services            | svcfs                | Active
/runtime             | runtime-memfs        | Active
/temporary           | tmp-memfs            | Active
```

---

### `rights` — Check Permissions

```text
rights <path>
```

Displays the current process's READ/WRITE/EXECUTE permissions for the specified Object.

```text
hyber:/$ rights /runtime/config.txt
READ:    Yes
WRITE:   Yes
EXECUTE: No
```

---

### `meta` — Extended Metadata

```text
meta ls  <path>
meta get <path> <key>
meta set <path> <key> <type> <value>
meta rm  <path> <key>
```

**Key format:** `namespace.name` (for example, `app.version`, `git.commit`)

| Type | Description |
|------|-------------|
| `string` | Text |
| `int` | 64-bit integer |
| `bool` | `true` / `false` |

```text
hyber:/$ meta set /runtime/config.txt app.version int 42
Metadata set.

hyber:/$ meta set /runtime/config.txt app.author string "neo"
Metadata set.

hyber:/$ meta set /runtime/config.txt app.debug bool true
Metadata set.

hyber:/$ meta ls /runtime/config.txt
app.author = "neo"
app.version = 42
app.debug = true

hyber:/$ meta get /runtime/config.txt app.version
42

hyber:/$ meta rm /runtime/config.txt app.debug
Metadata removed.
```

---

# Phase 10/11 — Process & System Commands

### `ps` — Process List

```text
ps
```

```text
hyber:/$ ps
PID   | PPID  | State      | UID   | GID
-------------------------------------------------------
1     | -     | Running    | 0     | 0
```

---

### `su` — Switch User

```text
su <uid> [gid]
```

Trusted bootstrap-mode administrative command. It requires CAP_SYS_ADMIN;
authenticated `--auth` sessions reject numeric `su`. Use a fresh authenticated
login to change accounts. See [identity and sessions](../security/identity-sessions.md).

If no GID is provided, the UID is used as the GID.

When switching to a non-root user, capabilities and supplementary groups are cleared.

```text
hyber:/$ su 1000 1000
Switched to UID: 1000, GID: 1000

hyber:/$ su 0
Error: Access denied: Missing capability 'CAP_SYS_ADMIN'
```

---

### `lsdev` — List Devices

```text
lsdev
```

Lists all virtual devices under `/devices`.

```text
hyber:/$ lsdev
Name         | Class      | Online   | Description
------------------------------------------------------------
null         | Virtual    | true     | Discard all writes, return zeros on read
zero         | Virtual    | true     | Always returns zero bytes
random       | Virtual    | true     | Pseudo-random byte generator
```

**Built-in virtual devices:**

| Device | Behavior |
|--------|----------|
| `/devices/null` | Discards all writes and returns zeros on read |
| `/devices/zero` | Always returns `0x00` bytes |
| `/devices/random` | Generates pseudo-random bytes using an LCG |

---

### `lssvc` — List Services

```text
lssvc
```

Lists registered services under `/services`.

```text
hyber:/$ lssvc
Name           | State      | PID    | Description
--------------------------------------------------------------
logger         | stopped    | -      | HyberKOS system event logger
scheduler      | stopped    | -      | HyberKOS cooperative task scheduler
netstack       | stopped    | -      | HyberKOS network stack (not yet active)
```

---

# Phase 12 — Lua Runtime

The HyberKOS Shell integrates the Lua 5.4 runtime. Lua scripts have full access to the Object Manager, VFS, and Namespace Manager through the `hyber.*` API.

### `lua` — Inline Lua Execution

```text
lua "<script>"
```

Executes a single-line or short Lua script directly. 
> ⚠️ **Note:** Since `;` is now a shell command separator, any Lua script containing `;` must be wrapped in quotes (`"..."`).

```text
hyber:/$ lua "hyber.log.info('Hello HyberKOS!')"
[hyber:info] Hello HyberKOS!

hyber:/$ lua "print('PID=' .. hyber.proc.pid() .. '  UID=' .. hyber.proc.uid())"
PID=1  UID=0

hyber:/$ lua "print(hyber.ns.exists('/runtime'))"
true
```

---

### `luafile` — File-Based Lua Execution

```text
luafile <path>
```

Reads a Lua script from the HyberKOS namespace through the VFS and executes it.

```text
hyber:/$ touch /runtime/hello.lua
hyber:/$ lua local f=hyber.fs.open("/runtime/hello.lua","w"); f:write('print("Hello from HyberKOS Lua!")'); f:close()
hyber:/$ luafile /runtime/hello.lua
Hello from HyberKOS Lua!
```

---

# Lua API Reference

## `hyber.fs` — File System

```lua
-- Open a file
local file = hyber.fs.open(path, mode)
-- mode: "r" | "read" | "w" | "write" | "rw" | "readwrite"

-- Read (returns a string, nil at EOF)
local data = file:read()

-- Write (returns the number of bytes written)
local n = file:write("content")

-- Close (returns true)
file:close()
```

### Example — Write and Read a File

```lua
local f = hyber.fs.open("/runtime/test.txt", "w")
f:write("Hello HyberKOS!\n")
f:close()

local f2 = hyber.fs.open("/runtime/test.txt", "r")
local content = f2:read()
f2:close()
print(content)
```

---

## `hyber.input` — Early Input Events

Lua receives OS-neutral input events from the current runtime queue. Synthetic
event injection is capability-protected and is intended for tests, system UI,
and trusted input adapters; it is not a replacement for the future native
keyboard/touch device subsystem.

```lua
-- Number of queued events
local count = hyber.input.pending()

-- Consume one event, or nil when the queue is empty
local event = hyber.input.next()
if event then
    print(event.kind, event.code, event.value, event.timestamp)
end

-- Requires CAP_INPUT_INJECT (root/system adapters have it)
hyber.input.emit("keyboard", "KEY_ENTER", 1)

-- Discard events belonging to this runtime
hyber.input.clear()
```

The event queue deliberately does not expose Linux evdev codes or host device
handles. A future GUI/input subsystem can feed the same neutral event shape.

---

## `hyber.ns` — Namespace

```lua
-- Does a path exist?
local exists = hyber.ns.exists("/runtime/myfile.txt")  -- bool

-- List directory contents
local entries = hyber.ns.list("/runtime")
-- Returns: { {name="foo", obj_id=42}, {name="bar", obj_id=43}, ... }
```

### Example — List All Root Entries

```lua
local entries = hyber.ns.list("/")
for _, e in ipairs(entries) do
    print(e.name .. " [obj:" .. e.obj_id .. "]")
end
```

---

## `hyber.obj` — Object Inspection

```lua
-- Get Object information (returns a table)
local info = hyber.obj.info("/runtime/test.txt")
-- info.id, info.type, info.state, info.references
-- info.owner, info.group, info.permissions
-- info.size, info.created_at, info.modified_at

-- Read extended metadata
local val = hyber.obj.meta_get(path, key)  -- nil if not found

-- Write extended metadata
-- type: "string" | "int" | "bool"
hyber.obj.meta_set(path, key, type, value)
```

### Example — Inspect Object Details

```lua
local info = hyber.obj.info("/devices/null")
print("Type:  " .. info.type)
print("Refs:  " .. info.references)
print("Owner: " .. info.owner)
```

### Example — Write and Read Metadata

```lua
hyber.obj.meta_set("/runtime/test.txt", "app.tag", "string", "production")
local tag = hyber.obj.meta_get("/runtime/test.txt", "app.tag")
print("Tag: " .. tag)
```

---

## `hyber.proc` — Process Information

```lua
local pid = hyber.proc.pid()   -- HyberKOS Process ID (u64)
local uid = hyber.proc.uid()   -- Current user ID (u32)
local child_pid = hyber.proc.spawn("/apps/worker.lua")
local exit_code = hyber.proc.wait(child_pid) -- nil while still running
```

## `hyber.sec` — Security Checks

```lua
local writable = hyber.sec.check_access("/runtime/test.txt", "w")
local is_admin = hyber.sec.check_capability("CAP_SYS_ADMIN")
```

`check_access` accepts `r`, `w`, or `rw`; it returns `false` when the current
process context lacks the requested permission.

---

## `hyber.log` — Logging

```lua
hyber.log.info("Normal information message")
hyber.log.warn("Warning message")
hyber.log.error("Error message")
```

Output format:

```text
[hyber:info] ...
[hyber:warn] ...
[hyber:error] ...
```

---

# Lua — Complete Example Scripts

### 1. System Summary

```lua
hyber.log.info("=== HyberKOS System Summary ===")
print("PID: " .. hyber.proc.pid())
print("UID: " .. hyber.proc.uid())

local roots = hyber.ns.list("/")
print("\nNamespace root (" .. #roots .. " entries):")
for _, e in ipairs(roots) do
    local info = hyber.obj.info("/" .. e.name)
    print("  /" .. e.name .. " [" .. info.type .. "] refs=" .. info.references)
end
```

### 2. Create a File and Add Metadata

```lua
local path = "/runtime/mylog.txt"

-- Write
local f = hyber.fs.open(path, "w")
f:write("Log started: " .. os.date())
f:close()

-- Metadata
hyber.obj.meta_set(path, "log.level", "string", "info")
hyber.obj.meta_set(path, "log.entries", "int", 1)

-- Verify
local info = hyber.obj.info(path)
print("File size: " .. info.size .. " bytes")
print("Log level: " .. hyber.obj.meta_get(path, "log.level"))
```

### 3. Device Check

```lua
local devices = hyber.ns.list("/devices")
print("Registered devices:")
for _, d in ipairs(devices) do
    local exists = hyber.ns.exists("/devices/" .. d.name)
    print("  /devices/" .. d.name .. " exists=" .. tostring(exists))
end
```

---

# Utility Commands

### `cls` / `clear` — Clear Screen

```text
cls
clear
```

Clears the terminal screen.

---

### `help` — Help

```text
help
```

Prints a short list of all available commands.

---

### `exit` — Exit

```text
exit
```

Closes all open handles and shuts down the shell.

---

# Automatic Demo

To test all features with a single command:

```bash
bash demo.sh
```

This script automatically executes all Phase 10–12 commands and displays their output.

---

# Error Conditions

| Error | Cause |
|-------|-------|
| `No provider mounted for path` | No mount point exists for the specified path |
| `Object not found` | The ObjectId no longer exists because the Object has been destroyed |
| `Cannot open: Object ... is destroyed` | Attempted to acquire a handle for a destroyed Object |
| `Access denied: READ permission missing` | The SecurityContext does not have permission to access the Object |
| `/services is read-only` | Services cannot be created through the VFS |
| `Lua error: ...` | Lua runtime error — the shell continues running |

---

# Architecture Note

Every shell operation follows the same architecture pipeline:

```text
Command
   ↓
VFS.open/read/write/create/remove
   ↓
SecurityManager.check_access(SecurityContext, Rights)
   ↓
Provider (HostFS | MemFS | ProcessProvider | DeviceProvider | ServiceProvider)
   ↓
ObjectManager + HandleManager
   ↓
Object (lifecycle: Live → Closing → Destroyed)
```

Lua scripts use the exact same pipeline. For example:

```lua
hyber.fs.open()
```

ultimately invokes the same:

```text
VFS.open()
```

used by native shell commands.
