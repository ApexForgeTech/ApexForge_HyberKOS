# HyberKOS Shell (`hyber-shell`) Command Reference

> **Status:** Design Document (Phase 7)
> **Objective:** Define the command-line interface for the first HyberKOS user-space environment.
> **Philosophy:** Provide standard POSIX-like familiarity for daily tasks, while exposing deep HyberKOS architectural primitives (Objects, Handles, Providers) for system introspection.

---

## 1. Standard Base Commands (Familiarity Layer)
These commands behave exactly like their Linux/Unix counterparts to ensure a smooth user experience. However, under the hood, they **do not use Linux syscalls**. They operate entirely through the HyberKOS VFS, Namespace, and Handle abstractions.

### Navigation & Context
* **`pwd`** (Print Working Directory)
  * Shows the current absolute Hyber namespace path.
* **`cd <path>`** (Change Directory)
  * Changes the shell's current working directory.
  * Supports `.` (current), `..` (parent), and absolute/relative paths.

### File & Directory Management
* **`ls [path]`**
  * Lists directory contents (names only).
  * *Flags:* `-l` (long format: shows size, type), `-a` (show hidden/dotfiles).
* **`mkdir <path>`**
  * Creates a new Directory Object and links it to the namespace.
  * *Flags:* `-p` (create parent directories as needed).
* **`touch <path>`**
  * Creates an empty File Object or updates the `modified_at` timestamp of an existing one.
* **`rm <path>`**
  * Removes a Node from the namespace and destroys the underlying Object (if reference count reaches 0).
  * *Flags:* `-r` (recursive delete for directories).
* **`mv <source> <dest>`**
  * Relocates a Node (renames or moves to a different parent directory).
* **`cp <source> <dest>`**
  * Copies file data. (Internally: `acquire` source for READ, `create` dest, `acquire` dest for WRITE, stream data, `release` both).

### Content Viewing
* **`cat <path>`**
  * Reads a File Object and prints its contents to standard output.

---

## 2. HyberKOS Native Commands (Introspection Layer)
These commands are unique to HyberKOS. They allow the user to interact directly with the Object Model, Handle Manager, and VFS Providers.

### Namespace & Object Introspection
* **`list [path]`** (The Hyber-aware `ls`)
  * Unlike `ls`, `list` exposes the underlying HyberKOS architecture.
  * *Output Format:* `Name | ObjectId | Type | Refs | Size`
  * *Example:* `test.txt | Obj(104) | FILE | 1 | 4096`
* **`look <path>`** (Replaces `stat` / `inspect`)
  * Dumps deep metadata about the Object behind a Node.
  * *Output:* Object ID, Type, State (Live/Closing), Reference Count, Created/Modified timestamps, Flags, and the Provider handling it.
  * *Flags:* `-v` (verbose: includes extended metadata).

### Handle Management (Capability System)
* **`acquire <path> [mode]`** (Replaces `open`)
  * Manually requests a Handle to an Object.
  * *Modes:* `r` (Read), `w` (Write), `rw` (Read/Write). Default is `r`.
  * *Output:* Prints the assigned `HandleId` (e.g., `Acquired Handle #7 for Object #104`).
* **`release <handle_id>`** (Replaces `close`)
  * Manually drops a Handle, decrementing the Object's reference count.
* **`handles`**
  * Displays the shell process's current Handle Table.
  * *Output Format:* `HandleId | ObjectId | Rights | Offset`

### VFS & Security Introspection
* **`mnts`** (Mounts / Providers)
  * Lists all active VFS mount points and their backing Providers.
  * *Output Format:* `Namespace Path | Provider Name | Status`
  * *Example:* `/ | HostFSProvider | Active`
* **`rights <path>`** (or `perms`)
  * Evaluates and displays the effective access rights the current shell process has for a given path based on Object permissions and Handle capabilities.
  * *Output:* `READ: Yes | WRITE: No | EXECUTE: No`

### System Control
* **`exit`**
  * Gracefully shuts down the shell.
  * *Crucial Action:* Automatically iterates through the Handle Table and calls `release` on all open handles to prevent memory/resource leaks before terminating the process.

---

## 3. Shell Path Handling Rules
1. **Hyber Paths Only:** All commands must accept Hyber namespace paths (e.g., `/users/neo/docs`). They must **never** accept or expose Linux host paths (e.g., `/home/neo/hyber-host/...`).
2. **Relative Resolution:** If a path does not start with `/`, it is resolved relative to the shell's current `pwd` context.
3. **Normalization:** Paths like `/users/../users/./neo` are automatically normalized by the `NamespaceManager` before execution.

---

## 4. Implementation Strategy (Phase 7)
* **REPL Loop:** The shell will run a continuous `Read-Eval-Print Loop` reading from `stdin`.
* **Parser:** A simple string tokenizer will split user input into `command` and `arguments`.
* **Execution:** 
  * Standard commands will map to `VFS` and `NamespaceManager` helper functions.
  * Native commands will map directly to `ObjectManager`, `HandleManager`, and `MountTable` queries.
* **Backend:** The shell will initialize the `HostFSProvider` at startup, mapping `/` to a safe, isolated directory on the Linux host (e.g., `~/hyber-host`).