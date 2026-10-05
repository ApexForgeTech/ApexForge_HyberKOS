//! HyberKOS Lua Runtime
//! Phase 12 & 12.5 — Lua Integration + Advanced System Orchestration
//!
//! ## Design: Borrow-safe Kernel State
//!
//! mlua closures must be `'static + Send`, so all Rust state is wrapped in
//! `Arc<Mutex<KernelState>>`.  The Rust borrow-checker prevents borrowing
//! multiple fields of a `MutexGuard` simultaneously when those borrows are
//! mixed (e.g., `&vfs` + `&mut handle_mgr` from the same lock-guard).
//!
//! Solution: destructure the guard into individual field references using
//! `let KernelState { vfs, ns_mgr, handle_mgr, obj_mgr, .. } = &mut *ks;`
//! This gives the borrow-checker independent borrows on each field and
//! avoids the "cannot borrow `ks` as mutable because it is also borrowed as
//! immutable" errors.
//!
//! ## Exposed Lua API
//!
//! ### `hyber.fs`
//! | Function | Description |
//! |---|---|
//! | `hyber.fs.open(path, mode)` | Open file ("r"/"w"/"rw"), returns file object |
//! | `file:read([size])` | Read bytes (returns string or nil at EOF) |
//! | `file:write(data)` | Write string to file |
//! | `file:close()` | Release handle |
//!
//! ### `hyber.ns`
//! | Function | Description |
//! |---|---|
//! | `hyber.ns.exists(path)` | true if path resolves |
//! | `hyber.ns.list(path)` | array of `{name, obj_id}` tables |
//!
//! ### `hyber.obj`
//! | Function | Description |
//! |---|---|
//! | `hyber.obj.info(path)` | table with all object fields |
//! | `hyber.obj.meta_get(path, key)` | read extended metadata |
//! | `hyber.obj.meta_set(path, key, type, value)` | write extended metadata |
//!
//! ### `hyber.proc`  *(Phase 12 + 12.5)*
//! | Function | Description |
//! |---|---|
//! | `hyber.proc.pid()` | current HyberKOS process ID |
//! | `hyber.proc.uid()` | current user ID |
//! | `hyber.proc.spawn(path)` | spawn a new child HyberKOS process, returns child PID |
//! | `hyber.proc.wait(pid)` | wait for process exit; returns exit code (int) or nil if still running |
//!
//! ### `hyber.sec`  *(Phase 12.5)*
//! | Function | Description |
//! |---|---|
//! | `hyber.sec.check_access(path, rights)` | evaluates R/W/RW access rights for current context |
//! | `hyber.sec.check_capability(cap)` | checks if current context has a named capability |
//!
//! ### `hyber.log`
//! | Function | Description |
//! |---|---|
//! | `hyber.log.info(msg)` | info print |
//! | `hyber.log.warn(msg)` | warning print |
//! | `hyber.log.error(msg)` | error print |
//!
//! ### `hyber.input` *(early, OS-neutral event queue)*
//! | Function | Description |
//! |---|---|
//! | `hyber.input.next()` | consume the next input event or return `nil` |
//! | `hyber.input.pending()` | number of queued events |
//! | `hyber.input.emit(kind, code, value)` | inject a synthetic event; capability checked |
//! | `hyber.input.clear()` | discard queued events |

use hyber_core::{MetadataValue, Path, ProcessId, Rights, SecurityContext, SecurityManager};
use hyber_handle::HandleManager;
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_process::ProcessManager;
use hyber_vfs::VFS;
use mlua::prelude::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ── Shared kernel state ───────────────────────────────────────────────────────

struct KernelState {
    session: Option<hyber_auth::SessionGuard>,
    vfs: VFS,
    ns_mgr: NamespaceManager,
    handle_mgr: HandleManager,
    obj_mgr: ObjectManager,
    proc_mgr: Arc<Mutex<ProcessManager>>,
    process_id: ProcessId,
    security_context: SecurityContext,
    input_queue: VecDeque<InputEvent>,
}

#[derive(Debug, Clone)]
struct InputEvent {
    kind: String,
    code: String,
    value: i64,
    timestamp: u64,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Execute a Lua script inside the HyberKOS environment.
///
/// All kernel state is moved into `Arc<Mutex<KernelState>>` for the duration
/// of the script and returned on success so the shell can swap it back in.
#[allow(
    clippy::arc_with_non_send_sync,
    clippy::too_many_arguments,
    reason = "mlua invokes this single-threaded runtime synchronously; the state is split into explicit managers for the shell boundary"
)]
pub fn run_lua_script(
    script: &str,
    vfs: VFS,
    ns_mgr: NamespaceManager,
    handle_mgr: HandleManager,
    obj_mgr: ObjectManager,
    proc_mgr: Arc<Mutex<ProcessManager>>,
    process_id: ProcessId,
    security_context: SecurityContext,
) -> (
    VFS,
    NamespaceManager,
    HandleManager,
    ObjectManager,
    Result<(), mlua::Error>,
) {
    run_lua_script_with_session(
        script,
        vfs,
        ns_mgr,
        handle_mgr,
        obj_mgr,
        proc_mgr,
        process_id,
        security_context,
        None,
    )
}

/// Authenticated callers provide a shared guard. Every Hyber operation
/// refreshes the context, including reads through previously opened handles.
#[allow(clippy::too_many_arguments, clippy::arc_with_non_send_sync)]
pub fn run_lua_script_with_session(
    script: &str,
    vfs: VFS,
    ns_mgr: NamespaceManager,
    handle_mgr: HandleManager,
    obj_mgr: ObjectManager,
    proc_mgr: Arc<Mutex<ProcessManager>>,
    process_id: ProcessId,
    security_context: SecurityContext,
    session: Option<hyber_auth::SessionGuard>,
) -> (
    VFS,
    NamespaceManager,
    HandleManager,
    ObjectManager,
    Result<(), mlua::Error>,
) {
    let state = Arc::new(Mutex::new(KernelState {
        session,
        vfs,
        ns_mgr,
        handle_mgr,
        obj_mgr,
        proc_mgr,
        process_id,
        security_context,
        input_queue: VecDeque::new(),
    }));

    let exec_res = (|| -> Result<(), mlua::Error> {
        let lua = Lua::new();
        // Host filesystem/process APIs bypass Hyber permissions and sessions.
        for name in [
            "io", "os", "package", "debug", "require", "dofile", "loadfile",
        ] {
            lua.globals().set(name, LuaValue::Nil)?;
        }
        if let Some(session) = &lock(&state)?.session {
            session.context().map_err(|e| lua_err(e.to_string()))?;
            let session = session.clone();
            lua.set_hook(
                mlua::HookTriggers::new().every_nth_instruction(10_000),
                move |_, _| {
                    session
                        .context()
                        .map(|_| ())
                        .map_err(|e| lua_err(e.to_string()))
                },
            );
        }
        build_hyber_table(&lua, Arc::clone(&state))?;
        lua.load(script).exec()?;
        Ok(())
    })();

    let ks = Arc::try_unwrap(state)
        .ok()
        .expect("Lua closures leaked Arc reference")
        .into_inner()
        .expect("Mutex poisoned");

    (ks.vfs, ks.ns_mgr, ks.handle_mgr, ks.obj_mgr, exec_res)
}

// ── Lua table builder ─────────────────────────────────────────────────────────

fn build_hyber_table(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<()> {
    let globals = lua.globals();
    let hyber = lua.create_table()?;

    hyber.set("fs", build_fs(lua, Arc::clone(&state))?)?;
    hyber.set("ns", build_ns(lua, Arc::clone(&state))?)?;
    hyber.set("obj", build_obj(lua, Arc::clone(&state))?)?;
    hyber.set("proc", build_proc(lua, Arc::clone(&state))?)?;
    hyber.set("sec", build_sec(lua, Arc::clone(&state))?)?;
    hyber.set("input", build_input(lua, Arc::clone(&state))?)?;
    hyber.set("log", build_log(lua)?)?;
    hyber.set(
        "cls",
        lua.create_function(|_lua, ()| {
            print!("\x1B[2J\x1B[1;1H");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            Ok(())
        })?,
    )?;

    globals.set("hyber", hyber)?;
    Ok(())
}

// ── hyber.fs ─────────────────────────────────────────────────────────────────

fn build_fs(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;

    // hyber.fs.open(path, mode) -> file_obj
    {
        let state = Arc::clone(&state);
        let open_fn = lua.create_function(move |lua, (path_str, mode): (String, String)| {
            let rights = parse_mode(&mode)?;
            let path = Path::parse(&path_str);

            let handle_id = {
                let mut ks = lock(&state)?;
                // Destructure to give borrow-checker independent field borrows
                let KernelState {
                    vfs,
                    ns_mgr,
                    handle_mgr,
                    obj_mgr,
                    process_id,
                    security_context,
                    ..
                } = &mut *ks;
                match vfs.open(
                    ns_mgr,
                    handle_mgr,
                    obj_mgr,
                    *process_id,
                    security_context,
                    &path,
                    rights,
                ) {
                    Ok(hid) => Ok(hid),
                    Err(e) => {
                        if rights.write {
                            if let Some((parent, name)) = path.parent_and_name() {
                                // Try to create the file
                                vfs.create(
                                    ns_mgr,
                                    obj_mgr,
                                    security_context,
                                    &parent,
                                    &name,
                                    hyber_core::ObjectType::File,
                                )
                                .map_err(lua_err)?;

                                // Try to open again
                                vfs.open(
                                    ns_mgr,
                                    handle_mgr,
                                    obj_mgr,
                                    *process_id,
                                    security_context,
                                    &path,
                                    rights,
                                )
                                .map_err(lua_err)
                            } else {
                                Err(lua_err(e.to_string()))
                            }
                        } else {
                            Err(lua_err(e.to_string()))
                        }
                    }
                }?
            };

            // Build Lua file object
            let file = lua.create_table()?;
            file.set("_hid", handle_id.0)?;

            // file:read([size]) -> string | nil
            {
                let state = Arc::clone(&state);
                let read_fn =
                    lua.create_function(move |lua, (this, size): (LuaTable, Option<usize>)| {
                        let hid: u64 = this.get("_hid")?;
                        if hid == 0 {
                            return Err(lua_err("Handle already closed".to_string()));
                        }
                        let mut buf = vec![0u8; size.unwrap_or(4096).max(1)];
                        let n = {
                            let mut ks = lock(&state)?;
                            let KernelState {
                                vfs,
                                handle_mgr,
                                obj_mgr,
                                process_id,
                                security_context,
                                ..
                            } = &mut *ks;
                            vfs.read_secure(
                                handle_mgr,
                                obj_mgr,
                                *process_id,
                                security_context,
                                hyber_core::HandleId(hid),
                                &mut buf,
                            )
                            .map_err(lua_err)?
                        };
                        if n == 0 {
                            Ok(LuaValue::Nil)
                        } else {
                            Ok(LuaValue::String(lua.create_string(&buf[..n])?))
                        }
                    })?;
                file.set("read", read_fn)?;
            }

            // file:write(data) -> bytes_written
            {
                let state = Arc::clone(&state);
                let write_fn =
                    lua.create_function(move |_lua, (this, data): (LuaTable, String)| {
                        let hid: u64 = this.get("_hid")?;
                        if hid == 0 {
                            return Err(lua_err("Handle already closed".to_string()));
                        }
                        let mut ks = lock(&state)?;
                        let KernelState {
                            vfs,
                            handle_mgr,
                            obj_mgr,
                            process_id,
                            security_context,
                            ..
                        } = &mut *ks;
                        vfs.write_secure(
                            handle_mgr,
                            obj_mgr,
                            *process_id,
                            security_context,
                            hyber_core::HandleId(hid),
                            data.as_bytes(),
                        )
                        .map_err(lua_err)
                    })?;
                file.set("write", write_fn)?;
            }

            // file:close() -> bool
            {
                let state = Arc::clone(&state);
                let close_fn = lua.create_function(move |_lua, this: LuaTable| {
                    let hid: u64 = this.get("_hid")?;
                    if hid == 0 {
                        return Ok(false);
                    }
                    {
                        let mut ks = lock(&state)?;
                        let KernelState {
                            vfs,
                            handle_mgr,
                            obj_mgr,
                            process_id,
                            ..
                        } = &mut *ks;
                        vfs.close(handle_mgr, obj_mgr, *process_id, hyber_core::HandleId(hid))
                            .map_err(lua_err)?;
                    }
                    this.set("_hid", 0u64)?;
                    Ok(true)
                })?;
                file.set("close", close_fn)?;
            }

            Ok(file)
        })?;
        t.set("open", open_fn)?;
    }

    Ok(t)
}

// ── hyber.ns ─────────────────────────────────────────────────────────────────

fn build_ns(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;

    // hyber.ns.exists(path) -> bool
    {
        let state = Arc::clone(&state);
        let exists_fn = lua.create_function(move |_lua, path_str: String| {
            let path = Path::parse(&path_str);
            let ks = lock(&state)?;
            Ok(
                VFS::check_traversal(&ks.ns_mgr, &ks.obj_mgr, &ks.security_context, &path, false)
                    .is_ok()
                    && ks.ns_mgr.resolve(&path, ks.ns_mgr.root()).is_ok(),
            )
        })?;
        t.set("exists", exists_fn)?;
    }

    // hyber.ns.list(path) -> table of {name, obj_id}
    {
        let state = Arc::clone(&state);
        let list_fn = lua.create_function(move |lua, path_str: String| {
            let path = Path::parse(&path_str);
            let ks = lock(&state)?;
            let nodes = ks
                .vfs
                .enumerate_secure(&ks.ns_mgr, &ks.obj_mgr, &ks.security_context, &path)
                .map_err(lua_err)?;
            let result = lua.create_table()?;
            for (i, (name, object_id)) in nodes.iter().enumerate() {
                let entry = lua.create_table()?;
                entry.set("name", name.clone())?;
                entry.set("obj_id", object_id.0)?;
                result.set(i + 1, entry)?;
            }
            Ok(result)
        })?;
        t.set("list", list_fn)?;
    }

    Ok(t)
}

// ── hyber.obj ────────────────────────────────────────────────────────────────

fn build_obj(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;

    // hyber.obj.info(path) -> table
    {
        let state = Arc::clone(&state);
        let info_fn = lua.create_function(move |lua, path_str: String| {
            let path = Path::parse(&path_str);
            let ks = lock(&state)?;
            VFS::check_traversal(&ks.ns_mgr, &ks.obj_mgr, &ks.security_context, &path, false)
                .map_err(lua_err)?;
            let obj_id = ks
                .ns_mgr
                .resolve(&path, ks.ns_mgr.root())
                .map_err(lua_err)?;
            let obj = ks
                .obj_mgr
                .lookup(obj_id)
                .ok_or_else(|| lua_err("Object not found".to_string()))?;
            SecurityManager::check_access(
                &ks.security_context,
                obj.owner,
                obj.group,
                obj.permissions,
                Rights::read_only(),
            )
            .map_err(lua_err)?;
            let out = lua.create_table()?;
            out.set("id", obj.id.0)?;
            out.set("type", obj.object_type.to_string())?;
            out.set("state", format!("{:?}", obj.state))?;
            out.set("references", obj.references)?;
            out.set("owner", obj.owner.0)?;
            out.set("group", obj.group.0)?;
            out.set("permissions", obj.permissions)?;
            out.set("size", obj.size)?;
            out.set("created_at", obj.created_at)?;
            out.set("modified_at", obj.modified_at)?;
            Ok(out)
        })?;
        t.set("info", info_fn)?;
    }

    // hyber.obj.meta_get(path, key) -> value | nil
    {
        let state = Arc::clone(&state);
        let meta_get = lua.create_function(move |lua, (path_str, key): (String, String)| {
            let path = Path::parse(&path_str);
            let ks = lock(&state)?;
            VFS::check_traversal(&ks.ns_mgr, &ks.obj_mgr, &ks.security_context, &path, false)
                .map_err(lua_err)?;
            let obj_id = ks
                .ns_mgr
                .resolve(&path, ks.ns_mgr.root())
                .map_err(lua_err)?;
            match ks
                .obj_mgr
                .get_metadata_secure(obj_id, &ks.security_context, &key)
                .map_err(lua_err)?
            {
                Some(v) => metadata_to_lua(lua, v),
                None => Ok(LuaValue::Nil),
            }
        })?;
        t.set("meta_get", meta_get)?;
    }

    // hyber.obj.meta_set(path, key, type, value)
    {
        let state = Arc::clone(&state);
        let meta_set = lua.create_function(
            move |_lua, (path_str, key, val_type, val_str): (String, String, String, String)| {
                let path = Path::parse(&path_str);
                let meta_val = parse_metadata_value(&val_type, val_str)?;
                let mut ks = lock(&state)?;
                VFS::check_traversal(&ks.ns_mgr, &ks.obj_mgr, &ks.security_context, &path, false)
                    .map_err(lua_err)?;
                let obj_id = ks
                    .ns_mgr
                    .resolve(&path, ks.ns_mgr.root())
                    .map_err(lua_err)?;
                let context = ks.security_context.clone();
                ks.obj_mgr
                    .set_metadata_secure(obj_id, &context, &key, meta_val)
                    .map_err(lua_err)?;
                Ok(true)
            },
        )?;
        t.set("meta_set", meta_set)?;
    }

    Ok(t)
}

// ── hyber.proc ───────────────────────────────────────────────────────────────

fn build_proc(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;

    {
        let state = Arc::clone(&state);
        t.set(
            "pid",
            lua.create_function(move |_lua, ()| Ok(lock(&state)?.process_id.0))?,
        )?;
    }
    {
        let state = Arc::clone(&state);
        t.set(
            "uid",
            lua.create_function(move |_lua, ()| Ok(lock(&state)?.security_context.user_id.0))?,
        )?;
    }
    {
        let state = Arc::clone(&state);
        t.set(
            "spawn",
            lua.create_function(move |_lua, target: String| {
                let mut ks = lock(&state)?;
                let target_path = Path::parse(&target).normalize();
                let target_id = ks
                    .ns_mgr
                    .resolve(&target_path, ks.ns_mgr.root())
                    .map_err(lua_err)?;
                let target_obj = ks
                    .obj_mgr
                    .lookup(target_id)
                    .ok_or_else(|| lua_err("Spawn target does not exist".to_string()))?;
                if target_obj.object_type != hyber_core::ObjectType::File {
                    return Err(lua_err("Spawn target is not a file".to_string()));
                }
                SecurityManager::check_access(
                    &ks.security_context,
                    target_obj.owner,
                    target_obj.group,
                    target_obj.permissions,
                    Rights::read_only(),
                )
                .map_err(lua_err)?;
                let pm_arc = Arc::clone(&ks.proc_mgr);
                let mut pm = pm_arc
                    .lock()
                    .map_err(|_| lua_err("Proc mgr poisoned".into()))?;
                let pid = ks.process_id;
                let sec = ks.security_context.clone();
                let new_pid = {
                    let KernelState {
                        obj_mgr,
                        handle_mgr,
                        ..
                    } = &mut *ks;
                    pm.create_process_with_handles(obj_mgr, Some(pid), sec, None, Some(handle_mgr))
                        .map_err(lua_err)?
                };
                pm.start_process(new_pid).map_err(lua_err)?;
                let process_dir = ks
                    .ns_mgr
                    .resolve(&Path::parse("/processes"), ks.ns_mgr.root())
                    .map_err(lua_err)?;
                let process_object = pm
                    .get_process(new_pid)
                    .ok_or_else(|| lua_err("Created process disappeared".to_string()))?
                    .object_id;
                {
                    let KernelState {
                        ns_mgr, obj_mgr, ..
                    } = &mut *ks;
                    ns_mgr
                        .create_node(obj_mgr, process_dir, &new_pid.0.to_string(), process_object)
                        .map_err(lua_err)?;
                }
                // Log the spawn action (target path stored as metadata for Phase 13 IPC)
                println!(
                    "[hyber:proc] spawned child PID {} for target '{}'",
                    new_pid.0, target
                );
                Ok(new_pid.0)
            })?,
        )?;
    }
    {
        let state = Arc::clone(&state);
        t.set(
            "wait",
            lua.create_function(move |_lua, pid_val: u64| {
                let ks = lock(&state)?;
                let pm_arc = Arc::clone(&ks.proc_mgr);
                let pm = pm_arc
                    .lock()
                    .map_err(|_| lua_err("Proc mgr poisoned".into()))?;
                match pm
                    .wait_process(hyber_core::ProcessId(pid_val))
                    .map_err(lua_err)?
                {
                    Some(code) => Ok(LuaValue::Integer(code as i64)),
                    None => Ok(LuaValue::Nil), // Still running
                }
            })?,
        )?;
    }

    Ok(t)
}

// ── hyber.sec ────────────────────────────────────────────────────────────────

fn build_sec(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;

    // hyber.sec.check_access(path, rights_str) -> bool
    {
        let state = Arc::clone(&state);
        let check_fn =
            lua.create_function(move |_lua, (path_str, rights_str): (String, String)| {
                let path = Path::parse(&path_str);
                let requested_rights = parse_mode(&rights_str)?;
                let ks = lock(&state)?;
                if VFS::check_traversal(&ks.ns_mgr, &ks.obj_mgr, &ks.security_context, &path, false)
                    .is_err()
                {
                    return Ok(false);
                }

                let obj_id = ks
                    .ns_mgr
                    .resolve(&path, ks.ns_mgr.root())
                    .map_err(lua_err)?;
                let obj = ks
                    .obj_mgr
                    .lookup(obj_id)
                    .ok_or_else(|| lua_err("Object not found".to_string()))?;

                match SecurityManager::check_access(
                    &ks.security_context,
                    obj.owner,
                    obj.group,
                    obj.permissions,
                    requested_rights,
                ) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            })?;
        t.set("check_access", check_fn)?;
    }

    // hyber.sec.check_capability(capability_name) -> bool
    {
        let state = Arc::clone(&state);
        let cap_fn = lua.create_function(move |_lua, cap: String| {
            let ks = lock(&state)?;
            match SecurityManager::check_capability(&ks.security_context, &cap) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        })?;
        t.set("check_capability", cap_fn)?;
    }

    Ok(t)
}

// ── hyber.input ─────────────────────────────────────────────────────────────

/// Input is intentionally an OS-neutral event queue.  A future display/input
/// subsystem can feed this queue; tests and privileged system scripts can
/// inject synthetic events through the capability-checked `emit` function.
fn build_input(lua: &Lua, state: Arc<Mutex<KernelState>>) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;

    {
        let state = Arc::clone(&state);
        t.set(
            "next",
            lua.create_function(move |lua, ()| {
                let mut ks = lock(&state)?;
                match ks.input_queue.pop_front() {
                    Some(event) => {
                        let out = lua.create_table()?;
                        out.set("kind", event.kind)?;
                        out.set("code", event.code)?;
                        out.set("value", event.value)?;
                        out.set("timestamp", event.timestamp)?;
                        Ok(LuaValue::Table(out))
                    }
                    None => Ok(LuaValue::Nil),
                }
            })?,
        )?;
    }

    {
        let state = Arc::clone(&state);
        t.set(
            "pending",
            lua.create_function(move |_lua, ()| Ok(lock(&state)?.input_queue.len() as u64))?,
        )?;
    }

    {
        let state = Arc::clone(&state);
        t.set(
            "clear",
            lua.create_function(move |_lua, ()| {
                lock(&state)?.input_queue.clear();
                Ok(())
            })?,
        )?;
    }

    {
        let state = Arc::clone(&state);
        t.set(
            "emit",
            lua.create_function(move |_lua, (kind, code, value): (String, String, i64)| {
                let mut ks = lock(&state)?;
                SecurityManager::check_capability(&ks.security_context, "CAP_INPUT_INJECT")
                    .map_err(lua_err)?;
                if kind.is_empty() || kind.len() > 32 || code.is_empty() || code.len() > 64 {
                    return Err(lua_err("input kind/code has an invalid length".into()));
                }
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                ks.input_queue.push_back(InputEvent {
                    kind,
                    code,
                    value,
                    timestamp,
                });
                Ok(true)
            })?,
        )?;
    }

    Ok(t)
}

// ── hyber.log ────────────────────────────────────────────────────────────────

fn build_log(lua: &Lua) -> LuaResult<LuaTable<'_>> {
    let t = lua.create_table()?;
    t.set(
        "info",
        lua.create_function(|_lua, msg: String| {
            println!("[hyber:info] {}", msg);
            Ok(())
        })?,
    )?;
    t.set(
        "warn",
        lua.create_function(|_lua, msg: String| {
            eprintln!("[hyber:warn] {}", msg);
            Ok(())
        })?,
    )?;
    t.set(
        "error",
        lua.create_function(|_lua, msg: String| {
            eprintln!("[hyber:error] {}", msg);
            Ok(())
        })?,
    )?;
    Ok(t)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn lock(state: &Arc<Mutex<KernelState>>) -> LuaResult<std::sync::MutexGuard<'_, KernelState>> {
    let mut state = state
        .lock()
        .map_err(|_| LuaError::RuntimeError("KernelState lock poisoned".into()))?;
    if let Some(session) = &state.session {
        state.security_context = session.context().map_err(|e| lua_err(e.to_string()))?;
    }
    Ok(state)
}

fn lua_err(msg: String) -> LuaError {
    LuaError::RuntimeError(msg)
}

fn parse_mode(mode: &str) -> LuaResult<Rights> {
    match mode {
        "r" | "read" => Ok(Rights::read_only()),
        "w" | "write" => Ok(Rights {
            write: true,
            ..Rights::empty()
        }),
        "rw" | "readwrite" => Ok(Rights::read_write()),
        _ => Err(LuaError::RuntimeError(format!(
            "Invalid mode '{}'. Use: r, w, rw",
            mode
        ))),
    }
}

fn parse_metadata_value(val_type: &str, val_str: String) -> LuaResult<MetadataValue> {
    match val_type {
        "string" => Ok(MetadataValue::String(val_str)),
        "int" => val_str
            .parse::<i64>()
            .map(MetadataValue::Integer)
            .map_err(|_| LuaError::RuntimeError("Invalid integer".into())),
        "bool" => val_str
            .parse::<bool>()
            .map(MetadataValue::Boolean)
            .map_err(|_| LuaError::RuntimeError("Invalid bool: use true or false".into())),
        _ => Err(LuaError::RuntimeError(
            "Type must be: string, int, bool".into(),
        )),
    }
}

fn metadata_to_lua<'lua>(lua: &'lua Lua, val: &MetadataValue) -> LuaResult<LuaValue<'lua>> {
    match val {
        MetadataValue::String(s) => Ok(LuaValue::String(lua.create_string(s.as_bytes())?)),
        MetadataValue::Integer(i) => Ok(LuaValue::Integer(*i)),
        MetadataValue::Boolean(b) => Ok(LuaValue::Boolean(*b)),
        MetadataValue::Timestamp(t) => Ok(LuaValue::Integer(*t as i64)),
        MetadataValue::Bytes(b) => Ok(LuaValue::String(lua.create_string(b.as_slice())?)),
        MetadataValue::List(items) => {
            let t = lua.create_table()?;
            for (i, item) in items.iter().enumerate() {
                t.set(i + 1, metadata_to_lua(lua, item)?)?;
            }
            Ok(LuaValue::Table(t))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_core::ObjectType;

    #[test]
    fn metadata_cannot_bypass_private_parent_directory() {
        let mut objects = ObjectManager::new();
        let mut ns = NamespaceManager::new(&mut objects);
        let dir = objects.create_object(ObjectType::Directory);
        objects.lookup_mut(dir).unwrap().permissions = 0o700;
        ns.create_node(&objects, ns.root(), "private", dir).unwrap();
        ns.initialize_directory(dir).unwrap();
        let file = objects.create_object(ObjectType::File);
        objects.lookup_mut(file).unwrap().permissions = 0o666;
        ns.create_node(&objects, dir, "file", file).unwrap();
        let context = SecurityContext {
            user_id: hyber_core::UserId(1000),
            group_id: hyber_core::GroupId(1000),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        let mut processes = ProcessManager::new();
        let pid = processes
            .create_process(&mut objects, None, context.clone(), None)
            .unwrap();
        let (_, _, _, _, result) = run_lua_script(
            r#"
            assert(not hyber.ns.exists('/private/file'))
            assert(not pcall(hyber.obj.info, '/private/file'))
            assert(not pcall(hyber.obj.meta_get, '/private/file', 'user.secret'))
            assert(not pcall(hyber.obj.meta_set, '/private/file', 'user.secret', 'string', 'changed'))
            "#,
            VFS::new(),
            ns,
            HandleManager::new(),
            objects,
            Arc::new(Mutex::new(processes)),
            pid,
            context,
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn authenticated_lua_rechecks_revocation_and_blocks_host_libraries() {
        use hyber_auth::{AuthService, SessionGuard, SessionKind, SystemClock};
        let password = b"test root credential";
        let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
        let token = auth
            .login("root", password, SessionKind::Interactive, 600)
            .unwrap();
        let guard = SessionGuard::new(Arc::new(Mutex::new(auth)), token).unwrap();
        let mut objects = ObjectManager::new();
        let namespaces = NamespaceManager::new(&mut objects);
        let mut processes = ProcessManager::new();
        let pid = processes
            .create_process(&mut objects, None, guard.context().unwrap(), None)
            .unwrap();
        let processes = Arc::new(Mutex::new(processes));
        let (vfs, namespaces, handles, objects, result) = run_lua_script_with_session(
            "assert(io == nil and os == nil and require == nil and package == nil and loadfile == nil); assert(hyber.proc.uid() == 0)",
            VFS::new(),
            namespaces,
            HandleManager::new(),
            objects,
            processes.clone(),
            pid,
            SecurityContext::root(),
            Some(guard.clone()),
        );
        assert!(result.is_ok(), "{result:?}");
        guard.logout().unwrap();
        let (_, _, _, _, result) = run_lua_script_with_session(
            "hyber.input.pending()",
            vfs,
            namespaces,
            handles,
            objects,
            processes,
            pid,
            SecurityContext::root(),
            Some(guard),
        );
        assert!(result.is_err());
    }

    #[test]
    fn input_queue_round_trip_is_available_to_lua() {
        let mut objects = ObjectManager::new();
        let namespaces = NamespaceManager::new(&mut objects);
        let handles = HandleManager::new();
        let mut processes = ProcessManager::new();
        let process_id = processes
            .create_process(&mut objects, None, SecurityContext::root(), None)
            .expect("process");
        processes.start_process(process_id).expect("start");
        let script = r#"
            assert(hyber.input.pending() == 0)
            assert(hyber.input.emit("keyboard", "KEY_A", 1))
            assert(hyber.input.pending() == 1)
            local event = hyber.input.next()
            assert(event.kind == "keyboard")
            assert(event.code == "KEY_A")
            assert(event.value == 1)
            assert(hyber.input.pending() == 0)
        "#;
        let (_, _, _, _, result) = run_lua_script(
            script,
            VFS::new(),
            namespaces,
            handles,
            objects,
            Arc::new(Mutex::new(processes)),
            process_id,
            SecurityContext::root(),
        );
        assert!(result.is_ok(), "Lua input script failed: {result:?}");
    }
}
