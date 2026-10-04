use hyber_core::{ObjectType, Path, ProcessId, SecurityContext};
use hyber_handle::HandleManager;
use hyber_memfs::MemFSProvider;
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_process::ProcessManager;
use hyber_vfs::VFS;
use std::sync::{Arc, Mutex};

/// The Lua-only Phase 14 command context.
///
/// This intentionally provides an in-memory Hyber namespace.  A future Phase
/// 13 application ABI can replace this constructor without changing the CLI
/// contract, and no Linux file descriptors escape into Lua.
pub struct AppContext {
    pub session: Option<hyber_auth::SessionGuard>,
    pub vfs: VFS,
    pub ns_mgr: NamespaceManager,
    pub handle_mgr: HandleManager,
    pub obj_mgr: ObjectManager,
    pub proc_mgr: Arc<Mutex<ProcessManager>>,
    pub process_id: ProcessId,
    pub security_context: SecurityContext,
}

impl AppContext {
    pub fn new() -> Result<Self, String> {
        let mut obj_mgr = ObjectManager::new();
        let ns_mgr = NamespaceManager::new(&mut obj_mgr);
        let security_context = SecurityContext::root();
        let mut process_manager = ProcessManager::new();
        let process_id =
            process_manager.create_process(&mut obj_mgr, None, security_context.clone(), None)?;
        process_manager.start_process(process_id)?;

        let mut vfs = VFS::new();
        vfs.register_provider("app-memfs".into(), Box::new(MemFSProvider::new()));
        vfs.mount(Path::parse("/"), "app-memfs".into());

        let mut context = Self {
            session: None,
            vfs,
            ns_mgr,
            handle_mgr: HandleManager::new(),
            obj_mgr,
            proc_mgr: Arc::new(Mutex::new(process_manager)),
            process_id,
            security_context,
        };

        // Give every command the same volatile application areas.  Persistent
        // HostFS and a stable cross-language ABI remain explicitly out of scope
        // until their planned phases.
        for name in ["apps", "data", "runtime", "temporary"] {
            context.vfs.create(
                &mut context.ns_mgr,
                &mut context.obj_mgr,
                &context.security_context,
                &Path::parse("/"),
                name,
                ObjectType::Directory,
            )?;
        }
        Ok(context)
    }

    pub fn authenticated(session: hyber_auth::SessionGuard) -> Result<Self, String> {
        let security = session.context().map_err(|e| e.to_string())?;
        let mut context = Self::new()?;
        // The private app namespace belongs to this session, including its root.
        let mut ids = vec![context.ns_mgr.root()];
        for path in ["/apps", "/data", "/runtime", "/temporary"] {
            ids.push(
                context
                    .ns_mgr
                    .resolve(&Path::parse(path), context.ns_mgr.root())?,
            );
        }
        for id in ids {
            if let Some(object) = context.obj_mgr.lookup_mut(id) {
                object.owner = security.user_id;
                object.group = security.group_id;
                object.permissions = 0o700;
            }
        }
        context
            .proc_mgr
            .lock()
            .map_err(|_| "process lock poisoned")?
            .get_process_mut(context.process_id)
            .ok_or("process missing")?
            .security_context = security.clone();
        context.security_context = security;
        context.session = Some(session);
        Ok(context)
    }
}
