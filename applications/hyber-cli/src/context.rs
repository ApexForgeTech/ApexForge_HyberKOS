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
}
