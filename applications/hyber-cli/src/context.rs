use hyber_core::{Path, ProcessId, SecurityContext};
use hyber_handle::HandleManager;
use hyber_layout::{AppLayout, LayoutManager, UserLayout};
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
    pub app_layout: AppLayout,
}

impl AppContext {
    pub fn new() -> Result<Self, String> {
        Self::new_for_app("script")
    }

    pub fn new_for_app(app_id: &str) -> Result<Self, String> {
        Self::for_identity(SecurityContext::root(), UserLayout::root(), app_id)
    }

    fn for_identity(
        security_context: SecurityContext,
        user_layout: UserLayout,
        app_id: &str,
    ) -> Result<Self, String> {
        let mut obj_mgr = ObjectManager::new();
        let mut ns_mgr = NamespaceManager::new(&mut obj_mgr);
        let mut process_manager = ProcessManager::new();
        let process_id =
            process_manager.create_process(&mut obj_mgr, None, security_context.clone(), None)?;
        process_manager.start_process(process_id)?;

        let mut vfs = VFS::new();
        vfs.register_provider("app-memfs".into(), Box::new(MemFSProvider::new()));
        vfs.mount(Path::parse("/"), "app-memfs".into());
        let layout = LayoutManager::default();
        let system = SecurityContext::root();
        layout.initialize_system(&mut vfs, &mut ns_mgr, &mut obj_mgr, &system)?;
        layout.provision_user(&mut vfs, &mut ns_mgr, &mut obj_mgr, &system, &user_layout)?;
        let app_layout = AppLayout::new(user_layout, app_id)?;
        layout.ensure_application(
            &mut vfs,
            &mut ns_mgr,
            &mut obj_mgr,
            &security_context,
            &app_layout,
        )?;

        Ok(Self {
            session: None,
            vfs,
            ns_mgr,
            handle_mgr: HandleManager::new(),
            obj_mgr,
            proc_mgr: Arc::new(Mutex::new(process_manager)),
            process_id,
            security_context,
            app_layout,
        })
    }

    pub fn authenticated_for_app(
        session: hyber_auth::SessionGuard,
        app_id: &str,
    ) -> Result<Self, String> {
        let security = session.context().map_err(|e| e.to_string())?;
        let username = session.username().map_err(|e| e.to_string())?;
        let home = session.home().map_err(|e| e.to_string())?;
        let user = UserLayout::new(security.user_id, security.group_id, username, home)?;
        let mut context = Self::for_identity(security.clone(), user, app_id)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_auth::{AuthService, SessionGuard, SessionKind, SystemClock};
    use hyber_identity::AccountState;

    #[test]
    fn authenticated_context_preserves_system_roots_and_provisions_private_layout() {
        let password = b"temporary root password";
        let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
        let admin = auth
            .login("root", password, SessionKind::Interactive, 600)
            .unwrap();
        let group = auth
            .edit_accounts(&admin, |accounts| accounts.create_group("users"))
            .unwrap();
        let alice = auth
            .edit_accounts(&admin, |accounts| {
                accounts.create_user("alice", group, AccountState::Active)
            })
            .unwrap();
        auth.set_password(&admin, alice, b"temporary alice password")
            .unwrap();
        let token = auth
            .login(
                "alice",
                b"temporary alice password",
                SessionKind::NonInteractive,
                600,
            )
            .unwrap();
        let context = AppContext::authenticated_for_app(
            SessionGuard::new(Arc::new(Mutex::new(auth)), token).unwrap(),
            "script",
        )
        .unwrap();
        let apps = context
            .ns_mgr
            .resolve(&Path::parse("/apps"), context.ns_mgr.root())
            .unwrap();
        let apps = context.obj_mgr.lookup(apps).unwrap();
        assert_eq!(apps.owner, hyber_core::UserId(0));
        assert_eq!(apps.permissions, 0o755);
        let home = context
            .ns_mgr
            .resolve(&Path::parse("/users/alice"), context.ns_mgr.root())
            .unwrap();
        let home = context.obj_mgr.lookup(home).unwrap();
        assert_eq!(home.owner, alice);
        assert_eq!(home.permissions, 0o700);
        assert_eq!(
            context.app_layout.data.to_string(),
            "/users/alice/.local/share/script"
        );
    }
}
