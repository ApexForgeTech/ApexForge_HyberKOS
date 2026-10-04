use super::*;
use hyber_auth::{AuthService, SessionGuard, SessionKind, SystemClock};
use hyber_identity::AccountState;

#[test]
fn authenticated_service_survives_caller_logout_but_stop_revokes_its_guard() {
    let password = b"service test root password";
    let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
    let admin = auth
        .login("root", password, SessionKind::Interactive, 600)
        .unwrap();
    let uid = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("logger")?;
            accounts.create_user("logger", group, AccountState::Service)
        })
        .unwrap();
    auth.set_password(&admin, uid, b"service test credential")
        .unwrap();
    let token = auth.service_session(&admin, uid, 600).unwrap();
    let shared = Arc::new(Mutex::new(auth));
    let admin_guard = SessionGuard::new(shared.clone(), admin).unwrap();
    let service_guard = SessionGuard::new(shared, token).unwrap();
    let mut manager = ServiceManager::new();
    let mut objects = ObjectManager::new();
    let id = manager.register_service(&mut objects, "logger", "session test");
    assert!(manager
        .start_authenticated(&mut objects, id, None, admin_guard.clone())
        .is_err());
    manager
        .start_authenticated(&mut objects, id, None, service_guard.clone())
        .unwrap();
    admin_guard.logout().unwrap();
    assert_eq!(manager.session_context(id).unwrap().user_id, uid);
    assert!(manager.start_service(id, None).is_err());
    manager.stop_service(id).unwrap();
    assert!(service_guard.context().is_err());
    manager.disable_service(id).unwrap();
    manager.stop_service(id).unwrap();
    manager.mark_failed(id).unwrap();
    assert!(manager.start_service(id, None).is_err());
}
