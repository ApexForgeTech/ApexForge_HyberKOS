use hyber_auth::*;
use hyber_core::{GroupId, Rights, SecurityManager, UserId};
use hyber_fs::{MemDevice, Volume};
use hyber_identity::{AccountState, IdentityError};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

const ROOT_PASSWORD: &[u8] = b"root test password only";
const USER_PASSWORD: &[u8] = b"alice test password only";

#[test]
fn group_and_capability_edits_revoke_sessions_and_survive_storage() {
    let (mut auth, admin, user, clock) = fixture();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    assert!(matches!(
        auth.edit_accounts(&token, |a| a.grant_capability(user, "CAP_SYS_ADMIN")),
        Err(AuthError::PermissionDenied)
    ));
    let group = auth
        .edit_accounts(&admin, |a| {
            let group = a.create_group("editors")?;
            a.add_to_group(user, group)?;
            a.set_primary_group(user, group)?;
            a.revoke_capability(user, "CAP_INPUT_INJECT")?;
            Ok(group)
        })
        .unwrap();
    assert!(auth.context(&token).is_err());
    let mut volume = Volume::format(MemDevice::new(64).unwrap()).unwrap();
    auth.save(&mut volume, STORE_PATH).unwrap();
    let volume = Volume::mount(volume.unmount().unwrap()).unwrap();
    let mut loaded = AuthService::load(&volume, STORE_PATH, clock).unwrap();
    let token = loaded
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    let context = loaded.context(&token).unwrap();
    assert_eq!(context.group_id, group);
    assert!(!context.supplementary_groups.contains(&group));
    assert!(SecurityManager::check_capability(&context, "CAP_INPUT_INJECT").is_err());
    loaded.accounts().validate().unwrap();
}
struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> Result<u64, AuthError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
fn fixture() -> (AuthService, SessionToken, UserId, Arc<TestClock>) {
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let mut auth = AuthService::provision(ROOT_PASSWORD, clock.clone()).unwrap();
    let admin = auth
        .login("root", ROOT_PASSWORD, SessionKind::Interactive, 3600)
        .unwrap();
    let user = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("alice")?;
            let user = accounts.create_user("alice", group, AccountState::Active)?;
            let shared = accounts.create_group("shared")?;
            accounts.add_to_group(user, shared)?;
            accounts.grant_capability(user, "CAP_INPUT_INJECT")?;
            Ok(user)
        })
        .unwrap();
    auth.set_password(&admin, user, USER_PASSWORD).unwrap();
    (auth, admin, user, clock)
}

#[test]
fn login_context_matches_group_and_capability_permissions_and_logout_revokes() {
    let (mut auth, _, user, _) = fixture();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    let ctx = auth.context(&token).unwrap();
    assert_eq!(ctx.user_id, user);
    let shared = auth.accounts().group_by_name("shared").unwrap().id;
    assert!(ctx.supplementary_groups.contains(&shared));
    assert!(
        SecurityManager::check_access(&ctx, UserId(4000), shared, 0o040, Rights::read_only())
            .is_ok()
    );
    assert!(SecurityManager::check_access(
        &ctx,
        UserId(4000),
        GroupId(9999),
        0o040,
        Rights::read_only()
    )
    .is_err());
    assert!(SecurityManager::check_capability(&ctx, "CAP_INPUT_INJECT").is_ok());
    assert!(SecurityManager::check_capability(&ctx, "CAP_SYS_ADMIN").is_err());
    let mut objects = hyber_object::ObjectManager::new();
    let mut processes = hyber_process::ProcessManager::new();
    let pid = processes
        .create_process(&mut objects, None, ctx.clone(), None)
        .unwrap();
    assert_eq!(processes.get_process(pid).unwrap().security_context, ctx);
    let shared = Arc::new(Mutex::new(auth));
    let guard = SessionGuard::new(shared, token).unwrap();
    let second = guard.clone();
    assert_eq!(guard.username().unwrap(), "alice");
    guard.logout().unwrap();
    assert!(matches!(second.username(), Err(AuthError::InvalidSession)));
    assert!(matches!(second.context(), Err(AuthError::InvalidSession)));
}

#[test]
fn failure_messages_do_not_disclose_account_existence_and_throttle_is_global() {
    let (mut auth, _, _, clock) = fixture();
    for (name, password) in [
        ("missing", USER_PASSWORD),
        ("alice", b"wrong".as_slice()),
        ("root", b"wrong".as_slice()),
        ("missing2", b"wrong".as_slice()),
        ("alice", b"wrong".as_slice()),
    ] {
        assert!(matches!(
            auth.login(name, password, SessionKind::Interactive, 600),
            Err(AuthError::AuthenticationFailed)
        ));
    }
    assert!(matches!(
        auth.login("alice", USER_PASSWORD, SessionKind::Interactive, 600),
        Err(AuthError::AuthenticationFailed)
    ));
    clock.0.store(130, Ordering::SeqCst);
    assert!(auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .is_ok());
}

#[test]
fn account_edits_are_atomic_and_invalidate_existing_sessions() {
    let (mut auth, admin, user, _) = fixture();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    let before = auth.accounts().encode();
    let failed: Result<(), _> = auth.edit_accounts(&admin, |accounts| {
        accounts.create_group("rolled-back")?;
        Err(IdentityError::InvalidState)
    });
    assert!(failed.is_err());
    assert_eq!(before, auth.accounts().encode());
    assert!(matches!(
        auth.edit_accounts(&token, |accounts| accounts
            .grant_capability(user, "CAP_SYS_ADMIN")),
        Err(AuthError::PermissionDenied)
    ));
    auth.edit_accounts(&admin, |accounts| {
        accounts.set_state(user, AccountState::Locked)
    })
    .unwrap();
    assert!(auth.context(&token).is_err());
    assert!(matches!(
        auth.login("alice", USER_PASSWORD, SessionKind::Interactive, 600),
        Err(AuthError::AuthenticationFailed)
    ));
    auth.edit_accounts(&admin, |accounts| {
        accounts.set_state(user, AccountState::Active)
    })
    .unwrap();
    assert!(auth.context(&token).is_err());
    assert!(auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .is_ok());
}

#[test]
fn session_account_and_password_expiry_are_enforced_at_exact_boundary() {
    let (mut auth, admin, user, clock) = fixture();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 1)
        .unwrap();
    clock.0.store(101, Ordering::SeqCst);
    assert!(auth.context(&token).is_err());
    auth.set_expiry(&admin, user, Some(200), Some(150)).unwrap();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::NonInteractive, 600)
        .unwrap();
    clock.0.store(150, Ordering::SeqCst);
    assert!(auth.context(&token).is_err());
    assert!(auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .is_err());
    auth.set_expiry(&admin, user, Some(160), None).unwrap();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    clock.0.store(160, Ordering::SeqCst);
    assert!(auth.context(&token).is_err());
    clock.0.store(159, Ordering::SeqCst);
    assert!(matches!(auth.context(&admin), Err(AuthError::Unavailable)));
    clock.0.store(161, Ordering::SeqCst);
    assert!(auth.context(&admin).is_err());
}

#[test]
fn password_change_revokes_all_sessions_and_old_password() {
    let (mut auth, _, _, _) = fixture();
    let one = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    let two = auth
        .login("alice", USER_PASSWORD, SessionKind::NonInteractive, 600)
        .unwrap();
    assert!(auth
        .change_password(&one, b"wrong", b"new secure password")
        .is_err());
    assert!(auth.context(&one).is_ok());
    auth.change_password(&one, USER_PASSWORD, b"new secure password")
        .unwrap();
    assert!(auth.context(&one).is_err());
    assert!(auth.context(&two).is_err());
    assert!(auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .is_err());
    assert!(auth
        .login(
            "alice",
            b"new secure password",
            SessionKind::Interactive,
            600
        )
        .is_ok());
}

#[test]
fn service_sessions_are_independent_of_interactive_logout() {
    let (mut auth, admin, _, _) = fixture();
    let service = auth
        .edit_accounts(&admin, |accounts| {
            let group = accounts.create_group("logger")?;
            accounts.create_user("logger", group, AccountState::Service)
        })
        .unwrap();
    auth.set_password(&admin, service, b"unexposed service secret")
        .unwrap();
    assert!(auth
        .login(
            "logger",
            b"unexposed service secret",
            SessionKind::Interactive,
            600
        )
        .is_err());
    assert!(auth
        .login(
            "logger",
            b"unexposed service secret",
            SessionKind::Service,
            600
        )
        .is_err());
    let token = auth.service_session(&admin, service, 600).unwrap();
    auth.logout(&admin).unwrap();
    assert_eq!(auth.context(&token).unwrap().user_id, service);
}

#[test]
fn persistence_is_atomic_private_and_contains_no_passwords_or_sessions() {
    let (mut auth, _, _, clock) = fixture();
    let token = auth
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .unwrap();
    let mut volume = Volume::format(MemDevice::new(256).unwrap()).unwrap();
    auth.save(&mut volume, STORE_PATH).unwrap();
    let volume = Volume::mount(volume.unmount().unwrap()).unwrap();
    let mut restored = AuthService::load(&volume, STORE_PATH, clock.clone()).unwrap();
    assert!(restored.context(&token).is_err());
    assert!(restored
        .login("alice", USER_PASSWORD, SessionKind::Interactive, 600)
        .is_ok());
    assert_eq!(auth.accounts().encode(), restored.accounts().encode());
    assert_eq!(volume.stat(STORE_PATH).unwrap().metadata.mode, 0o600);
    let encoded = auth.encode().unwrap();
    assert!(!encoded
        .windows(ROOT_PASSWORD.len())
        .any(|w| w == ROOT_PASSWORD));
    assert!(!encoded
        .windows(USER_PASSWORD.len())
        .any(|w| w == USER_PASSWORD));
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(AuthService::decode(&corrupt, clock.clone()).is_err());
    for n in [0, 8, 39, 40, encoded.len() - 1] {
        assert!(AuthService::decode(&encoded[..n], clock.clone()).is_err());
    }
    let mut volume = volume;
    let mut metadata = volume.stat(STORE_PATH).unwrap().metadata;
    metadata.mode = 0o644;
    volume.set_metadata(STORE_PATH, metadata).unwrap();
    assert!(AuthService::load(&volume, STORE_PATH, clock).is_err());
}
