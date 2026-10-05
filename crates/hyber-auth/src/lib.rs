//! Trusted user-space authentication authority. Credentials and accounts are
//! persisted together; sessions are volatile and store only token digests.
//! Do not expose constructors, snapshot bytes, or unrestricted mutable access
//! to applications. Applications receive a SessionGuard at a trusted boundary.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hyber_core::{SecurityContext, SecurityManager, UserId};
use hyber_fs::{BlockDevice, Metadata, ObjectKind, Volume};
use hyber_identity::{AccountRegistry, AccountState, IdentityError};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_PASSWORD: usize = 1024;
const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
const MAX_SESSIONS: usize = 4096;
const MAX_TTL: u64 = 24 * 60 * 60;
const MAX_AUDIT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    AuthenticationFailed,
    InvalidSession,
    PermissionDenied,
    InvalidInput,
    Corrupt,
    Unavailable,
    Storage(String),
    Identity(IdentityError),
}
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::InvalidSession => "session is invalid or expired",
            Self::PermissionDenied => "permission denied",
            Self::InvalidInput => "invalid authentication input",
            Self::Corrupt => "invalid authentication store",
            Self::Unavailable => "authentication service unavailable",
            Self::Storage(_) => "authentication storage failure",
            Self::Identity(_) => "identity mutation rejected",
        })
    }
}
impl std::error::Error for AuthError {}
impl From<IdentityError> for AuthError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

/// Supplied by the trusted runtime; values are seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, AuthError>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<u64, AuthError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| AuthError::Unavailable)
    }
}

/// Hosted terminal adapter: passwords never appear in argv, environment, or
/// shell command history. The returned allocation is zeroed on drop.
pub fn prompt_password(prompt: &str) -> Result<zeroize::Zeroizing<String>, AuthError> {
    rpassword::prompt_password(prompt)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| AuthError::Unavailable)
}

pub const STORE_PATH: &str = "/auth.store";

pub fn hosted_login(
    image: &str,
    blocks: u64,
    username: &str,
    kind: SessionKind,
) -> Result<SessionGuard, AuthError> {
    let volume = Volume::mount(
        hyber_fs::FileDevice::open_read_only(image, blocks)
            .map_err(|e| AuthError::Storage(e.to_string()))?,
    )
    .map_err(|e| AuthError::Storage(e.to_string()))?;
    let mut service = AuthService::load(&volume, STORE_PATH, Arc::new(SystemClock))?;
    let password = prompt_password("Password: ")?;
    let token = service.login(username, password.as_bytes(), kind, 3600)?;
    let fingerprint = store_fingerprint(&volume)?;
    let mut guard = SessionGuard::new(Arc::new(Mutex::new(service)), token)?;
    guard.hosted = Some((image.into(), blocks, fingerprint));
    Ok(guard)
}

fn store_fingerprint<D: BlockDevice>(volume: &Volume<D>) -> Result<[u8; 32], AuthError> {
    if !volume.recovery_warnings().is_empty() {
        return Err(AuthError::Corrupt);
    }
    let info = volume
        .stat(STORE_PATH)
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    if info.kind != ObjectKind::File
        || info.metadata.owner != 0
        || info.metadata.group != 0
        || info.metadata.mode != 0o600
        || info.size > MAX_SNAPSHOT as u64
    {
        return Err(AuthError::Corrupt);
    }
    let mut bytes = vec![0; info.size as usize];
    volume
        .read_file(STORE_PATH, 0, &mut bytes)
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

/// Opaque bearer secret: never serialize or log it. Debug deliberately redacts it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken([u8; 32]);
impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken([REDACTED])")
    }
}
impl SessionToken {
    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Interactive,
    NonInteractive,
    Service,
}
struct Session {
    user: UserId,
    kind: SessionKind,
    expires: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    user: u32,
    hash: String,
    account_expires: Option<u64>,
    password_expires: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub time: u64,
    pub actor: u32,
    pub action: String,
    pub target: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    identities: Vec<u8>,
    credentials: Vec<Credential>,
    audit: Vec<AuditEvent>,
}

pub struct AuthService {
    accounts: AccountRegistry,
    credentials: BTreeMap<UserId, Credential>,
    sessions: BTreeMap<[u8; 32], Session>,
    dummy_hash: String,
    clock: Arc<dyn Clock>,
    last_time: u64,
    audit: Vec<AuditEvent>,
    failed_logins: u32,
    retry_after: u64,
}

impl AuthService {
    /// Trusted first-boot enrollment only. There is no default password and no
    /// passwordless root session. Existing stores must be restored, not reset.
    pub fn provision(root_password: &[u8], clock: Arc<dyn Clock>) -> Result<Self, AuthError> {
        password_policy(root_password)?;
        let mut service = Self::empty(AccountRegistry::new(), clock)?;
        service.credentials.insert(
            UserId(0),
            Credential {
                user: 0,
                hash: hash_password(root_password)?,
                account_expires: None,
                password_expires: None,
            },
        );
        service.record(UserId(0), "provision", Some(UserId(0)))?;
        Ok(service)
    }

    fn empty(accounts: AccountRegistry, clock: Arc<dyn Clock>) -> Result<Self, AuthError> {
        let now = clock.now()?;
        let mut dummy = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut dummy)
            .map_err(|_| AuthError::Unavailable)?;
        let dummy_hash = hash_password(&dummy);
        dummy.zeroize();
        Ok(Self {
            accounts,
            credentials: BTreeMap::new(),
            sessions: BTreeMap::new(),
            dummy_hash: dummy_hash?,
            clock,
            last_time: now,
            audit: Vec::new(),
            failed_logins: 0,
            retry_after: 0,
        })
    }

    pub fn accounts(&self) -> &AccountRegistry {
        &self.accounts
    }
    pub fn audit(&self) -> &[AuditEvent] {
        &self.audit
    }

    fn now(&mut self) -> Result<u64, AuthError> {
        let now = self.clock.now()?;
        if now < self.last_time {
            self.sessions.clear();
            return Err(AuthError::Unavailable);
        }
        self.last_time = now;
        Ok(now)
    }

    pub fn login(
        &mut self,
        username: &str,
        password: &[u8],
        kind: SessionKind,
        ttl: u64,
    ) -> Result<SessionToken, AuthError> {
        let now = self.now()?;
        if ttl == 0 || ttl > MAX_TTL {
            return Err(AuthError::InvalidInput);
        }
        if now < self.retry_after {
            return Err(AuthError::AuthenticationFailed);
        }
        let user = self.accounts.user_by_name(username).map(|u| u.id);
        let credential = user.and_then(|id| self.credentials.get(&id));
        let hash = credential.map_or(self.dummy_hash.as_str(), |c| c.hash.as_str());
        let parsed = PasswordHash::new(hash).map_err(|_| AuthError::Corrupt)?;
        // Unknown names and wrong passwords both perform the same Argon2 work.
        let bounded = if password.len() <= MAX_PASSWORD {
            password
        } else {
            b""
        };
        let verified = Argon2::default().verify_password(bounded, &parsed).is_ok();
        let enrolled = credential.is_some();
        let now = self.now()?;
        let valid = user.is_some_and(|id| self.allowed(id, kind, now))
            && enrolled
            && kind != SessionKind::Service
            && password.len() <= MAX_PASSWORD
            && verified;
        if !valid {
            self.failed_logins = self.failed_logins.saturating_add(1);
            if self.failed_logins >= 5 {
                self.retry_after = now.saturating_add(30);
                self.failed_logins = 0;
            }
            return Err(AuthError::AuthenticationFailed);
        }
        self.failed_logins = 0;
        let user = user.ok_or(AuthError::AuthenticationFailed)?;
        self.issue(user, user, kind, now, ttl)
    }

    fn allowed(&self, user: UserId, kind: SessionKind, now: u64) -> bool {
        let Some(account) = self.accounts.user(user) else {
            return false;
        };
        let state_ok = match kind {
            SessionKind::Service => account.state == AccountState::Service,
            _ => matches!(account.state, AccountState::Active | AccountState::Guest),
        };
        state_ok
            && self.credentials.get(&user).is_some_and(|c| {
                c.account_expires.is_none_or(|t| now < t)
                    && (kind == SessionKind::Service || c.password_expires.is_none_or(|t| now < t))
            })
    }

    fn issue(
        &mut self,
        actor: UserId,
        user: UserId,
        kind: SessionKind,
        now: u64,
        ttl: u64,
    ) -> Result<SessionToken, AuthError> {
        if ttl == 0 || ttl > MAX_TTL {
            return Err(AuthError::InvalidInput);
        }
        self.sessions.retain(|_, s| now < s.expires);
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(AuthError::Unavailable);
        }
        let expires = now.checked_add(ttl).ok_or(AuthError::InvalidInput)?;
        let mut token = SessionToken([0; 32]);
        OsRng
            .try_fill_bytes(&mut token.0)
            .map_err(|_| AuthError::Unavailable)?;
        let digest = token.digest();
        if self.sessions.contains_key(&digest) {
            return Err(AuthError::Unavailable);
        }
        self.record(actor, "session-created", Some(user))?;
        self.sessions.insert(
            digest,
            Session {
                user,
                kind,
                expires,
            },
        );
        Ok(token)
    }

    /// Recheck current account state and derive current groups/capabilities on
    /// every operation. A context clone alone is not a revocable session.
    pub fn context(&mut self, token: &SessionToken) -> Result<SecurityContext, AuthError> {
        let now = self.now()?;
        let key = token.digest();
        let session = self.sessions.get(&key).ok_or(AuthError::InvalidSession)?;
        if now >= session.expires || !self.allowed(session.user, session.kind, now) {
            self.sessions.remove(&key);
            return Err(AuthError::InvalidSession);
        }
        self.accounts
            .security_context(session.user)
            .map_err(|_| AuthError::InvalidSession)
    }

    /// Return the authenticated account's validated Hyber home path.  The
    /// value comes from the identity registry, never from a host account or
    /// caller-provided path.
    pub fn home(&mut self, token: &SessionToken) -> Result<String, AuthError> {
        let user = self.context(token)?.user_id;
        self.accounts
            .user(user)
            .map(|account| account.home.clone())
            .ok_or(AuthError::InvalidSession)
    }

    fn admin(&mut self, token: &SessionToken) -> Result<UserId, AuthError> {
        let context = self.context(token)?;
        SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")
            .map_err(|_| AuthError::PermissionDenied)?;
        Ok(context.user_id)
    }

    pub fn logout(&mut self, token: &SessionToken) -> Result<(), AuthError> {
        let user = self.context(token)?.user_id;
        self.sessions.remove(&token.digest());
        self.record(user, "logout", Some(user))
    }

    pub fn invalidate_user(&mut self, admin: &SessionToken, user: UserId) -> Result<(), AuthError> {
        let actor = self.admin(admin)?;
        self.record(actor, "invalidate-user", Some(user))?;
        self.sessions.retain(|_, s| s.user != user);
        Ok(())
    }

    /// Trusted administrative workflow. Work on a clone so a rejected operation
    /// cannot partially alter membership, identity counters, or audit history.
    pub fn edit_accounts<T>(
        &mut self,
        admin: &SessionToken,
        edit: impl FnOnce(&mut AccountRegistry) -> Result<T, IdentityError>,
    ) -> Result<T, AuthError> {
        let actor = self.admin(admin)?;
        let mut next = self.accounts.clone();
        let result = edit(&mut next)?;
        self.accounts.validate_successor(&next)?;
        self.record(actor, "edit-accounts", None)?;
        self.sessions
            .retain(|_, session| self.accounts.user(session.user) == next.user(session.user));
        self.credentials.retain(|id, _| next.user(*id).is_some());
        self.accounts = next;
        Ok(result)
    }

    pub fn set_password(
        &mut self,
        admin: &SessionToken,
        user: UserId,
        password: &[u8],
    ) -> Result<(), AuthError> {
        let actor = self.admin(admin)?;
        self.replace_password(actor, user, password)
    }

    pub fn change_password(
        &mut self,
        token: &SessionToken,
        old: &[u8],
        new: &[u8],
    ) -> Result<(), AuthError> {
        let user = self.context(token)?.user_id;
        let c = self
            .credentials
            .get(&user)
            .ok_or(AuthError::AuthenticationFailed)?;
        if old.len() > MAX_PASSWORD
            || Argon2::default()
                .verify_password(
                    old,
                    &PasswordHash::new(&c.hash).map_err(|_| AuthError::Corrupt)?,
                )
                .is_err()
        {
            return Err(AuthError::AuthenticationFailed);
        }
        self.replace_password(user, user, new)
    }

    fn replace_password(
        &mut self,
        actor: UserId,
        user: UserId,
        password: &[u8],
    ) -> Result<(), AuthError> {
        password_policy(password)?;
        if self.accounts.user(user).is_none() {
            return Err(AuthError::InvalidInput);
        }
        let hash = hash_password(password)?;
        self.record(actor, "set-password", Some(user))?;
        let expiry = self.credentials.get(&user).and_then(|c| c.account_expires);
        self.credentials.insert(
            user,
            Credential {
                user: user.0,
                hash,
                account_expires: expiry,
                password_expires: None,
            },
        );
        self.sessions.retain(|_, s| s.user != user);
        Ok(())
    }

    pub fn set_expiry(
        &mut self,
        admin: &SessionToken,
        user: UserId,
        account: Option<u64>,
        password: Option<u64>,
    ) -> Result<(), AuthError> {
        let actor = self.admin(admin)?;
        if !self.credentials.contains_key(&user) {
            return Err(AuthError::InvalidInput);
        }
        self.record(actor, "set-expiry", Some(user))?;
        let credential = self.credentials.get_mut(&user).unwrap();
        credential.account_expires = account;
        credential.password_expires = password;
        self.sessions.retain(|_, s| s.user != user);
        Ok(())
    }

    pub fn service_session(
        &mut self,
        admin: &SessionToken,
        user: UserId,
        ttl: u64,
    ) -> Result<SessionToken, AuthError> {
        let actor = self.admin(admin)?;
        let now = self.now()?;
        if !self.allowed(user, SessionKind::Service, now) {
            return Err(AuthError::PermissionDenied);
        }
        self.issue(actor, user, SessionKind::Service, now, ttl)
    }

    fn record(
        &mut self,
        actor: UserId,
        action: &str,
        target: Option<UserId>,
    ) -> Result<(), AuthError> {
        // Fail closed at capacity; a service must export/rotate its audit log.
        if self.audit.len() >= MAX_AUDIT {
            return Err(AuthError::Unavailable);
        }
        let time = self.now()?;
        self.audit.push(AuditEvent {
            sequence: self.audit.len() as u64 + 1,
            time,
            actor: actor.0,
            action: action.into(),
            target: target.map(|u| u.0),
        });
        Ok(())
    }

    /// Trusted persistence boundary: snapshot includes hashes, never passwords
    /// or session tokens. Checksum detects damage, not malicious administrator edits.
    pub fn encode(&self) -> Result<Vec<u8>, AuthError> {
        let payload = serde_json::to_vec(&Snapshot {
            version: 1,
            identities: self.accounts.encode(),
            credentials: self.credentials.values().cloned().collect(),
            audit: self.audit.clone(),
        })
        .map_err(|_| AuthError::Corrupt)?;
        if payload.len() > MAX_SNAPSHOT - 40 {
            return Err(AuthError::InvalidInput);
        }
        let mut bytes = b"HYBAUTH1".to_vec();
        bytes.extend_from_slice(&Sha256::digest(&payload));
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], clock: Arc<dyn Clock>) -> Result<Self, AuthError> {
        if bytes.len() < 40
            || bytes.len() > MAX_SNAPSHOT
            || &bytes[..8] != b"HYBAUTH1"
            || bytes[8..40] != Sha256::digest(&bytes[40..])[..]
        {
            return Err(AuthError::Corrupt);
        }
        let data: Snapshot =
            serde_json::from_slice(&bytes[40..]).map_err(|_| AuthError::Corrupt)?;
        if data.version != 1 || data.audit.len() > MAX_AUDIT {
            return Err(AuthError::Corrupt);
        }
        let accounts = AccountRegistry::decode(&data.identities)?;
        let mut credentials = BTreeMap::new();
        for c in data.credentials {
            validate_hash(&c.hash)?;
            let id = UserId(c.user);
            if accounts.user(id).is_none() || credentials.insert(id, c).is_some() {
                return Err(AuthError::Corrupt);
            }
        }
        if !credentials.contains_key(&UserId(0)) {
            return Err(AuthError::Corrupt);
        }
        let mut previous_time = 0;
        for (index, event) in data.audit.iter().enumerate() {
            if event.sequence != index as u64 + 1
                || event.time < previous_time
                || !matches!(
                    event.action.as_str(),
                    "provision"
                        | "session-created"
                        | "logout"
                        | "invalidate-user"
                        | "edit-accounts"
                        | "set-password"
                        | "set-expiry"
                )
            {
                return Err(AuthError::Corrupt);
            }
            previous_time = event.time;
        }
        let mut service = Self::empty(accounts, clock)?;
        if service.last_time < previous_time {
            return Err(AuthError::Unavailable);
        }
        service.credentials = credentials;
        service.audit = data.audit;
        Ok(service)
    }

    pub fn save<D: BlockDevice>(
        &self,
        volume: &mut Volume<D>,
        path: &str,
    ) -> Result<(), AuthError> {
        let bytes = self.encode()?;
        volume
            .replace_file(
                path,
                &bytes,
                Metadata {
                    mode: 0o600,
                    ..Metadata::default()
                },
            )
            .and_then(|_| volume.sync())
            .map_err(|e| AuthError::Storage(e.to_string()))
    }

    pub fn load<D: BlockDevice>(
        volume: &Volume<D>,
        path: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AuthError> {
        if !volume.recovery_warnings().is_empty() {
            return Err(AuthError::Corrupt);
        }
        let info = volume
            .stat(path)
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        if info.kind != ObjectKind::File
            || info.metadata.owner != 0
            || info.metadata.group != 0
            || info.metadata.mode != 0o600
            || info.size > MAX_SNAPSHOT as u64
        {
            return Err(AuthError::Corrupt);
        }
        let mut bytes = vec![0; info.size as usize];
        volume
            .read_file(path, 0, &mut bytes)
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        Self::decode(&bytes, clock)
    }
}

/// Shared by shell, Lua, applications, and service dispatch. Revalidation
/// occurs at each operation; possessing an old SecurityContext grants no session.
#[derive(Clone)]
pub struct SessionGuard {
    service: Arc<Mutex<AuthService>>,
    token: SessionToken,
    hosted: Option<(String, u64, [u8; 32])>,
}
impl fmt::Debug for SessionGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionGuard([REDACTED])")
    }
}
impl SessionGuard {
    pub fn new(service: Arc<Mutex<AuthService>>, token: SessionToken) -> Result<Self, AuthError> {
        let guard = Self {
            service,
            token,
            hosted: None,
        };
        guard.context()?;
        Ok(guard)
    }
    pub fn context(&self) -> Result<SecurityContext, AuthError> {
        if let Some((image, blocks, fingerprint)) = &self.hosted {
            let checked = (|| {
                let device = hyber_fs::FileDevice::open_read_only(image, *blocks)
                    .map_err(|_| AuthError::InvalidSession)?;
                let volume = Volume::mount(device).map_err(|_| AuthError::InvalidSession)?;
                if &store_fingerprint(&volume)? != fingerprint {
                    return Err(AuthError::InvalidSession);
                }
                Ok(())
            })();
            if let Err(error) = checked {
                if let Ok(mut service) = self.service.lock() {
                    service.sessions.remove(&self.token.digest());
                }
                return Err(error);
            }
        }
        self.service
            .lock()
            .map_err(|_| AuthError::Unavailable)?
            .context(&self.token)
    }
    pub fn kind(&self) -> Result<SessionKind, AuthError> {
        self.context()?;
        let service = self.service.lock().map_err(|_| AuthError::Unavailable)?;
        service
            .sessions
            .get(&self.token.digest())
            .map(|s| s.kind)
            .ok_or(AuthError::InvalidSession)
    }
    pub fn home(&self) -> Result<String, AuthError> {
        // Run the hosted-volume freshness validation before consulting the
        // in-memory authority, just as `context` does.
        self.context()?;
        self.service
            .lock()
            .map_err(|_| AuthError::Unavailable)?
            .home(&self.token)
    }
    /// Resolve the current Hyber account name after validating the session,
    /// including hosted-store freshness. Never consult the host OS identity.
    pub fn username(&self) -> Result<String, AuthError> {
        self.context()?;
        let mut service = self.service.lock().map_err(|_| AuthError::Unavailable)?;
        let user = service.context(&self.token)?.user_id;
        service
            .accounts
            .user(user)
            .map(|account| account.username.clone())
            .ok_or(AuthError::InvalidSession)
    }
    /// Resolve a Hyber group name for authenticated ownership operations.
    pub fn group_id(&self, name: &str) -> Result<hyber_core::GroupId, AuthError> {
        self.context()?;
        let mut service = self.service.lock().map_err(|_| AuthError::Unavailable)?;
        service.context(&self.token)?;
        service
            .accounts
            .group_by_name(name)
            .map(|group| group.id)
            .ok_or(AuthError::InvalidInput)
    }
    /// Resolve a Hyber user name for an administrative ownership change.
    /// This remains inside the authenticated registry boundary; host account
    /// names and numeric, unverified IDs are never accepted by callers.
    pub fn user_id(&self, name: &str) -> Result<hyber_core::UserId, AuthError> {
        self.context()?;
        let mut service = self.service.lock().map_err(|_| AuthError::Unavailable)?;
        service.context(&self.token)?;
        service
            .accounts
            .user_by_name(name)
            .map(|user| user.id)
            .ok_or(AuthError::InvalidInput)
    }
    pub fn logout(&self) -> Result<(), AuthError> {
        self.service
            .lock()
            .map_err(|_| AuthError::Unavailable)?
            .logout(&self.token)
    }
}

fn password_policy(password: &[u8]) -> Result<(), AuthError> {
    if !(12..=MAX_PASSWORD).contains(&password.len()) {
        Err(AuthError::InvalidInput)
    } else {
        Ok(())
    }
}
fn hash_password(password: &[u8]) -> Result<String, AuthError> {
    let mut salt = [0; 16];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| AuthError::Unavailable)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| AuthError::Unavailable)?;
    Argon2::default()
        .hash_password(password, &salt)
        .map(|p| p.to_string())
        .map_err(|_| AuthError::Unavailable)
}
fn validate_hash(hash: &str) -> Result<(), AuthError> {
    if hash.len() > 256 {
        return Err(AuthError::Corrupt);
    }
    let parsed = PasswordHash::new(hash).map_err(|_| AuthError::Corrupt)?;
    let mut salt_bytes = [0; 64];
    if parsed
        .salt
        .ok_or(AuthError::Corrupt)?
        .decode_b64(&mut salt_bytes)
        .map_err(|_| AuthError::Corrupt)?
        .len()
        != 16
    {
        return Err(AuthError::Corrupt);
    }
    // Exact parameters bound work on untrusted snapshots and ensure the dummy
    // verifier uses the same cost as every stored credential.
    if parsed.algorithm.as_str() != "argon2id"
        || parsed.version != Some(19)
        || parsed.params.get_decimal("m") != Some(19456)
        || parsed.params.get_decimal("t") != Some(2)
        || parsed.params.get_decimal("p") != Some(1)
        || parsed.params.iter().count() != 3
        || parsed.hash.is_none_or(|h| h.len() != 32)
        || parsed.salt.is_none_or(|s| s.len() != 22)
    {
        return Err(AuthError::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use hyber_fs::{MemDevice, BLOCK_SIZE};

    #[test]
    fn hosted_guard_detects_external_store_changes() {
        let path =
            std::env::temp_dir().join(format!("hyber-auth-guard-{}.img", std::process::id()));
        let password = b"temporary test root password";
        let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
        let token = auth
            .login("root", password, SessionKind::Interactive, 600)
            .unwrap();
        let admin = token.clone();
        let mut volume =
            Volume::format(hyber_fs::FileDevice::create(&path, 64, false).unwrap()).unwrap();
        auth.save(&mut volume, STORE_PATH).unwrap();
        let fingerprint = store_fingerprint(&volume).unwrap();
        drop(volume.unmount().unwrap());
        let shared = Arc::new(Mutex::new(auth));
        let mut guard = SessionGuard::new(shared.clone(), token).unwrap();
        guard.hosted = Some((path.to_str().unwrap().into(), 64, fingerprint));
        assert!(guard.context().is_ok());
        let mut volume = Volume::mount(hyber_fs::FileDevice::open(&path, 64).unwrap()).unwrap();
        {
            let mut auth = shared.lock().unwrap();
            auth.edit_accounts(&admin, |accounts| accounts.create_group("external-update"))
                .unwrap();
            auth.save(&mut volume, STORE_PATH).unwrap();
        }
        drop(volume.unmount().unwrap());
        assert!(matches!(guard.context(), Err(AuthError::InvalidSession)));
        assert!(shared.lock().unwrap().context(&admin).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forged_checksums_cannot_bypass_credential_schema_validation() {
        let auth =
            AuthService::provision(b"temporary test password", Arc::new(SystemClock)).unwrap();
        let bytes = auth.encode().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes[40..]).unwrap();
        for variant in 0..7 {
            let mut value = original.clone();
            match variant {
                0 => value["version"] = serde_json::json!(2),
                1 => value["credentials"][0]["hash"] = serde_json::json!("plaintext"),
                2 => {
                    let hash = value["credentials"][0]["hash"]
                        .as_str()
                        .unwrap()
                        .replace("m=19456", "m=4294967295");
                    value["credentials"][0]["hash"] = serde_json::json!(hash);
                }
                3 => {
                    let duplicate = value["credentials"][0].clone();
                    value["credentials"].as_array_mut().unwrap().push(duplicate);
                }
                4 => value["credentials"][0]["user"] = serde_json::json!(99999),
                5 => value["audit"][0]["sequence"] = serde_json::json!(99),
                _ => value["unexpected"] = serde_json::json!(true),
            }
            let payload = serde_json::to_vec(&value).unwrap();
            let mut forged = b"HYBAUTH1".to_vec();
            forged.extend_from_slice(&Sha256::digest(&payload));
            forged.extend_from_slice(&payload);
            assert!(AuthService::decode(&forged, Arc::new(SystemClock)).is_err());
        }
    }

    #[test]
    fn credential_loader_refuses_old_generation_after_committed_slot_damage() {
        let mut auth =
            AuthService::provision(b"temporary root password", Arc::new(SystemClock)).unwrap();
        let mut volume = Volume::format(MemDevice::new(64).unwrap()).unwrap();
        auth.save(&mut volume, STORE_PATH).unwrap();
        let admin = auth
            .login(
                "root",
                b"temporary root password",
                SessionKind::Interactive,
                600,
            )
            .unwrap();
        auth.set_password(&admin, UserId(0), b"replacement root password")
            .unwrap();
        auth.save(&mut volume, STORE_PATH).unwrap();
        let mut device = volume.unmount().unwrap();
        let a = BLOCK_SIZE;
        let b = BLOCK_SIZE + 31 * BLOCK_SIZE;
        let generation = |offset: usize| {
            u64::from_le_bytes(
                device.as_bytes()[offset + 12..offset + 20]
                    .try_into()
                    .unwrap(),
            )
        };
        let offset = if generation(a) > generation(b) { a } else { b };
        let byte = device.as_bytes()[offset + 40] ^ 0x80;
        device.write_at((offset + 40) as u64, &[byte]).unwrap();
        let mut recovered = Volume::mount(device).unwrap();
        assert!(!recovered.recovery_warnings().is_empty());
        assert!(matches!(
            AuthService::load(&recovered, STORE_PATH, Arc::new(SystemClock)),
            Err(AuthError::Corrupt)
        ));
        assert!(recovered.create_file("/overwrite-evidence", 0o600).is_err());
    }

    #[test]
    fn logout_revokes_even_if_audit_is_full() {
        let mut auth =
            AuthService::provision(b"temporary root password", Arc::new(SystemClock)).unwrap();
        let token = auth
            .login(
                "root",
                b"temporary root password",
                SessionKind::Interactive,
                600,
            )
            .unwrap();
        auth.audit.resize(MAX_AUDIT, auth.audit[0].clone());
        assert!(matches!(auth.logout(&token), Err(AuthError::Unavailable)));
        assert!(matches!(
            auth.context(&token),
            Err(AuthError::InvalidSession)
        ));
    }
}
