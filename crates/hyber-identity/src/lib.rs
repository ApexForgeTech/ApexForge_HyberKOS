//! Special_1 — Hyber users, groups, account state, and identity persistence.
//!
//! This is a user-space identity registry. It deliberately does not expose
//! host UIDs/GIDs, plaintext credentials, or host account files. Authentication
//! credentials belong to the later session/authentication boundary; this crate
//! only stores account identity and derives a least-privilege SecurityContext.

use hyber_core::{Capability, GroupId, SecurityContext, UserId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const FORMAT_MAGIC: &[u8; 8] = b"HYBID01\0";
const FORMAT_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Active,
    Locked,
    Disabled,
    Service,
    Guest,
}

impl AccountState {
    fn tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Locked => 2,
            Self::Disabled => 3,
            Self::Service => 4,
            Self::Guest => 5,
        }
    }
    fn from_tag(tag: u8) -> Result<Self, IdentityError> {
        match tag {
            1 => Ok(Self::Active),
            2 => Ok(Self::Locked),
            3 => Ok(Self::Disabled),
            4 => Ok(Self::Service),
            5 => Ok(Self::Guest),
            _ => Err(IdentityError::Corrupt("unknown account state")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAccount {
    pub id: GroupId,
    pub name: String,
    pub members: BTreeSet<UserId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub id: UserId,
    pub username: String,
    pub primary_group: GroupId,
    pub supplementary_groups: BTreeSet<GroupId>,
    pub home: String,
    pub state: AccountState,
    /// Capabilities explicitly granted to this account.  An empty set is the
    /// least-privileged default; capabilities are never inferred from names.
    pub capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    InvalidName(&'static str),
    DuplicateName,
    DuplicateId,
    NotFound,
    AlreadyMember,
    NotMember,
    ReservedIdentity,
    InvalidHome,
    InvalidState,
    Corrupt(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(s) | Self::Corrupt(s) | Self::Unsupported(s) => f.write_str(s),
            Self::DuplicateName => f.write_str("identity name already exists"),
            Self::DuplicateId => f.write_str("identity id already exists"),
            Self::NotFound => f.write_str("identity not found"),
            Self::AlreadyMember => f.write_str("user is already a group member"),
            Self::NotMember => f.write_str("user is not a group member"),
            Self::ReservedIdentity => f.write_str("reserved identity cannot be changed"),
            Self::InvalidHome => f.write_str("invalid home path"),
            Self::InvalidState => f.write_str("account state disallows this operation"),
        }
    }
}
impl std::error::Error for IdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRegistry {
    users: BTreeMap<UserId, UserAccount>,
    groups: BTreeMap<GroupId, GroupAccount>,
    next_user: u32,
    next_group: u32,
    revision: u64,
}

impl Default for AccountRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountRegistry {
    pub fn new() -> Self {
        let mut groups = BTreeMap::new();
        groups.insert(
            GroupId(0),
            GroupAccount {
                id: GroupId(0),
                name: "root".into(),
                members: BTreeSet::from([UserId(0)]),
            },
        );
        let mut users = BTreeMap::new();
        users.insert(
            UserId(0),
            UserAccount {
                id: UserId(0),
                username: "root".into(),
                primary_group: GroupId(0),
                supplementary_groups: BTreeSet::new(),
                home: "/users/root".into(),
                state: AccountState::Active,
                capabilities: BTreeSet::from(["CAP_SYS_ADMIN".into()]),
            },
        );
        Self {
            users,
            groups,
            next_user: 1000,
            next_group: 1000,
            revision: 0,
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn users(&self) -> impl Iterator<Item = &UserAccount> {
        self.users.values()
    }
    pub fn groups(&self) -> impl Iterator<Item = &GroupAccount> {
        self.groups.values()
    }
    pub fn user(&self, id: UserId) -> Option<&UserAccount> {
        self.users.get(&id)
    }
    pub fn group(&self, id: GroupId) -> Option<&GroupAccount> {
        self.groups.get(&id)
    }
    pub fn user_by_name(&self, name: &str) -> Option<&UserAccount> {
        self.users.values().find(|u| u.username == name)
    }
    pub fn group_by_name(&self, name: &str) -> Option<&GroupAccount> {
        self.groups.values().find(|g| g.name == name)
    }

    pub fn create_group(&mut self, name: &str) -> Result<GroupId, IdentityError> {
        self.ensure_mutable()?;
        validate_name(name)?;
        if self.group_by_name(name).is_some() {
            return Err(IdentityError::DuplicateName);
        }
        let id = GroupId(self.next_group);
        self.next_group = self
            .next_group
            .checked_add(1)
            .ok_or(IdentityError::DuplicateId)?;
        self.groups.insert(
            id,
            GroupAccount {
                id,
                name: name.into(),
                members: BTreeSet::new(),
            },
        );
        self.bump();
        Ok(id)
    }

    pub fn create_user(
        &mut self,
        username: &str,
        primary_group: GroupId,
        state: AccountState,
    ) -> Result<UserId, IdentityError> {
        self.ensure_mutable()?;
        validate_name(username)?;
        if self.user_by_name(username).is_some() {
            return Err(IdentityError::DuplicateName);
        }
        if !self.groups.contains_key(&primary_group) {
            return Err(IdentityError::NotFound);
        }
        let id = UserId(self.next_user);
        let home = format!("/users/{username}");
        validate_home(&home)?;
        if self.users.values().any(|u| u.home == home) {
            return Err(IdentityError::InvalidHome);
        }
        self.next_user = self
            .next_user
            .checked_add(1)
            .ok_or(IdentityError::DuplicateId)?;
        self.users.insert(
            id,
            UserAccount {
                id,
                username: username.into(),
                primary_group,
                supplementary_groups: BTreeSet::new(),
                home,
                state,
                capabilities: BTreeSet::new(),
            },
        );
        self.groups
            .get_mut(&primary_group)
            .unwrap()
            .members
            .insert(id);
        self.bump();
        Ok(id)
    }

    pub fn add_to_group(&mut self, user: UserId, group: GroupId) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        let u = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        if matches!(u.state, AccountState::Disabled) {
            return Err(IdentityError::InvalidState);
        }
        let g = self.groups.get_mut(&group).ok_or(IdentityError::NotFound)?;
        if g.members.contains(&user) {
            return Err(IdentityError::AlreadyMember);
        }
        g.members.insert(user);
        u.supplementary_groups.insert(group);
        self.bump();
        Ok(())
    }

    pub fn set_primary_group(&mut self, user: UserId, group: GroupId) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        if user == UserId(0) && group != GroupId(0) {
            return Err(IdentityError::ReservedIdentity);
        }
        if !self.groups.contains_key(&group) {
            return Err(IdentityError::NotFound);
        }
        let account = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        if account.primary_group == group {
            return Ok(());
        }
        self.groups
            .get_mut(&account.primary_group)
            .unwrap()
            .members
            .remove(&user);
        account.supplementary_groups.remove(&group);
        account.primary_group = group;
        self.groups.get_mut(&group).unwrap().members.insert(user);
        self.bump();
        Ok(())
    }

    pub fn remove_from_group(&mut self, user: UserId, group: GroupId) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        let u = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        if u.primary_group == group {
            return Err(IdentityError::ReservedIdentity);
        }
        let g = self.groups.get_mut(&group).ok_or(IdentityError::NotFound)?;
        if !g.members.remove(&user) {
            return Err(IdentityError::NotMember);
        }
        u.supplementary_groups.remove(&group);
        self.bump();
        Ok(())
    }

    pub fn set_state(&mut self, user: UserId, state: AccountState) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        if user == UserId(0) && !matches!(state, AccountState::Active) {
            return Err(IdentityError::ReservedIdentity);
        }
        let u = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        u.state = state;
        self.bump();
        Ok(())
    }

    pub fn set_home(&mut self, user: UserId, home: &str) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        validate_home(home)?;
        if user == UserId(0) && home != "/users/root" {
            return Err(IdentityError::ReservedIdentity);
        }
        if self.users.values().any(|u| u.id != user && u.home == home) {
            return Err(IdentityError::InvalidHome);
        }
        let u = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        u.home = home.into();
        self.bump();
        Ok(())
    }

    pub fn grant_capability(
        &mut self,
        user: UserId,
        capability: &str,
    ) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        validate_capability(capability)?;
        let u = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        if u.capabilities.insert(capability.into()) {
            self.bump();
        }
        Ok(())
    }

    pub fn revoke_capability(
        &mut self,
        user: UserId,
        capability: &str,
    ) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        if user == UserId(0) && capability == "CAP_SYS_ADMIN" {
            return Err(IdentityError::ReservedIdentity);
        }
        let u = self.users.get_mut(&user).ok_or(IdentityError::NotFound)?;
        if !u.capabilities.remove(capability) {
            return Err(IdentityError::NotMember);
        }
        self.bump();
        Ok(())
    }

    pub fn delete_user(&mut self, user: UserId) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        if user == UserId(0) {
            return Err(IdentityError::ReservedIdentity);
        }
        if self.users.remove(&user).is_none() {
            return Err(IdentityError::NotFound);
        }
        for group in self.groups.values_mut() {
            group.members.remove(&user);
        }
        self.bump();
        self.validate()?;
        Ok(())
    }

    pub fn delete_group(&mut self, group: GroupId) -> Result<(), IdentityError> {
        self.ensure_mutable()?;
        if group == GroupId(0) {
            return Err(IdentityError::ReservedIdentity);
        }
        let g = self.groups.get(&group).ok_or(IdentityError::NotFound)?;
        if !g.members.is_empty() || self.users.values().any(|u| u.primary_group == group) {
            return Err(IdentityError::InvalidState);
        }
        self.groups.remove(&group);
        self.bump();
        Ok(())
    }

    pub fn security_context(&self, user: UserId) -> Result<SecurityContext, IdentityError> {
        let u = self.users.get(&user).ok_or(IdentityError::NotFound)?;
        if matches!(u.state, AccountState::Locked | AccountState::Disabled) {
            return Err(IdentityError::InvalidState);
        }
        let capabilities = u
            .capabilities
            .iter()
            .map(|name| Capability { name: name.clone() })
            .collect();
        Ok(SecurityContext {
            user_id: u.id,
            group_id: u.primary_group,
            supplementary_groups: u.supplementary_groups.iter().copied().collect(),
            capabilities,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::new();
        put(&mut p, FORMAT_VERSION as u64);
        put(&mut p, self.revision);
        put(&mut p, self.next_user as u64);
        put(&mut p, self.next_group as u64);
        put(&mut p, self.users.len() as u64);
        for u in self.users.values() {
            put_user(&mut p, u);
        }
        put(&mut p, self.groups.len() as u64);
        for g in self.groups.values() {
            put_group(&mut p, g);
        }
        let checksum = hash(&p);
        let mut out = Vec::from(FORMAT_MAGIC.as_slice());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&p);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < 16 || &bytes[..8] != FORMAT_MAGIC {
            return Err(IdentityError::Corrupt("invalid identity magic"));
        }
        let expected = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let payload = &bytes[16..];
        if hash(payload) != expected {
            return Err(IdentityError::Corrupt("identity checksum mismatch"));
        }
        let mut r = Reader { b: payload, pos: 0 };
        if r.u64()? != u64::from(FORMAT_VERSION) {
            return Err(IdentityError::Unsupported("identity format version"));
        }
        let revision = r.u64()?;
        let next_user = r.u32()?;
        let next_group = r.u32()?;
        let uc = r.count()?;
        let mut users = BTreeMap::new();
        for _ in 0..uc {
            let u = read_user(&mut r)?;
            if users.insert(u.id, u).is_some() {
                return Err(IdentityError::Corrupt("duplicate user id"));
            }
        }
        let gc = r.count()?;
        let mut groups = BTreeMap::new();
        for _ in 0..gc {
            let g = read_group(&mut r)?;
            if groups.insert(g.id, g).is_some() {
                return Err(IdentityError::Corrupt("duplicate group id"));
            }
        }
        if r.pos != payload.len() {
            return Err(IdentityError::Corrupt("trailing identity bytes"));
        }
        let reg = Self {
            users,
            groups,
            next_user,
            next_group,
            revision,
        };
        reg.validate()?;
        Ok(reg)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        let root = self
            .users
            .get(&UserId(0))
            .ok_or(IdentityError::Corrupt("missing root user"))?;
        if root.username != "root"
            || root.primary_group != GroupId(0)
            || root.state != AccountState::Active
            || root.home != "/users/root"
        {
            return Err(IdentityError::Corrupt("invalid root identity"));
        }
        if !root.capabilities.contains("CAP_SYS_ADMIN") {
            return Err(IdentityError::Corrupt("root capability missing"));
        }
        if self
            .groups
            .get(&GroupId(0))
            .is_none_or(|g| g.name != "root")
        {
            return Err(IdentityError::Corrupt("missing root group"));
        }
        if self.next_user < 1000
            || self.next_group < 1000
            || self
                .users
                .keys()
                .any(|id| id.0 >= self.next_user || (id.0 != 0 && id.0 < 1000))
            || self
                .groups
                .keys()
                .any(|id| id.0 >= self.next_group || (id.0 != 0 && id.0 < 1000))
        {
            return Err(IdentityError::Corrupt(
                "invalid identity allocation counters",
            ));
        }
        let mut names = BTreeSet::new();
        let mut homes = BTreeSet::new();
        for (id, u) in &self.users {
            if !names.insert(&u.username) || !homes.insert(&u.home) {
                return Err(IdentityError::Corrupt("duplicate user name or home"));
            }
            if u.supplementary_groups.contains(&u.primary_group) {
                return Err(IdentityError::Corrupt(
                    "primary group repeated as supplementary",
                ));
            }
            if *id != u.id {
                return Err(IdentityError::Corrupt("user id mismatch"));
            }
            validate_name(&u.username)?;
            validate_home(&u.home)?;
            for capability in &u.capabilities {
                validate_capability(capability)?;
            }
            let g = self
                .groups
                .get(&u.primary_group)
                .ok_or(IdentityError::Corrupt("missing primary group"))?;
            if !g.members.contains(id) {
                return Err(IdentityError::Corrupt("primary membership mismatch"));
            }
            for gid in &u.supplementary_groups {
                if !self
                    .groups
                    .get(gid)
                    .map(|g| g.members.contains(id))
                    .unwrap_or(false)
                {
                    return Err(IdentityError::Corrupt("supplementary membership mismatch"));
                }
            }
        }
        let mut names = BTreeSet::new();
        for (id, g) in &self.groups {
            if !names.insert(&g.name) {
                return Err(IdentityError::Corrupt("duplicate group name"));
            }
            if *id != g.id {
                return Err(IdentityError::Corrupt("group id mismatch"));
            }
            validate_name(&g.name)?;
            for uid in &g.members {
                let u = self
                    .users
                    .get(uid)
                    .ok_or(IdentityError::Corrupt("group references missing user"))?;
                if u.primary_group != *id && !u.supplementary_groups.contains(id) {
                    return Err(IdentityError::Corrupt("group membership mismatch"));
                }
            }
        }
        Ok(())
    }
    /// Validate an administrative replacement without permitting ID reuse or
    /// rollback of allocation watermarks, even after deleted accounts disappear.
    pub fn validate_successor(&self, next: &Self) -> Result<(), IdentityError> {
        next.validate()?;
        if next.revision < self.revision
            || next.next_user < self.next_user
            || next.next_group < self.next_group
            || next
                .users
                .keys()
                .any(|id| !self.users.contains_key(id) && id.0 < self.next_user)
            || next
                .groups
                .keys()
                .any(|id| !self.groups.contains_key(id) && id.0 < self.next_group)
        {
            return Err(IdentityError::Corrupt("identity rollback or ID reuse"));
        }
        Ok(())
    }
    fn ensure_mutable(&self) -> Result<(), IdentityError> {
        if self.revision == u64::MAX {
            Err(IdentityError::Unsupported("identity revision exhausted"))
        } else {
            Ok(())
        }
    }
    fn bump(&mut self) {
        self.revision += 1;
    }
}

fn validate_name(name: &str) -> Result<(), IdentityError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        || name == "."
        || name == ".."
    {
        Err(IdentityError::InvalidName(
            "identity name must contain only safe ASCII characters",
        ))
    } else {
        Ok(())
    }
}
fn validate_home(path: &str) -> Result<(), IdentityError> {
    let name = path
        .strip_prefix("/users/")
        .ok_or(IdentityError::InvalidHome)?;
    validate_name(name).map_err(|_| IdentityError::InvalidHome)
}
fn validate_capability(capability: &str) -> Result<(), IdentityError> {
    if capability.is_empty()
        || capability.len() > 64
        || !capability
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(IdentityError::InvalidName("invalid capability name"));
    }
    Ok(())
}
fn put(v: &mut Vec<u8>, n: u64) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn put_str(v: &mut Vec<u8>, s: &str) {
    put(v, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
}
fn put_user(v: &mut Vec<u8>, u: &UserAccount) {
    put(v, u.id.0 as u64);
    put_str(v, &u.username);
    put(v, u.primary_group.0 as u64);
    put_str(v, &u.home);
    v.push(u.state.tag());
    put(v, u.supplementary_groups.len() as u64);
    for g in &u.supplementary_groups {
        put(v, g.0 as u64);
    }
    put(v, u.capabilities.len() as u64);
    for capability in &u.capabilities {
        put_str(v, capability);
    }
}
fn put_group(v: &mut Vec<u8>, g: &GroupAccount) {
    put(v, g.id.0 as u64);
    put_str(v, &g.name);
    put(v, g.members.len() as u64);
    for u in &g.members {
        put(v, u.0 as u64);
    }
}
fn hash(b: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for x in b {
        h ^= *x as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], IdentityError> {
        let e = self
            .pos
            .checked_add(n)
            .ok_or(IdentityError::Corrupt("identity length overflow"))?;
        if e > self.b.len() {
            return Err(IdentityError::Corrupt("truncated identity"));
        }
        let x = &self.b[self.pos..e];
        self.pos = e;
        Ok(x)
    }
    fn u64(&mut self) -> Result<u64, IdentityError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, IdentityError> {
        u32::try_from(self.u64()?).map_err(|_| IdentityError::Corrupt("identity integer overflow"))
    }
    fn count(&mut self) -> Result<usize, IdentityError> {
        usize::try_from(self.u64()?).map_err(|_| IdentityError::Corrupt("identity count overflow"))
    }
    fn string(&mut self) -> Result<String, IdentityError> {
        let n = self.count()?;
        String::from_utf8(self.take(n)?.to_vec())
            .map_err(|_| IdentityError::Corrupt("identity invalid utf8"))
    }
    fn byte(&mut self) -> Result<u8, IdentityError> {
        Ok(self.take(1)?[0])
    }
}
fn read_user(r: &mut Reader<'_>) -> Result<UserAccount, IdentityError> {
    let id = UserId(r.u32()?);
    let username = r.string()?;
    let primary_group = GroupId(r.u32()?);
    let home = r.string()?;
    let state = AccountState::from_tag(r.byte()?)?;
    let n = r.count()?;
    let mut supplementary_groups = BTreeSet::new();
    for _ in 0..n {
        if !supplementary_groups.insert(GroupId(r.u32()?)) {
            return Err(IdentityError::Corrupt("duplicate supplementary group"));
        }
    }
    let n = r.count()?;
    let mut capabilities = BTreeSet::new();
    for _ in 0..n {
        let capability = r.string()?;
        if !capabilities.insert(capability) {
            return Err(IdentityError::Corrupt("duplicate capability"));
        }
    }
    Ok(UserAccount {
        id,
        username,
        primary_group,
        supplementary_groups,
        home,
        state,
        capabilities,
    })
}
fn read_group(r: &mut Reader<'_>) -> Result<GroupAccount, IdentityError> {
    let id = GroupId(r.u32()?);
    let name = r.string()?;
    let n = r.count()?;
    let mut members = BTreeSet::new();
    for _ in 0..n {
        if !members.insert(UserId(r.u32()?)) {
            return Err(IdentityError::Corrupt("duplicate member"));
        }
    }
    Ok(GroupAccount { id, name, members })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_revision_and_successor_rollback_are_rejected_without_mutation() {
        let mut accounts = AccountRegistry::new();
        accounts.create_group("allocated").unwrap();
        assert!(accounts
            .validate_successor(&AccountRegistry::new())
            .is_err());
        accounts.revision = u64::MAX;
        let before = accounts.clone();
        assert!(accounts.create_group("never").is_err());
        assert!(accounts.set_home(UserId(0), "/users/root").is_err());
        assert_eq!(accounts, before);
    }
    #[test]
    fn decoder_rejects_semantic_corruption_even_with_valid_checksum() {
        let mut r = AccountRegistry::new();
        let group = r.create_group("users").unwrap();
        let a = r.create_user("alice", group, AccountState::Active).unwrap();
        let b = r.create_user("bob", group, AccountState::Active).unwrap();
        for case in 0..7 {
            let mut bad = r.clone();
            match case {
                0 => bad.next_user = a.0,
                1 => bad.users.get_mut(&b).unwrap().username = "alice".into(),
                2 => bad.users.get_mut(&UserId(0)).unwrap().state = AccountState::Disabled,
                3 => bad.groups.get_mut(&group).unwrap().name = "root".into(),
                4 => bad.users.get_mut(&a).unwrap().home = "/users/./".into(),
                5 => {
                    bad.users
                        .get_mut(&a)
                        .unwrap()
                        .supplementary_groups
                        .insert(group);
                }
                _ => bad.users.get_mut(&b).unwrap().home = "/users/alice".into(),
            }
            assert!(AccountRegistry::decode(&bad.encode()).is_err());
        }
        let encoded = r.encode();
        for n in 0..encoded.len() {
            assert!(AccountRegistry::decode(&encoded[..n]).is_err());
        }
        let mut wrong_version = encoded;
        wrong_version[16..24]
            .copy_from_slice(&(u64::from(FORMAT_VERSION) + (1u64 << 32)).to_le_bytes());
        let checksum = hash(&wrong_version[16..]);
        wrong_version[8..16].copy_from_slice(&checksum.to_le_bytes());
        assert!(AccountRegistry::decode(&wrong_version).is_err());
    }

    #[test]
    fn home_and_membership_mutations_preserve_invariants() {
        let mut r = AccountRegistry::new();
        let g = r.create_group("users").unwrap();
        let other = r.create_group("other").unwrap();
        let u = r.create_user("a..b", g, AccountState::Active).unwrap();
        let before = r.clone();
        for home in ["/users/.", "/users//x", "/users/x/", "/users/root"] {
            assert!(r.set_home(u, home).is_err());
            assert_eq!(r, before);
        }
        r.add_to_group(u, other).unwrap();
        r.set_primary_group(u, other).unwrap();
        assert!(!r.group(g).unwrap().members.contains(&u));
        assert!(r.user(u).unwrap().supplementary_groups.is_empty());
        r.validate().unwrap();
    }
    #[test]
    fn account_membership_and_context_are_consistent() {
        let mut r = AccountRegistry::new();
        let g = r.create_group("developers").unwrap();
        let u = r.create_user("neo", g, AccountState::Active).unwrap();
        r.add_to_group(u, GroupId(0)).unwrap();
        assert_eq!(r.user_by_name("neo").unwrap().home, "/users/neo");
        assert_eq!(r.security_context(u).unwrap().group_id, g);
        r.validate().unwrap();
    }
    #[test]
    fn persistence_round_trip_and_corruption_detection() {
        let mut r = AccountRegistry::new();
        let g = r.create_group("users").unwrap();
        r.create_user("alice", g, AccountState::Guest).unwrap();
        let bytes = r.encode();
        assert_eq!(AccountRegistry::decode(&bytes).unwrap(), r);
        let mut bad = bytes;
        bad[20] ^= 1;
        assert!(matches!(
            AccountRegistry::decode(&bad),
            Err(IdentityError::Corrupt("identity checksum mismatch"))
        ));
    }
    #[test]
    fn reserved_and_invalid_mutations_are_rejected() {
        let mut r = AccountRegistry::new();
        assert_eq!(
            r.create_group("../bad"),
            Err(IdentityError::InvalidName(
                "identity name must contain only safe ASCII characters"
            ))
        );
        assert_eq!(
            r.set_state(UserId(0), AccountState::Disabled),
            Err(IdentityError::ReservedIdentity)
        );
    }

    #[test]
    fn capabilities_lifecycle_and_safe_deletion() {
        let mut r = AccountRegistry::new();
        let g = r.create_group("operators").unwrap();
        let u = r.create_user("sam", g, AccountState::Active).unwrap();
        r.grant_capability(u, "CAP_NET_ADMIN").unwrap();
        assert!(r
            .security_context(u)
            .unwrap()
            .capabilities
            .iter()
            .any(|c| c.name == "CAP_NET_ADMIN"));
        assert_eq!(
            r.revoke_capability(UserId(0), "CAP_SYS_ADMIN"),
            Err(IdentityError::ReservedIdentity)
        );
        r.set_home(u, "/users/sam-data").unwrap();
        r.delete_user(u).unwrap();
        assert!(r.user(u).is_none());
        r.delete_group(g).unwrap();
        r.validate().unwrap();
    }
}
