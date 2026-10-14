//! Phase 20 hosted networking boundary.
//!
//! This crate owns logical Socket Objects, capability/policy checks and Hyber
//! handles. `NetworkProvider` intentionally contains no platform socket type:
//! host adapters keep those implementation details private.

use hyber_core::{
    HandleId, ObjectId, ObjectState, ObjectType, ProcessId, Rights, SecurityContext,
    SecurityManager, UserId,
};
use hyber_handle::{HandleFlags, HandleManager};
use hyber_manifest::ApplicationGrant;
use hyber_object::ObjectManager;
use hyber_service_contract::ServiceDefinition;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const NETWORK_PROVIDER: &str = "network";
pub const MAX_HOSTNAME_BYTES: usize = 253;
pub const MAX_IO_BYTES: usize = 64 * 1024;
pub const MAX_SOCKETS: usize = 4096;
pub const MAX_DATAGRAM_BYTES: usize = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitInterest {
    Readable,
    Writable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Created,
    Connecting,
    Connected,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderSocketId(pub u64);

/// Validated logical DNS name. Numeric destinations are deliberately rejected
/// in v1 so manifest domain policy cannot be bypassed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);
impl HostName {
    pub fn parse(value: &str) -> Result<Self, NetworkError> {
        if value.is_empty() || value.len() > MAX_HOSTNAME_BYTES || value != value.trim() {
            return Err(NetworkError::InvalidDestination);
        }
        let value = value.to_ascii_lowercase();
        if value.parse::<std::net::IpAddr>().is_ok()
            || value.ends_with('.')
            || value
                .split('.')
                .all(|label| label.bytes().all(|b| b.is_ascii_digit()) || label.starts_with("0x"))
        {
            return Err(NetworkError::InvalidDestination);
        }
        if value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) {
            return Err(NetworkError::InvalidDestination);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: HostName,
    pub port: u16,
}
impl Endpoint {
    pub fn new(host: &str, port: u16) -> Result<Self, NetworkError> {
        if port == 0 {
            return Err(NetworkError::InvalidDestination);
        }
        Ok(Self {
            host: HostName::parse(host)?,
            port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub active: bool,
    pub provider: String,
}

/// Bounded resolver diagnostics, without transport addresses or reusable
/// connect authority. TTL is a local cache maximum, not an authoritative DNS TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionInfo {
    pub host: HostName,
    pub answers: usize,
    pub cached: bool,
    pub cache_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAudit {
    pub owner: UserId,
    pub application: String,
    pub operation: &'static str,
    pub allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketInfo {
    pub object_id: ObjectId,
    pub owner: UserId,
    pub protocol: Protocol,
    pub state: SocketState,
    pub peer: Endpoint,
    pub provider: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    Timeout,
    Refused,
    Unreachable,
    WouldBlock,
    Closed,
    Io,
    Unsupported,
    MessageTooLarge,
}

/// Provider token is opaque and logical; it is never a host descriptor.
pub trait NetworkProvider {
    fn wait(
        &mut self,
        _socket: ProviderSocketId,
        _interest: WaitInterest,
        _timeout_ms: u32,
    ) -> Result<bool, ProviderError> {
        Err(ProviderError::Unsupported)
    }
    fn resolve(&mut self, _host: &HostName) -> Result<ResolutionInfo, ProviderError> {
        Err(ProviderError::Unsupported)
    }
    fn interfaces(&mut self) -> Result<Vec<InterfaceInfo>, ProviderError>;
    fn connect(
        &mut self,
        protocol: Protocol,
        endpoint: &Endpoint,
    ) -> Result<ProviderSocketId, ProviderError>;
    fn send(&mut self, socket: ProviderSocketId, data: &[u8]) -> Result<usize, ProviderError>;
    fn receive(&mut self, socket: ProviderSocketId, limit: usize)
        -> Result<Vec<u8>, ProviderError>;
    fn close(&mut self, socket: ProviderSocketId) -> Result<(), ProviderError>;
}

impl<T: NetworkProvider + ?Sized> NetworkProvider for Box<T> {
    fn wait(
        &mut self,
        socket: ProviderSocketId,
        interest: WaitInterest,
        timeout_ms: u32,
    ) -> Result<bool, ProviderError> {
        (**self).wait(socket, interest, timeout_ms)
    }
    fn resolve(&mut self, host: &HostName) -> Result<ResolutionInfo, ProviderError> {
        (**self).resolve(host)
    }
    fn interfaces(&mut self) -> Result<Vec<InterfaceInfo>, ProviderError> {
        (**self).interfaces()
    }
    fn connect(
        &mut self,
        protocol: Protocol,
        endpoint: &Endpoint,
    ) -> Result<ProviderSocketId, ProviderError> {
        (**self).connect(protocol, endpoint)
    }
    fn send(&mut self, socket: ProviderSocketId, data: &[u8]) -> Result<usize, ProviderError> {
        (**self).send(socket, data)
    }
    fn receive(
        &mut self,
        socket: ProviderSocketId,
        limit: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        (**self).receive(socket, limit)
    }
    fn close(&mut self, socket: ProviderSocketId) -> Result<(), ProviderError> {
        (**self).close(socket)
    }
}

/// Core runtimes have no ambient transport authority. The composition root
/// supplies a provider explicitly for an approved execution.
pub struct UnavailableNetworkProvider;
impl NetworkProvider for UnavailableNetworkProvider {
    fn interfaces(&mut self) -> Result<Vec<InterfaceInfo>, ProviderError> {
        Err(ProviderError::Unsupported)
    }
    fn connect(&mut self, _: Protocol, _: &Endpoint) -> Result<ProviderSocketId, ProviderError> {
        Err(ProviderError::Unsupported)
    }
    fn send(&mut self, _: ProviderSocketId, _: &[u8]) -> Result<usize, ProviderError> {
        Err(ProviderError::Unsupported)
    }
    fn receive(&mut self, _: ProviderSocketId, _: usize) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported)
    }
    fn close(&mut self, _: ProviderSocketId) -> Result<(), ProviderError> {
        Err(ProviderError::Closed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    AccessDenied,
    InvalidDestination,
    DeniedByPolicy,
    InvalidHandle,
    WrongHandle,
    InvalidState,
    TooLarge,
    Capacity,
    MessageTooLarge,
    Unsupported,
    Timeout,
    Refused,
    Unreachable,
    WouldBlock,
    Closed,
    Io,
}
impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AccessDenied => "network access denied",
            Self::InvalidDestination => "invalid network destination",
            Self::DeniedByPolicy => "network destination denied by policy",
            Self::InvalidHandle => "invalid network handle",
            Self::WrongHandle => "handle is not a network socket",
            Self::InvalidState => "network socket is in an invalid state",
            Self::TooLarge => "network I/O exceeds the bound",
            Self::Capacity => "network socket capacity reached",
            Self::Unsupported => "network operation is unsupported",
            Self::Timeout => "network operation timed out",
            Self::Refused => "network connection refused",
            Self::Unreachable => "network destination unreachable",
            Self::WouldBlock => "network operation would block",
            Self::Closed => "network socket is closed",
            Self::Io => "network provider I/O failure",
            Self::MessageTooLarge => "network datagram exceeds receive buffer",
        })
    }
}
impl std::error::Error for NetworkError {}
impl From<ProviderError> for NetworkError {
    fn from(value: ProviderError) -> Self {
        match value {
            ProviderError::Timeout => Self::Timeout,
            ProviderError::Refused => Self::Refused,
            ProviderError::Unreachable => Self::Unreachable,
            ProviderError::WouldBlock => Self::WouldBlock,
            ProviderError::Closed => Self::Closed,
            ProviderError::Io => Self::Io,
            ProviderError::Unsupported => Self::Unsupported,
            ProviderError::MessageTooLarge => Self::MessageTooLarge,
        }
    }
}

struct SocketRecord {
    info: SocketInfo,
    provider_socket: ProviderSocketId,
    process: ProcessId,
    handle: HandleId,
    grant: ApplicationGrant,
}

/// Authority comes from the trusted dispatcher, which must refresh its
/// SessionGuard before constructing this view. Applications never construct it.
pub struct NetworkAccess<'a> {
    pub objects: &'a ObjectManager,
    pub handles: &'a HandleManager,
    pub process: ProcessId,
    pub context: &'a SecurityContext,
    pub grant: &'a ApplicationGrant,
}

/// Rust-owned policy/lifecycle manager. Caller identity and approved grant are
/// supplied at every sensitive operation; the provider is invoked only after
/// those checks succeed.
pub struct NetworkManager<P> {
    provider: P,
    sockets: BTreeMap<ObjectId, SocketRecord>,
    interfaces: BTreeMap<String, ObjectId>,
    audit: VecDeque<NetworkAudit>,
}
impl<P: NetworkProvider> NetworkManager<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            sockets: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            audit: VecDeque::new(),
        }
    }
    #[cfg(test)]
    fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
    fn authorize(
        &mut self,
        context: &SecurityContext,
        grant: &ApplicationGrant,
        host: &str,
        operation: &'static str,
    ) -> Result<(), NetworkError> {
        let result = authorize_outbound(context, grant, host);
        if self.audit.len() == 128 {
            self.audit.pop_front();
        }
        self.audit.push_back(NetworkAudit {
            owner: context.user_id,
            application: grant
                .manifest
                .app_id
                .0
                .chars()
                .take(64)
                .filter(|c| !c.is_control())
                .collect(),
            operation,
            allowed: result.is_ok(),
        });
        result
    }
    pub fn audit(&self, context: &SecurityContext) -> Result<Vec<NetworkAudit>, NetworkError> {
        SecurityManager::check_capability(context, "CAP_SYS_ADMIN")
            .map_err(|_| NetworkError::AccessDenied)?;
        Ok(self.audit.iter().cloned().collect())
    }
    pub fn interfaces(
        &mut self,
        context: &SecurityContext,
    ) -> Result<Vec<InterfaceInfo>, NetworkError> {
        SecurityManager::check_capability(context, "CAP_SYS_ADMIN")
            .map_err(|_| NetworkError::AccessDenied)?;
        let mut interfaces = self.provider.interfaces()?;
        if interfaces.len() > 64
            || interfaces.iter().any(|i| {
                i.name.is_empty()
                    || i.name.len() > 64
                    || !i
                        .name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    || i.provider.is_empty()
                    || i.provider.len() > 64
                    || i.provider.chars().any(char::is_control)
            })
        {
            return Err(NetworkError::Io);
        }
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        if interfaces
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(NetworkError::Io);
        }
        Ok(interfaces)
    }
    /// Interfaces are Device Objects with a network-interface class; this
    /// reuses the existing Device vocabulary without changing disk enum tags.
    pub fn interface_objects(
        &mut self,
        objects: &mut ObjectManager,
        context: &SecurityContext,
    ) -> Result<Vec<(ObjectId, InterfaceInfo)>, NetworkError> {
        let interfaces = self.interfaces(context)?;
        let removed: Vec<_> = self
            .interfaces
            .keys()
            .filter(|name| !interfaces.iter().any(|entry| &entry.name == *name))
            .cloned()
            .collect();
        for name in removed {
            if let Some(id) = self.interfaces.remove(&name) {
                objects.release(id);
                objects.destroy(id);
            }
        }
        let mut result = Vec::new();
        for interface in interfaces {
            let id = *self
                .interfaces
                .entry(interface.name.clone())
                .or_insert_with(|| {
                    let id = objects.create_object(ObjectType::Device);
                    let object = objects.lookup_mut(id).expect("created interface");
                    object.permissions = 0o600;
                    object.extended_metadata.insert(
                        "network.class".into(),
                        hyber_core::MetadataValue::String("interface".into()),
                    );
                    id
                });
            let object = objects.lookup_mut(id).ok_or(NetworkError::InvalidState)?;
            object.extended_metadata.insert(
                "network.active".into(),
                hyber_core::MetadataValue::Boolean(interface.active),
            );
            object.extended_metadata.insert(
                "network.provider".into(),
                hyber_core::MetadataValue::String(interface.provider.clone()),
            );
            result.push((id, interface));
        }
        Ok(result)
    }
    pub fn shutdown(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
    ) -> Result<(), NetworkError> {
        let processes: std::collections::BTreeSet<_> =
            self.sockets.values().map(|s| s.process).collect();
        let mut failure = None;
        for process in processes {
            if let Err(error) = self.close_process(objects, handles, process) {
                failure = Some(error);
            }
        }
        for (_, object) in std::mem::take(&mut self.interfaces) {
            objects.release(object);
            objects.destroy(object);
        }
        failure.map_or(Ok(()), Err)
    }
    pub fn resolve(
        &mut self,
        context: &SecurityContext,
        grant: &ApplicationGrant,
        host: &str,
    ) -> Result<ResolutionInfo, NetworkError> {
        self.authorize(context, grant, host, "resolve")?;
        let host = HostName::parse(host)?;
        let result = self.provider.resolve(&host)?;
        if result.host != host
            || result.answers == 0
            || result.answers > 16
            || result.cache_seconds > 30
        {
            return Err(NetworkError::Io);
        }
        Ok(result)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "the network boundary makes every authority-bearing dependency explicit"
    )]
    pub fn connect(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        grant: &ApplicationGrant,
        protocol: Protocol,
        host: &str,
        port: u16,
    ) -> Result<HandleId, NetworkError> {
        self.authorize(context, grant, host, "connect")?;
        let endpoint = Endpoint::new(host, port)?;
        if self.sockets.len() >= MAX_SOCKETS
            || handles.list_handles(process).len() >= grant.manifest.resources.handles as usize
        {
            return Err(NetworkError::Capacity);
        }
        let object_id = objects.create_object(ObjectType::Socket);
        {
            let object = objects.lookup_mut(object_id).expect("new object");
            object.owner = context.user_id;
            object.group = context.group_id;
            object.permissions = 0o600;
        }
        let provider_socket = match self.provider.connect(protocol, &endpoint) {
            Ok(id) => id,
            Err(error) => {
                objects.release(object_id);
                objects.destroy(object_id);
                return Err(error.into());
            }
        };
        let rights = Rights {
            read: true,
            write: true,
            connect: true,
            wait: true,
            signal: true,
            ..Rights::empty()
        };
        let handle = match handles.open_with_flags(
            objects,
            process,
            object_id,
            rights,
            NETWORK_PROVIDER.into(),
            HandleFlags::not_inheritable(),
        ) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = self.provider.close(provider_socket);
                objects.release(object_id);
                objects.destroy(object_id);
                return Err(NetworkError::Capacity);
            }
        };
        objects.release(object_id); // transfer creation reference to handle
        self.sockets.insert(
            object_id,
            SocketRecord {
                provider_socket,
                process,
                handle,
                grant: grant.clone(),
                info: SocketInfo {
                    object_id,
                    owner: context.user_id,
                    protocol,
                    state: SocketState::Connected,
                    peer: endpoint,
                    provider: NETWORK_PROVIDER.into(),
                    bytes_sent: 0,
                    bytes_received: 0,
                },
            },
        );
        Ok(handle)
    }

    fn authorized_object(
        &self,
        access: &NetworkAccess<'_>,
        handle: HandleId,
        write: bool,
    ) -> Result<ObjectId, NetworkError> {
        let object = socket_for(access.handles, access.process, handle, write)?;
        let record = self
            .sockets
            .get(&object)
            .ok_or(NetworkError::InvalidHandle)?;
        if record.process != access.process
            || record.handle != handle
            || record.info.owner != access.context.user_id
            || record.grant.manifest.app_id != access.grant.manifest.app_id
        {
            return Err(NetworkError::AccessDenied);
        }
        authorize_outbound(access.context, access.grant, record.info.peer.host.as_str())?;
        authorize_outbound(
            access.context,
            &record.grant,
            record.info.peer.host.as_str(),
        )?;
        let metadata = access
            .objects
            .lookup(object)
            .ok_or(NetworkError::InvalidHandle)?;
        if metadata.state != ObjectState::Live || metadata.object_type != ObjectType::Socket {
            return Err(NetworkError::InvalidState);
        }
        SecurityManager::check_access(
            access.context,
            metadata.owner,
            metadata.group,
            metadata.permissions,
            Rights {
                read: !write,
                write,
                ..Rights::empty()
            },
        )
        .map_err(|_| NetworkError::AccessDenied)?;
        Ok(object)
    }

    /// Advisory readiness, not a reservation: subsequent I/O may still time out.
    /// A zero timeout polls once; waits are capped at 30 seconds.
    pub fn wait(
        &mut self,
        access: &NetworkAccess<'_>,
        handle: HandleId,
        interest: WaitInterest,
        timeout_ms: u32,
    ) -> Result<bool, NetworkError> {
        let object = self.authorized_object(access, handle, interest == WaitInterest::Writable)?;
        if !access
            .handles
            .get_handle(access.process, handle)
            .ok_or(NetworkError::InvalidHandle)?
            .rights
            .wait
        {
            return Err(NetworkError::AccessDenied);
        }
        if timeout_ms > 30_000 {
            return Err(NetworkError::TooLarge);
        }
        let record = self
            .sockets
            .get(&object)
            .ok_or(NetworkError::InvalidHandle)?;
        if record.info.state != SocketState::Connected {
            return Err(NetworkError::InvalidState);
        }
        self.provider
            .wait(record.provider_socket, interest, timeout_ms)
            .map_err(Into::into)
    }

    /// Cancel this endpoint's transport. The handle remains inspectable until
    /// close; cancellation is not process signalling or TCP half-close.
    pub fn cancel(
        &mut self,
        access: &NetworkAccess<'_>,
        handle: HandleId,
    ) -> Result<(), NetworkError> {
        let object = self.authorized_object(access, handle, true)?;
        if !access
            .handles
            .get_handle(access.process, handle)
            .ok_or(NetworkError::InvalidHandle)?
            .rights
            .signal
        {
            return Err(NetworkError::AccessDenied);
        }
        let record = self
            .sockets
            .get_mut(&object)
            .ok_or(NetworkError::InvalidHandle)?;
        if record.info.state == SocketState::Closed {
            return Ok(());
        }
        record.info.state = SocketState::Closing;
        match self.provider.close(record.provider_socket) {
            Ok(()) | Err(ProviderError::Closed) => {
                record.info.state = SocketState::Closed;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Trusted supervisor diagnostics. Records are logical, bounded by the
    /// manager socket cap, and must be qualified by process/broker identity.
    pub fn diagnostics(
        &self,
        context: &SecurityContext,
    ) -> Result<Vec<(ProcessId, HandleId, SocketInfo)>, NetworkError> {
        SecurityManager::check_capability(context, "CAP_SYS_ADMIN")
            .map_err(|_| NetworkError::AccessDenied)?;
        Ok(self
            .sockets
            .values()
            .map(|r| (r.process, r.handle, r.info.clone()))
            .collect())
    }

    pub fn send(
        &mut self,
        access: &NetworkAccess<'_>,
        handle: HandleId,
        data: &[u8],
    ) -> Result<usize, NetworkError> {
        let object = self.authorized_object(access, handle, true)?;
        let record = self
            .sockets
            .get_mut(&object)
            .ok_or(NetworkError::InvalidHandle)?;
        if data.len() > MAX_IO_BYTES
            || (record.info.protocol == Protocol::Udp && data.len() > MAX_DATAGRAM_BYTES)
        {
            return Err(NetworkError::TooLarge);
        }
        if record.info.state != SocketState::Connected {
            return Err(NetworkError::InvalidState);
        }
        match self.provider.send(record.provider_socket, data) {
            Ok(n)
                if n <= data.len()
                    && (record.info.protocol == Protocol::Tcp || n == data.len()) =>
            {
                record.info.bytes_sent = record.info.bytes_sent.saturating_add(n as u64);
                Ok(n)
            }
            Ok(_) => {
                record.info.state = SocketState::Failed;
                Err(NetworkError::Io)
            }
            Err(e) => {
                if fatal(&e) {
                    record.info.state = SocketState::Failed;
                }
                Err(e.into())
            }
        }
    }

    pub fn receive(
        &mut self,
        access: &NetworkAccess<'_>,
        handle: HandleId,
        limit: usize,
    ) -> Result<Vec<u8>, NetworkError> {
        let object = self.authorized_object(access, handle, false)?;
        if limit == 0 || limit > MAX_IO_BYTES {
            return Err(NetworkError::TooLarge);
        }
        let record = self
            .sockets
            .get_mut(&object)
            .ok_or(NetworkError::InvalidHandle)?;
        if record.info.state != SocketState::Connected {
            return Err(NetworkError::InvalidState);
        }
        match self.provider.receive(record.provider_socket, limit) {
            Ok(data) if data.len() <= limit => {
                record.info.bytes_received =
                    record.info.bytes_received.saturating_add(data.len() as u64);
                Ok(data)
            }
            Ok(_) => {
                record.info.state = SocketState::Failed;
                Err(NetworkError::Io)
            }
            Err(e) => {
                if fatal(&e) {
                    record.info.state = SocketState::Failed;
                }
                Err(e.into())
            }
        }
    }

    /// Release does not require READ or a still-valid grant: revoked callers
    /// must always be able to relinquish their own resources. The exact
    /// registered process/handle pair is checked, even after a raw handle close.
    pub fn close(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        handle: HandleId,
    ) -> Result<(), NetworkError> {
        let object = self
            .sockets
            .iter()
            .find(|(_, r)| r.process == process && r.handle == handle)
            .map(|(id, _)| *id)
            .ok_or(NetworkError::InvalidHandle)?;
        let record = self
            .sockets
            .get_mut(&object)
            .ok_or(NetworkError::InvalidHandle)?;
        if record.info.state != SocketState::Closed {
            record.info.state = SocketState::Closing;
            match self.provider.close(record.provider_socket) {
                Ok(()) | Err(ProviderError::Closed) => (),
                Err(e) => return Err(e.into()), // retain state for retry; never lose a live provider resource
            }
        }
        self.sockets.remove(&object);
        if let Some(entry) = handles.get_handle(process, handle) {
            if entry.object_id != object || entry.provider_name != NETWORK_PROVIDER {
                return Err(NetworkError::WrongHandle);
            }
            handles
                .close(objects, process, handle)
                .map_err(|_| NetworkError::InvalidHandle)?;
        }
        Ok(())
    }

    pub fn close_process(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
    ) -> Result<(), NetworkError> {
        let owned: Vec<_> = self
            .sockets
            .values()
            .filter(|r| r.process == process)
            .map(|r| r.handle)
            .collect();
        let mut failure = None;
        for handle in owned {
            if let Err(error) = self.close(objects, handles, process, handle) {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    pub fn inspect(
        &self,
        access: &NetworkAccess<'_>,
        handle: HandleId,
    ) -> Result<&SocketInfo, NetworkError> {
        let object = self.authorized_object(access, handle, false)?;
        self.sockets
            .get(&object)
            .map(|s| &s.info)
            .ok_or(NetworkError::InvalidHandle)
    }
}

fn fatal(error: &ProviderError) -> bool {
    !matches!(
        error,
        ProviderError::Timeout | ProviderError::WouldBlock | ProviderError::MessageTooLarge
    )
}

fn socket_for(
    handles: &HandleManager,
    process: ProcessId,
    handle: HandleId,
    write: bool,
) -> Result<ObjectId, NetworkError> {
    let entry = handles
        .get_handle(process, handle)
        .ok_or(NetworkError::InvalidHandle)?;
    if entry.provider_name != NETWORK_PROVIDER {
        return Err(NetworkError::WrongHandle);
    }
    if write && !entry.rights.write {
        return Err(NetworkError::AccessDenied);
    }
    if !write && !entry.rights.read {
        return Err(NetworkError::AccessDenied);
    }
    Ok(entry.object_id)
}

pub fn authorize_outbound(
    _context: &SecurityContext,
    grant: &ApplicationGrant,
    host: &str,
) -> Result<(), NetworkError> {
    // An account's global capabilities are not application grants. Identity
    // is bound at connect and rechecked in authorized_object; the trusted
    // dispatcher supplies the grant and revalidates session proofs.
    grant
        .manifest
        .validate()
        .map_err(|_| NetworkError::AccessDenied)?;
    let host = HostName::parse(host)?;
    if !grant.capability_granted("network.outbound") || !grant.manifest.network.outbound {
        return Err(NetworkError::AccessDenied);
    }
    if grant
        .manifest
        .network
        .domains
        .iter()
        .any(|rule| domain_matches(host.as_str(), rule))
    {
        Ok(())
    } else {
        Err(NetworkError::DeniedByPolicy)
    }
}

/// Service workers use the exact already-validated service declaration rather
/// than inventing a second socket policy at launch time.
pub fn authorize_service_outbound(
    context: &SecurityContext,
    grant: &ApplicationGrant,
    service: &ServiceDefinition,
    host: &str,
) -> Result<(), NetworkError> {
    if context.user_id != service.identity.user_id || context.group_id != service.identity.group_id
    {
        return Err(NetworkError::AccessDenied);
    }
    service
        .validate_against(grant)
        .map_err(|_| NetworkError::AccessDenied)?;
    if !service.socket_policy.outbound
        || service.socket_policy.domains != grant.manifest.network.domains
    {
        return Err(NetworkError::DeniedByPolicy);
    }
    authorize_outbound(context, grant, host)
}
fn domain_matches(host: &str, rule: &str) -> bool {
    let Ok(rule) = HostName::parse(rule) else {
        return false;
    };
    host == rule.as_str()
        || host
            .strip_suffix(rule.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_core::{GroupId, UserId};
    use hyber_manifest::{
        ApplicationId, CapabilityName, ExecutionMode, GrantPolicy, Manifest, NetworkPolicy,
        ResourceQuotas, Runtime, StorageScopes,
    };
    use std::collections::BTreeSet;
    #[derive(Default)]
    struct Fake {
        next: u64,
        calls: usize,
        closed: usize,
        send_error: Option<ProviderError>,
        close_error: Option<ProviderError>,
        connect_error: Option<ProviderError>,
    }
    impl NetworkProvider for Fake {
        fn interfaces(&mut self) -> Result<Vec<InterfaceInfo>, ProviderError> {
            Ok(vec![InterfaceInfo {
                name: "host0".into(),
                active: true,
                provider: "fake".into(),
            }])
        }
        fn connect(
            &mut self,
            _: Protocol,
            _: &Endpoint,
        ) -> Result<ProviderSocketId, ProviderError> {
            self.calls += 1;
            if let Some(error) = self.connect_error.take() {
                return Err(error);
            }
            self.next += 1;
            Ok(ProviderSocketId(self.next))
        }
        fn send(&mut self, _: ProviderSocketId, d: &[u8]) -> Result<usize, ProviderError> {
            if let Some(error) = self.send_error.take() {
                return Err(error);
            }
            Ok(d.len())
        }
        fn receive(&mut self, _: ProviderSocketId, _: usize) -> Result<Vec<u8>, ProviderError> {
            Ok(b"ok".to_vec())
        }
        fn close(&mut self, _: ProviderSocketId) -> Result<(), ProviderError> {
            if let Some(error) = self.close_error.take() {
                return Err(error);
            }
            self.closed += 1;
            Ok(())
        }
    }
    fn grant() -> ApplicationGrant {
        let manifest = Manifest {
            format_version: 1,
            app_id: ApplicationId("net.test".into()),
            version: "1.0.0".into(),
            publisher: "hyber".into(),
            display_name: "Net".into(),
            entrypoint: "main.lua".into(),
            runtime: Runtime::Lua,
            requested_capabilities: BTreeSet::from([CapabilityName("network.outbound".into())]),
            storage: StorageScopes::default(),
            execution: ExecutionMode::Background,
            network: NetworkPolicy {
                outbound: true,
                inbound: false,
                domains: BTreeSet::from(["example.test".into()]),
            },
            resources: ResourceQuotas {
                memory_bytes: 1,
                cpu_shares: 1,
                handles: 1,
                storage_bytes: 1,
            },
        };
        GrantPolicy {
            capabilities: BTreeSet::from([CapabilityName("network.outbound".into())]),
            allow_gui: false,
            allow_background: true,
            allow_service: false,
            max_resources: manifest.resources,
        }
        .approve(manifest)
        .unwrap()
    }
    #[test]
    fn policy_denial_never_calls_provider() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let c = SecurityContext {
            user_id: UserId(7),
            group_id: GroupId(7),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        assert_eq!(
            n.connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &grant(),
                Protocol::Tcp,
                "denied.test",
                443
            )
            .unwrap_err(),
            NetworkError::DeniedByPolicy
        );
        assert_eq!(n.provider_mut().calls, 0);
    }
    #[test]
    fn refused_connect_and_invalid_port_leave_no_handle_or_socket() {
        let mut network = NetworkManager::new(Fake {
            connect_error: Some(ProviderError::Refused),
            ..Fake::default()
        });
        let mut objects = ObjectManager::new();
        let mut handles = HandleManager::new();
        let context = SecurityContext::root();
        let grant = grant();
        assert_eq!(
            network.connect(
                &mut objects,
                &mut handles,
                ProcessId(1),
                &context,
                &grant,
                Protocol::Tcp,
                "example.test",
                0
            ),
            Err(NetworkError::InvalidDestination)
        );
        assert_eq!(network.provider_mut().calls, 0);
        assert_eq!(
            network.connect(
                &mut objects,
                &mut handles,
                ProcessId(1),
                &context,
                &grant,
                Protocol::Tcp,
                "example.test",
                80
            ),
            Err(NetworkError::Refused)
        );
        assert!(handles.list_handles(ProcessId(1)).is_empty());
        assert!(network.diagnostics(&context).unwrap().is_empty());
        assert!(objects.lookup(ObjectId(1)).is_none());
    }
    #[test]
    fn wait_checks_bounds_and_closed_handles_before_provider() {
        let mut network = NetworkManager::new(Fake::default());
        let mut objects = ObjectManager::new();
        let mut handles = HandleManager::new();
        let context = SecurityContext::root();
        let grant = grant();
        let process = ProcessId(1);
        let handle = network
            .connect(
                &mut objects,
                &mut handles,
                process,
                &context,
                &grant,
                Protocol::Tcp,
                "example.test",
                80,
            )
            .unwrap();
        let access = NetworkAccess {
            objects: &objects,
            handles: &handles,
            process,
            context: &context,
            grant: &grant,
        };
        assert_eq!(
            network.wait(&access, handle, WaitInterest::Readable, 30_001),
            Err(NetworkError::TooLarge)
        );
        assert_eq!(
            network.wait(&access, handle, WaitInterest::Readable, 0),
            Err(NetworkError::Unsupported)
        );
        network
            .close(&mut objects, &mut handles, process, handle)
            .unwrap();
        let access = NetworkAccess {
            objects: &objects,
            handles: &handles,
            process,
            context: &context,
            grant: &grant,
        };
        assert_eq!(
            network.wait(&access, handle, WaitInterest::Readable, 0),
            Err(NetworkError::InvalidHandle)
        );
    }
    #[test]
    fn cancellation_is_idempotent_and_cleanup_closes_transport_once() {
        let mut network = NetworkManager::new(Fake::default());
        let mut objects = ObjectManager::new();
        let mut handles = HandleManager::new();
        let context = SecurityContext::root();
        let grant = grant();
        let process = ProcessId(1);
        let handle = network
            .connect(
                &mut objects,
                &mut handles,
                process,
                &context,
                &grant,
                Protocol::Tcp,
                "example.test",
                80,
            )
            .unwrap();
        let access = NetworkAccess {
            objects: &objects,
            handles: &handles,
            process,
            context: &context,
            grant: &grant,
        };
        assert_eq!(
            network.wait(&access, handle, WaitInterest::Writable, 0),
            Err(NetworkError::Unsupported)
        );
        handles
            .get_handle_mut(process, handle)
            .unwrap()
            .rights
            .signal = false;
        handles.get_handle_mut(process, handle).unwrap().rights.wait = false;
        let access = NetworkAccess {
            objects: &objects,
            handles: &handles,
            process,
            context: &context,
            grant: &grant,
        };
        assert_eq!(
            network.cancel(&access, handle),
            Err(NetworkError::AccessDenied)
        );
        assert_eq!(
            network.wait(&access, handle, WaitInterest::Writable, 0),
            Err(NetworkError::AccessDenied)
        );
        handles
            .get_handle_mut(process, handle)
            .unwrap()
            .rights
            .signal = true;
        let access = NetworkAccess {
            objects: &objects,
            handles: &handles,
            process,
            context: &context,
            grant: &grant,
        };
        network.cancel(&access, handle).unwrap();
        network.cancel(&access, handle).unwrap();
        assert_eq!(
            network.inspect(&access, handle).unwrap().state,
            SocketState::Closed
        );
        assert_eq!(
            network.send(&access, handle, b"x"),
            Err(NetworkError::InvalidState)
        );
        let mut unprivileged = context.clone();
        unprivileged.user_id = UserId(7);
        unprivileged.capabilities.clear();
        assert_eq!(
            network.diagnostics(&unprivileged),
            Err(NetworkError::AccessDenied)
        );
        assert_eq!(network.diagnostics(&context).unwrap().len(), 1);
        network
            .close(&mut objects, &mut handles, process, handle)
            .unwrap();
        assert_eq!(network.provider_mut().closed, 1);
        assert!(network.diagnostics(&context).unwrap().is_empty());
    }
    #[test]
    fn socket_is_handle_backed_and_closes_once() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let c = SecurityContext::root();
        let id = n
            .connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &grant(),
                Protocol::Tcp,
                "api.example.test",
                443,
            )
            .unwrap();
        let g = grant();
        let access = NetworkAccess {
            objects: &o,
            handles: &h,
            process: ProcessId(1),
            context: &c,
            grant: &g,
        };
        assert_eq!(n.send(&access, id, b"x").unwrap(), 1);
        assert_eq!(n.receive(&access, id, 2).unwrap(), b"ok");
        n.close(&mut o, &mut h, ProcessId(1), id).unwrap();
        assert_eq!(n.provider_mut().closed, 1);
        assert!(h.get_handle(ProcessId(1), id).is_none());
    }
    #[test]
    fn numeric_and_suffix_bypass_are_rejected() {
        assert!(HostName::parse("127.0.0.1").is_err());
        for host in [
            "127.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "::1",
            "evil..test",
            "x.test.",
        ] {
            assert!(HostName::parse(host).is_err(), "{host}");
        }
        assert!(!domain_matches("evil-example.test", "example.test"));
    }

    #[test]
    fn process_cleanup_closes_each_provider_socket() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let c = SecurityContext::root();
        let _ = n
            .connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &grant(),
                Protocol::Tcp,
                "api.example.test",
                443,
            )
            .unwrap();
        n.close_process(&mut o, &mut h, ProcessId(1)).unwrap();
        assert_eq!(n.provider_mut().closed, 1);
        assert!(h.handles_for_process(ProcessId(1)).is_empty());
    }

    #[test]
    fn current_identity_permissions_and_grant_are_rechecked() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let c = SecurityContext {
            user_id: UserId(7),
            group_id: GroupId(7),
            supplementary_groups: vec![],
            capabilities: vec![],
        };
        let g = grant();
        let id = n
            .connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &g,
                Protocol::Tcp,
                "api.example.test",
                80,
            )
            .unwrap();
        let object = h.get_handle(ProcessId(1), id).unwrap().object_id;
        let foreign = SecurityContext::root();
        let access = NetworkAccess {
            objects: &o,
            handles: &h,
            process: ProcessId(1),
            context: &foreign,
            grant: &g,
        };
        assert_eq!(n.send(&access, id, b"x"), Err(NetworkError::AccessDenied));
        o.chmod(object, &c, 0o400).unwrap();
        let access = NetworkAccess {
            objects: &o,
            handles: &h,
            process: ProcessId(1),
            context: &c,
            grant: &g,
        };
        assert_eq!(n.send(&access, id, b"x"), Err(NetworkError::AccessDenied));
        let mut tampered = g.clone();
        tampered
            .manifest
            .network
            .domains
            .insert("other.test".into());
        let access = NetworkAccess {
            objects: &o,
            handles: &h,
            process: ProcessId(1),
            context: &c,
            grant: &tampered,
        };
        assert_eq!(n.receive(&access, id, 2), Err(NetworkError::AccessDenied));
        h.revoke_rights(object, Rights::all());
        n.close(&mut o, &mut h, ProcessId(1), id).unwrap();
        assert!(o.lookup(object).is_none());
    }

    #[test]
    fn raw_close_and_failed_provider_close_remain_reclaimable() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let id = n
            .connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &SecurityContext::root(),
                &grant(),
                Protocol::Tcp,
                "example.test",
                80,
            )
            .unwrap();
        h.close(&mut o, ProcessId(1), id).unwrap();
        n.provider_mut().close_error = Some(ProviderError::Io);
        assert_eq!(
            n.close_process(&mut o, &mut h, ProcessId(1)),
            Err(NetworkError::Io)
        );
        n.close_process(&mut o, &mut h, ProcessId(1)).unwrap();
        assert_eq!(n.provider_mut().closed, 1);
        assert!(n.sockets.is_empty());
    }

    #[test]
    fn quota_precedes_io_and_transient_failure_does_not_poison_socket() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let c = SecurityContext::root();
        let g = grant();
        let id = n
            .connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &g,
                Protocol::Tcp,
                "example.test",
                80,
            )
            .unwrap();
        assert_eq!(
            n.connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &g,
                Protocol::Tcp,
                "example.test",
                80
            ),
            Err(NetworkError::Capacity)
        );
        assert_eq!(n.provider_mut().calls, 1);
        n.provider_mut().send_error = Some(ProviderError::Timeout);
        let access = NetworkAccess {
            objects: &o,
            handles: &h,
            process: ProcessId(1),
            context: &c,
            grant: &g,
        };
        assert_eq!(n.send(&access, id, b"x"), Err(NetworkError::Timeout));
        assert_eq!(n.send(&access, id, b"x"), Ok(1));
    }

    #[test]
    fn copied_handle_is_not_an_authorized_endpoint() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let c = SecurityContext::root();
        let g = grant();
        let id = n
            .connect(
                &mut o,
                &mut h,
                ProcessId(1),
                &c,
                &g,
                Protocol::Tcp,
                "example.test",
                80,
            )
            .unwrap();
        let object = h.get_handle(ProcessId(1), id).unwrap().object_id;
        let alias = h
            .open(
                &mut o,
                ProcessId(2),
                object,
                Rights::all(),
                NETWORK_PROVIDER.into(),
            )
            .unwrap();
        let access = NetworkAccess {
            objects: &o,
            handles: &h,
            process: ProcessId(2),
            context: &c,
            grant: &g,
        };
        assert_eq!(
            n.send(&access, alias, b"x"),
            Err(NetworkError::AccessDenied)
        );
        n.close_process(&mut o, &mut h, ProcessId(1)).unwrap();
        h.close(&mut o, ProcessId(2), alias).unwrap();
        assert!(o.lookup(object).is_none());
    }

    #[test]
    fn interface_objects_are_stable_private_and_released() {
        let mut n = NetworkManager::new(Fake::default());
        let mut o = ObjectManager::new();
        let mut h = HandleManager::new();
        let entries = n
            .interface_objects(&mut o, &SecurityContext::root())
            .unwrap();
        let id = entries[0].0;
        assert_eq!(o.lookup(id).unwrap().object_type, ObjectType::Device);
        assert_eq!(o.lookup(id).unwrap().permissions, 0o600);
        assert_eq!(
            n.interface_objects(&mut o, &SecurityContext::root())
                .unwrap()[0]
                .0,
            id
        );
        n.shutdown(&mut o, &mut h).unwrap();
        assert!(o.lookup(id).is_none());
    }
}
