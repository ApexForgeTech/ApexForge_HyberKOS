//! Phase 19 hosted Object/Handle IPC.
//!
//! This crate deliberately contains no host descriptors, paths, threads or
//! sockets. Queues are volatile objects; access always goes through a Hyber
//! process-local HandleId and current security metadata.

#![allow(
    clippy::too_many_arguments,
    reason = "IPC entry points deliberately make every authority boundary explicit: object registry, handle registry, caller process, caller context, endpoint, and peer context."
)]

use hyber_core::{
    HandleId, ObjectId, ObjectState, ObjectType, ProcessId, Rights, SecurityContext,
    SecurityManager,
};
use hyber_handle::{HandleFlags, HandleManager};
use hyber_object::{Object, ObjectManager};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub const MAX_QUEUE_BYTES: usize = 64 * 1024;
pub const MAX_QUEUE_MESSAGES: usize = 1024;
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;
pub const MAX_PIPE_WRITE_BYTES: usize = 4 * 1024;
pub const MAX_ATTACHMENTS: usize = 8;
pub const MAX_ENDPOINTS_PER_OBJECT: usize = 32;
pub const MAX_PENDING_REQUESTS: usize = 1024;
pub const IPC_PROVIDER: &str = "ipc";
/// Version of the in-memory channel record. It is explicit so an eventual
/// cross-process transport cannot accidentally treat an incompatible record as
/// a current message.
pub const IPC_MESSAGE_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSide {
    Reader,
    Writer,
    A,
    B,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Data,
    RpcRequest,
    RpcResponse,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcAttachment {
    pub object_id: ObjectId,
    pub handle_id: HandleId,
    pub rights: Rights,
    pub provider_name: String,
    receiver: ProcessId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcMessage {
    pub version: u16,
    pub kind: MessageKind,
    pub request_id: u64,
    pub sender: ProcessId,
    pub payload: Vec<u8>,
    pub attachments: Vec<IpcAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveResult {
    Message(IpcMessage),
    Empty,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    InvalidHandle,
    WrongKind,
    WrongEndpoint,
    AccessDenied,
    PeerClosed,
    WouldBlock,
    MessageTooLarge,
    InvalidMessage,
    InvalidRequest,
    EndpointLimit,
    ObjectGone,
    Overflow,
}
impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidHandle => "invalid IPC handle",
            Self::WrongKind => "handle is not an IPC endpoint",
            Self::WrongEndpoint => "operation is invalid for this endpoint",
            Self::AccessDenied => "IPC access denied",
            Self::PeerClosed => "IPC peer is closed",
            Self::WouldBlock => "IPC queue is full",
            Self::MessageTooLarge => "IPC message exceeds the bound",
            Self::InvalidMessage => "invalid IPC message",
            Self::InvalidRequest => "invalid IPC request",
            Self::EndpointLimit => "IPC endpoint limit reached",
            Self::ObjectGone => "IPC object is no longer live",
            Self::Overflow => "IPC identifier or size overflow",
        };
        f.write_str(message)
    }
}
impl std::error::Error for IpcError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeEndpoints {
    pub reader: HandleId,
    pub writer: HandleId,
    pub object_id: ObjectId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelEndpoints {
    pub a: HandleId,
    pub b: HandleId,
    pub object_id: ObjectId,
}

#[derive(Debug, Clone)]
struct Binding {
    object: ObjectId,
    side: EndpointSide,
}
#[derive(Debug, Default)]
struct Queue {
    bytes: usize,
    messages: VecDeque<IpcMessage>,
}
#[derive(Debug)]
struct Pipe {
    queue: VecDeque<u8>,
    readers: usize,
    writers: usize,
}
#[derive(Debug)]
struct Channel {
    a_in: Queue,
    b_in: Queue,
    a_open: usize,
    b_open: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RpcKey {
    object: ObjectId,
    side: EndpointSideKey,
    process: ProcessId,
    request: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EndpointSideKey {
    A,
    B,
}
impl EndpointSideKey {
    fn of(side: EndpointSide) -> Result<Self, IpcError> {
        match side {
            EndpointSide::A => Ok(Self::A),
            EndpointSide::B => Ok(Self::B),
            _ => Err(IpcError::WrongKind),
        }
    }
}

/// Volatile registry. Its base Object reference is released only after every
/// IPC endpoint has closed. The manager itself never exposes host resources.
#[derive(Debug, Default)]
pub struct IpcManager {
    pipes: BTreeMap<ObjectId, Pipe>,
    channels: BTreeMap<ObjectId, Channel>,
    bindings: BTreeMap<(ProcessId, HandleId), Binding>,
    next_request: BTreeMap<(ObjectId, EndpointSideKey, ProcessId), u64>,
    client_pending: BTreeSet<RpcKey>,
    server_pending: BTreeSet<RpcKey>,
}

impl IpcManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_pipe(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        owner: &SecurityContext,
        reader: (ProcessId, &SecurityContext),
        writer: (ProcessId, &SecurityContext),
    ) -> Result<PipeEndpoints, IpcError> {
        let object = self.create_object(objects, owner, ObjectType::Pipe);
        self.pipes.insert(
            object,
            Pipe {
                queue: VecDeque::new(),
                readers: 0,
                writers: 0,
            },
        );
        let reader_handle = match self.open_endpoint(
            objects,
            handles,
            reader.0,
            reader.1,
            object,
            EndpointSide::Reader,
            Rights {
                read: true,
                signal: true,
                ..Rights::empty()
            },
        ) {
            Ok(handle) => handle,
            Err(error) => {
                self.pipes.remove(&object);
                objects.release(object);
                objects.destroy(object);
                return Err(error);
            }
        };
        let writer_handle = match self.open_endpoint(
            objects,
            handles,
            writer.0,
            writer.1,
            object,
            EndpointSide::Writer,
            Rights {
                write: true,
                signal: true,
                ..Rights::empty()
            },
        ) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = self.close(objects, handles, reader.0, reader_handle);
                return Err(error);
            }
        };
        let pipe = self.pipes.get_mut(&object).expect("new pipe exists");
        pipe.readers = 1;
        pipe.writers = 1;
        Ok(PipeEndpoints {
            reader: reader_handle,
            writer: writer_handle,
            object_id: object,
        })
    }

    pub fn create_channel(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        owner: &SecurityContext,
        a: (ProcessId, &SecurityContext),
        b: (ProcessId, &SecurityContext),
    ) -> Result<ChannelEndpoints, IpcError> {
        let object = self.create_object(objects, owner, ObjectType::Channel);
        self.channels.insert(
            object,
            Channel {
                a_in: Queue::default(),
                b_in: Queue::default(),
                a_open: 0,
                b_open: 0,
            },
        );
        let rights = Rights {
            read: true,
            write: true,
            signal: true,
            ..Rights::empty()
        };
        let a_handle =
            match self.open_endpoint(objects, handles, a.0, a.1, object, EndpointSide::A, rights) {
                Ok(handle) => handle,
                Err(error) => {
                    self.channels.remove(&object);
                    objects.release(object);
                    objects.destroy(object);
                    return Err(error);
                }
            };
        let b_handle =
            match self.open_endpoint(objects, handles, b.0, b.1, object, EndpointSide::B, rights) {
                Ok(handle) => handle,
                Err(error) => {
                    let _ = self.close(objects, handles, a.0, a_handle);
                    return Err(error);
                }
            };
        let channel = self.channels.get_mut(&object).expect("new channel exists");
        channel.a_open = 1;
        channel.b_open = 1;
        Ok(ChannelEndpoints {
            a: a_handle,
            b: b_handle,
            object_id: object,
        })
    }

    pub fn pipe_write(
        &mut self,
        objects: &mut ObjectManager,
        handles: &HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        bytes: &[u8],
    ) -> Result<usize, IpcError> {
        if bytes.len() > MAX_PIPE_WRITE_BYTES {
            return Err(IpcError::MessageTooLarge);
        }
        let binding = self.authorize(objects, handles, process, context, handle, true, false)?;
        if binding.side != EndpointSide::Writer {
            return Err(IpcError::WrongEndpoint);
        }
        let pipe = self
            .pipes
            .get_mut(&binding.object)
            .ok_or(IpcError::ObjectGone)?;
        if pipe.readers == 0 {
            return Err(IpcError::PeerClosed);
        }
        if pipe
            .queue
            .len()
            .checked_add(bytes.len())
            .ok_or(IpcError::Overflow)?
            > MAX_QUEUE_BYTES
        {
            return Err(IpcError::WouldBlock);
        }
        pipe.queue.extend(bytes);
        touch(objects, binding.object);
        Ok(bytes.len())
    }

    pub fn pipe_read(
        &mut self,
        objects: &mut ObjectManager,
        handles: &HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        limit: usize,
    ) -> Result<ReceiveResult, IpcError> {
        if limit == 0 {
            return Err(IpcError::InvalidMessage);
        }
        let binding = self.authorize(objects, handles, process, context, handle, false, true)?;
        if binding.side != EndpointSide::Reader {
            return Err(IpcError::WrongEndpoint);
        }
        let pipe = self
            .pipes
            .get_mut(&binding.object)
            .ok_or(IpcError::ObjectGone)?;
        if pipe.queue.is_empty() {
            return Ok(if pipe.writers == 0 {
                ReceiveResult::Eof
            } else {
                ReceiveResult::Empty
            });
        }
        let take = limit.min(pipe.queue.len());
        let payload: Vec<_> = pipe.queue.drain(..take).collect();
        touch(objects, binding.object);
        Ok(ReceiveResult::Message(IpcMessage {
            version: IPC_MESSAGE_VERSION,
            kind: MessageKind::Data,
            request_id: 0,
            sender: process,
            payload,
            attachments: vec![],
        }))
    }

    pub fn channel_send(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        kind: MessageKind,
        request_id: u64,
        payload: Vec<u8>,
        attachments: &[(HandleId, Rights)],
        receiver: (ProcessId, &SecurityContext),
    ) -> Result<(), IpcError> {
        validate_message(kind, request_id, &payload, attachments)?;
        let binding = self.authorize(objects, handles, process, context, handle, true, false)?;
        let side = EndpointSideKey::of(binding.side)?;
        let target = match side {
            EndpointSideKey::A => EndpointSideKey::B,
            EndpointSideKey::B => EndpointSideKey::A,
        };
        self.ensure_channel_peer(binding.object, target)?;
        let cost = payload.len();
        let receiver_rights = receiver.1;
        // Preflight before allocating any receiver handles, preserving queue atomicity.
        self.ensure_queue_space(binding.object, target, cost)?;
        let mut copied = Vec::with_capacity(attachments.len());
        for (source_handle, rights) in attachments {
            match self.duplicate_attachment(
                objects,
                handles,
                process,
                context,
                *source_handle,
                *rights,
                receiver.0,
                receiver_rights,
            ) {
                Ok(attachment) => copied.push(attachment),
                Err(error) => {
                    for attachment in copied {
                        let _ = handles.close(objects, receiver.0, attachment.handle_id);
                    }
                    return Err(error);
                }
            }
        }
        let message = IpcMessage {
            version: IPC_MESSAGE_VERSION,
            kind,
            request_id,
            sender: process,
            payload,
            attachments: copied,
        };
        self.queue_mut(binding.object, target)?
            .messages
            .push_back(message);
        self.queue_mut(binding.object, target)?.bytes += cost;
        touch(objects, binding.object);
        Ok(())
    }

    pub fn channel_receive(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
    ) -> Result<ReceiveResult, IpcError> {
        let binding = self.authorize(objects, handles, process, context, handle, false, true)?;
        let side = EndpointSideKey::of(binding.side)?;
        let peer = match side {
            EndpointSideKey::A => EndpointSideKey::B,
            EndpointSideKey::B => EndpointSideKey::A,
        };
        let message = match self.queue_mut(binding.object, side)?.messages.front() {
            Some(message) => message.clone(),
            None => {
                return Ok(if self.is_side_closed(binding.object, peer)? {
                    ReceiveResult::Eof
                } else {
                    ReceiveResult::Empty
                })
            }
        };
        let key = RpcKey {
            object: binding.object,
            side,
            process,
            request: message.request_id,
        };
        match message.kind {
            MessageKind::RpcRequest => {
                self.server_pending.insert(key);
            }
            MessageKind::RpcResponse => {
                if !self.client_pending.remove(&key) {
                    return Err(IpcError::InvalidRequest);
                }
            }
            MessageKind::Cancel => {
                self.server_pending.remove(&key);
            }
            MessageKind::Data => {}
        }
        let queue = self.queue_mut(binding.object, side)?;
        let message = queue.messages.pop_front().expect("checked IPC queue front");
        queue.bytes -= message.payload.len();
        touch(objects, binding.object);
        Ok(ReceiveResult::Message(message))
    }

    pub fn rpc_request(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        payload: Vec<u8>,
        receiver: (ProcessId, &SecurityContext),
    ) -> Result<u64, IpcError> {
        let binding = self.authorize(objects, handles, process, context, handle, true, false)?;
        let side = EndpointSideKey::of(binding.side)?;
        if self
            .client_pending
            .iter()
            .filter(|key| {
                key.object == binding.object && key.side == side && key.process == process
            })
            .count()
            >= MAX_PENDING_REQUESTS
        {
            return Err(IpcError::WouldBlock);
        }
        let next = self
            .next_request
            .entry((binding.object, side, process))
            .or_insert(1);
        let request = *next;
        *next = next.checked_add(1).ok_or(IpcError::Overflow)?;
        if request == 0 {
            return Err(IpcError::Overflow);
        }
        self.channel_send(
            objects,
            handles,
            process,
            context,
            handle,
            MessageKind::RpcRequest,
            request,
            payload,
            &[],
            receiver,
        )?;
        self.client_pending.insert(RpcKey {
            object: binding.object,
            side,
            process,
            request,
        });
        Ok(request)
    }

    pub fn rpc_respond(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        request: u64,
        payload: Vec<u8>,
        receiver: (ProcessId, &SecurityContext),
    ) -> Result<(), IpcError> {
        let binding = self.authorize(objects, handles, process, context, handle, true, false)?;
        let side = EndpointSideKey::of(binding.side)?;
        let key = RpcKey {
            object: binding.object,
            side,
            process,
            request,
        };
        if request == 0 || !self.server_pending.contains(&key) {
            return Err(IpcError::InvalidRequest);
        }
        self.channel_send(
            objects,
            handles,
            process,
            context,
            handle,
            MessageKind::RpcResponse,
            request,
            payload,
            &[],
            receiver,
        )?;
        self.server_pending.remove(&key);
        Ok(())
    }

    pub fn rpc_cancel(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        request: u64,
        receiver: (ProcessId, &SecurityContext),
    ) -> Result<(), IpcError> {
        let binding = self.authorize(objects, handles, process, context, handle, true, false)?;
        if !handles
            .get_handle(process, handle)
            .is_some_and(|entry| entry.rights.signal)
        {
            return Err(IpcError::AccessDenied);
        }
        authorize_object(
            objects.lookup(binding.object).ok_or(IpcError::ObjectGone)?,
            context,
            Rights {
                signal: true,
                ..Rights::empty()
            },
        )?;
        let side = EndpointSideKey::of(binding.side)?;
        let key = RpcKey {
            object: binding.object,
            side,
            process,
            request,
        };
        if request == 0 || !self.client_pending.contains(&key) {
            return Err(IpcError::InvalidRequest);
        }
        self.channel_send(
            objects,
            handles,
            process,
            context,
            handle,
            MessageKind::Cancel,
            request,
            vec![],
            &[],
            receiver,
        )?;
        self.client_pending.remove(&key);
        Ok(())
    }

    /// Receive exactly the next response for a live client request. FIFO is
    /// preserved: an unrelated front message is left queued rather than being
    /// consumed by a convenience API for a different request.
    pub fn rpc_receive_response(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        request: u64,
    ) -> Result<ReceiveResult, IpcError> {
        let binding = self.authorize(objects, handles, process, context, handle, false, true)?;
        let side = EndpointSideKey::of(binding.side)?;
        let key = RpcKey {
            object: binding.object,
            side,
            process,
            request,
        };
        if request == 0 || !self.client_pending.contains(&key) {
            return Err(IpcError::InvalidRequest);
        }
        let peer = match side {
            EndpointSideKey::A => EndpointSideKey::B,
            EndpointSideKey::B => EndpointSideKey::A,
        };
        let front = match self.queue_mut(binding.object, side)?.messages.front() {
            Some(message) => message.clone(),
            None => {
                return Ok(if self.is_side_closed(binding.object, peer)? {
                    ReceiveResult::Eof
                } else {
                    ReceiveResult::Empty
                });
            }
        };
        if front.kind != MessageKind::RpcResponse || front.request_id != request {
            return Err(IpcError::InvalidRequest);
        }
        let queue = self.queue_mut(binding.object, side)?;
        let message = queue.messages.pop_front().expect("checked IPC queue front");
        queue.bytes -= message.payload.len();
        self.client_pending.remove(&key);
        touch(objects, binding.object);
        Ok(ReceiveResult::Message(message))
    }

    pub fn close(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        handle: HandleId,
    ) -> Result<(), IpcError> {
        let binding = self
            .bindings
            .remove(&(process, handle))
            .ok_or(IpcError::InvalidHandle)?;
        // A legacy caller may already have closed the raw HandleManager entry.
        // The IPC binding still owns endpoint accounting, so reconcile it
        // rather than leaving an object permanently live. A second IPC close
        // remains invalid because the binding was removed above.
        let _ = handles.close(objects, process, handle);
        match binding.side {
            EndpointSide::Reader => {
                if let Some(pipe) = self.pipes.get_mut(&binding.object) {
                    pipe.readers = pipe.readers.saturating_sub(1);
                }
            }
            EndpointSide::Writer => {
                if let Some(pipe) = self.pipes.get_mut(&binding.object) {
                    pipe.writers = pipe.writers.saturating_sub(1);
                }
            }
            EndpointSide::A => {
                if let Some(channel) = self.channels.get_mut(&binding.object) {
                    channel.a_open = channel.a_open.saturating_sub(1);
                }
            }
            EndpointSide::B => {
                if let Some(channel) = self.channels.get_mut(&binding.object) {
                    channel.b_open = channel.b_open.saturating_sub(1);
                }
            }
        }
        self.client_pending
            .retain(|key| !(key.object == binding.object && key.process == process));
        self.server_pending
            .retain(|key| !(key.object == binding.object && key.process == process));
        self.cleanup_if_closed(objects, handles, binding.object);
        Ok(())
    }

    /// Capability-checked endpoint closure for ordinary callers. `close` is
    /// retained for trusted process-exit cleanup and legacy reconciliation.
    pub fn close_authorized(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
    ) -> Result<(), IpcError> {
        let binding = self.authorize(objects, handles, process, context, handle, false, false)?;
        if !handles
            .get_handle(process, handle)
            .is_some_and(|entry| entry.rights.signal)
        {
            return Err(IpcError::AccessDenied);
        }
        authorize_object(
            objects.lookup(binding.object).ok_or(IpcError::ObjectGone)?,
            context,
            Rights {
                signal: true,
                ..Rights::empty()
            },
        )?;
        // `authorize` confirmed the binding is live; the trusted bookkeeping
        // path below releases the exact same endpoint once.
        let _ = binding;
        self.close(objects, handles, process, handle)
    }

    pub fn close_process(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
    ) {
        let ids: Vec<_> = self
            .bindings
            .keys()
            .filter_map(|(owner, handle)| (*owner == process).then_some(*handle))
            .collect();
        for handle in ids {
            let _ = self.close(objects, handles, process, handle);
        }
    }

    pub fn inspect(&self, process: ProcessId, handle: HandleId) -> Result<IpcInspection, IpcError> {
        let binding = self
            .bindings
            .get(&(process, handle))
            .ok_or(IpcError::InvalidHandle)?;
        let (queued_bytes, queued_messages, peer_closed) = match binding.side {
            EndpointSide::Reader => {
                let pipe = self
                    .pipes
                    .get(&binding.object)
                    .ok_or(IpcError::ObjectGone)?;
                (pipe.queue.len(), 0, pipe.writers == 0)
            }
            EndpointSide::Writer => {
                let pipe = self
                    .pipes
                    .get(&binding.object)
                    .ok_or(IpcError::ObjectGone)?;
                (pipe.queue.len(), 0, pipe.readers == 0)
            }
            EndpointSide::A => {
                let c = self
                    .channels
                    .get(&binding.object)
                    .ok_or(IpcError::ObjectGone)?;
                (c.a_in.bytes, c.a_in.messages.len(), c.b_open == 0)
            }
            EndpointSide::B => {
                let c = self
                    .channels
                    .get(&binding.object)
                    .ok_or(IpcError::ObjectGone)?;
                (c.b_in.bytes, c.b_in.messages.len(), c.a_open == 0)
            }
        };
        Ok(IpcInspection {
            object_id: binding.object,
            side: binding.side,
            queued_bytes,
            queued_messages,
            peer_closed,
        })
    }

    fn create_object(
        &self,
        objects: &mut ObjectManager,
        owner: &SecurityContext,
        kind: ObjectType,
    ) -> ObjectId {
        let object = objects.create_object(kind);
        let metadata = objects.lookup_mut(object).expect("new IPC object exists");
        metadata.owner = owner.user_id;
        metadata.group = owner.group_id;
        metadata.permissions = 0o600;
        object
    }
    fn open_endpoint(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        object: ObjectId,
        side: EndpointSide,
        rights: Rights,
    ) -> Result<HandleId, IpcError> {
        if self
            .bindings
            .values()
            .filter(|binding| binding.object == object)
            .count()
            >= MAX_ENDPOINTS_PER_OBJECT
        {
            return Err(IpcError::EndpointLimit);
        }
        // Endpoint construction is an owner/trusted-manager operation. A
        // latent SIGNAL bit may be placed on the resulting handle, but using
        // it later still requires CAP_OBJECT_SIGNAL (checked by close/cancel).
        let metadata_rights = Rights {
            signal: false,
            wait: false,
            ..rights
        };
        authorize_object(
            objects.lookup(object).ok_or(IpcError::ObjectGone)?,
            context,
            metadata_rights,
        )?;
        let handle = handles
            .open_with_flags(
                objects,
                process,
                object,
                rights,
                IPC_PROVIDER.into(),
                HandleFlags::not_inheritable(),
            )
            .map_err(|_| IpcError::ObjectGone)?;
        self.bindings
            .insert((process, handle), Binding { object, side });
        Ok(handle)
    }
    fn authorize(
        &self,
        objects: &ObjectManager,
        handles: &HandleManager,
        process: ProcessId,
        context: &SecurityContext,
        handle: HandleId,
        write: bool,
        read: bool,
    ) -> Result<Binding, IpcError> {
        let binding = self
            .bindings
            .get(&(process, handle))
            .ok_or(IpcError::InvalidHandle)?
            .clone();
        let current = handles
            .get_handle(process, handle)
            .ok_or(IpcError::InvalidHandle)?;
        if current.object_id != binding.object || current.provider_name != IPC_PROVIDER {
            return Err(IpcError::WrongKind);
        }
        if (write && !current.rights.write) || (read && !current.rights.read) {
            return Err(IpcError::AccessDenied);
        }
        let object = objects.lookup(binding.object).ok_or(IpcError::ObjectGone)?;
        authorize_object(
            object,
            context,
            if write {
                Rights {
                    write: true,
                    ..Rights::empty()
                }
            } else {
                Rights::read_only()
            },
        )?;
        Ok(binding)
    }
    fn ensure_channel_peer(&self, object: ObjectId, peer: EndpointSideKey) -> Result<(), IpcError> {
        if self.is_side_closed(object, peer)? {
            Err(IpcError::PeerClosed)
        } else {
            Ok(())
        }
    }
    fn is_side_closed(&self, object: ObjectId, side: EndpointSideKey) -> Result<bool, IpcError> {
        let c = self.channels.get(&object).ok_or(IpcError::ObjectGone)?;
        Ok(match side {
            EndpointSideKey::A => c.a_open == 0,
            EndpointSideKey::B => c.b_open == 0,
        })
    }
    fn queue_mut(
        &mut self,
        object: ObjectId,
        side: EndpointSideKey,
    ) -> Result<&mut Queue, IpcError> {
        let c = self.channels.get_mut(&object).ok_or(IpcError::ObjectGone)?;
        Ok(match side {
            EndpointSideKey::A => &mut c.a_in,
            EndpointSideKey::B => &mut c.b_in,
        })
    }
    fn ensure_queue_space(
        &self,
        object: ObjectId,
        side: EndpointSideKey,
        bytes: usize,
    ) -> Result<(), IpcError> {
        let c = self.channels.get(&object).ok_or(IpcError::ObjectGone)?;
        let queue = match side {
            EndpointSideKey::A => &c.a_in,
            EndpointSideKey::B => &c.b_in,
        };
        if queue.messages.len() >= MAX_QUEUE_MESSAGES
            || queue.bytes.checked_add(bytes).ok_or(IpcError::Overflow)? > MAX_QUEUE_BYTES
        {
            Err(IpcError::WouldBlock)
        } else {
            Ok(())
        }
    }
    fn duplicate_attachment(
        &self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        source_process: ProcessId,
        source_context: &SecurityContext,
        source: HandleId,
        rights: Rights,
        receiver: ProcessId,
        receiver_context: &SecurityContext,
    ) -> Result<IpcAttachment, IpcError> {
        let source_handle = handles
            .get_handle(source_process, source)
            .ok_or(IpcError::InvalidHandle)?
            .clone();
        if rights == Rights::empty()
            || source_handle.provider_name == IPC_PROVIDER
            || !subset(rights, source_handle.rights)
        {
            return Err(IpcError::AccessDenied);
        }
        let object = objects
            .lookup(source_handle.object_id)
            .ok_or(IpcError::ObjectGone)?;
        authorize_object(object, source_context, rights)?;
        authorize_object(object, receiver_context, rights)?;
        let handle = handles
            .open_with_flags(
                objects,
                receiver,
                source_handle.object_id,
                rights,
                source_handle.provider_name.clone(),
                HandleFlags::not_inheritable(),
            )
            .map_err(|_| IpcError::ObjectGone)?;
        Ok(IpcAttachment {
            object_id: source_handle.object_id,
            handle_id: handle,
            rights,
            provider_name: source_handle.provider_name,
            receiver,
        })
    }
    fn cleanup_if_closed(
        &mut self,
        objects: &mut ObjectManager,
        handles: &mut HandleManager,
        object: ObjectId,
    ) {
        let empty = self
            .pipes
            .get(&object)
            .is_some_and(|pipe| pipe.readers == 0 && pipe.writers == 0)
            || self
                .channels
                .get(&object)
                .is_some_and(|channel| channel.a_open == 0 && channel.b_open == 0);
        if !empty {
            return;
        }
        if let Some(channel) = self.channels.remove(&object) {
            for message in channel
                .a_in
                .messages
                .into_iter()
                .chain(channel.b_in.messages)
            {
                for attachment in message.attachments {
                    let _ = handles.close(objects, attachment.receiver, attachment.handle_id);
                }
            }
        }
        self.pipes.remove(&object);
        self.next_request.retain(|(id, _, _), _| *id != object);
        self.client_pending.retain(|key| key.object != object);
        self.server_pending.retain(|key| key.object != object);
        objects.release(object);
        objects.destroy(object);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcInspection {
    pub object_id: ObjectId,
    pub side: EndpointSide,
    pub queued_bytes: usize,
    pub queued_messages: usize,
    pub peer_closed: bool,
}

fn validate_message(
    kind: MessageKind,
    request: u64,
    payload: &[u8],
    attachments: &[(HandleId, Rights)],
) -> Result<(), IpcError> {
    if payload.len() > MAX_MESSAGE_BYTES || attachments.len() > MAX_ATTACHMENTS {
        return Err(IpcError::MessageTooLarge);
    }
    if matches!(kind, MessageKind::Data) != (request == 0) {
        return Err(IpcError::InvalidMessage);
    }
    if !matches!(kind, MessageKind::Data) && request == 0 {
        return Err(IpcError::InvalidMessage);
    }
    let mut ids = BTreeSet::new();
    if attachments.iter().any(|(id, _)| !ids.insert(*id)) {
        return Err(IpcError::InvalidMessage);
    }
    Ok(())
}
fn subset(requested: Rights, allowed: Rights) -> bool {
    (!requested.read || allowed.read)
        && (!requested.write || allowed.write)
        && (!requested.execute || allowed.execute)
        && (!requested.delete || allowed.delete)
        && (!requested.rename || allowed.rename)
        && (!requested.enumerate || allowed.enumerate)
        && (!requested.connect || allowed.connect)
        && (!requested.wait || allowed.wait)
        && (!requested.signal || allowed.signal)
}
fn authorize_object(
    object: &Object,
    context: &SecurityContext,
    rights: Rights,
) -> Result<(), IpcError> {
    if object.state != ObjectState::Live || object.references == 0 {
        return Err(IpcError::ObjectGone);
    }
    SecurityManager::check_access(
        context,
        object.owner,
        object.group,
        object.permissions,
        rights,
    )
    .map_err(|_| IpcError::AccessDenied)
}
fn touch(objects: &mut ObjectManager, object: ObjectId) {
    if let Some(o) = objects.lookup_mut(object) {
        o.modified_at = o.modified_at.saturating_add(1).max(o.created_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_core::{GroupId, UserId};

    fn context(id: u32) -> SecurityContext {
        SecurityContext {
            user_id: UserId(id),
            group_id: GroupId(id),
            supplementary_groups: vec![],
            capabilities: vec![],
        }
    }
    fn setup() -> (
        IpcManager,
        ObjectManager,
        HandleManager,
        SecurityContext,
        ProcessId,
        ProcessId,
    ) {
        (
            IpcManager::new(),
            ObjectManager::new(),
            HandleManager::new(),
            SecurityContext::root(),
            ProcessId(1),
            ProcessId(2),
        )
    }

    #[test]
    fn bounded_pipe_is_directional_fifo_and_reports_eof() {
        let (mut ipc, mut objects, mut handles, root, reader, writer) = setup();
        let endpoints = ipc
            .create_pipe(
                &mut objects,
                &mut handles,
                &root,
                (reader, &root),
                (writer, &root),
            )
            .unwrap();
        assert_eq!(
            ipc.pipe_read(&mut objects, &handles, reader, &root, endpoints.reader, 8)
                .unwrap(),
            ReceiveResult::Empty
        );
        assert_eq!(
            ipc.pipe_write(
                &mut objects,
                &handles,
                writer,
                &root,
                endpoints.writer,
                b"abc"
            )
            .unwrap(),
            3
        );
        let ReceiveResult::Message(message) = ipc
            .pipe_read(&mut objects, &handles, reader, &root, endpoints.reader, 2)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(message.payload, b"ab");
        let ReceiveResult::Message(message) = ipc
            .pipe_read(&mut objects, &handles, reader, &root, endpoints.reader, 8)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(message.payload, b"c");
        assert_eq!(
            ipc.pipe_write(
                &mut objects,
                &handles,
                reader,
                &root,
                endpoints.reader,
                b"x"
            ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            ipc.pipe_read(&mut objects, &handles, writer, &root, endpoints.writer, 1),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            ipc.pipe_write(
                &mut objects,
                &handles,
                writer,
                &root,
                endpoints.writer,
                &vec![0; MAX_PIPE_WRITE_BYTES + 1]
            ),
            Err(IpcError::MessageTooLarge)
        );
        ipc.close(&mut objects, &mut handles, writer, endpoints.writer)
            .unwrap();
        assert_eq!(
            ipc.pipe_read(&mut objects, &handles, reader, &root, endpoints.reader, 1)
                .unwrap(),
            ReceiveResult::Eof
        );
        ipc.close(&mut objects, &mut handles, reader, endpoints.reader)
            .unwrap();
        assert!(objects.lookup(endpoints.object_id).is_none());
    }

    #[test]
    fn permissions_cross_process_and_stale_handles_fail_without_queue_change() {
        let mut ipc = IpcManager::new();
        let mut objects = ObjectManager::new();
        let mut handles = HandleManager::new();
        let alice = context(10);
        let bob = context(11);
        let endpoints = ipc.create_channel(
            &mut objects,
            &mut handles,
            &alice,
            (ProcessId(1), &alice),
            (ProcessId(2), &bob),
        );
        assert_eq!(endpoints, Err(IpcError::AccessDenied));
        let endpoints = ipc
            .create_channel(
                &mut objects,
                &mut handles,
                &alice,
                (ProcessId(1), &alice),
                (ProcessId(2), &alice),
            )
            .unwrap();
        objects.lookup_mut(endpoints.object_id).unwrap().permissions = 0o000;
        assert_eq!(
            ipc.channel_send(
                &mut objects,
                &mut handles,
                ProcessId(1),
                &alice,
                endpoints.a,
                MessageKind::Data,
                0,
                b"x".to_vec(),
                &[],
                (ProcessId(2), &alice)
            ),
            Err(IpcError::AccessDenied)
        );
        objects.lookup_mut(endpoints.object_id).unwrap().permissions = 0o600;
        ipc.close(&mut objects, &mut handles, ProcessId(1), endpoints.a)
            .unwrap();
        assert_eq!(
            ipc.channel_send(
                &mut objects,
                &mut handles,
                ProcessId(1),
                &alice,
                endpoints.a,
                MessageKind::Data,
                0,
                vec![],
                &[],
                (ProcessId(2), &alice)
            ),
            Err(IpcError::InvalidHandle)
        );
    }

    #[test]
    fn channel_rpc_fifo_and_cancellation_are_correlated() {
        let (mut ipc, mut objects, mut handles, root, a, b) = setup();
        let endpoints = ipc
            .create_channel(&mut objects, &mut handles, &root, (a, &root), (b, &root))
            .unwrap();
        let id = ipc
            .rpc_request(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                b"ping".to_vec(),
                (b, &root),
            )
            .unwrap();
        let ReceiveResult::Message(request) = ipc
            .channel_receive(&mut objects, &mut handles, b, &root, endpoints.b)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (request.kind, request.request_id, request.payload),
            (MessageKind::RpcRequest, id, b"ping".to_vec())
        );
        ipc.rpc_respond(
            &mut objects,
            &mut handles,
            b,
            &root,
            endpoints.b,
            id,
            b"pong".to_vec(),
            (a, &root),
        )
        .unwrap();
        let ReceiveResult::Message(response) = ipc
            .channel_receive(&mut objects, &mut handles, a, &root, endpoints.a)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (response.kind, response.request_id, response.payload),
            (MessageKind::RpcResponse, id, b"pong".to_vec())
        );
        assert_eq!(
            ipc.rpc_respond(
                &mut objects,
                &mut handles,
                b,
                &root,
                endpoints.b,
                id,
                vec![],
                (a, &root)
            ),
            Err(IpcError::InvalidRequest)
        );
        let cancelled = ipc
            .rpc_request(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                vec![],
                (b, &root),
            )
            .unwrap();
        ipc.rpc_cancel(
            &mut objects,
            &mut handles,
            a,
            &root,
            endpoints.a,
            cancelled,
            (b, &root),
        )
        .unwrap();
        let ReceiveResult::Message(_) = ipc
            .channel_receive(&mut objects, &mut handles, b, &root, endpoints.b)
            .unwrap()
        else {
            panic!()
        };
        let ReceiveResult::Message(cancel) = ipc
            .channel_receive(&mut objects, &mut handles, b, &root, endpoints.b)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(cancel.kind, MessageKind::Cancel);
    }

    #[test]
    fn attachments_attenuate_and_queued_attachment_is_released_on_close() {
        let (mut ipc, mut objects, mut handles, root, a, b) = setup();
        let endpoints = ipc
            .create_channel(&mut objects, &mut handles, &root, (a, &root), (b, &root))
            .unwrap();
        let file = objects.create_object(ObjectType::File);
        let source = handles
            .open(&mut objects, a, file, Rights::read_write(), "memfs".into())
            .unwrap();
        ipc.channel_send(
            &mut objects,
            &mut handles,
            a,
            &root,
            endpoints.a,
            MessageKind::Data,
            0,
            vec![],
            &[(source, Rights::read_only())],
            (b, &root),
        )
        .unwrap();
        assert_eq!(objects.lookup(file).unwrap().references, 3);
        ipc.close(&mut objects, &mut handles, a, endpoints.a)
            .unwrap();
        ipc.close(&mut objects, &mut handles, b, endpoints.b)
            .unwrap();
        assert_eq!(objects.lookup(file).unwrap().references, 2);
        handles.close(&mut objects, a, source).unwrap();
        assert_eq!(objects.lookup(file).unwrap().references, 1);
    }

    #[test]
    fn close_reconciles_a_legacy_raw_handle_close_and_reclaims_the_object() {
        let (mut ipc, mut objects, mut handles, root, reader, writer) = setup();
        let endpoints = ipc
            .create_pipe(
                &mut objects,
                &mut handles,
                &root,
                (reader, &root),
                (writer, &root),
            )
            .unwrap();
        // A legacy consumer bypassed IPC and closed the raw entry. The IPC
        // manager must still remove its endpoint bookkeeping.
        handles
            .close(&mut objects, writer, endpoints.writer)
            .unwrap();
        ipc.close(&mut objects, &mut handles, writer, endpoints.writer)
            .unwrap();
        assert_eq!(
            ipc.pipe_read(&mut objects, &handles, reader, &root, endpoints.reader, 1)
                .unwrap(),
            ReceiveResult::Eof
        );
        ipc.close(&mut objects, &mut handles, reader, endpoints.reader)
            .unwrap();
        assert!(objects.lookup(endpoints.object_id).is_none());
    }

    #[test]
    fn endpoint_creation_does_not_require_signal_but_signal_operations_do() {
        let mut ipc = IpcManager::new();
        let mut objects = ObjectManager::new();
        let mut handles = HandleManager::new();
        let alice = context(9);
        let endpoints = ipc
            .create_pipe(
                &mut objects,
                &mut handles,
                &alice,
                (ProcessId(1), &alice),
                (ProcessId(2), &alice),
            )
            .unwrap();
        assert_eq!(
            ipc.close_authorized(
                &mut objects,
                &mut handles,
                ProcessId(1),
                &alice,
                endpoints.reader,
            ),
            Err(IpcError::AccessDenied)
        );
        // Process-exit cleanup is a trusted manager path and still releases
        // both ends even when an application lacks CAP_OBJECT_SIGNAL.
        ipc.close_process(&mut objects, &mut handles, ProcessId(1));
        ipc.close_process(&mut objects, &mut handles, ProcessId(2));
        assert!(objects.lookup(endpoints.object_id).is_none());
    }

    #[test]
    fn rpc_response_must_match_the_front_request_without_consuming_it() {
        let (mut ipc, mut objects, mut handles, root, a, b) = setup();
        let endpoints = ipc
            .create_channel(&mut objects, &mut handles, &root, (a, &root), (b, &root))
            .unwrap();
        let first = ipc
            .rpc_request(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                b"first".to_vec(),
                (b, &root),
            )
            .unwrap();
        let second = ipc
            .rpc_request(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                b"second".to_vec(),
                (b, &root),
            )
            .unwrap();
        let ReceiveResult::Message(request) = ipc
            .channel_receive(&mut objects, &mut handles, b, &root, endpoints.b)
            .unwrap()
        else {
            panic!()
        };
        ipc.rpc_respond(
            &mut objects,
            &mut handles,
            b,
            &root,
            endpoints.b,
            request.request_id,
            b"one".to_vec(),
            (a, &root),
        )
        .unwrap();
        assert_eq!(
            ipc.rpc_receive_response(&mut objects, &mut handles, a, &root, endpoints.a, second),
            Err(IpcError::InvalidRequest)
        );
        let ReceiveResult::Message(response) = ipc
            .rpc_receive_response(&mut objects, &mut handles, a, &root, endpoints.a, first)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(response.payload, b"one");
    }

    #[test]
    fn zero_byte_messages_and_pending_rpcs_are_bounded() {
        let (mut ipc, mut objects, mut handles, root, a, b) = setup();
        let endpoints = ipc
            .create_channel(&mut objects, &mut handles, &root, (a, &root), (b, &root))
            .unwrap();
        for _ in 0..MAX_QUEUE_MESSAGES {
            ipc.channel_send(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                MessageKind::Data,
                0,
                vec![],
                &[],
                (b, &root),
            )
            .unwrap();
        }
        assert_eq!(
            ipc.channel_send(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                MessageKind::Data,
                0,
                vec![],
                &[],
                (b, &root),
            ),
            Err(IpcError::WouldBlock)
        );
        for _ in 0..MAX_QUEUE_MESSAGES {
            ipc.channel_receive(&mut objects, &mut handles, b, &root, endpoints.b)
                .unwrap();
        }
        for _ in 0..MAX_PENDING_REQUESTS {
            ipc.rpc_request(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                vec![],
                (b, &root),
            )
            .unwrap();
            let _ = ipc
                .channel_receive(&mut objects, &mut handles, b, &root, endpoints.b)
                .unwrap();
        }
        assert_eq!(
            ipc.rpc_request(
                &mut objects,
                &mut handles,
                a,
                &root,
                endpoints.a,
                vec![],
                (b, &root),
            ),
            Err(IpcError::WouldBlock)
        );
    }
}
