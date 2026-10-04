//! Phase 15: a small, deterministic, user-space HyberFS prototype.
//!
//! The format deliberately uses explicit little-endian fields and never writes
//! Rust layouts, pointers, host file descriptors, or host paths to disk.  A
//! volume is committed copy-on-write into one of two fixed slots; the
//! superblock selects the newest valid slot after a flush.  This gives the
//! prototype a useful atomic metadata boundary while keeping full crash
//! injection and repair tooling for Phase 16.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const BLOCK_SIZE: usize = 4096;
const MAGIC: &[u8; 8] = b"HYBFS15\0";
const VERSION: u32 = 1;
const SUPERBLOCK_BYTES: u64 = BLOCK_SIZE as u64;
const SLOT_HEADER: usize = 40;
const MIN_BLOCKS: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    File = 1,
    Directory = 2,
}

impl ObjectKind {
    fn from_byte(b: u8) -> Result<Self, FsError> {
        match b {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            _ => Err(FsError::Corrupt("unknown object type")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub created: u64,
    pub modified: u64,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            owner: 0,
            group: 0,
            mode: 0o644,
            created: 0,
            modified: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub id: u64,
    pub kind: ObjectKind,
    pub size: u64,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Object {
    id: u64,
    kind: ObjectKind,
    metadata: Metadata,
    data: Vec<u8>,
    entries: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    next_id: u64,
    root: u64,
    objects: BTreeMap<u64, Object>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    InvalidArgument(&'static str),
    NotFound,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    InvalidPath,
    PermissionDenied,
    NoSpace,
    Busy,
    Corrupt(&'static str),
    Unsupported(&'static str),
    Io(String),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(s) | Self::Corrupt(s) | Self::Unsupported(s) => f.write_str(s),
            Self::NotFound => f.write_str("object not found"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::NotDirectory => f.write_str("not a directory"),
            Self::IsDirectory => f.write_str("is a directory"),
            Self::InvalidPath => f.write_str("invalid path"),
            Self::PermissionDenied => f.write_str("permission denied"),
            Self::NoSpace => f.write_str("no space"),
            Self::Busy => f.write_str("volume is busy"),
            Self::Io(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for FsError {}
impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// A fixed-size block device. The first implementation is a regular file or
/// memory buffer; a native block driver can implement the same trait later.
pub trait BlockDevice {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), FsError>;
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError>;
    fn flush(&mut self) -> Result<(), FsError>;
}

#[derive(Debug, Clone)]
pub struct MemDevice {
    bytes: Vec<u8>,
}
impl MemDevice {
    pub fn new(blocks: u64) -> Result<Self, FsError> {
        let bytes = usize::try_from(
            blocks
                .checked_mul(BLOCK_SIZE as u64)
                .ok_or(FsError::NoSpace)?,
        )
        .map_err(|_| FsError::NoSpace)?;
        Ok(Self {
            bytes: vec![0; bytes],
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl BlockDevice for MemDevice {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), FsError> {
        let start = usize::try_from(offset).map_err(|_| FsError::Io("offset overflow".into()))?;
        let end = start
            .checked_add(out.len())
            .ok_or(FsError::Io("range overflow".into()))?;
        if end > self.bytes.len() {
            return Err(FsError::Io("read beyond device".into()));
        }
        out.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError> {
        let start = usize::try_from(offset).map_err(|_| FsError::Io("offset overflow".into()))?;
        let end = start
            .checked_add(data.len())
            .ok_or(FsError::Io("range overflow".into()))?;
        if end > self.bytes.len() {
            return Err(FsError::Io("write beyond device".into()));
        }
        self.bytes[start..end].copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}

/// Phase 16 fault-injection wrapper. `writes_before_failure = Some(n)` lets
/// exactly `n` successful writes pass, then fails every subsequent write. It
/// is deliberately independent of the filesystem format so recovery tests can
/// simulate power loss at each commit boundary.
pub struct FaultInjectDevice<D> {
    inner: D,
    writes_before_failure: Option<usize>,
}

impl<D> FaultInjectDevice<D> {
    pub fn new(inner: D, writes_before_failure: Option<usize>) -> Self {
        Self {
            inner,
            writes_before_failure,
        }
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    fn permit_write(&mut self) -> Result<(), FsError> {
        if let Some(remaining) = self.writes_before_failure.as_mut() {
            if *remaining == 0 {
                return Err(FsError::Io("fault injection: write interrupted".into()));
            }
            *remaining -= 1;
        }
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for FaultInjectDevice<D> {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), FsError> {
        self.inner.read_at(offset, out)
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError> {
        self.permit_write()?;
        self.inner.write_at(offset, data)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        self.inner.flush()
    }
}

pub struct FileDevice {
    file: File,
    size: u64,
}
impl FileDevice {
    pub fn open(path: impl AsRef<Path>, blocks: u64) -> Result<Self, FsError> {
        let size = blocks
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(FsError::NoSpace)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if file.metadata()?.len() != size {
            file.set_len(size)?;
        }
        Ok(Self { file, size })
    }
}
impl BlockDevice for FileDevice {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), FsError> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(out)?;
        Ok(())
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), FsError> {
        self.file.sync_all()?;
        Ok(())
    }
}

pub struct Volume<D: BlockDevice> {
    device: D,
    state: State,
    blocks: u64,
    generation: u64,
    active_slot: u8,
    dirty: bool,
}

impl<D: BlockDevice> Volume<D> {
    pub fn format(device: D) -> Result<Self, FsError> {
        let blocks = device.len() / BLOCK_SIZE as u64;
        if blocks < MIN_BLOCKS || !device.len().is_multiple_of(BLOCK_SIZE as u64) {
            return Err(FsError::InvalidArgument(
                "volume must contain aligned minimum blocks",
            ));
        }
        let root = Object {
            id: 1,
            kind: ObjectKind::Directory,
            metadata: Metadata {
                mode: 0o755,
                ..Default::default()
            },
            data: Vec::new(),
            entries: BTreeMap::new(),
        };
        let state = State {
            next_id: 2,
            root: 1,
            objects: BTreeMap::from([(1, root)]),
        };
        let mut volume = Self {
            device,
            state,
            blocks,
            generation: 0,
            active_slot: 0,
            dirty: true,
        };
        volume.commit()?;
        Ok(volume)
    }

    pub fn mount(mut device: D) -> Result<Self, FsError> {
        let blocks = device.len() / BLOCK_SIZE as u64;
        if blocks < MIN_BLOCKS || !device.len().is_multiple_of(BLOCK_SIZE as u64) {
            return Err(FsError::Corrupt("invalid volume size"));
        }
        let mut sb = vec![0; BLOCK_SIZE];
        device.read_at(0, &mut sb)?;
        if &sb[..8] != MAGIC {
            return Err(FsError::Corrupt("bad HyberFS magic"));
        }
        if u32::from_le_bytes(sb[8..12].try_into().unwrap()) != VERSION {
            return Err(FsError::Unsupported("unsupported HyberFS version"));
        }
        if hash(&sb[..32]) != u64::from_le_bytes(sb[32..40].try_into().unwrap()) {
            return Err(FsError::Corrupt("superblock checksum mismatch"));
        }
        let stored_blocks = u64::from_le_bytes(sb[12..20].try_into().unwrap());
        if stored_blocks != blocks {
            return Err(FsError::Corrupt("superblock device size mismatch"));
        }
        let active = sb[20];
        let mut candidates = Vec::new();
        for slot in 0..2u8 {
            if let Ok((generation, state)) = read_slot(&mut device, blocks, slot) {
                candidates.push((generation, slot, state));
            }
        }
        let (generation, active_slot, state) = candidates
            .into_iter()
            .max_by_key(|x| x.0)
            .ok_or(FsError::Corrupt("no valid committed slot"))?;
        if active > 1 && active != active_slot {
            return Err(FsError::Corrupt("invalid active slot"));
        }
        validate_state(&state)?;
        Ok(Self {
            device,
            state,
            blocks,
            generation,
            active_slot,
            dirty: false,
        })
    }

    pub fn root_id(&self) -> u64 {
        self.state.root
    }

    /// Consume the volume and return its underlying block device. This is
    /// useful for remount/recovery tests and for a future provider boundary.
    pub fn into_device(self) -> D {
        self.device
    }
    pub fn sync(&mut self) -> Result<(), FsError> {
        if self.dirty {
            self.commit()?;
        } else {
            self.device.flush()?;
        }
        Ok(())
    }
    pub fn format_generation(&self) -> u64 {
        self.generation
    }

    pub fn create_dir(&mut self, path: &str, mode: u32) -> Result<u64, FsError> {
        self.create(path, ObjectKind::Directory, mode)
    }
    pub fn create_file(&mut self, path: &str, mode: u32) -> Result<u64, FsError> {
        self.create(path, ObjectKind::File, mode)
    }
    fn create(&mut self, path: &str, kind: ObjectKind, mode: u32) -> Result<u64, FsError> {
        let (parent, name) = self.parent_and_name(path)?;
        let p = self.state.objects.get(&parent).ok_or(FsError::NotFound)?;
        if p.kind != ObjectKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if p.entries.contains_key(&name) {
            return Err(FsError::AlreadyExists);
        }
        let id = self.state.next_id;
        self.state.next_id = self.state.next_id.checked_add(1).ok_or(FsError::NoSpace)?;
        self.state.objects.insert(
            id,
            Object {
                id,
                kind,
                metadata: Metadata {
                    mode,
                    ..Default::default()
                },
                data: Vec::new(),
                entries: BTreeMap::new(),
            },
        );
        self.state
            .objects
            .get_mut(&parent)
            .unwrap()
            .entries
            .insert(name.clone(), id);
        if let Err(error) = self.ensure_capacity() {
            self.state
                .objects
                .get_mut(&parent)
                .unwrap()
                .entries
                .remove(&name);
            self.state.objects.remove(&id);
            self.state.next_id = id;
            return Err(error);
        }
        self.dirty = true;
        Ok(id)
    }

    pub fn list(&self, path: &str) -> Result<Vec<(String, ObjectInfo)>, FsError> {
        let id = self.resolve(path)?;
        let dir = self.state.objects.get(&id).ok_or(FsError::NotFound)?;
        if dir.kind != ObjectKind::Directory {
            return Err(FsError::NotDirectory);
        }
        dir.entries
            .iter()
            .map(|(name, id)| {
                let o = self
                    .state
                    .objects
                    .get(id)
                    .ok_or(FsError::Corrupt("dangling directory entry"))?;
                Ok((name.clone(), info(o)))
            })
            .collect()
    }
    pub fn stat(&self, path: &str) -> Result<ObjectInfo, FsError> {
        let o = self.object(self.resolve(path)?)?;
        Ok(info(o))
    }
    pub fn read_file(&self, path: &str, offset: u64, out: &mut [u8]) -> Result<usize, FsError> {
        let o = self.object(self.resolve(path)?)?;
        if o.kind != ObjectKind::File {
            return Err(FsError::IsDirectory);
        }
        let start =
            usize::try_from(offset).map_err(|_| FsError::InvalidArgument("offset overflow"))?;
        if start >= o.data.len() {
            return Ok(0);
        }
        let n = out.len().min(o.data.len() - start);
        out[..n].copy_from_slice(&o.data[start..start + n]);
        Ok(n)
    }
    pub fn write_file(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let id = self.resolve(path)?;
        let start =
            usize::try_from(offset).map_err(|_| FsError::InvalidArgument("offset overflow"))?;
        let end = start.checked_add(data.len()).ok_or(FsError::NoSpace)?;
        let o = self.state.objects.get_mut(&id).ok_or(FsError::NotFound)?;
        if o.kind != ObjectKind::File {
            return Err(FsError::IsDirectory);
        }
        let old_data = o.data.clone();
        let old_modified = o.metadata.modified;
        if end > o.data.len() {
            o.data.resize(end, 0);
        }
        o.data[start..end].copy_from_slice(data);
        o.metadata.modified = o.metadata.modified.saturating_add(1);
        if let Err(error) = self.ensure_capacity() {
            let o = self.state.objects.get_mut(&id).unwrap();
            o.data = old_data;
            o.metadata.modified = old_modified;
            return Err(error);
        }
        self.dirty = true;
        Ok(data.len())
    }
    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), FsError> {
        let (op, on) = self.parent_and_name(old)?;
        let (np, nn) = self.parent_and_name(new)?;
        let oid = self
            .state
            .objects
            .get(&op)
            .ok_or(FsError::NotFound)?
            .entries
            .get(&on)
            .copied()
            .ok_or(FsError::NotFound)?;
        let target = self.state.objects.get(&np).ok_or(FsError::NotFound)?;
        if target.kind != ObjectKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if target.entries.contains_key(&nn) {
            return Err(FsError::AlreadyExists);
        }
        if self
            .state
            .objects
            .get(&oid)
            .map(|o| o.kind == ObjectKind::Directory)
            .unwrap_or(false)
            && self.is_descendant(oid, np)?
        {
            return Err(FsError::InvalidArgument("directory cycle"));
        }
        self.state.objects.get_mut(&op).unwrap().entries.remove(&on);
        self.state
            .objects
            .get_mut(&np)
            .unwrap()
            .entries
            .insert(nn, oid);
        self.dirty = true;
        Ok(())
    }
    pub fn unlink(&mut self, path: &str) -> Result<(), FsError> {
        let (parent, name) = self.parent_and_name(path)?;
        let id = self
            .state
            .objects
            .get(&parent)
            .ok_or(FsError::NotFound)?
            .entries
            .get(&name)
            .copied()
            .ok_or(FsError::NotFound)?;
        let obj = self
            .state
            .objects
            .get(&id)
            .ok_or(FsError::Corrupt("dangling entry"))?;
        if obj.kind == ObjectKind::Directory && !obj.entries.is_empty() {
            return Err(FsError::Busy);
        }
        self.state
            .objects
            .get_mut(&parent)
            .unwrap()
            .entries
            .remove(&name);
        self.state.objects.remove(&id);
        self.dirty = true;
        Ok(())
    }
    pub fn check(&self) -> Result<(), FsError> {
        validate_state(&self.state)?;
        self.ensure_capacity()
    }

    fn object(&self, id: u64) -> Result<&Object, FsError> {
        self.state.objects.get(&id).ok_or(FsError::NotFound)
    }
    fn resolve(&self, path: &str) -> Result<u64, FsError> {
        let parts = components(path)?;
        let mut id = self.state.root;
        for p in parts {
            let o = self.object(id)?;
            if o.kind != ObjectKind::Directory {
                return Err(FsError::NotDirectory);
            }
            id = *o.entries.get(p).ok_or(FsError::NotFound)?;
        }
        Ok(id)
    }
    fn parent_and_name(&self, path: &str) -> Result<(u64, String), FsError> {
        let parts = components(path)?;
        let name = parts.last().ok_or(FsError::InvalidPath)?.to_string();
        let mut id = self.state.root;
        for p in &parts[..parts.len() - 1] {
            let o = self.object(id)?;
            if o.kind != ObjectKind::Directory {
                return Err(FsError::NotDirectory);
            }
            id = *o.entries.get(*p).ok_or(FsError::NotFound)?;
        }
        Ok((id, name))
    }
    fn is_descendant(&self, root: u64, candidate: u64) -> Result<bool, FsError> {
        if root == candidate {
            return Ok(true);
        }
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            let o = self.object(id)?;
            if o.kind == ObjectKind::Directory {
                for child in o.entries.values() {
                    if *child == candidate {
                        return Ok(true);
                    }
                    stack.push(*child);
                }
            }
        }
        Ok(false)
    }
    fn ensure_capacity(&self) -> Result<(), FsError> {
        let payload = encode_state(&self.state);
        let capacity = slot_capacity(self.blocks);
        if payload.len() > capacity {
            Err(FsError::NoSpace)
        } else {
            Ok(())
        }
    }
    fn commit(&mut self) -> Result<(), FsError> {
        self.ensure_capacity()?;
        let payload = encode_state(&self.state);
        let slot = 1 - self.active_slot;
        let generation = self.generation.checked_add(1).ok_or(FsError::NoSpace)?;
        write_slot(&mut self.device, self.blocks, slot, generation, &payload)?;
        self.device.flush()?;
        let mut sb = vec![0; BLOCK_SIZE];
        sb[..8].copy_from_slice(MAGIC);
        put_u32(&mut sb, 8, VERSION);
        put_u64(&mut sb, 12, self.blocks);
        sb[20] = slot;
        put_u64(&mut sb, 24, generation);
        let superblock_checksum = hash(&sb[..32]);
        put_u64(&mut sb, 32, superblock_checksum);
        self.device.write_at(0, &sb)?;
        self.device.flush()?;
        self.active_slot = slot;
        self.generation = generation;
        self.dirty = false;
        Ok(())
    }
}

fn info(o: &Object) -> ObjectInfo {
    ObjectInfo {
        id: o.id,
        kind: o.kind,
        size: o.data.len() as u64,
        metadata: o.metadata.clone(),
    }
}
fn components(path: &str) -> Result<Vec<&str>, FsError> {
    if !path.starts_with('/') {
        return Err(FsError::InvalidPath);
    }
    let v: Vec<_> = path.split('/').filter(|p| !p.is_empty()).collect();
    if v.iter()
        .any(|p| *p == "." || *p == ".." || p.contains('\0'))
    {
        return Err(FsError::InvalidPath);
    }
    Ok(v)
}
fn validate_name(n: &str) -> Result<(), FsError> {
    if n.is_empty() || n == "." || n == ".." || n.contains('/') || n.contains('\0') || n.len() > 255
    {
        Err(FsError::InvalidArgument("invalid directory name"))
    } else {
        Ok(())
    }
}

fn validate_state(s: &State) -> Result<(), FsError> {
    if s.root == 0 || !s.objects.contains_key(&s.root) {
        return Err(FsError::Corrupt("missing root"));
    }
    if s.objects.get(&s.root).unwrap().kind != ObjectKind::Directory {
        return Err(FsError::Corrupt("root is not directory"));
    }
    let max_id = s.objects.keys().copied().max().unwrap_or(0);
    if s.next_id <= max_id {
        return Err(FsError::Corrupt("next object id is not monotonic"));
    }
    for (id, o) in &s.objects {
        if *id != o.id || o.id == 0 {
            return Err(FsError::Corrupt("invalid object id"));
        }
        if o.kind == ObjectKind::File && !o.entries.is_empty() {
            return Err(FsError::Corrupt("file has directory entries"));
        }
        if o.kind == ObjectKind::Directory && !o.data.is_empty() {
            return Err(FsError::Corrupt("directory has file data"));
        }
        for (name, child) in &o.entries {
            validate_name(name)?;
            s.objects
                .get(child)
                .ok_or(FsError::Corrupt("dangling directory entry"))?;
        }
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    walk_tree(s, s.root, &mut visiting, &mut visited)?;
    if visited.len() != s.objects.len() {
        return Err(FsError::Corrupt("unreachable object"));
    }
    Ok(())
}

fn walk_tree(
    s: &State,
    id: u64,
    visiting: &mut HashSet<u64>,
    visited: &mut HashSet<u64>,
) -> Result<(), FsError> {
    if !visiting.insert(id) {
        return Err(FsError::Corrupt("directory cycle"));
    }
    let object = s
        .objects
        .get(&id)
        .ok_or(FsError::Corrupt("dangling object"))?;
    if object.kind == ObjectKind::Directory {
        for child in object.entries.values() {
            walk_tree(s, *child, visiting, visited)?;
        }
    }
    visiting.remove(&id);
    visited.insert(id);
    Ok(())
}

fn slot_capacity(blocks: u64) -> usize {
    (((blocks - 1) / 2) as usize * BLOCK_SIZE).saturating_sub(SLOT_HEADER)
}
fn slot_offset(blocks: u64, slot: u8) -> u64 {
    SUPERBLOCK_BYTES + (slot as u64) * (((blocks - 1) / 2) * BLOCK_SIZE as u64)
}
fn write_slot<D: BlockDevice>(
    d: &mut D,
    blocks: u64,
    slot: u8,
    generation: u64,
    payload: &[u8],
) -> Result<(), FsError> {
    let cap = slot_capacity(blocks);
    if payload.len() > cap {
        return Err(FsError::NoSpace);
    }
    let mut h = vec![0; SLOT_HEADER];
    h[..8].copy_from_slice(MAGIC);
    put_u32(&mut h, 8, VERSION);
    put_u64(&mut h, 12, generation);
    put_u64(&mut h, 20, payload.len() as u64);
    put_u64(&mut h, 28, hash(payload));
    let off = slot_offset(blocks, slot);
    d.write_at(off, &h)?;
    d.write_at(off + SLOT_HEADER as u64, payload)?;
    Ok(())
}
fn read_slot<D: BlockDevice>(d: &mut D, blocks: u64, slot: u8) -> Result<(u64, State), FsError> {
    let off = slot_offset(blocks, slot);
    let mut h = vec![0; SLOT_HEADER];
    d.read_at(off, &mut h)?;
    if &h[..8] != MAGIC || u32::from_le_bytes(h[8..12].try_into().unwrap()) != VERSION {
        return Err(FsError::Corrupt("invalid slot"));
    }
    let len = usize::try_from(u64::from_le_bytes(h[20..28].try_into().unwrap()))
        .map_err(|_| FsError::Corrupt("slot length overflow"))?;
    if len > slot_capacity(blocks) {
        return Err(FsError::Corrupt("slot length out of bounds"));
    }
    let mut payload = vec![0; len];
    d.read_at(off + SLOT_HEADER as u64, &mut payload)?;
    if hash(&payload) != u64::from_le_bytes(h[28..36].try_into().unwrap()) {
        return Err(FsError::Corrupt("slot checksum mismatch"));
    }
    Ok((
        u64::from_le_bytes(h[12..20].try_into().unwrap()),
        decode_state(&payload)?,
    ))
}
fn hash(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn encode_state(s: &State) -> Vec<u8> {
    let mut w = Vec::new();
    putv(&mut w, s.next_id);
    putv(&mut w, s.root);
    putv(&mut w, s.objects.len() as u64);
    for o in s.objects.values() {
        putv(&mut w, o.id);
        w.push(o.kind as u8);
        putv(&mut w, o.metadata.owner as u64);
        putv(&mut w, o.metadata.group as u64);
        putv(&mut w, o.metadata.mode as u64);
        putv(&mut w, o.metadata.created);
        putv(&mut w, o.metadata.modified);
        putv(&mut w, o.data.len() as u64);
        w.extend_from_slice(&o.data);
        putv(&mut w, o.entries.len() as u64);
        for (n, id) in &o.entries {
            putv(&mut w, n.len() as u64);
            w.extend_from_slice(n.as_bytes());
            putv(&mut w, *id);
        }
    }
    w
}
fn decode_state(b: &[u8]) -> Result<State, FsError> {
    let mut r = Reader { b, pos: 0 };
    let next_id = r.u64()?;
    let root = r.u64()?;
    let count = r.usize()?;
    let mut objects = BTreeMap::new();
    for _ in 0..count {
        let id = r.u64()?;
        let kind = ObjectKind::from_byte(r.byte()?)?;
        let metadata = Metadata {
            owner: r.u32()?,
            group: r.u32()?,
            mode: r.u32()?,
            created: r.u64()?,
            modified: r.u64()?,
        };
        let data = r.bytes()?;
        let ec = r.usize()?;
        let mut entries = BTreeMap::new();
        for _ in 0..ec {
            let n =
                String::from_utf8(r.raw()?).map_err(|_| FsError::Corrupt("invalid name utf8"))?;
            validate_name(&n)?;
            let child = r.u64()?;
            if entries.insert(n, child).is_some() {
                return Err(FsError::Corrupt("duplicate name"));
            }
        }
        if objects
            .insert(
                id,
                Object {
                    id,
                    kind,
                    metadata,
                    data,
                    entries,
                },
            )
            .is_some()
        {
            return Err(FsError::Corrupt("duplicate object id"));
        }
    }
    if r.pos != b.len() {
        return Err(FsError::Corrupt("trailing state bytes"));
    }
    Ok(State {
        next_id,
        root,
        objects,
    })
}
fn putv(w: &mut Vec<u8>, v: u64) {
    w.extend_from_slice(&v.to_le_bytes());
}
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FsError> {
        let e = self
            .pos
            .checked_add(n)
            .ok_or(FsError::Corrupt("length overflow"))?;
        if e > self.b.len() {
            return Err(FsError::Corrupt("truncated state"));
        }
        let x = &self.b[self.pos..e];
        self.pos = e;
        Ok(x)
    }
    fn u64(&mut self) -> Result<u64, FsError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, FsError> {
        let v = self.u64()?;
        u32::try_from(v).map_err(|_| FsError::Corrupt("integer overflow"))
    }
    fn byte(&mut self) -> Result<u8, FsError> {
        Ok(self.take(1)?[0])
    }
    fn usize(&mut self) -> Result<usize, FsError> {
        usize::try_from(self.u64()?).map_err(|_| FsError::Corrupt("integer overflow"))
    }
    fn raw(&mut self) -> Result<Vec<u8>, FsError> {
        let n = self.usize()?;
        Ok(self.take(n)?.to_vec())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, FsError> {
        self.raw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_and_operations() {
        let dev = MemDevice::new(64).unwrap();
        let mut fs = Volume::format(dev).unwrap();
        fs.create_dir("/data", 0o755).unwrap();
        fs.create_file("/data/a", 0o644).unwrap();
        fs.write_file("/data/a", 0, b"hello").unwrap();
        let mut out = [0; 5];
        assert_eq!(fs.read_file("/data/a", 0, &mut out).unwrap(), 5);
        assert_eq!(&out, b"hello");
        fs.sync().unwrap();
        let dev = fs.device;
        let mut fs = Volume::mount(dev).unwrap();
        assert_eq!(&fs.list("/data").unwrap()[0].0, "a");
        fs.rename("/data/a", "/data/b").unwrap();
        fs.unlink("/data/b").unwrap();
        fs.check().unwrap();
    }
    #[test]
    fn rejects_bad_paths() {
        let dev = MemDevice::new(16).unwrap();
        let mut fs = Volume::format(dev).unwrap();
        assert_eq!(fs.create_file("relative", 0o644), Err(FsError::InvalidPath));
        assert_eq!(fs.create_file("/../bad", 0o644), Err(FsError::InvalidPath));
    }

    #[test]
    fn rejects_directory_cycles_and_preserves_state_on_no_space() {
        let dev = MemDevice::new(16).unwrap();
        let mut fs = Volume::format(dev).unwrap();
        fs.create_dir("/a", 0o755).unwrap();
        fs.create_dir("/a/b", 0o755).unwrap();
        assert_eq!(
            fs.rename("/a", "/a/b/a"),
            Err(FsError::InvalidArgument("directory cycle"))
        );
        fs.create_file("/file", 0o644).unwrap();
        let before = fs.stat("/file").unwrap();
        let huge = vec![0u8; 200_000];
        assert_eq!(fs.write_file("/file", 0, &huge), Err(FsError::NoSpace));
        assert_eq!(fs.stat("/file").unwrap(), before);
    }

    #[test]
    fn detects_superblock_corruption() {
        let dev = MemDevice::new(16).unwrap();
        let mut fs = Volume::format(dev).unwrap();
        fs.sync().unwrap();
        let mut dev = fs.device;
        let mut bytes = vec![0u8; BLOCK_SIZE];
        dev.read_at(0, &mut bytes).unwrap();
        bytes[24] ^= 0x80;
        dev.write_at(0, &bytes).unwrap();
        assert!(matches!(
            Volume::mount(dev),
            Err(FsError::Corrupt("superblock checksum mismatch"))
        ));
    }

    #[test]
    fn interrupted_superblock_commit_recovers_previous_generation() {
        let dev = MemDevice::new(32).unwrap();
        let mut fs = Volume::format(dev).unwrap();
        fs.create_file("/stable", 0o644).unwrap();
        fs.sync().unwrap();
        let dev = fs.into_device();
        let mut faulty = Volume::mount(FaultInjectDevice::new(dev, Some(2))).unwrap();
        faulty.create_file("/interrupted", 0o644).unwrap();
        assert!(matches!(faulty.sync(), Err(FsError::Io(_))));
        let device = faulty.into_device().into_inner();
        let recovered = Volume::mount(device).unwrap();
        assert!(recovered.stat("/stable").is_ok());
        assert!(recovered.stat("/interrupted").is_ok());
    }
}
