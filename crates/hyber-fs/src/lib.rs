//! Phase 15: a small, deterministic, user-space HyberFS prototype.
//!
//! The format deliberately uses explicit little-endian fields and never writes
//! Rust layouts, pointers, host file descriptors, or host paths to disk.  A
//! volume is committed copy-on-write into one of two fixed slots. Immutable
//! superblock geometry and checksummed generation headers support newest-valid
//! recovery. Phase 16 tests model torn writes and failed flushes; damaged-slot
//! fallback is observable and read-only.

use rand_core::{OsRng, RngCore};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const BLOCK_SIZE: usize = 4096;
const MAGIC: &[u8; 8] = b"HYBFS15\0";
const VERSION: u32 = 2;
const SUPERBLOCK_BYTES: u64 = BLOCK_SIZE as u64;
const SLOT_HEADER: usize = 40;
const MIN_BLOCKS: u64 = 8;
/// Snapshot prototype bound; a streaming/extent format is needed above this.
const MAX_BLOCKS: u64 = 32769;

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
    pub flags: u32,
    pub extended: BTreeMap<String, Vec<u8>>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            owner: 0,
            group: 0,
            mode: 0o644,
            created: 0,
            modified: 0,
            flags: 0,
            extended: BTreeMap::new(),
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
        if blocks > MAX_BLOCKS {
            return Err(FsError::NoSpace);
        }
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
    /// Open an existing image without creating, truncating, or resizing it.
    pub fn open(path: impl AsRef<Path>, blocks: u64) -> Result<Self, FsError> {
        let size = blocks
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(FsError::NoSpace)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock().map_err(|_| FsError::Busy)?;
        if file.metadata()?.len() != size {
            return Err(FsError::InvalidArgument("image size mismatch"));
        }
        Ok(Self { file, size })
    }

    /// Destructive formatting is explicit. Without force, creation is exclusive.
    pub fn create(path: impl AsRef<Path>, blocks: u64, force: bool) -> Result<Self, FsError> {
        if !(MIN_BLOCKS..=MAX_BLOCKS).contains(&blocks) {
            return Err(FsError::InvalidArgument("image too small"));
        }
        let size = blocks
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(FsError::NoSpace)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(force)
            .create_new(!force)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.try_lock().map_err(|_| FsError::Busy)?;
        if force {
            file.set_len(0)?;
        }
        file.set_len(size)?;
        Ok(Self { file, size })
    }

    pub fn open_read_only(path: impl AsRef<Path>, blocks: u64) -> Result<Self, FsError> {
        let size = blocks
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(FsError::NoSpace)?;
        let file = File::open(path)?;
        file.try_lock_shared().map_err(|_| FsError::Busy)?;
        if file.metadata()?.len() != size {
            return Err(FsError::InvalidArgument("image size mismatch"));
        }
        Ok(Self { file, size })
    }
}
impl BlockDevice for FileDevice {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), FsError> {
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(FsError::Io("read beyond device".into()));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(out)?;
        Ok(())
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), FsError> {
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(FsError::Io("write beyond device".into()));
        }
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
    failed: bool,
    recovery_warnings: Vec<String>,
    uuid: [u8; 16],
}

impl<D: BlockDevice> Volume<D> {
    pub fn format(mut device: D) -> Result<Self, FsError> {
        let timestamp = timestamp()?;
        let blocks = device.len() / BLOCK_SIZE as u64;
        if !(MIN_BLOCKS..=MAX_BLOCKS).contains(&blocks)
            || !device.len().is_multiple_of(BLOCK_SIZE as u64)
        {
            return Err(FsError::InvalidArgument(
                "volume must contain aligned minimum blocks",
            ));
        }
        // Clear both old headers: an older high generation must never survive reformat.
        for slot in 0..2 {
            device.write_at(slot_offset(blocks, slot), &[0; SLOT_HEADER])?;
        }
        device.flush()?;
        let mut sb = vec![0; BLOCK_SIZE];
        let mut uuid = [0; 16];
        OsRng
            .try_fill_bytes(&mut uuid)
            .map_err(|e| FsError::Io(e.to_string()))?;
        sb[..8].copy_from_slice(MAGIC);
        put_u32(&mut sb, 8, VERSION);
        put_u64(&mut sb, 12, blocks);
        sb[40..56].copy_from_slice(&uuid);
        let checksum = slot_hash(&sb[..32], &sb[40..56]);
        put_u64(&mut sb, 32, checksum);
        device.write_at(0, &sb)?;
        device.flush()?;
        let root = Object {
            id: 1,
            kind: ObjectKind::Directory,
            metadata: Metadata {
                mode: 0o755,
                created: timestamp,
                modified: timestamp,
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
            failed: false,
            recovery_warnings: Vec::new(),
            uuid,
        };
        volume.commit()?;
        Ok(volume)
    }

    pub fn mount(mut device: D) -> Result<Self, FsError> {
        let blocks = device.len() / BLOCK_SIZE as u64;
        if !(MIN_BLOCKS..=MAX_BLOCKS).contains(&blocks)
            || !device.len().is_multiple_of(BLOCK_SIZE as u64)
        {
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
        if slot_hash(&sb[..32], &sb[40..56]) != u64::from_le_bytes(sb[32..40].try_into().unwrap()) {
            return Err(FsError::Corrupt("superblock checksum mismatch"));
        }
        if sb[20..32]
            .iter()
            .chain(sb[56..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(FsError::Corrupt("superblock reserved bytes are not zero"));
        }
        let stored_blocks = u64::from_le_bytes(sb[12..20].try_into().unwrap());
        if stored_blocks != blocks {
            return Err(FsError::Corrupt("superblock device size mismatch"));
        }
        let mut candidates = Vec::new();
        let mut recovery_warnings = Vec::new();
        for slot in 0..2u8 {
            match read_slot(&mut device, blocks, slot) {
                Ok((generation, state)) => candidates.push((generation, slot, state)),
                Err(FsError::NotFound) => (),
                Err(error @ FsError::Io(_)) => return Err(error),
                Err(error) => recovery_warnings.push(format!("slot {slot}: {error}")),
            }
        }
        if candidates.len() == 2
            && candidates[0].0 == candidates[1].0
            && candidates[0].2 != candidates[1].2
        {
            return Err(FsError::Corrupt("conflicting equal-generation snapshots"));
        }
        let (generation, active_slot, state) = candidates
            .into_iter()
            .max_by_key(|x| x.0)
            .ok_or(FsError::Corrupt("no valid committed slot"))?;
        validate_state(&state)?;
        Ok(Self {
            device,
            state,
            blocks,
            generation,
            active_slot,
            dirty: false,
            failed: false,
            recovery_warnings,
            uuid: sb[40..56].try_into().unwrap(),
        })
    }

    pub fn root_id(&self) -> u64 {
        self.state.root
    }
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// A recovered older generation is observable, never advertised as a
    /// completely clean image. The checker reports these diagnostics.
    pub fn recovery_warnings(&self) -> &[String] {
        &self.recovery_warnings
    }

    /// Consume the volume and return its underlying block device. This is
    /// useful for remount/recovery tests and for a future provider boundary.
    pub fn into_device(self) -> D {
        self.device
    }
    pub fn sync(&mut self) -> Result<(), FsError> {
        self.writable()?;
        if self.dirty {
            self.commit()?;
        } else {
            if let Err(error) = self.device.flush() {
                self.failed = true;
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn unmount(mut self) -> Result<D, FsError> {
        self.sync()?;
        Ok(self.device)
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
        self.writable()?;
        validate_mode(mode)?;
        let timestamp = timestamp()?;
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
                    created: timestamp,
                    modified: timestamp,
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
        let metadata = &mut self.state.objects.get_mut(&parent).unwrap().metadata;
        metadata.modified = metadata.modified.max(timestamp);
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
        self.writable()?;
        let id = self.resolve(path)?;
        if self.object(id)?.kind != ObjectKind::File {
            return Err(FsError::IsDirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let start =
            usize::try_from(offset).map_err(|_| FsError::InvalidArgument("offset overflow"))?;
        let end = start.checked_add(data.len()).ok_or(FsError::NoSpace)?;
        self.ensure_growth(id, end)?;
        let timestamp = timestamp()?;
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
        o.metadata.modified = o.metadata.modified.max(timestamp);
        if let Err(error) = self.ensure_capacity() {
            let o = self.state.objects.get_mut(&id).unwrap();
            o.data = old_data;
            o.metadata.modified = old_modified;
            return Err(error);
        }
        self.dirty = true;
        Ok(data.len())
    }

    pub fn truncate_file(&mut self, path: &str, length: u64) -> Result<(), FsError> {
        self.writable()?;
        let id = self.resolve(path)?;
        let length = usize::try_from(length).map_err(|_| FsError::NoSpace)?;
        self.ensure_growth(id, length)?;
        let timestamp = timestamp()?;
        let object = self.state.objects.get_mut(&id).ok_or(FsError::NotFound)?;
        if object.kind != ObjectKind::File {
            return Err(FsError::IsDirectory);
        }
        let old_data = object.data.clone();
        let old_modified = object.metadata.modified;
        object.data.resize(length, 0);
        object.metadata.modified = object.metadata.modified.max(timestamp);
        if let Err(error) = self.ensure_capacity() {
            let object = self.state.objects.get_mut(&id).unwrap();
            object.data = old_data;
            object.metadata.modified = old_modified;
            return Err(error);
        }
        self.dirty = true;
        Ok(())
    }
    pub fn append_file(&mut self, path: &str, data: &[u8]) -> Result<usize, FsError> {
        let offset = self.stat(path)?.size;
        self.write_file(path, offset, data)
    }
    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), FsError> {
        self.writable()?;
        let timestamp = timestamp()?;
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
        if op == np && on == nn {
            return Ok(());
        }
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
            .insert(nn.clone(), oid);
        if let Err(error) = self.ensure_capacity() {
            self.state.objects.get_mut(&np).unwrap().entries.remove(&nn);
            self.state
                .objects
                .get_mut(&op)
                .unwrap()
                .entries
                .insert(on, oid);
            return Err(error);
        }
        for parent in [op, np] {
            let metadata = &mut self.state.objects.get_mut(&parent).unwrap().metadata;
            metadata.modified = metadata.modified.max(timestamp);
        }
        self.dirty = true;
        Ok(())
    }
    pub fn unlink(&mut self, path: &str) -> Result<(), FsError> {
        self.writable()?;
        let timestamp = timestamp()?;
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
        let metadata = &mut self.state.objects.get_mut(&parent).unwrap().metadata;
        metadata.modified = metadata.modified.max(timestamp);
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
        if self.object(id)?.kind != ObjectKind::Directory {
            return Err(FsError::NotDirectory);
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
        self.writable()?;
        validate_state(&self.state)?;
        self.ensure_capacity()?;
        let payload = encode_state(&self.state);
        let slot = 1 - self.active_slot;
        let generation = self.generation.checked_add(1).ok_or(FsError::NoSpace)?;
        // Geometry never changes during a transaction. A torn slot cannot
        // invalidate the superblock or the previous committed slot.
        if let Err(error) = write_slot(&mut self.device, self.blocks, slot, generation, &payload) {
            self.failed = true;
            return Err(error);
        }
        self.active_slot = slot;
        self.generation = generation;
        self.dirty = false;
        Ok(())
    }

    fn writable(&self) -> Result<(), FsError> {
        if !self.recovery_warnings.is_empty() {
            return Err(FsError::Corrupt(
                "damaged-slot recovery is read-only; export to a new volume",
            ));
        }
        if self.failed {
            Err(FsError::Io(
                "commit outcome uncertain; remount required".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn ensure_growth(&self, id: u64, size: usize) -> Result<(), FsError> {
        let old = self.object(id)?;
        if old.kind != ObjectKind::File {
            return Err(FsError::IsDirectory);
        }
        let growth = size.saturating_sub(old.data.len());
        if growth > slot_capacity(self.blocks).saturating_sub(encode_state(&self.state).len()) {
            return Err(FsError::NoSpace);
        }
        Ok(())
    }

    pub fn set_metadata(&mut self, path: &str, metadata: Metadata) -> Result<(), FsError> {
        self.writable()?;
        validate_metadata(&metadata)?;
        let id = self.resolve(path)?;
        let old = std::mem::replace(
            &mut self.state.objects.get_mut(&id).unwrap().metadata,
            metadata,
        );
        if let Err(error) = self.ensure_capacity() {
            self.state.objects.get_mut(&id).unwrap().metadata = old;
            return Err(error);
        }
        self.dirty = true;
        Ok(())
    }

    /// Replace one file in memory atomically; sync commits it with all other pending changes.
    pub fn replace_file(
        &mut self,
        path: &str,
        data: &[u8],
        metadata: Metadata,
    ) -> Result<(), FsError> {
        self.writable()?;
        validate_metadata(&metadata)?;
        if data.len() > slot_capacity(self.blocks) {
            return Err(FsError::NoSpace);
        }
        let before = self.state.clone();
        let was_dirty = self.dirty;
        let result = (|| {
            match self.stat(path) {
                Ok(info) if info.kind == ObjectKind::File => (),
                Ok(_) => return Err(FsError::IsDirectory),
                Err(FsError::NotFound) => {
                    self.create_file(path, metadata.mode)?;
                }
                Err(error) => return Err(error),
            }
            self.truncate_file(path, 0)?;
            self.write_file(path, 0, data)?;
            self.set_metadata(path, metadata)
        })();
        if result.is_err() {
            self.state = before;
            self.dirty = was_dirty;
        }
        result
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
    for name in &v {
        validate_name(name)?;
    }
    Ok(v)
}
fn validate_mode(mode: u32) -> Result<(), FsError> {
    if mode & !0o777 != 0 {
        Err(FsError::InvalidArgument("unsupported permission bits"))
    } else {
        Ok(())
    }
}
fn validate_name(n: &str) -> Result<(), FsError> {
    if n.is_empty() || n == "." || n == ".." || n.contains('/') || n.contains('\0') || n.len() > 255
    {
        Err(FsError::InvalidArgument("invalid directory name"))
    } else {
        Ok(())
    }
}
fn validate_metadata(metadata: &Metadata) -> Result<(), FsError> {
    validate_mode(metadata.mode)?;
    if metadata.modified < metadata.created {
        return Err(FsError::InvalidArgument("modification precedes creation"));
    }
    if metadata.flags != 0 {
        return Err(FsError::Unsupported("unknown metadata flags"));
    }
    if metadata.extended.len() > 64 {
        return Err(FsError::InvalidArgument("too many metadata keys"));
    }
    for (key, value) in &metadata.extended {
        if key.is_empty() || key.len() > 128 || key.contains('\0') || value.len() > 4096 {
            return Err(FsError::InvalidArgument("invalid extended metadata"));
        }
    }
    Ok(())
}
fn timestamp() -> Result<u64, FsError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| FsError::Io("clock precedes epoch".into()))
}

fn validate_state(s: &State) -> Result<(), FsError> {
    if s.root != 1 || !s.objects.contains_key(&s.root) {
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
        validate_metadata(&o.metadata)?;
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
    let mut visited = HashSet::new();
    let mut stack = vec![s.root];
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            return Err(FsError::Corrupt("cycle or multiple parent reference"));
        }
        stack.extend(s.objects[&id].entries.values().copied());
    }
    if visited.len() != s.objects.len() {
        return Err(FsError::Corrupt("unreachable object"));
    }
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
    let checksum = slot_hash(&h[..28], payload);
    put_u64(&mut h, 28, checksum);
    let off = slot_offset(blocks, slot);
    d.write_at(off, &[0; SLOT_HEADER])?;
    d.flush()?;
    d.write_at(off + SLOT_HEADER as u64, payload)?;
    d.flush()?;
    d.write_at(off, &h)?;
    d.flush()?;
    Ok(())
}
fn read_slot<D: BlockDevice>(d: &mut D, blocks: u64, slot: u8) -> Result<(u64, State), FsError> {
    let off = slot_offset(blocks, slot);
    let mut h = vec![0; SLOT_HEADER];
    d.read_at(off, &mut h)?;
    if h.iter().all(|byte| *byte == 0) {
        return Err(FsError::NotFound);
    }
    if &h[..8] != MAGIC || u32::from_le_bytes(h[8..12].try_into().unwrap()) != VERSION {
        return Err(FsError::Corrupt("invalid slot"));
    }
    if h[36..40].iter().any(|byte| *byte != 0) {
        return Err(FsError::Corrupt("slot reserved bytes are not zero"));
    }
    let len = usize::try_from(u64::from_le_bytes(h[20..28].try_into().unwrap()))
        .map_err(|_| FsError::Corrupt("slot length overflow"))?;
    if len > slot_capacity(blocks) {
        return Err(FsError::Corrupt("slot length out of bounds"));
    }
    let mut payload = vec![0; len];
    d.read_at(off + SLOT_HEADER as u64, &mut payload)?;
    if slot_hash(&h[..28], &payload) != u64::from_le_bytes(h[28..36].try_into().unwrap()) {
        return Err(FsError::Corrupt("slot checksum mismatch"));
    }
    let generation = u64::from_le_bytes(h[12..20].try_into().unwrap());
    if generation == 0 {
        return Err(FsError::Corrupt("zero generation"));
    }
    let state = decode_state(&payload)?;
    validate_state(&state)?;
    Ok((generation, state))
}
fn slot_hash(header: &[u8], payload: &[u8]) -> u64 {
    header
        .iter()
        .chain(payload)
        .fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        })
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
        putv(&mut w, u64::from(o.metadata.flags));
        putv(&mut w, o.metadata.extended.len() as u64);
        for (key, value) in &o.metadata.extended {
            putv(&mut w, key.len() as u64);
            w.extend_from_slice(key.as_bytes());
            putv(&mut w, value.len() as u64);
            w.extend_from_slice(value);
        }
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
        if objects
            .last_key_value()
            .is_some_and(|(previous, _)| *previous >= id)
        {
            return Err(FsError::Corrupt("object records are not strictly sorted"));
        }
        let kind = ObjectKind::from_byte(r.byte()?)?;
        let mut metadata = Metadata {
            owner: r.u32()?,
            group: r.u32()?,
            mode: r.u32()?,
            created: r.u64()?,
            modified: r.u64()?,
            flags: r.u32()?,
            extended: BTreeMap::new(),
        };
        let mc = r.usize()?;
        if mc > 64 {
            return Err(FsError::Corrupt("too many metadata keys"));
        }
        for _ in 0..mc {
            let key = String::from_utf8(r.raw()?)
                .map_err(|_| FsError::Corrupt("invalid metadata utf8"))?;
            let value = r.raw()?;
            if metadata
                .extended
                .last_key_value()
                .is_some_and(|(previous, _)| previous >= &key)
            {
                return Err(FsError::Corrupt("metadata keys are not strictly sorted"));
            }
            if metadata.extended.insert(key, value).is_some() {
                return Err(FsError::Corrupt("duplicate metadata key"));
            }
        }
        let data = r.bytes()?;
        let ec = r.usize()?;
        let mut entries = BTreeMap::new();
        for _ in 0..ec {
            let n =
                String::from_utf8(r.raw()?).map_err(|_| FsError::Corrupt("invalid name utf8"))?;
            validate_name(&n)?;
            let child = r.u64()?;
            if entries
                .last_key_value()
                .is_some_and(|(previous, _)| previous >= &n)
            {
                return Err(FsError::Corrupt("directory names are not strictly sorted"));
            }
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
    fn directory_mutation_times_persist_and_failed_operations_preserve_state() {
        let mut fs = Volume::format(MemDevice::new(8).unwrap()).unwrap();
        fs.create_dir("/a", 0o700).unwrap();
        fs.create_dir("/b", 0o700).unwrap();
        let old = Metadata {
            created: 1,
            modified: 1,
            ..Metadata::default()
        };
        fs.set_metadata("/a", old.clone()).unwrap();
        fs.create_file("/a/file", 0o600).unwrap();
        assert!(fs.stat("/a").unwrap().metadata.modified > 1);
        fs.set_metadata("/a", old.clone()).unwrap();
        fs.set_metadata("/b", old.clone()).unwrap();
        fs.rename("/a/file", "/b/file").unwrap();
        assert!(fs.stat("/a").unwrap().metadata.modified > 1);
        assert!(fs.stat("/b").unwrap().metadata.modified > 1);
        fs.set_metadata("/b", old).unwrap();
        fs.unlink("/b/file").unwrap();
        let expected = fs.stat("/b").unwrap().metadata;
        assert!(expected.modified > 1);
        let before = fs.state.clone();
        assert!(fs.unlink("/b/missing").is_err());
        assert_eq!(fs.state, before);
        let fs = Volume::mount(fs.unmount().unwrap()).unwrap();
        assert_eq!(fs.stat("/b").unwrap().metadata, expected);
    }

    #[test]
    fn noncanonical_record_order_is_rejected_and_recovery_is_read_only() {
        let mut fs = Volume::format(MemDevice::new(16).unwrap()).unwrap();
        fs.create_file("/alpha", 0o600).unwrap();
        fs.sync().unwrap();
        let state = fs.state.clone();
        let mut payload = Vec::new();
        putv(&mut payload, state.next_id);
        putv(&mut payload, state.root);
        putv(&mut payload, state.objects.len() as u64);
        for (&id, object) in state.objects.iter().rev() {
            let single = State {
                objects: BTreeMap::from([(id, object.clone())]),
                ..state.clone()
            };
            payload.extend_from_slice(&encode_state(&single)[24..]);
        }
        assert!(decode_state(&payload).is_err());
        let inactive = 1 - fs.active_slot;
        let generation = fs.generation + 1;
        let mut device = fs.into_device();
        write_slot(&mut device, 16, inactive, generation, &payload).unwrap();
        let mut recovered = Volume::mount(device).unwrap();
        assert!(!recovered.recovery_warnings().is_empty());
        assert!(recovered.stat("/alpha").is_ok());
        assert!(recovered.create_file("/must-not-write", 0o600).is_err());
        assert!(recovered.sync().is_err());
    }

    #[test]
    fn metadata_and_directory_key_order_are_validated() {
        let mut fs = Volume::format(MemDevice::new(16).unwrap()).unwrap();
        fs.create_file("/entry-alpha", 0o600).unwrap();
        fs.create_file("/entry-bravo", 0o600).unwrap();
        let mut metadata = fs.stat("/").unwrap().metadata;
        metadata.extended.insert("key-alpha".into(), vec![]);
        metadata.extended.insert("key-bravo".into(), vec![]);
        fs.set_metadata("/", metadata).unwrap();
        let original = encode_state(&fs.state);
        for (first, second) in [
            (b"key-alpha".as_slice(), b"key-bravo".as_slice()),
            (b"entry-alpha".as_slice(), b"entry-bravo".as_slice()),
        ] {
            let mut payload = original.clone();
            let a = payload
                .windows(first.len())
                .position(|bytes| bytes == first)
                .unwrap();
            let b = payload
                .windows(second.len())
                .position(|bytes| bytes == second)
                .unwrap();
            payload[a..a + first.len()].copy_from_slice(second);
            payload[b..b + second.len()].copy_from_slice(first);
            assert!(decode_state(&payload).is_err());
        }
        assert_eq!(decode_state(&original).unwrap(), fs.state);
    }

    #[test]
    fn metadata_roundtrip_uuid_and_invalid_updates() {
        let mut fs = Volume::format(MemDevice::new(16).unwrap()).unwrap();
        let uuid = fs.uuid();
        fs.create_file("/a", 0o600).unwrap();
        fs.append_file("/a", b"first").unwrap();
        fs.append_file("/a", b"second").unwrap();
        let mut metadata = fs.stat("/a").unwrap().metadata;
        metadata.owner = 123;
        metadata.group = 456;
        metadata
            .extended
            .insert("content.type".into(), b"text/plain".to_vec());
        fs.set_metadata("/a", metadata.clone()).unwrap();
        let mut bad = metadata.clone();
        bad.extended.insert("oversized".into(), vec![0; 4097]);
        assert!(fs.set_metadata("/a", bad).is_err());
        let fs = Volume::mount(fs.unmount().unwrap()).unwrap();
        assert_eq!(fs.uuid(), uuid);
        assert_eq!(fs.stat("/a").unwrap().metadata, metadata);
        let mut bytes = [0; 11];
        fs.read_file("/a", 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"firstsecond");
    }
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
        fs.truncate_file("/data/b", 2).unwrap();
        let mut short = [0; 4];
        assert_eq!(fs.read_file("/data/b", 0, &mut short).unwrap(), 2);
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
    fn interrupted_header_commit_recovers_previous_generation() {
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
        assert_eq!(recovered.stat("/interrupted"), Err(FsError::NotFound));
    }

    #[test]
    fn bounded_mutations_and_reformat() {
        let mut fs = Volume::format(MemDevice::new(8).unwrap()).unwrap();
        fs.create_file("/a", 0o600).unwrap();
        assert_eq!(fs.write_file("/a", u64::MAX, b"x"), Err(FsError::NoSpace));
        assert_eq!(fs.truncate_file("/a", u64::MAX), Err(FsError::NoSpace));
        assert_eq!(fs.write_file("/a", u64::MAX, b""), Ok(0));
        assert!(fs
            .create_file(&format!("/{}", "x".repeat(256)), 0o600)
            .is_err());
        assert!(fs.create_file("/bad-mode", 0o1000).is_err());
        let capacity = slot_capacity(fs.blocks) - encode_state(&fs.state).len();
        fs.write_file("/a", 0, &vec![7; capacity]).unwrap();
        assert_eq!(fs.rename("/a", "/longer"), Err(FsError::NoSpace));
        assert!(fs.stat("/a").is_ok());
        fs.rename("/a", "/a").unwrap();
        fs.sync().unwrap();
        for _ in 0..3 {
            fs.write_file("/a", 0, b"z").unwrap();
            fs.sync().unwrap();
        }
        let fs = Volume::format(fs.into_device()).unwrap();
        let fs = Volume::mount(fs.unmount().unwrap()).unwrap();
        assert!(fs.list("/").unwrap().is_empty());
    }

    #[test]
    fn corruption_checks_include_generation_and_graph() {
        let mut fs = Volume::format(MemDevice::new(16).unwrap()).unwrap();
        fs.create_file("/old", 0o600).unwrap();
        fs.sync().unwrap();
        let slot = fs.active_slot;
        let blocks = fs.blocks;
        let mut dev = fs.into_device();
        dev.bytes[slot_offset(blocks, slot) as usize + 12] ^= 0x40;
        let fs = Volume::mount(dev).unwrap();
        assert_eq!(fs.stat("/old"), Err(FsError::NotFound));
        let mut state = fs.state.clone();
        state
            .objects
            .get_mut(&1)
            .unwrap()
            .entries
            .insert("loop".into(), 1);
        assert!(validate_state(&state).is_err());
    }

    /// Power-loss device: writes affect volatile bytes; flush publishes them.
    /// Every write/flush may fail after a prefix, modeling torn writes and
    /// uncertain flush outcomes without relying on host cache behavior.
    struct CrashDevice {
        live: MemDevice,
        stable: MemDevice,
        left: usize,
        prefix: usize,
    }
    impl BlockDevice for CrashDevice {
        fn len(&self) -> u64 {
            self.live.len()
        }
        fn read_at(&mut self, o: u64, b: &mut [u8]) -> Result<(), FsError> {
            self.live.read_at(o, b)
        }
        fn write_at(&mut self, o: u64, b: &[u8]) -> Result<(), FsError> {
            if self.left == 0 {
                let n = self.prefix.min(b.len());
                self.live.write_at(o, &b[..n])?;
                self.stable.write_at(o, &b[..n])?;
                return Err(FsError::Io("torn write".into()));
            }
            self.left -= 1;
            self.live.write_at(o, b)
        }
        fn flush(&mut self) -> Result<(), FsError> {
            if self.left == 0 {
                if self.prefix > 0 {
                    self.stable = self.live.clone();
                }
                return Err(FsError::Io("flush interrupted".into()));
            }
            self.left -= 1;
            self.stable = self.live.clone();
            Ok(())
        }
    }

    #[test]
    fn crash_matrix_preserves_entire_old_or_new_transaction() {
        let mut fs = Volume::format(MemDevice::new(32).unwrap()).unwrap();
        fs.create_file("/old", 0o600).unwrap();
        fs.write_file("/old", 0, b"before").unwrap();
        fs.sync().unwrap();
        let base = fs.into_device();
        for point in 0..7 {
            for prefix in [0, 1, 12, 28, 39, 4096] {
                let device = CrashDevice {
                    live: base.clone(),
                    stable: base.clone(),
                    left: point,
                    prefix,
                };
                let mut fs = Volume::mount(device).unwrap();
                fs.rename("/old", "/new").unwrap();
                fs.write_file("/new", 0, b"after!").unwrap();
                fs.set_metadata(
                    "/new",
                    Metadata {
                        owner: 123,
                        mode: 0o400,
                        ..Metadata::default()
                    },
                )
                .unwrap();
                let committed = fs.sync().is_ok();
                if !committed {
                    assert!(fs.create_file("/retry", 0o600).is_err());
                }
                let fs = Volume::mount(fs.into_device().stable).unwrap();
                fs.check().unwrap();
                let new = fs.stat("/new").is_ok();
                if committed {
                    assert!(new);
                }
                let path = if new { "/new" } else { "/old" };
                let mut bytes = [0; 6];
                fs.read_file(path, 0, &mut bytes).unwrap();
                assert_eq!(&bytes, if new { b"after!" } else { b"before" });
                assert_eq!(
                    fs.stat(path).unwrap().metadata.owner,
                    if new { 123 } else { 0 }
                );
                assert_eq!(fs.list("/").unwrap().len(), 1);
            }
        }
    }

    #[test]
    fn operation_sequences_match_reference_after_every_remount() {
        let mut fs = Volume::format(MemDevice::new(64).unwrap()).unwrap();
        let mut reference: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut seed = 47u64;
        for _ in 0..400 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let path = format!("/f{}", (seed >> 32) % 12);
            match seed % 4 {
                0 => {
                    if let std::collections::btree_map::Entry::Vacant(e) =
                        reference.entry(path.clone())
                    {
                        fs.create_file(&path, 0o600).unwrap();
                        e.insert(Vec::new());
                    }
                }
                1 => {
                    if let Some(data) = reference.get_mut(&path) {
                        let n = (seed >> 40) as usize % 100;
                        fs.truncate_file(&path, n as u64).unwrap();
                        data.resize(n, 0);
                    }
                }
                2 => {
                    if let Some(data) = reference.get_mut(&path) {
                        let offset = (seed >> 40) as usize % 80;
                        fs.write_file(&path, offset as u64, b"hello").unwrap();
                        data.resize(data.len().max(offset + 5), 0);
                        data[offset..offset + 5].copy_from_slice(b"hello");
                    }
                }
                _ => {
                    if reference.remove(&path).is_some() {
                        fs.unlink(&path).unwrap();
                    }
                }
            }
            fs = Volume::mount(fs.unmount().unwrap()).unwrap();
            assert_eq!(fs.list("/").unwrap().len(), reference.len());
            for (path, data) in &reference {
                let mut actual = vec![0; data.len()];
                assert_eq!(fs.read_file(path, 0, &mut actual).unwrap(), data.len());
                assert_eq!(&actual, data);
            }
        }
    }
}
