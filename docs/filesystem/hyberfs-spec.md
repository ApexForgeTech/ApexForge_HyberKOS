# HyberFS Phase 15 Prototype Format

This document specifies the current user-space HyberFS prototype. It is a
portable format description, not a native-kernel ABI.

## Physical layout

All values are little-endian fixed-width integers. The device size is a whole
number of 4096-byte blocks and must contain at least eight blocks.

```text
block 0                 superblock
blocks 1..N             slot 0 (copy-on-write committed state)
remaining blocks        slot 1 (copy-on-write committed state)
```

The two slots have equal capacity. A slot contains a 40-byte header followed by
one encoded state payload. The newest valid generation is selected at mount;
the superblock records the active slot but a valid generation remains the
recovery authority if the superblock update was interrupted.

## Superblock

```text
bytes 0..7      magic: HYBFS15\0
bytes 8..11     format version: 1
bytes 12..19    device block count
byte  20        active slot (0 or 1)
bytes 24..31    committed generation
bytes 32..39    FNV-1a-64 checksum of bytes 0..31
```

The implementation rejects bad magic, unsupported versions, invalid alignment,
invalid checksums, and a device smaller than the minimum.

## Slot header

```text
bytes 0..7      magic: HYBFS15\0
bytes 8..11     format version: 1
bytes 12..19    generation
bytes 20..27    payload length
bytes 28..35    FNV-1a-64 payload checksum
bytes 36..39    reserved, must be zero when written
```

Payloads that exceed slot capacity, fail checksum validation, or contain
invalid records are rejected.

## State payload

The payload contains `next_object_id`, `root_object_id`, and an object count,
followed by object records. Each record has an explicit object ID, object kind,
owner, group, mode, timestamps, data length/data bytes, and directory-entry
count. Directory entries store a length-prefixed UTF-8 name and child object
ID. Rust memory layouts are never written directly.

The root is object ID 1 and must be a directory. IDs are monotonic and are not
reused. Every directory reference must target an existing object, all objects
must be reachable from root, and the graph must not contain cycles. Files may
not contain directory entries; directories may not contain file data.

## Operations and atomicity

Mutations update an in-memory state and are committed by writing the complete
new payload to the inactive slot, flushing it, then updating and flushing the
superblock. A failed mutation does not mark a partial state as committed. A
failed mount exposes no state. Phase 16 will add fault injection, recovery
repair, and broader checksum coverage.

## Path and error rules

Only absolute paths are accepted. Empty components are ignored; `.` and `..`,
embedded NULs, empty names, names longer than 255 bytes, and path separators
inside a name are rejected. Operations return typed errors for missing objects,
wrong object type, duplicate names, cycles, busy non-empty directories, no
space, corruption, unsupported versions, and I/O failure.

## Scope

This prototype uses serialized state snapshots and slot-capacity accounting.
It intentionally does not claim native block-device data extents, encryption,
compression, snapshots, deduplication, or kernel VFS integration. Those require
later native storage phases and a versioned format migration plan.
