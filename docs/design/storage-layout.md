# Special_3 Storage Layout Contract

`hyber-layout` is the single Rust authority for the canonical user and
application-data namespace. It operates only through Hyber VFS, ObjectManager,
and NamespaceManager; it never accepts a host path or maps identities to host
UIDs/GIDs.

## Canonical paths

For user `alice` (UID `1000`) and application `editor`:

```text
/users/alice/Documents/
/users/alice/Downloads/
/users/alice/.config/editor/
/users/alice/.local/share/editor/
/users/alice/.local/state/editor/
/users/alice/.cache/editor/
/users/alice/.local/bin/
/runtime/users/1000/editor/
/temporary/users/1000/editor/
```

`AppLayout` constructs these paths only after validating both username and
application ID. Components are bounded, ASCII-only (`A-Z`, `a-z`, `0-9`, `.`,
`_`, `-`), and cannot be `.` or `..`. A home is accepted only when it is exactly
`/users/<username>`.

## Ownership and isolation

The system authority provisions global roots. Each user home, its private
subdirectories, `/runtime/users/<uid>`, and `/temporary/users/<uid>` is owned
by that Hyber user and starts at mode `0700`. This prevents sibling users from
traversing private trees. Application directories inherit the same owner and
mode. An unprivileged caller cannot create a layout for another user or adopt a
pre-existing directory owned by another identity.

This also applies to privileged provisioning: an existing foreign-owned home
is an error, not an implicit ownership transfer. Reprovisioning preserves the
mode and group of existing same-owner directories. Reusing an account name
with a new UID requires an explicit administrative data-migration decision.
Public layout fields are revalidated at mutation boundaries; changing a
derived application path cannot redirect provisioning or cleanup.

Service state is separate from user state:

```text
/data/services/<service-id>/
/runtime/services/<service-id>/
```

Shared data is under `/data/shared/<namespace>/`; creating a namespace requires
`CAP_SHARED_DATA_ADMIN`. The first implementation keeps it authority-owned
until a later ACL/group grant model deliberately widens access.

## Persistence, volatility, and cleanup

`config`, `data`, and `state` are persistent classes. `cache`, `temporary`, and
`runtime` are disposable classes. The cleanup API accepts only a user and one
of those disposable classes; it cannot receive an arbitrary path. It walks and
removes only children of the derived root, has depth/object safety limits, and
returns a `CleanupReport` containing the exact target and object count.

Cleanup preflights the complete tree before any removal. It refuses mount
points at or below the target, foreign-owned or non-live objects, active
references, aliases, unsupported object kinds, and depth/object-limit
violations. Unicode and spaces in ordinary filenames are supported (the
ASCII identifier restriction does not apply to user filenames). Provider I/O
failure during deletion is not transactional; the error reports the number
already removed. No cleanup operation deletes persistent classes.

The layout authority registers aggregate logical-byte quotas in VFS for each
user's config/data/state/cache/runtime/temporary tree and each service's data
and runtime tree. VFS checks file growth (including sparse offsets) before
writing. Overwrites without growth remain possible, deletion releases usage,
and empty writes do not grow files. Moving across quota domains or moving a
quota root/ancestor is rejected; use copy then remove. Fresh provisioning
rebuilds membership and usage from imported objects. These are hosted VFS
logical-file-byte limits, not native block, inode, or metadata quotas. Raw
provider and ObjectManager access is a trusted internal boundary.

The shell maps `/runtime` and `/temporary` to MemFS, so those locations are
lost at shell restart. HostFS stores versioned, checksummed Hyber ownership,
mode, timestamps, flags, and extended metadata in `user.hyber.metadata.v1`
xattrs. Metadata updates use atomic xattr replacement and a file sync; VFS
restores its previous metadata on error and HostFS refuses further operations
after uncertain writes until reopened. Host Unix ownership is never imported.
Names and contents survive restart; metadata follows rename. Corrupt records
fail import. The host filesystem must support user xattrs; its own xattr size
limit may be smaller than the codec's 60 KiB maximum and failures are surfaced.
A cooperating exclusive root lock prevents independent hosted writers from
using stale quota/accounting state. This does not protect against the host OS
owner editing files or attributes directly. Data and xattr updates are not a
single crash-atomic transaction; HyberFS's snapshot journal is a separate
storage contract. Legacy homes without trustworthy ownership require explicit
migration and are never silently reassigned.
Per-app paths also do not yet sandbox two applications running with the same
user identity; manifest-derived confinement belongs to Special_6.

## Lua API

The Lua runtime exposes logical paths only:

```lua
hyber.app.config_dir()
hyber.app.data_dir()
hyber.app.state_dir()
hyber.app.cache_dir()
hyber.app.temp_dir()
hyber.app.runtime_dir()
```

Lua still accesses these paths through `hyber.fs`, so VFS traversal, object
permissions, handles, and session revalidation remain authoritative. No API
returns a Linux path.
Before Lua executes, the supplied layout is validated and its user must match
the current execution/session identity.
