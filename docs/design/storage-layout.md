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

The layout policy declares explicit byte quotas for every class. Providers or
future write mediators must call `Quotas::check_quota` before committing a new
allocation; the current VFS provider trait has no quota callback, so this
hosted foundation does not claim kernel-enforced write quotas yet.

The shell maps `/runtime` and `/temporary` to MemFS, so those locations are
lost at shell restart. HostFS currently persists path contents but not Hyber
owner/group/mode metadata across a fresh shell import. Persistent ownership
metadata therefore requires the planned persistent provider integration; it
must not be substituted with host Unix ownership.

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
