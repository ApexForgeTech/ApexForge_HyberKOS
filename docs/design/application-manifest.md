# Special_6 application manifest and sandbox contract

`hyber.toml` is an untrusted request, never an authority document. It uses
format version 1 and must declare an application ID, `major.minor.patch`
version, publisher, display name, relative entrypoint, runtime, execution
mode, storage scopes, network policy, and bounded resource requests.

```toml
format_version = 1
app_id = "example.editor"
version = "1.0.0"
publisher = "example"
display_name = "Example Editor"
entrypoint = "main.lua"
runtime = "lua"
execution = "background"

[storage]
config = "read-write"
data = "read-write"
state = "read-write"
cache = "read-write"
temporary = "read-write"
runtime = "read-write"

[resources]
memory_bytes = 67108864
cpu_shares = 100
handles = 64
storage_bytes = 67108864
```

Storage values are `none`, `read`, or `read-write`. They refer only to the
canonical logical paths produced by `AppLayout`; the manifest never supplies a
host path. `hyber-manifest` rejects absolute or escaping entrypoints, unknown
fields/capabilities, invalid resource bounds, malformed network domains, and
incoherent GUI/service/network declarations.

## Approval and launch

The trusted installer or administrator creates a `GrantPolicy`. It checks every
requested capability, execution mode, and resource value, then produces an
`ApplicationGrant`. The manifest alone cannot grant capabilities. The hosted
`hyber run <directory>` launcher currently uses a deny-by-default policy, so a
manifest requesting a capability needs a future authenticated policy/installer
to approve it; it is never silently accepted.

The launcher builds an `ApplicationSandbox` from the approved grant and the
current user's `AppLayout`. Lua filesystem, namespace, metadata, access-check,
logical-directory, and process-spawn entry points consult this sandbox before
VFS. Thus owner/group permissions are necessary but not sufficient: an app
cannot access a sibling app's directory even when both run as the same user.
Its aggregate logical file size across six own roots is checked before a Lua
write against `resources.storage_bytes`.

Memory, CPU, and handle requests are validated and passed through the grant
contract, but the current hosted single-process runtime has no scheduler or
allocator enforcement mechanism. They are deliberately not described as
enforced limits. Native runtime enforcement belongs to later process/kernel
phases. Network, GUI, and service requests are likewise explicit and require
grants; unsupported runtime operations are not exposed as a bypass.

`ManifestRegistry` retains ordered approved versions, refuses duplicate or
downgrade installs, and can roll back one active version without re-parsing or
changing the grant contract. Phase 17 persists and signs that registry; it must
consume this model rather than define a second manifest meaning.

Direct `hyber run file.lua` remains an explicitly trusted Phase-14 developer
mode, not a manifest application launch. It has no manifest sandbox and must
not be used as a package/service execution path.
