# Identity and session integration

`hyber-identity` implements Special_1; `hyber-auth` implements the Special_2
hosted user-space authority. They use Hyber IDs and never import host accounts.
The raw Rust registry, volume, and manager interfaces are trusted internals.
They are not callable directly by an untrusted application or Lua profile.

## Identity persistence

Identity snapshots start with eight bytes `HYBID01\0`, then a little-endian
u64 FNV-1a checksum of the remaining payload. Payload scalar fields are
little-endian u64: version (2), revision, next user ID, next group ID, user
count, users, group count, groups. IDs must fit u32. Strings carry a u64 byte
length followed by UTF-8 bytes. A user has ID, name, primary group, home,
one-byte state (active=1, locked=2, disabled=3, service=4, guest=5), supplementary
group count/IDs, capability count/strings. A group has ID, name, member count/IDs.
Encoding sorts IDs and sets. Decoder rejects truncation, overflow, unknown
versions, duplicate entries/names/homes, non-monotonic allocation, and invalid
reverse membership. Root (0) is reserved; automatic IDs start at 1000.

The root account is active, home `/users/root`, primary group 0, and carries
CAP_SYS_ADMIN. Home paths must be exactly `/users/<safe-name>` and unique.
These are logical ownership declarations. Physical directories, quotas,
service data paths, and cleanup are Special_3 responsibilities.

## Authentication store

`AuthService` encapsulates the registry and credentials. The store envelope
is `HYBAUTH1`, a 32-byte SHA-256 checksum, then bounded UTF-8 JSON (version 1).
The JSON contains the identity snapshot bytes, credential records, and audit
records. Serde rejects unknown fields and duplicate fields. Each credential
references an existing Hyber user, a PHC hash, and optional account/password
expiry times (Unix seconds). No plaintext password or session token is encoded.

Passwords use RustCrypto Argon2id v19, m=19456 KiB, t=2, p=1, 32-byte output,
and random 16-byte salts. Loaded parameters must match this policy; accepting
arbitrary PHC costs would permit excessive work or weaken verification. New
passwords must contain 12..1024 bytes. Terminal buffers are zeroed on drop.
Borrowed password buffers supplied by other trusted callers remain their
responsibility. Cryptographic implementation details follow the
[RustCrypto Argon2 API](https://docs.rs/argon2/0.5.3/argon2/).

Snapshots are bounded to 4 MiB and stored with root-owned mode 0600. The hosted
image should remain outside `~/hyber-host`, application roots, and shared
directories. Newly created Unix images are mode 0600. Checksums detect damage;
an attacker who controls the image or trusted host process can rewrite it.
Full-disk encryption and protection from a malicious host are not implemented.

The authority stages mutations in memory. `save` commits accounts, credentials,
and audit together with `Volume::replace_file` + `sync`. A caller must not
acknowledge durable administration until save succeeds. On an uncertain I/O
failure discard/remount the writer and reload; do not retry with stale state.
The CLI holds an exclusive image lock through administration. Read-only
adapters hold shared locks while reading. Credential loading rejects degraded
slot recovery rather than quietly reactivating an old password.

## Session authority and dispatch

Session tokens have 256 random bits, private fields, redacted Debug, and
zeroization on drop. The authority retains SHA-256 token digests. Sessions are
bounded to 4096, live for 1..86400 seconds, and are never persisted. A snapshot
restore therefore invalidates every old session. Expiry is exclusive: a token
is invalid at exactly its expiration time. Backwards time revokes all sessions.

Every trusted dispatch must use `SessionGuard::context()`, not a previously
cached SecurityContext. It supplies primary/supplementary groups and explicit
capabilities. Editing an account invalidates its sessions; password rotation
invalidates all of that user's sessions. Logout revokes shared guard clones.
Service accounts cannot password-login interactively; a live admin session
issues their separate service token. Caller/GUI logout leaves it running.

Unknown names and invalid passwords return the same public failure and perform
Argon2 verification (using a dummy record when needed). Five failures impose
a 30-second authority-wide cooldown. Network-facing deployments still need
their own ingress rate limits and a long-lived shared authority.

Audit entries contain sequence, timestamp, actor, action, and optional target;
they never contain secrets. The prototype keeps at most 4096 entries and
fails closed at capacity. Logout still revokes before audit errors. Persistent
audit rotation/export is future service infrastructure, not silent truncation.

## Hosted commands

```sh
cargo run -p hyber-auth --bin hyber-auth-tool -- init ./identity.img 256
cargo run -p hyber-auth --bin hyber-auth-tool -- user-add ./identity.img 256 alice
cargo run -p hyber-shell -- --auth ./identity.img 256 alice
cargo run -p hyber-cli --bin hyber -- run --auth ./identity.img 256 alice ./main.lua
cargo run -p hyber-auth --bin hyber-auth-tool -- lock ./identity.img 256 alice
cargo run -p hyber-auth --bin hyber-auth-tool -- check ./identity.img 256
```

Passwords are read from the controlling terminal without echo. Never put them
in argv, environment variables, scripts, or a shell history file. Hosted guards
fingerprint the persisted store on each dispatch and fail closed on changes,
damage, or unreadability; another administrator's changes revoke old adapters.
These adapters do not implement a shared system-wide IPC login daemon.
Unlock requires an explicit target state: `unlock <image> <blocks> <username>
<active|service|guest>`. This prevents a locked service account from implicitly
becoming an interactive account. The administrative choice is audited.

No-argument shell and ordinary `hyber run` remain trusted development modes.
The HostFS shell imports a development tree with prototype metadata; it does
not yet provide Special_3 home ownership provisioning or persist VFS ACLs.
The authenticated Lua app runner owns a private MemFS namespace. Applications
do not receive the authority object. Lua has no host io/os/package/debug or
filesystem loader globals; it revalidates Hyber calls and instruction hooks.

ProcessManager receives the same context, but its scheduling/lifetime code is
not a native session daemon. ServiceManager provides authenticated start and
per-dispatch validation; native process termination and IPC enforcement remain
runtime work. Revocation denies subsequent guarded operations; it does not
retroactively erase already returned bytes or reclaim unguarded trusted calls.

## Verification

Run workspace tests, clippy with warnings denied, format checking, and
`hyberfsck` against clean/damaged disposable images. Tests cover identity
corruption with recomputed checksums, supplementary groups, atomic account
edits, password/expiry/state/session transitions, service independence,
credential round trips, malformed payloads, and Lua revocation/host isolation.
