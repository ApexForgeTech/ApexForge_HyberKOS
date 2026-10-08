# Phase 18 hosted service manager

The Rust supervisor now runs actual Lua and Go payload processes. The hosted
implementation targets Linux x86-64 with `/usr/bin/bwrap`, user namespaces and
seccomp available. Missing isolation support is a launch failure, not a reason
to execute without a sandbox. This is not the native service runtime of Phase 28.

## Ownership and activation

`hyber-service` owns lifecycle, dependency readiness, restart budgets and service
sessions. `hyber-service-host` privately owns host processes and pipes;
`hyber-serviced` owns the persistent supervisor loop and authenticated operator
socket. Linux PIDs, descriptors and host paths are not service identifiers.

The daemon loads the installed Phase 17 registry, revalidates its artifacts and
trust records, and activates only explicitly selected `package=user` mappings.
Each package contains a signed `service.lua` and the signed manifest entrypoint.
Identity is an existing Special_2 service account chosen by the operator, never
an identity supplied by Lua. Definitions are registered atomically and the hosted
catalog is limited to 64 services. The package image stays read-locked for the
daemon lifetime: shut down the daemon before updates or trust changes. Activation
and enable/disable overrides are session-local; signed startup policy is loaded
again on daemon restart. This is intentional, not a persistent policy editor.

Definitions are bounded, data-only Lua tables. Unknown fields, invalid types,
duplicate/sparse lists, cycles, absent dependencies, endpoint collisions and
unapproved capabilities fail validation. Go declarations additionally specify
`max_concurrency` and optional ordered `arguments`. See the two example packages
in `examples/lua-service` and `examples/go-service`.

## Lifecycle and authority

Automatic services start after all their dependencies are ready. Manual `start`
queues the dependency closure. `stop` refuses live dependents, revokes dispatch
authority and waits for observed process exit; it never equates a stop request
with an exit. Stop timeout is 10 seconds; readiness timeout is 30 seconds.
An uncooperative worker is killed and reaped before its Hyber process objects
are reclaimed. Manual stop cancels retry. Abnormal exits with `on-failure` use
a five-retry budget and exponential backoff capped at 32 seconds. Stale events
cannot affect a replacement process.

Every operator request authenticates independently and requires `CAP_SYS_ADMIN`.
Passwords are terminal prompts, not command arguments or persisted configuration.
Interactive client logout does not revoke the independent service session.
The hosted authority and service sessions have bounded lifetimes (currently one
hour for daemon authority); expiry or credential-store change fails closed and
stops payloads. This is a hosted administrative adapter, not a renewable native
login daemon. The host user running it is trusted; it does not protect against
that same host user or host root modifying the executable or authority files.

The socket must be in a host-user-owned private directory, mode 0700, and is
created with mode 0600. Existing socket paths are never overwritten. Normal
shutdown removes the socket; after abrupt termination the operator must verify
the old daemon is gone before removing that specific stale socket. Closing an
attached shell does not stop the daemon. Killing the daemon kills its sandboxed
children; native reboot persistence and init supervision remain later work.

## Payload boundary and resource policy

Payloads run with a read-only minimal root, no host home/configuration mount,
no network, no inherited credentials, and no writable filesystem. Payloads and
seccomp filters are sealed anonymous files. Seccomp rejects process creation,
network sockets and namespace manipulation while allowing runtime threads.
Lua additionally has no host I/O, module loader, dynamic compilation or protected
calls that could swallow cancellation. Payload stderr is not a control channel.

Memory/address-space and descriptor limits are kernel-enforced. Lua heap uses
half the memory grant and periodically checks cancellation. At least 64 MiB and
16 descriptors are needed for hosted startup. Go's `GOMEMLIMIT` uses half the
grant, and `GOMAXPROCS` reflects declared concurrency. Go should be statically
built (`CGO_ENABLED=0`); its runtime reserves substantial virtual address space,
so the example grants 2 GiB. CPU shares map to relative host priority, with
additional Lua instruction throttling; they are **not** a hard CPU bandwidth
quota. Go concurrency is cooperative, not an adversarial thread-count limit.

This initial hosted worker exposes lifecycle and bounded logs only. Storage
grants do not yet expose filesystem methods inside this worker; writable storage
is denied entirely. Network requests are rejected until Phase 20. It is not the
full `hyber run` Lua application API. General inter-service channels, RPC and
shared memory remain Phase 19; endpoint reservation is not endpoint delivery.
These limits must not be represented as a general-purpose production sandbox.

Private newline-delimited JSON messages over backend pipes are:

```text
payload -> supervisor: {"op":"ready"}
payload -> supervisor: {"op":"log","message":"bounded text"}
supervisor -> payload: {"op":"stop"}
```

The effective frame bound is the smaller of 8192 bytes and the declaration's
`max_message_bytes`. Invalid messages or invalidated sessions terminate the
payload. Log text is bounded and escaped for terminal output; the in-memory
128-entry ring is lossy, not a durable logging service. `logs` drains the ring
with a 16 KiB output bound. Lua uses `hyber.service.ready()`,
`hyber.service.stopping()`, `hyber.service.wait(milliseconds)` and
`hyber.log.info(text)`. This private protocol is not the deferred public ABI.

## Build and operate

```sh
cargo build --workspace
# Build the Go example separately before packaging its directory:
(cd examples/go-service && CGO_ENABLED=0 go build -o main .)
```

Use the existing Phase 17 signing/trust workflow (32-byte raw Ed25519 key files).
For an existing authenticated package image and a separately protected signing
key, the Lua example workflow is:

```sh
target/debug/hyber-pkg build examples/lua-service worker.hybp example-key private.key
target/debug/hyber-pkg trust-add system.img 4096 root example-key example public.key
target/debug/hyber-pkg import system.img 4096 root worker.hybp
target/debug/hyber-pkg install-service system.img 4096 root lua-worker@1.0.0
target/debug/hyber-auth-tool user-add system.img 4096 worker service
```

Initialize a new image first with `hyber-auth-tool init` and `hyber-pkg init` if
necessary; never reinitialize an existing store. The block count must match the
actual image. `install-service`/`update-service` explicitly approve only requested
`service.background`, not network/device capabilities. Ordinary install retains
deny-all policy. Keep signing keys and output artifacts outside the staging tree.

After creating a private socket directory, run in one terminal:

```sh
target/debug/hyber-serviced serve system.img 4096 root system.img 4096 /private/directory/services.sock lua-worker=worker
```

In another terminal:

```sh
target/debug/hyber-serviced ctl /private/directory/services.sock root status lua-worker
target/debug/hyber-serviced ctl /private/directory/services.sock root restart lua-worker
target/debug/hyber-serviced ctl /private/directory/services.sock root logs
target/debug/hyber-serviced ctl /private/directory/services.sock root shutdown
```

For shell attachment, put `--service-socket` first:

```sh
target/debug/hyber-shell --service-socket /private/directory/services.sock --auth system.img 4096 root
```

`svc status`, `svc start/stop/restart/enable/disable <id>`, `svc logs`, and
`svc shutdown` use the same authenticated endpoint. `lssvc` and
`/services/<id>` expose the actual daemon catalog, not bootstrap placeholders.
The catalog is fixed for that attachment; reconnect after changing activation.
Provider reads prompt per authenticated request (including subsequent reads);
credentials are not cached by the VFS provider. Without attachment, development
shell placeholders are not running services.

## Object, handle and permission audit

The shell's remote Service Objects are private administrative projections owned
by the attaching administrator, not by the payload identity. The directory is
0500 and service entries are 0400. Payload Process and Thread Objects instead
carry the attenuated service identity and 0400 permissions. Process state and
service lifecycle state remain distinct from Object reference lifetime.

VFS checks both owner/group permissions and provider-supported rights before
allocating a handle. Service projections reject WRITE, EXECUTE, DELETE, RENAME,
CONNECT, WAIT and SIGNAL even for root: lifecycle authority is not a file
handle permission. Secure reads recheck current Object metadata and handle
rights; wrong-process and closed handles fail. Closing releases the retained
Object reference. Projection metadata is supervisor/adapter-owned; chmod,
chown and extended-metadata mutation through VFS fail and restore the previous
Object metadata. Shell/Lua rights introspection includes provider restrictions.

Dependent dispatch revalidates the entire dependency closure with a visited set.
A revoked or unavailable dependency causes dependent shutdown before its parent
can finish stopping. Failed graceful-stop delivery still revokes the session
and starts the forced-stop deadline, without discarding the live process ID.
Explicit administrative start after retry exhaustion resets the failed state
and retry budget; automatic retries remain bounded.

These are trusted Rust-internal managers. Raw ObjectManager/HandleManager access
is not a sandbox boundary. Hosted worker pipes are private backend resources,
not exported Hyber handles; general inter-service handle transfer and IPC remain
Phase 19. Virtual status content is generated on read, so Object `size` is not
a durable status-file length and payload state is obtained through status reads.

## Verification

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

After building the workspace, exercise actual shell attachment in a PTY too:

```sh
HYBER_SHELL_TEST_BINARY="$PWD/target/debug/hyber-shell" cargo test -p hyber-serviced --test daemon
```

Hosted integration tests require working bubblewrap/user namespaces and the Go
compiler; they fail rather than silently skip a missing backend. Tests cover
real Lua readiness/stop, infinite-loop cancellation, memory/frame bounds,
revoked-session dispatch, real Go denial of host file/socket/process access,
signed-package activation, non-admin denial, client independence, restart with a
new Hyber process ID, stop/disable/enable and daemon shutdown. Deterministic
supervisor tests cover graph/order, failures, budgets, stale events, deadline
termination and read-only projection separately. These tests are not physical
power-loss tests or a production security certification.

Backend references: [bubblewrap](https://github.com/containers/bubblewrap/blob/main/README.md)
and [Linux seccomp filters](https://docs.kernel.org/userspace-api/seccomp_filter.html).
