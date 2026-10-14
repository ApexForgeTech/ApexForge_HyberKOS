# Hosted networking contract

Phase 20 provides outbound TCP/UDP through a Rust-owned policy and object
boundary. This is a hosted implementation, not a native network stack or a
production security certification.

## Authority and objects

`hyber-network` owns Socket Objects, process-local handles and authorization.
`hyber-network-host` owns host sockets and resolver results. Each connection is
bound to its original process, handle, user and approved application grant.
Reads, writes and inspection recheck current object permissions, handle rights,
and both the original and current grant. Copying a handle does not transfer a
network endpoint. Mutating a manifest after approval invalidates its capability
grants; policy changes require approval again.

Trusted dispatchers must authenticate the supplied security context. Lua and
service dispatchers revalidate session guards, including after blocking I/O.
Revocation cannot undo bytes already transmitted before it was observed.
Closing an owned resource does not require a still-valid grant: revocation must
not prevent cleanup. Failed provider closes remain registered for retry.
Lua close is idempotent; raw manager use of an already-reclaimed handle returns
an invalid-handle error. Timeouts, WouldBlock and oversized datagrams do not
poison the connection; fatal transport failures do.

Interface inventory uses root-owned Device Objects with
`network.class = "interface"`, stable ObjectIds while present, and synthetic
names. It requires `CAP_SYS_ADMIN`. `net interfaces` exposes this inventory in
the shell without host interface names. Manager authorization audit retains the
latest 128 connect/resolve decisions; it contains no payloads or raw addresses.

## Bounds and transport semantics

- A manager permits at most 4096 sockets, also respecting the application's
  process handle limit before connecting.
- Core reads/writes are at most 65536 bytes; UDP writes at most 65507 bytes.
  TCP writes may be partial and callers must loop. Empty TCP reads mean EOF;
  empty UDP reads are valid datagrams. An oversized received UDP datagram is
  consumed and returns `MessageTooLarge`, never silent truncation.
- Hosted operation timeout defaults to five seconds; configuration is clamped
  to 1 ms–30 s. TCP resolution and address fallback share a connection deadline.
- Resolver answers are bounded to 16, cache entries to 128, and outstanding
  resolver threads to four across providers. Timed-out libc resolution cannot
  be cancelled, so its worker keeps its permit until completion.
- Cache expiry is a local maximum of 30 seconds, **not authoritative DNS TTL**.
  Resolution diagnostics return counts and expiry, not host IP addresses.

Domain policy is checked before resolution. Canonical names match exact names
or dot-delimited suffixes. Literal IPs and alternative numeric spellings are
rejected. This is name-based policy, not DNSSEC, address pinning, CIDR filtering,
SSRF protection against an approved domain resolving privately, or TLS. Do not
grant untrusted domain control where those additional protections are needed.

## Lua and service integration

Generic Lua execution defaults to an unavailable transport. A trusted
composition root explicitly injects a provider with an approved application
grant using `run_lua_script_with_application_network`. Merely requesting a
capability in a manifest or running inline shell Lua does not grant networking.
Sockets are opaque userdata; this runtime offers connect, read, write, wait, inspect,
close and resolution diagnostics. Invocation completion or error closes its
sockets; separate shell Lua invocations do not share a VM or socket state.

Hosted services use a Rust broker while their child sandbox continues to deny
host socket creation. The broker validates the service definition, application
grant and service session. Its ObjectManager and HandleManager are scoped to
that broker and are not the shell's object registry. Each service has one
request in flight, bounded channels and at most 512 payload bytes per request.
The existing service IPC frame limit must be at least 4096 bytes. The worker
Lua binding supplies connect/read/write/wait/inspect/close and policy-checked resolution
diagnostics, with binary data support.

The private JSON transport uses `op=network`, a nonzero correlation `id`, and
an `action` of connect/write/read/wait/inspect/close/resolve. Responses use `op=network-result`, the
same id, `ok`, and either `result` or a redacted `error`. This is a provisional
hosted service protocol, not a public ABI. Optional Go payloads must use the
same broker protocol and sandbox; they receive no native socket authority.

There are at most 64 live broker workers. Transport operations time out after
two seconds. Supervisor polling never waits on socket I/O: stop/revocation
cancels the worker client immediately and broker cleanup follows when its
bounded current operation returns. Service exit closes all its sockets, even
when Lua throws or omits close. Caller shell lifetime does not own the service.

## Verification and remaining boundaries

Hosted outbound v1 acceptance maps to the following executable coverage:

| Requirement | Coverage |
| --- | --- |
| Grant, identity, rights, quotas, lifecycle | `hyber-network` unit tests |
| TCP/UDP, resolver cache, readiness and datagram bounds | `hyber-network-host` loopback tests |
| Opaque application sockets and error cleanup | `hyber-lua` injected-provider tests |
| Service policy, cancellation, metadata, administrator diagnostics | `hyber-serviced/tests/hosted.rs` |
| Service independence and authenticated activation | `hyber-serviced/tests/daemon.rs` |

Completion is for this hosted v1 scope. It is not a guarantee of absence of
defects, a frozen ABI, DNS security or native-device qualification.

Tests cover grant tampering, permission changes, wrong/copied handles, capacity,
retryable failures, cleanup after raw handle close, interface identity, resolver
cache expiry, TCP/UDP loopback, empty/oversized datagrams, Lua error cleanup,
service destination denial and stop during blocked receive. They require no
public Internet. Run:

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

`socket:wait("readable" | "writable", timeout_ms)` provides advisory readiness.
It requires WAIT and the corresponding READ/WRITE right and rechecks authority.
Zero timeout is a poll; the core limit is 30000 ms and service limit is 2000 ms.
Readiness includes EOF/error notification, not a promise that I/O succeeds.
Host descriptors remain private to the polling provider.

`socket:cancel()` is the v1 network signal: it requires SIGNAL and WRITE,
closes the endpoint transport and leaves the handle inspectable until close.
Repeated cancellation is harmless; close after cancellation does not close the
transport twice. This is not TCP half-close or arbitrary process signalling.

`HostedRunner::network_diagnostics` takes a current administrator SessionGuard
and aggregates all live broker snapshots without waiting on transport I/O.
Each record retains service, process, handle and ObjectId qualifiers because
ObjectIds are broker-local. Snapshots reflect the last completed request, not
live intermediate I/O state; they disappear when the service is reaped.
The snapshot contains logical metadata only and is not an authority token.

Inbound sockets remain unsupported. Native drivers/protocol stacks are Phase
27. Public cross-language ABI/bindings belong to the deferred API phase; Go is
optional and the hosted JSON broker protocol is not a frozen Go SDK.
