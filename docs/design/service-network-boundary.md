# Service and Network Boundary (Special_7)

`hyber-service-contract` is the versioned, Rust-owned hand-off between an
application grant and a future service supervisor/network implementation. It
does not start a service and it does not open a socket.

A definition contains a service ID, an application ID, Hyber `UserId` and
`GroupId`, dependency IDs, startup/restart/health policy, IPC endpoints, a
payload declaration, and an exact socket policy. The definition is valid only
when its application has an approved `service` execution mode and the
`service.background` capability. Every service capability must be in the
application's approved grant; requested manifest permissions are never enough.

Lua supplies only a restricted data table represented by `LuaServiceTable`.
Callbacks, userdata, and arbitrary Lua functions never become supervisor
authority. The Rust adapter accepts only version 1, `manual`/`automatic`
startup, `never`/`on-failure` restart policy, `none`/`ipc-readiness` health
checks, validated IDs, bounded dependencies, and bounded IPC message sizes.

Go payloads provide a module identity, bounded arguments and concurrency, and
must declare cooperative cancellation. They are not host command lines. A
future launcher selects the Go runtime and supplies its Hyber IPC context.

Socket intent must exactly equal the application grant's network policy and
requires the matching approved `network.outbound` or `network.inbound`
capability. The contract supplies no host socket handle or adapter.

`ServiceCatalog` validates missing dependencies and cycles and gives a stable
dependency-first launch order. Phase 18 will consume this contract to implement
actual lifecycle, readiness, crash handling, and supervision; Phase 20 will
consume the socket policy for a Hyber socket API.
