# Special_8 Integration and Migration Gate

Phase 17 must consume, rather than replace, the identity, session,
storage-layout, manifest, capability, shell, and service contracts.

`hyber-gate` validates a `MigrationDecision` for every incompatible cross-layer
change. Such a decision needs a monotonic target version, affected layers,
explicit migration steps, and rollback steps. It rejects missing evidence.

Its integration tests remount a HyberFS volume containing account and app data,
then authenticate the persisted user. They also exercise profile aliases and
history navigation through one controller. Existing dedicated corruption,
session-revocation, application-sandbox, input, profile, layout, and
service-contract tests remain mandatory workspace evidence.

This gate does not implement a package manager, supervisor, IPC, networking,
or durable application registry.
