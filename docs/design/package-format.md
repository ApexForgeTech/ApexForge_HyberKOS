# Phase 17 Package Artifact Format

This document specifies the first hosted `.hybp` artifact implemented by
`hyber-package-format`. It is an artifact format, not a host archive format,
and it never stores host paths, inode values, UIDs/GIDs, permissions, or
compiler layouts.

## Trust boundary

All artifact bytes are untrusted until they pass structural parsing, digest
verification, Ed25519 signature verification, and an external `TrustStore`
policy check. The artifact's publisher and key ID are assertions; only the
trusted public-key record determines whether they are acceptable.

`hyber.toml` is included as bytes and parsed through `hyber-manifest`. It is a
request for an `ApplicationGrant`, not authority. A package cannot add a
capability beyond that manifest or an administrator's `GrantPolicy`.

## Outer encoding

All integers are unsigned little-endian. The exact signed byte sequence is:

```text
magic[8] = "HYBPKG1\\0"
format_version: u32 = 1
canonical_body_length: u64
payload_digest: [u8; 32] = SHA-256(canonical_body)
key_id: length-prefixed UTF-8 string
canonical_body: bytes
signature: [u8; 64] = Ed25519(signature over every preceding byte)
```

There are no trailing bytes. Signature verification is intentionally separate
from structural decoding so a repository can report an invalid signature
without trusting the contents. The trusted manager must always verify before
import or activation.

## Canonical body

The body is length-delimited fields in this order:

```text
package ID
package version: major u64, minor u64, patch u64
application ID
publisher
dependency count + dependency records
exact application manifest (`hyber.toml`) bytes
file count + file records
```

A dependency record is package ID, one-byte requirement kind (`0` exact, `1`
minimum inclusive), then a three-part version. Files are sorted by relative
UTF-8 path bytes before encoding. Dependencies are sorted by package ID. Each
file record is its relative path and exact data bytes, both length-prefixed.

The format validates before encoding and after decoding:

- maximum artifact, manifest, file, path, dependency, and file-count bounds;
- strict `major.minor.patch` versions with no leading zeroes;
- no absolute paths, `.`/`..`, empty components, backslashes, control bytes,
  duplicate paths, symlinks, or special files;
- one matching application manifest, publisher, application ID, and version;
- presence of the application manifest's entrypoint in the payload;
- SHA-256 body digest and exact Ed25519 signature.

## Staging convention

The hosted builder reads a real staging directory containing:

```text
package.toml  package ID and dependency declarations; build control only
hyber.toml    Special_6 application request; included application content
main.lua      or another manifest entrypoint
...           regular application assets
```

`package.toml` is excluded from the installed payload. The builder walks only
regular files, sorts every directory listing, rejects symlinks/special files,
and constructs logical relative paths only. Artifact publication uses a flushed
temporary file and an atomic no-replace publish by default; replacement needs
an explicit force mode.

## Registry relationship

Repository artifacts are addressed by SHA-256 of their complete encoded bytes.
The registry snapshot records package version, artifact digest, approved
capability set, installer Hyber user ID, and ordered activation history; it
does not contain private keys. On reload it resolves every record back through
the repository and verifies each active artifact under the current trust
policy. A revoked/disabled key therefore cannot remain active after reload.

## Hosted transaction store

`HyberFsPackageStore` persists Phase 17 authority state in the same Phase
15/16 HyberFS volume as the authenticated account store:

```text
/packages/.state/trust                 checksummed public-key policy
/packages/.state/registry              activation/grant registry
/packages/.state/artifacts/<sha256>.hybp
/apps/<application-id>/.hyber-package-owner
/apps/<application-id>/<version>/...   immutable materialized payload
```

It prepares artifacts, package trees, trust state, and registry state before a
single volume `sync()`. On reopen it verifies the trust checksum, artifact
names/digests/signatures, active grants, owner marker, and installed files.
Damage or a revoked key fails closed. Mutating `hyber-pkg` commands first
require a Special_2 interactive session with `CAP_SYS_ADMIN`. The current CLI
uses an explicit deny-all capability policy; packages requesting capabilities
are rejected rather than silently receiving authority.
