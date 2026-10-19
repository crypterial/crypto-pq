# Versions

| specification | status | date |
|---|---|---|
| SPEC 1.0 | release candidate | 2026-10-19 |

## Specification versions and package versions

The rules below restate [Section 20.1](20-versioning.md#201-versions) and
[Decision D-66](decisions.md#decision-d-66).

1. Each crypto-pq package (Rust, Go, Zig, TypeScript and Python) follows Semantic Versioning 2.0.0 and
   is released on its own.
2. A package's MAJOR.MINOR equals the version of this specification that it implements: every 1.0.x
   package implements SPEC 1.0. PATCH is counted per package.
3. The first production release of each package is 1.0.0, preceded by release candidates 1.0.0-rc.N.
4. A package release starts from a signed, annotated tag `<language>-vX.Y.Z` (for example
   `rust-v1.0.0`) in the implementation repository. A Go release also tags the Go mirror repository
   `vX.Y.Z`, as Go modules require; a Zig release tags its mirror the same way
   ([Section 20.4](20-versioning.md#204-release-process)).
5. Compatibility within 1.x follows [Section 20.3](20-versioning.md#203-compatibility-within-1x).
