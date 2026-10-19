# 20. Versioning, compatibility and release

## 20.1 Versions

1. Each package follows Semantic Versioning 2.0.0 and is released on its own [[D-66](decisions.md#decision-d-66)]. Its MAJOR.MINOR
   equals the version of this specification it implements (1.0.x implements SPEC 1.0); PATCH is
   counted per package. The first production release of each package is 1.0.0, preceded by release
   candidates 1.0.0-rc.N.
2. A package's manifests (for Rust, Cargo.toml and Cargo.lock) carry its release version; CI checks
   that they agree.

## 20.2 Format and interface versions

| item | version in 1.0 |
|---|---|
| state record | writes and reads 2; refuses 1 ([11.7](11-stateful-signatures.md#117-state-record-version-2), [11.8](11-stateful-signatures.md#118-state-record-version-1)) |
| tree cache | 1 ([11.10](11-stateful-signatures.md#1110-tree-cache)) |
| PKCS#8 export | OneAsymmetricKey version 0 ([10.3](10-key-formats.md#103-pkcs8-oneasymmetrickey)) |
| C ABI of the core | 3 (25.5) |

## 20.3 Compatibility within 1.x

1. No public item is removed or renamed, and no behaviour specified here changes, before 2.0.0.
2. A 1.x release MAY add algorithm values, options and operations. Options are added only in forms that do not
   break existing callers ([23.1](profiles/rust.md#231-public-api-idiom) for Rust).
3. A 1.x release MAY add error codes (for example `DECRYPTION_FAILED` with AEAD in 1.1). Callers MUST handle
   codes they do not know; the Rust `Error` enum is non-exhaustive, and the Zig profile states how a
   grown error set is handled (25.1).
4. Byte formats change only by a new version number, and every 1.x release reads every format version
   that an earlier 1.x release wrote. Formats written before 1.0 are not covered ([11.8](11-stateful-signatures.md#118-state-record-version-1)).
5. `name` strings and C ABI identifiers are never reused for another algorithm.

## 20.4 Release process

1. A release of one package starts from a signed, annotated tag `<language>-vX.Y.Z` (for example
   `rust-v1.0.0`) on a commit of `main` [[D-43](decisions.md#decision-d-43-revised-by-d-66), [D-66](decisions.md#decision-d-66)]. A Go release also tags the mirror repository
   `vX.Y.Z`, as Go modules require; a Zig release tags its mirror the same way.
2. A release check verifies that the tag equals the package's manifest versions, that the commit is on
   `main`, and that [19.5](19-conformance.md#195-release-gate) holds.
3. The artifacts are built on x86-64 and ARM64 hosts, compared byte for byte, and listed in
   `SHA256SUMS`. Build provenance is attested for every artifact.
4. Publishing runs only after approval by the maintainers in a protected environment: crates.io for Rust (trusted
   publishing); the mirror repository for Go and Zig (the generated tree, committed and tagged);
   PyPI for Python (trusted publishing); npm for TypeScript (with provenance).
5. After publishing, the published artifacts are downloaded and verified against `SHA256SUMS`.
6. Every package contains `LICENSE-APACHE` and `LICENSE-MIT`; the license is `Apache-2.0 OR MIT`.
7. Package descriptions and release notes follow P14 and state the policies of [9.1.3](09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa), [9.1.5](09-signatures.md#915-no-external-μ), [11.6](11-stateful-signatures.md#116-state-store-contract) and
   [8.2.6](08-key-encapsulation.md#826-efrodokem-usage-limit).
