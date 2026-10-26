# 20. Versioning, compatibility and release

## 20.1 Versions

1. The package follows Semantic Versioning 2.0.0 [[D-66](decisions.md#decision-d-66-revised-by-d-71)]. Its MAJOR.MINOR equals the version of this
   specification it implements (1.0.x implements SPEC 1.0, 1.1.x SPEC 1.1); PATCH is independent
   of the specification. The first release that implements this specification is 1.1.0.
2. The package manifests (`Cargo.toml` and `Cargo.lock`) carry the release version; CI checks that
   they agree.

## 20.2 Format and interface versions

| item | version in 1.1 |
|---|---|
| state record | writes and reads 2; refuses 1 ([11.7](11-stateful-signatures.md#117-state-record-version-2), [11.8](11-stateful-signatures.md#118-state-record-version-1)) |
| tree cache | 1 ([11.10](11-stateful-signatures.md#1110-tree-cache)) |
| PKCS#8 export | OneAsymmetricKey version 0 ([10.3](10-key-formats.md#103-pkcs8-oneasymmetrickey)) |

## 20.3 Compatibility within 1.x

1. No public item is removed or renamed, and no behaviour specified here changes, before 2.0.0.
2. A 1.x release MAY add algorithm values, options and operations. Options are added only in forms that do not
   break existing callers ([23.1](profiles/rust.md#231-public-api-idiom) item 4).
3. A 1.x release MAY add error codes. Callers MUST handle
   codes they do not know; the Rust `Error` enum is non-exhaustive ([23.1](profiles/rust.md#231-public-api-idiom) item 2).
4. Byte formats change only by a new version number, and every 1.x release reads every format version
   that an earlier 1.x release wrote. State record version 1 is not covered ([11.8](11-stateful-signatures.md#118-state-record-version-1)).
5. `name` strings are never reused for another algorithm.

## 20.4 Release process

1. A release starts from a signed, annotated tag `rust-vX.Y.Z` (for example `rust-v1.0.0`) on a
   commit of the default branch of the repository `crypterial/crypto-pq` [[D-66](decisions.md#decision-d-66-revised-by-d-71), [D-71](decisions.md#decision-d-71)].
2. A release check verifies that the tag equals the manifest versions, that the commit is on
   the default branch, and that [19.5](19-conformance.md#195-release-gate) holds.
3. The artifacts are built on x86-64 and ARM64 hosts, compared byte for byte, and listed in
   `SHA256SUMS`. Build provenance is attested for every artifact.
4. Publishing runs only after approval by the maintainers in a protected environment, to crates.io
   ([23.4](profiles/rust.md#234-build-packaging-and-platforms) item 3). Where the registry offers trusted publishing or provenance, the release uses it.
5. After publishing, the published artifacts are downloaded and verified against `SHA256SUMS`.
6. The package contains `LICENSE-APACHE` and `LICENSE-MIT`; the license is `Apache-2.0 OR MIT`.
7. Package descriptions and release notes follow P14. The package documentation states the policies
   of [9.1.3](09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa), [9.1.5](09-signatures.md#915-no-external-μ), [11.6](11-stateful-signatures.md#116-state-store-contract) and [8.2.6](08-key-encapsulation.md#826-efrodokem-usage-limit).
