# Versions

| specification | status | date |
|---|---|---|
| SPEC 1.0 | published | 2026-10-23 |

## Specification versions and package versions

The rules below restate [Section 20.1](20-versioning.md#201-versions) and
Decisions [D-66](decisions.md#decision-d-66-revised-by-d-71) and [D-71](decisions.md#decision-d-71).

1. The crypto-pq package, the Rust crate `crypto-pq`, follows Semantic Versioning 2.0.0.
2. Its MAJOR.MINOR equals the version of this specification that it implements: every 1.0.x release
   implements SPEC 1.0. PATCH is independent of the specification.
3. The first release that implements this specification is 1.0.0.
4. A release starts from a signed, annotated tag `rust-vX.Y.Z` (for example `rust-v1.0.0`) on the
   default branch of the repository `crypterial/crypto-pq`
   ([Section 20.4](20-versioning.md#204-release-process)).
5. Compatibility within 1.x follows [Section 20.3](20-versioning.md#203-compatibility-within-1x).

## Corrections to SPEC 1.0

A correction makes the text agree with itself, with the releases that implement it, or with what
its continuous integration runs. It changes neither the behaviour of a release nor the version.

| date | sections | correction |
|---|---|---|
| 2026-10-25 | [6.4](06-api.md#64-operations-by-category), [7.1](07-errors.md#71-error-codes), [11.9](11-stateful-signatures.md#119-loading) | `loadPrivateKey` does not list STATE_CONFLICT, which no step of 11.9 returns. SELF_TEST_FAILED also covers a stored signature that fails its verification at load (11.9 item 6). A top tree taken from a tree cache whose root differs from the stored root fails with INVALID_ENCODING, as [11.10](11-stateful-signatures.md#1110-tree-cache) item 4 states. |
| 2026-10-25 | [15.3](15-platforms.md#153-cpu-specific-code), [18.5](18-testing.md#185-supply-chain), [19.2](19-conformance.md#192-compliance-suite), [19.4](19-conformance.md#194-official-vector-sets), [23.1](profiles/rust.md#231-public-api-idiom), [23.2](profiles/rust.md#232-security-mechanics), [23.4](profiles/rust.md#234-build-packaging-and-platforms), [23.5](profiles/rust.md#235-conformance-checklist) | The text states what CI runs and what the suite holds: the CI platform's own actions only; valgrind with the minimum and the stable toolchain on x86-64 and with the stable toolchain on ARM64; clippy for `hazmat` with each family whose operations it extends; the AESAVS tests of the internal AES core. RISC-V has no kernel in 1.0. A failure to allocate memory goes to the Rust allocation error handler. |
| 2026-10-25 | [20.1](20-versioning.md#201-versions), [Appendix B](principles-review.md) | Wording. |
| 2026-10-25 | [8.2.3](08-key-encapsulation.md#823-constant-time-and-memory), [D-50](decisions.md#decision-d-50) | 8.2.3 item 4 and D-50 name the AES-128 code that computes matrix A: the AES instructions or the bitsliced code ([14.1](14-security.md#141-constant-time) item 3). The requirement that it is constant time is unchanged. |
| 2026-10-25 | [14.1](14-security.md#141-constant-time), [23.2](profiles/rust.md#232-security-mechanics), [23.3](profiles/rust.md#233-performance-mechanics), [23.5](profiles/rust.md#235-conformance-checklist) | The constant-time check also runs on x86-64 in a build capped at SSE4.1 (`--cfg crypto_pq_sse41`), so that it covers the SSE4.1 kernels on CI runners that have AVX2. |
