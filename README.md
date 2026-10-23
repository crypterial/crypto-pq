# crypto-pq

[![CI](https://github.com/crypterial/crypto-pq/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/crypterial/crypto-pq/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/crypto-pq.svg)](https://crates.io/crates/crypto-pq)
[![docs.rs](https://img.shields.io/docsrs/crypto-pq)](https://docs.rs/crypto-pq)
[![license](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)

crypto-pq is a post-quantum cryptography library in pure Rust. It provides the key encapsulation
mechanisms ML-KEM and FrodoKEM, the signature schemes ML-DSA and SLH-DSA, the stateful hash-based
signature schemes HSS/LMS and XMSS, and standard hash functions, XOFs, MACs and KDFs. It is
`no_std` with `alloc`, has no dependencies, and implements a [specification](spec/00-contents.md)
that fixes every operation, size, format and error.

**Status:** 1.0.0-rc.1, the first release candidate of the 1.0 line. The code has not had a
third-party audit yet. The 0.1.x prototype on crates.io is withdrawn and unsupported.

## Algorithms

| family | standard | parameter sets | feature |
|---|---|---|---|
| ML-KEM | FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | `ml-kem` |
| FrodoKEM | ISO/IEC 18033-2:2006/Amd 2:2026 | FrodoKEM-976 and -1344, eFrodoKEM-976 and -1344, each with AES or SHAKE | `frodokem` |
| ML-DSA | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87, pure and HashML-DSA | `ml-dsa` |
| SLH-DSA | FIPS 205, RFC 9909 | 12 sets (SHA2 or SHAKE; 128, 192 or 256; s or f), pure and HashSLH-DSA, plus the 12 HashSLH-DSA values with the pre-hash that RFC 9909 fixes | `slh-dsa` |
| HSS/LMS | RFC 8554, RFC 9858, NIST SP 800-208 | LMS with SHA-256 or SHAKE256, m = 24 or 32, heights 5, 10, 15, 20, 25; LM-OTS with w = 1, 2, 4, 8 | `lms` |
| XMSS, XMSS^MT | RFC 8391, NIST SP 800-208 | the SP 800-208 sets: SHA2 and SHAKE256, n = 24 or 32; XMSS heights 10, 16, 20; XMSS^MT 8 height and layer pairs | `xmss` |
| SHA-2 | FIPS 180-4 | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | `sha2` |
| SHA-3 | FIPS 202, NIST SP 800-185 | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256, KMAC128, KMAC256 | `sha3` |
| BLAKE2 | RFC 7693 | BLAKE2b-160, -256, -384, -512; BLAKE2s-128, -160, -224, -256; BLAKE2b-MAC, BLAKE2s-MAC | `blake2` |
| BLAKE3 | BLAKE3 specification | BLAKE3 (XOF), BLAKE3-256, BLAKE3-MAC, BLAKE3-KDF | `blake3` |
| Ascon | NIST SP 800-232 | Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 | `ascon` |
| HMAC | FIPS 198-1 | HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 | `hmac` |
| HKDF | RFC 5869 | HKDF-SHA-256, HKDF-SHA-384, HKDF-SHA-512 | `hkdf` |

ML-KEM, ML-DSA and SLH-DSA keys encode as raw bytes, DER (SubjectPublicKeyInfo, PKCS #8) and PEM;
FrodoKEM keys are raw only. HSS/LMS and XMSS public keys encode as raw bytes, DER and PEM; their
private keys are never exported or imported, and live in their state store. The full catalogue,
with every size, is in [Section 5](spec/05-algorithms.md) of the specification, and the excluded
algorithms and the reasons are in [Section 4](spec/04-scope.md).

## Install

```toml
[dependencies]
crypto-pq = "1.0.0-rc.1"
```

- **Rust 1.88** or later, edition 2024. CI tests 1.88 and the current stable release.
- **`no_std` with `alloc`.** The crate needs a global allocator and nothing from `std`.
- **No dependencies**, and no build script.
- **Features.** Each algorithm family in the table above is a feature, and the default features
  enable all of them. `hmac` enables `sha2`, and `hkdf` enables `hmac`. To build only some families:

  ```toml
  [dependencies]
  crypto-pq = { version = "1.0.0-rc.1", default-features = false, features = ["ml-kem", "ml-dsa"] }
  ```

- **`hazmat` is opt-in.** It adds the `hazmat` module, with deterministic operations that take
  seeds and randomness from the caller, for known-answer and interoperability tests. It is never
  enabled by default; see [the warning](#hazmat) below.

## Examples

The API documentation on [docs.rs](https://docs.rs/crypto-pq) covers every operation. Each example
below is a complete program, and each one runs as a test.

Key encapsulation. The two sides confirm that they hold the same secret with a MAC, whose
verification compares in constant time; the crate offers no constant-time equality, so secrets are
never compared with `==`.

```rust
use crypto_pq::{Error, HMAC_SHA_256, KeyGenOptions, ML_KEM_768};

fn main() -> Result<(), Error> {
    // The receiver generates a key pair and publishes the public key.
    let receiver = ML_KEM_768.generate_key_pair(&KeyGenOptions::default())?;

    // The sender encapsulates a fresh shared secret to it and sends the ciphertext.
    let sent = receiver.public_key.encapsulate()?;

    // The receiver decapsulates the ciphertext.
    let received = receiver.private_key.decapsulate(&sent.ciphertext)?;

    // Key confirmation: a tag made with one copy of the secret verifies with the other.
    let tag = HMAC_SHA_256.digest(&sent.shared_secret, b"key confirmation")?;

    assert!(HMAC_SHA_256.verify(&received, b"key confirmation", &tag));

    Ok(())
}
```

Signatures, with the public key exported and imported as DER:

```rust
use crypto_pq::{Error, KeyFormat, KeyGenOptions, ML_DSA_65, SignOptions, VerifyOptions};

fn main() -> Result<(), Error> {
    let pair = ML_DSA_65.generate_key_pair(&KeyGenOptions::default())?;

    let der = pair.public_key.export_key(KeyFormat::Der)?;

    let public_key = ML_DSA_65.import_public_key(&der, KeyFormat::Der)?;

    let options = SignOptions::default().with_context(b"example v1");

    let signature = pair.private_key.sign(b"message", &options)?;

    let verify = VerifyOptions::default().with_context(b"example v1");

    assert!(public_key.verify(&signature, b"message", &verify));

    Ok(())
}
```

Stateful signatures. The key keeps its signing state in a `StateStore` that the application
provides. The store below lives in memory to keep the example short; a real store must meet the
[state store contract](#stateful-signatures-and-the-state-store).

```rust
use crypto_pq::{
    Error, HSS_LMS, StateStore, StatefulKeyGenOptions, StatefulLoadOptions, StatefulParameters,
};

#[derive(Default)]
struct MemoryStore(Option<Vec<u8>>);

impl StateStore for MemoryStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.clone())
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        if self.0.as_deref() != previous {
            return Ok(false);
        }

        self.0 = Some(next.to_vec());

        Ok(true)
    }
}

fn main() -> Result<(), Error> {
    let mut store = MemoryStore::default();

    // One LMS tree of height 5: 32 signatures.
    let levels = [("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")];

    let pair = HSS_LMS.generate_key_pair(
        StatefulParameters::Levels(&levels),
        &mut store,
        &StatefulKeyGenOptions::default(),
    )?;

    let public_key = pair.public_key;

    let mut private_key = pair.private_key;

    let signature = private_key.sign(b"message")?;

    assert!(public_key.verify(&signature, b"message"));

    drop(private_key);

    // Later, or in another process: the key resumes from its store.
    let mut private_key = HSS_LMS.load_private_key(&mut store, &StatefulLoadOptions::default())?;

    let signature = private_key.sign(b"another message")?;

    assert!(public_key.verify(&signature, b"another message"));

    assert_eq!(private_key.remaining_signatures(), 30);

    Ok(())
}
```

Hashes, XOFs, MACs and key derivation:

```rust
use crypto_pq::{BLAKE3_KDF, Error, HKDF_SHA_256, HMAC_SHA_256, KdfOptions, SHA3_256, SHAKE256};

fn main() -> Result<(), Error> {
    let digest = SHA3_256.digest(b"message");

    let mut hasher = SHA3_256.create();

    hasher.update(b"mess");

    hasher.update(b"age");

    assert_eq!(hasher.digest(), digest);

    let output = SHAKE256.digest(b"message", 64)?;

    assert_eq!(output.len(), 64);

    let mac_key = [7; 32];

    let tag = HMAC_SHA_256.digest(&mac_key, b"message")?;

    assert!(HMAC_SHA_256.verify(&mac_key, b"message", &tag));

    let options = KdfOptions::default().with_salt(b"salt").with_info(b"example v1 session key");

    let session_key = HKDF_SHA_256.derive(b"input keying material", 32, &options)?;

    assert_eq!(session_key.len(), 32);

    // BLAKE3-KDF takes a hard-coded, globally unique, application-specific context string.
    let context = KdfOptions::default().with_info(b"example.com 2026-10-23 session key v1");

    let derived = BLAKE3_KDF.derive(b"input keying material", 32, &context)?;

    assert_eq!(derived.len(), 32);

    Ok(())
}
```

## Security

[Section 14 of the specification](spec/14-security.md) states the security requirements, and
[Section 23.2](spec/profiles/rust.md) how this crate meets them. This section summarises them and the
duties they leave to the application.

### Audit status

crypto-pq has not had a third-party audit. Until it has, weigh that before you rely on it.

### Constant time

The specification requires that no branch, memory address or variable-latency instruction depends
on a secret. Table lookups indexed by secret data are not used: AES runs on the CPU's AES
instructions or a bitsliced implementation, and secret selections and comparisons use masks behind
an optimization barrier. A value derived from secrets is made public only where the specification
allows it: the outcome of a validity check that fails the call, values that become public outputs
(public keys, ciphertexts, signatures), the rejection decisions of ML-DSA signing, whether ML-DSA's
SampleInBall needs a second SHAKE256 block, and the matrix generation of ML-KEM and FrodoKEM from
public seeds ([14.1](spec/14-security.md)).

CI checks branches and memory addresses mechanically. A build with `--cfg crypto_pq_ct` marks every secret as undefined
memory for valgrind memcheck, so that a branch or a memory index that depends on a secret fails the
test run. The check runs in the default build and in the portable build, on x86-64 (Rust 1.88 and
stable) and on ARM64 (stable). Valgrind cannot execute the SHA instructions on x86-64 or the SHA-3,
SHA-512 and DIT instructions on ARM64, so that build leaves those kernels out; the other kernels and
the portable code are checked. The CPU kernels are also tested against the portable code on random
and edge inputs.

The check covers the code that CI's compilers generate for its targets; it cannot see timing
differences that the hardware introduces below the instruction level, which is what DIT addresses
on ARM64.

### Data-independent timing (DIT)

On ARM64 CPUs with FEAT_DIT, the crate sets PSTATE.DIT for the whole of every asymmetric secret
operation and restores the previous value afterwards: KEM key generation, encapsulation and
decapsulation; signature key generation and signing; stateful key generation, loading, signing and
tree cache export; private-key import and export; and the hazmat forms of these. Verification,
public-key import and hashing do not set it.

MAC and KDF calls run without DIT unless the process calls `enable_data_independent_timing()`. After
that call, every MAC and KDF call on every thread sets DIT; the switch cannot be turned off. The
function returns `true` only where DIT is supported and will be used.

DIT is detected through the hardware capabilities on Linux and Android, and assumed on Apple targets
that guarantee it (macOS on Apple silicon). Windows reports no DIT, and other systems, other
architectures and the portable build do not use it ([14.2](spec/14-security.md)).

### Wiping and its limits

Every secret that the crate holds is overwritten with zeros, by writes that the compiler cannot
remove, when it is no longer needed: key objects when dropped, seeds, expanded keys, intermediate
values and secret stack buffers, on success and on every error path. Secret outputs are
`SecretBytes`, which wipe themselves when dropped and implement neither `Clone` nor `PartialEq`.

The limits ([14.5](spec/14-security.md), [23.2](spec/profiles/rust.md)):

- copies that the compiler makes in registers or stack spill slots cannot be controlled or wiped;
- a secret that the caller copies out of a `SecretBytes`, and every record that a `StateStore`
  keeps, belong to the caller, who must wipe them;
- the crate does not lock memory, so the operating system can page or dump it.

### Comparing secrets

The crate offers no constant-time equality, and `==` on byte slices is not constant time. Do not
compare secrets. To check that two parties hold the same secret, use each copy as a MAC key over
the same data and verify the tag from one with the other, as the KEM example does: MAC
verification compares in constant time.

### Randomness

Every random value comes from the operating system, requested for the operation that uses it. There
is no user-space generator, no caller seeding outside `hazmat`, and no fallback.

| platform | source |
|---|---|
| Linux, Android, FreeBSD, NetBSD, DragonFly, illumos, Solaris | `getrandom(2)` |
| Apple platforms, OpenBSD | `getentropy` |
| Windows | `ProcessPrng` |
| WASI preview 1 | `random_get` |

A failure, a short read, or a platform without a source, such as `wasm32-unknown-unknown`, WASI
preview 2 or bare metal, fails the operation with `Error::RngFailure`. Hashes, XOFs, MACs, KDFs,
verification, decapsulation and deterministic signing need no randomness. A source can block at boot until the operating system has seeded it.

### Hazmat

The `hazmat` feature exposes operations that take seeds and randomness from the caller instead of
the operating system. They exist for known-answer and interoperability tests only. **Reusing a seed
or randomness with a different key, message or ciphertext breaks the security of the scheme.**
Production code must not enable the feature. Hazmat key generation skips the pairwise self-test,
and stateful keys made by hazmat do not conform to SP 800-208 ([13](spec/13-hazmat.md)).

### Stateful signatures and the state store

An HSS/LMS, XMSS or XMSS^MT private key can sign each one-time key only once, so its index lives in a
`StateStore` that the application implements. The key writes the index to the store before it
releases a signature and verifies every signature before release. The store must meet this
contract ([11.6](spec/11-stateful-signatures.md)):

1. `update(previous, next)` is an atomic compare-and-swap: if the stored record is byte for byte
   `previous` (`None`: the store is empty), it replaces it with `next` and returns `true`; otherwise
   it changes nothing and returns `false`.
2. `update` makes `next` durable, written to storage that survives a crash and a power loss, before
   it returns `true`.
3. The record contains secrets. The store protects it like a private key.
4. A record is never restored from a copy or a backup, cloned, or used by two key objects or
   processes at once. Restoring an old record makes the key sign again with one-time keys that were
   already used, which breaks the scheme. Compare-and-swap detects another writer on the same store;
   it cannot detect a rollback of the storage itself, such as a virtual machine or disk snapshot.

An error from the store becomes `Error::StatePersistFailed`, and a lost compare-and-swap becomes
`Error::StateConflict`. A larger `reserve` claims several indices per store write; the indices that
a dropped key object reserved but did not use are lost by design.

### Signature policies

- **Pre-hash** ([9.1.3](spec/09-signatures.md)). `SignOptions::with_pre_hash` selects HashML-DSA or
  HashSLH-DSA. Only SHA-2, SHA-3, SHAKE128 and SHAKE256 are accepted, and the function must give at
  least the collision strength of the signature: 128 bits for ML-DSA-44 and the SLH-DSA 128 sets,
  192 bits for ML-DSA-65 and the 192 sets, 256 bits for ML-DSA-87 and the 256 sets. SHA-224,
  SHA-512/224 and SHA3-224 are never accepted. Signing with a refused pre-hash fails with
  `Error::InvalidOption`, and verification returns `false`. The policy is fixed; only the hazmat
  functions skip the strength rule, for test vectors.
- **HashSLH-DSA values.** The `HASH_SLH_DSA_*_WITH_*` values always pre-hash with the function that
  RFC 9909 fixes for them.
- **No external μ** ([9.1.5](spec/09-signatures.md)). No public function accepts μ, the message
  representative or a precomputed digest in place of the message: a caller-supplied μ would bypass
  the binding of the public key and the context. The pre-hash modes cover these uses with a checked
  hash. Only the hazmat test functions take the message representative, for the ACVP test groups.
- **One key, one mode** ([9.1.2](spec/09-signatures.md)). Use each key with only one of the hedged
  (default) and deterministic variants, and with only one of the pure and pre-hash modes.
- **X.509.** A key object does not record whether its encoding used a pure or a pre-hash OID. Keep
  keys identified by the pure OIDs in pure mode ([9.4](spec/09-signatures.md); RFC 9881 forbids
  HashML-DSA in X.509).

### KEM policies

- **eFrodoKEM** ([8.2.6](spec/08-key-encapsulation.md)). An eFrodoKEM public key must be used for
  fewer than 2^8 ciphertexts. The crate cannot count ciphertexts across processes and does not
  enforce the limit, and it never chooses an eFrodoKEM set by default. Use the FrodoKEM sets for
  keys that receive more ciphertexts.
- **Self-tests.** Key generation runs a pairwise consistency test unless
  `KeyGenOptions::with_self_test(false)` turns it off. The private-key import checks of ML-KEM and
  FrodoKEM include one that cannot be turned off ([14.4](spec/14-security.md)).
- **Implicit rejection.** ML-KEM decapsulation of a ciphertext of the right length never fails: an
  invalid ciphertext gives a pseudorandom secret, as FIPS 203 specifies. Confirm the key, as the
  example above does, where the protocol needs to detect it.

### MAC and KDF advice

- Use MAC keys with at least the desired security strength. Tags shorter than 64 bits need a risk
  analysis ([12.6](spec/12-symmetric-primitives.md)).
- The BLAKE3-KDF context string should be hard-coded, globally unique and application-specific
  ([12.7.2](spec/12-symmetric-primitives.md)).
- SHA-224, SHA-512/224, SHA3-224, BLAKE2b-160, BLAKE2s-128, BLAKE2s-160, BLAKE2s-224 and truncated MAC
  tags are below the quantum-resistant collision sizes. They exist for interoperability and are never
  a default.

### Validation

crypto-pq implements the parameter sets of NIST SP 800-208, the modified XMSS^MT algorithms of its
Section 7.2.1 and its signing requirements of Section 8.1: the index is stored in non-volatile storage
before a signature is released, and, with a store that meets the contract above, no one-time key
signs twice. It does not claim SP 800-208
validation or FIPS 140 validation. SP 800-208 also requires a hardware module validated at FIPS 140
level 3, which a software library cannot be, and crypto-pq is not a validated module
([11.15](spec/11-stateful-signatures.md)).

### Reporting a vulnerability

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/crypterial/crypto-pq/security/advisories/new). Do not
open a public issue for a security bug. [SECURITY.md](SECURITY.md) describes the process and the
supported versions.

## Platforms and CPU paths

| | |
|---|---|
| tested in CI | Linux x86-64 and ARM64, macOS ARM64, Windows x86-64 and ARM64, Linux musl; 32-bit x86, RISC-V 64 and big-endian s390x under emulation |
| other targets | the portable code; without an [entropy source](#randomness), operations that need randomness fail with `Error::RngFailure` |
| x86-64 kernels | AVX2 (with BMI1, BMI2 and operating-system support for the YMM state), SSE4.1, SHA-NI, AES-NI |
| ARM64 kernels | NEON; the AES, SHA-2, SHA-3 and SHA-512 extensions; DIT |
| everything else | portable code, including 32-bit, big-endian and RISC-V |

CPU-specific code is selected at run time, with no target CPU flag needed. x86-64 uses CPUID and
XGETBV. ARM64 reads the hardware capabilities on Linux and Android, calls `IsProcessorFeaturePresent`
on Windows, and uses the Apple baseline on Apple targets; other ARM64 systems run NEON and what the
build target guarantees. Detection runs once and is cached in an atomic. CPU-specific code is not used
inside an SGX enclave.

`RUSTFLAGS="--cfg crypto_pq_portable"` removes every kernel and every use of DIT. CI runs the test
suite in that build, and on emulated x86-64 CPU models that select each x86-64 code path.

Every operation is synchronous. Fixed-size operations allocate only their returned value, and the
`_into` forms allocate nothing.

## Specification, vectors and versions

- **[`spec/`](spec/00-contents.md)** is the normative specification in RFC style: the API, the
  algorithms, the key formats, the errors, the security requirements and the conformance rules.
  [`spec/profiles/rust.md`](spec/profiles/rust.md) maps it to Rust, and
  [`spec/decisions.md`](spec/decisions.md) records the reasons behind its choices.
- **[`vectors/`](vectors/)** is the compliance suite: NIST ACVP and CAVP vectors, C2SP Wycheproof
  vectors, RFC test vectors, Ascon, BLAKE2, BLAKE3 and FrodoKEM known-answer tests, XMSS vectors
  from the RFC 8391 reference implementation, and the crypto-pq files in `vectors/cross/` that cover
  every error case, option and format. CI runs all of it on every push and checks the files against
  [`vectors/SHA256SUMS`](vectors/SHA256SUMS). The full ACVP sets and the large-data tests run
  weekly; a tool in [`tools/`](tools/) downloads them from their pinned sources and checks their
  SHA-256.
- **Versions.** The crate follows Semantic Versioning, and its MAJOR.MINOR is the version of the
  specification that it implements: every 1.0.x release implements specification 1.0, and PATCH
  counts the crate's releases ([20.1](spec/20-versioning.md), [VERSIONS.md](spec/VERSIONS.md)).
  Within 1.x, no public item is removed or renamed and no specified behaviour changes; a minor
  release can add algorithms, options, operations and error codes, so match `Error` with a wildcard
  arm. Byte formats change only with a new version number, and every 1.x release reads every format
  that an earlier 1.x release wrote ([20.3](spec/20-versioning.md)).
- **Releases** start from a signed, annotated tag `rust-vX.Y.Z` on `main`. The crate is built on
  x86-64 and ARM64 hosts and the two builds are compared byte for byte; the crate gets a build
  provenance attestation, is published through crates.io trusted publishing after a maintainer's
  approval, and is downloaded again and compared with the attested hash.

The changes in each release are in [CHANGELOG.md](CHANGELOG.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
crypto-pq by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
