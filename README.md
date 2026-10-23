# crypto-pq

[![CI](https://github.com/crypterial/crypto-pq/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/crypterial/crypto-pq/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/crypto-pq.svg)](https://crates.io/crates/crypto-pq)
[![docs.rs](https://img.shields.io/docsrs/crypto-pq)](https://docs.rs/crypto-pq)
[![license](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)

crypto-pq is a post-quantum cryptography library in pure Rust. It provides the key encapsulation
mechanisms ML-KEM and FrodoKEM, the signature schemes ML-DSA and SLH-DSA, and the stateful hash-based
signature schemes HSS/LMS, XMSS and XMSS^MT, together with SHA-2, SHA-3, BLAKE2, BLAKE3, Ascon, HMAC
and HKDF. It is `no_std` with `alloc`, has no dependencies, and implements a
[specification](spec/00-contents.md) that fixes every operation, size, format and error.

- API documentation: [docs.rs/crypto-pq](https://docs.rs/crypto-pq)
- Project page: [crypterial.com/projects/crypto-pq](https://crypterial.com/projects/crypto-pq/)
- Changes: [CHANGELOG.md](CHANGELOG.md)

## Algorithms

| family | standard | parameter sets | feature |
|---|---|---|---|
| ML-KEM | FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | `ml-kem` |
| FrodoKEM | ISO/IEC 18033-2:2006/Amd 2:2026 | FrodoKEM-976 and FrodoKEM-1344, eFrodoKEM-976 and eFrodoKEM-1344, each with AES or SHAKE | `frodokem` |
| ML-DSA | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87; pure and HashML-DSA | `ml-dsa` |
| SLH-DSA | FIPS 205, RFC 9909 | 12 sets (SHA2 or SHAKE; 128, 192 or 256; s or f); pure and HashSLH-DSA, and the 12 HashSLH-DSA values with the pre-hash that RFC 9909 fixes | `slh-dsa` |
| HSS/LMS | RFC 8554, RFC 9858, NIST SP 800-208 | LMS with SHA-256 or SHAKE256, m = 24 or 32, heights 5, 10, 15, 20, 25; LM-OTS with w = 1, 2, 4, 8 | `lms` |
| XMSS, XMSS^MT | RFC 8391, NIST SP 800-208 | the SP 800-208 sets: SHA-2 or SHAKE256, n = 24 or 32; XMSS heights 10, 16, 20; XMSS^MT with 8 height and layer combinations | `xmss` |
| SHA-2 | FIPS 180-4 | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | `sha2` |
| SHA-3 | FIPS 202, NIST SP 800-185 | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256, KMAC128, KMAC256 | `sha3` |
| BLAKE2 | RFC 7693 | BLAKE2b-160, -256, -384, -512; BLAKE2s-128, -160, -224, -256; BLAKE2b-MAC, BLAKE2s-MAC | `blake2` |
| BLAKE3 | BLAKE3 specification | BLAKE3 (XOF), BLAKE3-256, BLAKE3-MAC, BLAKE3-KDF | `blake3` |
| Ascon | NIST SP 800-232 | Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 | `ascon` |
| HMAC | FIPS 198-1 | HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 | `hmac` |
| HKDF | RFC 5869 | HKDF-SHA-256, HKDF-SHA-384, HKDF-SHA-512 | `hkdf` |

ML-KEM, ML-DSA and SLH-DSA keys encode as raw bytes, DER (SubjectPublicKeyInfo, PKCS #8) and PEM;
FrodoKEM keys are raw only. HSS/LMS, XMSS and XMSS^MT public keys encode as raw bytes, DER and PEM;
their private keys live in their state store and are not exported. [Section 5](spec/05-algorithms.md)
of the specification lists every size.

## Install

```toml
[dependencies]
crypto-pq = "1"
```

- Rust 1.88 or later, edition 2024.
- `no_std` with `alloc`: the crate needs a global allocator and nothing from `std`.
- Each algorithm family in the table above is a Cargo feature, and the default features enable all
  of them. `hmac` enables `sha2`, and `hkdf` enables `hmac`. To build only some families:

  ```toml
  [dependencies]
  crypto-pq = { version = "1", default-features = false, features = ["ml-kem", "ml-dsa"] }
  ```

- The `hazmat` feature is opt-in. It adds the `hazmat` module, with deterministic operations that
  take seeds and randomness from the caller, for known-answer and interoperability tests.

## Examples

The [API documentation](https://docs.rs/crypto-pq) covers every operation. Each example below is a
complete program and runs as a test.

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
[state store contract](#usage-requirements).

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

## Usage requirements

These rules are part of the API contract; the [API documentation](https://docs.rs/crypto-pq) and the
specification state them in full.

- **State store.** An HSS/LMS, XMSS or XMSS^MT private key keeps its signing state in a
  `StateStore` that the application implements ([11.6](spec/11-stateful-signatures.md)). `update`
  must be an atomic compare-and-swap that makes the new record durable, surviving a crash and a power
  loss, before it returns `true`. The record contains secrets and must be protected like a private
  key. It must never be restored from a copy, a backup or a snapshot, cloned, or used by two key
  objects or processes at once: an older record would sign again with one-time keys that are already
  used.
- **Hazmat.** The `hazmat` operations are for test vectors only. Never reuse a seed or randomness
  with a different key, message or ciphertext ([13](spec/13-hazmat.md)).
- **eFrodoKEM.** Use an eFrodoKEM public key for fewer than 2^8 ciphertexts; the crate does not
  count them ([8.2.6](spec/08-key-encapsulation.md)). Use the FrodoKEM sets for keys that receive
  more.
- **One key, one mode.** Use each ML-DSA or SLH-DSA key with only one of the hedged (default) and
  deterministic variants, and only one of the pure and pre-hash modes
  ([9.1.2](spec/09-signatures.md)).
- **Pre-hash policy.** HashML-DSA and HashSLH-DSA accept SHA-2, SHA-3, SHAKE128 and SHAKE256 with at
  least the collision strength of the signature: 128 bits for ML-DSA-44 and the SLH-DSA 128 sets,
  192 bits for ML-DSA-65 and the 192 sets, 256 bits for ML-DSA-87 and the 256 sets. Signing with any
  other pre-hash fails with `Error::InvalidOption`, and verification returns `false`
  ([9.1.3](spec/09-signatures.md)).
- **No external μ.** Outside the `hazmat` test functions, the API takes the message itself, never μ,
  the message representative or a precomputed digest; the pre-hash modes cover that use with a
  checked hash ([9.1.5](spec/09-signatures.md)).

## Design

- **Pure Rust, no dependencies.** Every algorithm is implemented in the crate, with no build
  script. `unsafe` code is confined to the entropy source, the wipe, one-time initialization and the
  CPU modules, plus the valgrind requests of the constant-time check build, and each block states
  why it is sound.
- **Constant-time code.** Code that handles secret data has no branch or memory access that depends
  on a secret. CI checks this with valgrind memcheck, every secret marked as undefined, on x86-64
  and ARM64, in the default and the portable build.
- **Data-independent timing.** On ARM64 CPUs with FEAT_DIT, the asymmetric secret operations run
  with DIT set; `enable_data_independent_timing()` extends it to MACs and KDFs.
- **Wiping.** Private keys and `SecretBytes`, the type of every secret output, wipe their memory
  when dropped, with writes that the compiler cannot remove. Neither implements `Clone`.
- **Self-tests.** Key generation runs a pairwise consistency test by default, private-key import
  validates the key, and every stateful signature is verified before it is released.
- **Randomness** comes only from the operating system: `getrandom` on Linux, Android, FreeBSD,
  NetBSD, DragonFly, illumos and Solaris, `getentropy` on Apple platforms and OpenBSD, `ProcessPrng` on Windows, and
  `random_get` on WASI preview 1. On a target without one, operations that need randomness return
  `Error::RngFailure`.
- **CPU paths.** Kernels for x86-64 (AVX2, SSE4.1, SHA-NI, AES-NI) and ARM64 (NEON, AES, SHA-2,
  SHA-3, SHA-512) are selected at run time, with portable code on every target and no target CPU
  flag needed. `RUSTFLAGS="--cfg crypto_pq_portable"` builds the portable code only.
- **Allocation.** Every operation is synchronous. Fixed-size operations allocate only their returned
  value, and the `_into` forms allocate nothing.

CI builds and tests the crate on Linux x86-64 and ARM64, macOS ARM64, Windows x86-64 and ARM64 and
Linux musl, and under emulation on 32-bit x86, RISC-V 64 and big-endian s390x, on Rust 1.88 and stable.

## Specification and test vectors

- [`spec/`](spec/00-contents.md) is the specification, in RFC style: the API, the algorithms, the key
  formats, the errors, the security requirements and the conformance rules.
  [`spec/profiles/rust.md`](spec/profiles/rust.md) maps it to Rust, and
  [`spec/decisions.md`](spec/decisions.md) records the reasons for its choices.
- [`vectors/`](vectors/) is the compliance suite: NIST ACVP and CAVP vectors, C2SP Wycheproof
  vectors, RFC test vectors, Ascon, BLAKE2, BLAKE3 and FrodoKEM known-answer tests, XMSS vectors
  from the RFC 8391 reference implementation, and the files of `vectors/cross/`, which cover every
  error case, option and format. CI runs the suite on every push and checks every file against
  [`vectors/SHA256SUMS`](vectors/SHA256SUMS); the full ACVP sets and the large-data tests run weekly.
- The crate's MAJOR.MINOR is the version of the specification that it implements: every 1.0.x
  release implements specification 1.0 ([20.1](spec/20-versioning.md),
  [VERSIONS.md](spec/VERSIONS.md)). Within 1.x, no public item is removed or renamed and no specified
  behaviour changes; a minor release can add algorithms, options, operations and error codes, which
  is why `Error` is non-exhaustive ([20.3](spec/20-versioning.md)).
- Releases are published from signed tags `rust-vX.Y.Z` on `main`. The crate is built on x86-64 and
  ARM64 hosts and the two builds are compared byte for byte; it carries a build provenance
  attestation and is published through crates.io trusted publishing.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
crypto-pq by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
