# crypto-pq

[![crates.io](https://img.shields.io/crates/v/crypto-pq.svg)](https://crates.io/crates/crypto-pq)
[![docs.rs](https://img.shields.io/docsrs/crypto-pq)](https://docs.rs/crypto-pq)
[![license](https://img.shields.io/crates/l/crypto-pq.svg)](#license)

Secure, optimized post-quantum cryptography in pure Rust with no dependencies: ML-KEM, FrodoKEM,
ML-DSA, SLH-DSA, HSS/LMS and XMSS, plus SHA-2, SHA-3, BLAKE2, BLAKE3, Ascon, HMAC and HKDF. The crate
is `no_std` with `alloc` and needs Rust 1.88 or later.

- API documentation: [docs.rs/crypto-pq](https://docs.rs/crypto-pq)
- Project page: [crypterial.com/research/crypto-pq](https://crypterial.com/research/crypto-pq/)
- Repository: [github.com/crypterial/crypto-pq](https://github.com/crypterial/crypto-pq)
- Specification: [`spec/`](https://github.com/crypterial/crypto-pq/tree/main/spec), with the Rust
  profile in [`spec/profiles/rust.md`](https://github.com/crypterial/crypto-pq/blob/main/spec/profiles/rust.md)

## Install

```toml
[dependencies]
crypto-pq = "1"
```

The default features enable every algorithm family. To build only some, turn the defaults off and
name the families:

```toml
[dependencies]
crypto-pq = { version = "1", default-features = false, features = ["ml-kem", "ml-dsa"] }
```

| feature | algorithms |
|---|---|
| `ml-kem` | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| `frodokem` | FrodoKEM-976, FrodoKEM-1344, eFrodoKEM-976, eFrodoKEM-1344, each with AES or SHAKE |
| `ml-dsa` | ML-DSA-44, ML-DSA-65, ML-DSA-87; pure and HashML-DSA |
| `slh-dsa` | the 12 SLH-DSA sets, pure and HashSLH-DSA, and the 12 HashSLH-DSA values of RFC 9909 |
| `lms` | HSS/LMS |
| `xmss` | XMSS, XMSS^MT |
| `sha2` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 |
| `sha3` | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256, KMAC128, KMAC256 |
| `blake2` | BLAKE2b, BLAKE2s, BLAKE2b-MAC, BLAKE2s-MAC |
| `blake3` | BLAKE3, BLAKE3-256, BLAKE3-MAC, BLAKE3-KDF |
| `ascon` | Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 |
| `hmac` | HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512; enables `sha2` |
| `hkdf` | HKDF-SHA-256, HKDF-SHA-384, HKDF-SHA-512; enables `hmac` |
| `hazmat` | deterministic operations for test vectors; not a default feature |

## Examples

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
contract that follows the example.

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

A store must:

- make `update` an atomic compare-and-swap: replace the record only if the stored one is byte for
  byte `previous`, and otherwise change nothing and return `false`;
- make `next` durable, surviving a crash and a power loss, before `update` returns `true`;
- protect the record like a private key, since it contains the key's secrets;
- never restore the record from a copy, a backup or a virtual machine or disk snapshot, never clone
  it, and never let two key objects or processes use it at once: an older record would sign again
  with one-time keys that are already used. Compare-and-swap detects another writer on the same
  store, not a rollback of the storage itself.

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

- `hazmat` operations are for test vectors only. Never reuse a seed or randomness with a different
  key, message or ciphertext.
- Use an eFrodoKEM public key for fewer than 2^8 ciphertexts; the crate does not count them.
- Use each ML-DSA or SLH-DSA key with only one of the hedged and deterministic variants, and only
  one of the pure and pre-hash modes.
- HashML-DSA and HashSLH-DSA accept only SHA-2, SHA-3, SHAKE128 and SHAKE256 with at least the
  collision strength of the signature; any other pre-hash fails with `Error::InvalidOption`. The API
  takes the message itself, never μ or a precomputed digest, outside the `hazmat` test functions.

## Design

Code that handles secret data has no branch or memory access that depends on a secret, which CI
checks under valgrind on x86-64 and ARM64. On ARM64 CPUs with FEAT_DIT, the asymmetric secret
operations run with DIT set. Private keys and `SecretBytes`, the type of every secret output, wipe
their memory when dropped. Randomness comes only from the operating system; on a target without a
source, operations that need it return `Error::RngFailure`. CPU-specific code for x86-64 and ARM64 is
selected at run time, with portable code on every target.

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/crypterial/crypto-pq/security/advisories/new).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
