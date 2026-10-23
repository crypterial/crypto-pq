//! Fast, secure post-quantum cryptography in pure Rust with no dependencies: ML-KEM, ML-DSA,
//! SLH-DSA, FrodoKEM, HSS/LMS and XMSS, plus SHA-2, SHA-3, BLAKE2, BLAKE3, Ascon, HMAC and HKDF.
//!
//! The crate is `no_std` and needs `alloc`. Every operation is a synchronous function; fallible
//! ones return [`Result`] with [`Error`]. Algorithms are constants of `Copy` types, such as
//! `ML_KEM_768` or `SHA_256`, and keys are objects made from them. Secret outputs are
//! `SecretBytes`, which wipe themselves when dropped. Code that handles secret data has no branch
//! or memory access that depends on a secret, which CI checks under valgrind; on ARM64 CPUs with
//! FEAT_DIT, the asymmetric operations also run in the data-independent timing mode (see
//! [`enable_data_independent_timing`]). CPU-specific code for x86-64 and ARM64 is chosen at run
//! time, with a portable fallback on every target.
//!
//! # Features
//!
//! Each algorithm family is a Cargo feature, and the default features enable all of them. A build
//! that needs only some takes `default-features = false` and names them, for example
//! `crypto-pq = { version = "1", default-features = false, features = ["ml-kem", "ml-dsa"] }`.
//!
//! | feature | enables |
//! |---|---|
//! | `ml-kem` | `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024` (FIPS 203) |
//! | `frodokem` | FrodoKEM and eFrodoKEM, such as `FRODOKEM_976_AES` (ISO/IEC 18033-2 Amd 2) |
//! | `ml-dsa` | `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87` (FIPS 204) |
//! | `slh-dsa` | SLH-DSA and HashSLH-DSA, such as `SLH_DSA_SHA2_128S` (FIPS 205, RFC 9909) |
//! | `lms` | `HSS_LMS` (RFC 8554, NIST SP 800-208) |
//! | `xmss` | `XMSS`, `XMSS_MT` (RFC 8391, NIST SP 800-208) |
//! | `sha2` | SHA-2, such as `SHA_256` (FIPS 180-4) |
//! | `sha3` | SHA-3, SHAKE, cSHAKE and KMAC, such as `SHA3_256` (FIPS 202, NIST SP 800-185) |
//! | `blake2` | BLAKE2b, BLAKE2s and their MACs, such as `BLAKE2B_512` (RFC 7693) |
//! | `blake3` | `BLAKE3`, `BLAKE3_256`, `BLAKE3_MAC`, `BLAKE3_KDF` |
//! | `ascon` | `ASCON_HASH256`, `ASCON_XOF128`, `ASCON_CXOF128` (NIST SP 800-232) |
//! | `hmac` | HMAC with SHA-2, such as `HMAC_SHA_256` (FIPS 198-1); enables `sha2` |
//! | `hkdf` | HKDF with SHA-2, such as `HKDF_SHA_256` (RFC 5869); enables `hmac` |
//! | `hazmat` | `hazmat`: deterministic operations for test vectors; not a default feature |
//!
//! A feature also enables the types that its constants use, such as `KemAlgorithm` for
//! `ml-kem`. The signature features make the SHA-2 and SHA-3 values that FIPS 204 and FIPS 205
//! allow as pre-hashes public as well, for `SignOptions::with_pre_hash`. The internal building
//! blocks that a family needs, such as Keccak or the SHA-2 cores, compile with it.
//!
//! `hazmat` takes seeds and randomness from the caller instead of the operating-system entropy
//! source, where a reused value breaks the scheme, so it is opt-in.
//!
//! # Randomness
//!
//! Randomness comes from the operating system: `getrandom` on Linux, Android, FreeBSD, NetBSD,
//! DragonFly, illumos and Solaris, `getentropy` on Apple platforms and OpenBSD, `ProcessPrng` on
//! Windows and `random_get` on WASI preview 1. On every other target, such as
//! `wasm32-unknown-unknown` or bare metal, every operation that draws randomness fails with
//! [`Error::RngFailure`]; hashes, XOFs, MACs, KDFs, verification, decapsulation and
//! deterministic signing need no randomness.
//!
//! # Examples
//!
//! Key encapsulation, with key confirmation: the two sides hold the same secret when a MAC tag made
//! with one copy verifies with the other, which compares in constant time. Secrets are never
//! compared with `==`: see "Comparing secrets" in the `SecretBytes` documentation.
//!
//! ```
//! # #[cfg(all(feature = "ml-kem", feature = "hmac"))] {
//! use crypto_pq::{HMAC_SHA_256, KeyGenOptions, ML_KEM_768};
//!
//! let pair = ML_KEM_768.generate_key_pair(&KeyGenOptions::default())?;
//!
//! let encapsulation = pair.public_key.encapsulate()?;
//!
//! let shared_secret = pair.private_key.decapsulate(&encapsulation.ciphertext)?;
//!
//! let tag = HMAC_SHA_256.digest(&encapsulation.shared_secret, b"key confirmation")?;
//!
//! assert!(HMAC_SHA_256.verify(&shared_secret, b"key confirmation", &tag));
//! # }
//! # Ok::<(), crypto_pq::Error>(())
//! ```
//!
//! Signatures:
//!
//! ```
//! # #[cfg(feature = "ml-dsa")] {
//! use crypto_pq::{KeyGenOptions, ML_DSA_65, SignOptions, VerifyOptions};
//!
//! let pair = ML_DSA_65.generate_key_pair(&KeyGenOptions::default())?;
//!
//! let options = SignOptions::default().with_context(b"example");
//!
//! let signature = pair.private_key.sign(b"message", &options)?;
//!
//! let verify = VerifyOptions::default().with_context(b"example");
//!
//! assert!(pair.public_key.verify(&signature, b"message", &verify));
//! # }
//! # Ok::<(), crypto_pq::Error>(())
//! ```
//!
//! Stateful signatures, with a `StateStore` that a real application makes durable:
//!
//! ```
//! # #[cfg(feature = "lms")] {
//! use crypto_pq::{
//!     Error, HSS_LMS, StateStore, StatefulKeyGenOptions, StatefulParameters,
//! };
//!
//! struct Memory(Option<Vec<u8>>);
//!
//! impl StateStore for Memory {
//!     fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
//!         Ok(self.0.clone())
//!     }
//!
//!     fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
//!         if self.0.as_deref() != previous {
//!             return Ok(false);
//!         }
//!
//!         self.0 = Some(next.to_vec());
//!
//!         Ok(true)
//!     }
//! }
//!
//! let levels = [("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")];
//!
//! let mut pair = HSS_LMS.generate_key_pair(
//!     StatefulParameters::Levels(&levels),
//!     Memory(None),
//!     &StatefulKeyGenOptions::default(),
//! )?;
//!
//! let signature = pair.private_key.sign(b"message")?;
//!
//! assert!(pair.public_key.verify(&signature, b"message"));
//!
//! assert_eq!(pair.private_key.remaining_signatures(), 31);
//! # }
//! # Ok::<(), crypto_pq::Error>(())
//! ```
//!
//! Hash functions and XOFs:
//!
//! ```
//! # #[cfg(all(feature = "sha2", feature = "sha3"))] {
//! use crypto_pq::{SHA_256, SHAKE256};
//!
//! let digest = SHA_256.digest(b"message");
//!
//! let mut hasher = SHA_256.create();
//!
//! hasher.update(b"mess");
//!
//! hasher.update(b"age");
//!
//! assert_eq!(hasher.digest(), digest);
//!
//! let output = SHAKE256.digest(b"message", 64)?;
//!
//! assert_eq!(output.len(), 64);
//! # }
//! # Ok::<(), crypto_pq::Error>(())
//! ```
//!
//! MACs and key derivation:
//!
//! ```
//! # #[cfg(feature = "hkdf")] {
//! use crypto_pq::{HKDF_SHA_256, HMAC_SHA_256, KdfOptions};
//!
//! let tag = HMAC_SHA_256.digest(b"key", b"message")?;
//!
//! assert!(HMAC_SHA_256.verify(b"key", b"message", &tag));
//!
//! let options = KdfOptions::default().with_salt(b"salt").with_info(b"context");
//!
//! let key = HKDF_SHA_256.derive(b"input keying material", 32, &options)?;
//!
//! assert_eq!(key.len(), 32);
//! # }
//! # Ok::<(), crypto_pq::Error>(())
//! ```
//!
//! # Specification
//!
//! The behaviour of every operation, the sizes, the key formats, the errors and the security
//! requirements are specified in the `spec/` directory of the
//! [repository](https://github.com/crypterial/crypto-pq), and `spec/profiles/rust.md` states how
//! this crate expresses them in Rust. The crate's MAJOR.MINOR version is the version of the
//! specification that it implements.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// A build without every algorithm family compiles out enum variants and the code that only they
// use. That leaves items, imports and parameters unused and patterns unreachable or irrefutable,
// and it gives clippy enum sizes and closures to flag that only such builds have. A build with
// every family, with or without the default feature, keeps all these lints.
#![cfg_attr(
    not(all(
        feature = "ml-kem",
        feature = "frodokem",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss",
        feature = "sha2",
        feature = "sha3",
        feature = "blake2",
        feature = "blake3",
        feature = "ascon",
        feature = "hmac",
        feature = "hkdf"
    )),
    allow(
        dead_code,
        unused_imports,
        unused_variables,
        unreachable_code,
        unreachable_patterns,
        irrefutable_let_patterns,
        clippy::infallible_destructuring_match,
        clippy::large_enum_variant,
        clippy::unnecessary_lazy_evaluations
    )
)]

extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(feature = "frodokem")]
mod aes;

#[cfg(feature = "ascon")]
mod ascon;

#[cfg(feature = "blake2")]
mod blake2;

#[cfg(feature = "blake3")]
mod blake3;

mod cpu;

mod ct;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
mod encoding;

mod error;

#[cfg(feature = "frodokem")]
mod frodokem;

#[cfg(any(
    feature = "sha2",
    feature = "sha3",
    feature = "blake2",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
mod hash;

#[cfg(any(feature = "hazmat", test))]
pub mod hazmat;

#[cfg(any(feature = "hkdf", feature = "blake3"))]
mod kdf;

#[cfg(any(feature = "ml-kem", feature = "frodokem"))]
mod kem;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
mod keccak;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
mod keys;

#[cfg(feature = "lms")]
mod lms;

#[cfg(any(
    feature = "hmac",
    feature = "sha3",
    feature = "blake2",
    feature = "blake3",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
mod mac;

#[cfg(any(feature = "lms", feature = "xmss"))]
mod merkle;

#[cfg(feature = "ml-dsa")]
mod mldsa;

#[cfg(feature = "ml-kem")]
mod mlkem;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
mod once;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
mod primitives;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
mod rng;

mod sha2;

#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
mod signature;

#[cfg(feature = "slh-dsa")]
mod slhdsa;

#[cfg(feature = "sha3")]
mod sp800_185;

#[cfg(any(feature = "lms", feature = "xmss"))]
mod stateful;

mod wipe;

#[cfg(feature = "xmss")]
mod xmss;

pub use cpu::enable_data_independent_timing;
pub use error::Error;

#[cfg(any(
    feature = "sha2",
    feature = "sha3",
    feature = "blake2",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
pub use hash::{HashAlgorithm, HashOptions, Hasher};

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
pub use hash::{Xof, XofAlgorithm, XofOptions};

// The hash functions that FIPS 204 and FIPS 205 allow as a pre-hash are part of the signature
// API, so the signature families make them public too.
#[cfg(any(feature = "sha2", feature = "ml-dsa", feature = "slh-dsa"))]
pub use hash::{SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256};

#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub use hash::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

#[cfg(feature = "sha3")]
pub use hash::{CSHAKE128, CSHAKE256};

#[cfg(feature = "blake2")]
pub use hash::{
    BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512, BLAKE2S_128, BLAKE2S_160, BLAKE2S_224,
    BLAKE2S_256,
};

#[cfg(feature = "blake3")]
pub use hash::{BLAKE3, BLAKE3_256};

#[cfg(feature = "ascon")]
pub use hash::{ASCON_CXOF128, ASCON_HASH256, ASCON_XOF128};

#[cfg(any(
    feature = "hmac",
    feature = "sha3",
    feature = "blake2",
    feature = "blake3"
))]
pub use mac::{Mac, MacAlgorithm, MacOptions};

#[cfg(feature = "hmac")]
pub use mac::{HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512};

#[cfg(feature = "sha3")]
pub use mac::{KMAC128, KMAC256};

#[cfg(feature = "blake2")]
pub use mac::{BLAKE2B_MAC, BLAKE2S_MAC};

#[cfg(feature = "blake3")]
pub use mac::BLAKE3_MAC;

#[cfg(any(feature = "hkdf", feature = "blake3"))]
pub use kdf::{KdfAlgorithm, KdfOptions};

#[cfg(feature = "hkdf")]
pub use kdf::{HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512};

#[cfg(feature = "blake3")]
pub use kdf::BLAKE3_KDF;

#[cfg(any(feature = "ml-kem", feature = "frodokem"))]
pub use kem::{Encapsulation, KemAlgorithm, KemKeyPair, KemPrivateKey, KemPublicKey};

#[cfg(feature = "ml-kem")]
pub use kem::{ML_KEM_512, ML_KEM_768, ML_KEM_1024};

#[cfg(feature = "frodokem")]
pub use kem::{
    EFRODOKEM_976_AES, EFRODOKEM_976_SHAKE, EFRODOKEM_1344_AES, EFRODOKEM_1344_SHAKE,
    FRODOKEM_976_AES, FRODOKEM_976_SHAKE, FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE,
};

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub use keys::KeyFormat;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
pub use keys::KeyGenOptions;

#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
pub use signature::{
    PreHash, SignOptions, SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey,
    SignaturePublicKey, VerifyOptions,
};

#[cfg(feature = "ml-dsa")]
pub use signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};

#[cfg(feature = "slh-dsa")]
pub use signature::{
    HASH_SLH_DSA_SHA2_128F_WITH_SHA256, HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
    HASH_SLH_DSA_SHA2_192F_WITH_SHA512, HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
    HASH_SLH_DSA_SHA2_256F_WITH_SHA512, HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
    HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128, HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
    HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256, HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
    HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256, HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256,
    SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F,
    SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S,
};

#[cfg(any(feature = "lms", feature = "xmss"))]
pub use stateful::{
    StateStore, StatefulKeyGenOptions, StatefulKeyPair, StatefulLoadOptions, StatefulParameters,
    StatefulPrivateKey, StatefulPublicKey, StatefulSignatureAlgorithm,
};

#[cfg(feature = "lms")]
pub use stateful::HSS_LMS;

#[cfg(feature = "xmss")]
pub use stateful::{XMSS, XMSS_MT};

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "hkdf",
    feature = "blake3"
))]
pub use wipe::SecretBytes;

// What the constant-time check of tests/ct.rs needs; it exists only under the crypto_pq_ct cfg.
#[cfg(crypto_pq_ct)]
#[doc(hidden)]
pub mod ct_check {
    pub use crate::ct::{declassify, secret};

    // The key expansion and the encryption of the blocks, in place, under the AES instructions
    // where the CPU has them and in the portable code otherwise.
    #[cfg(feature = "frodokem")]
    pub fn aes_encrypt(key: &[u8], blocks: &mut [[u8; 16]], hardware: bool) {
        let aes = if hardware {
            crate::aes::Aes::new(key)
        } else {
            crate::aes::Aes::portable(key)
        };

        aes.encrypt_blocks(blocks);
    }
}
