#![no_std]
#![deny(unsafe_code)]
// A build without every algorithm family compiles out enum variants and the code that only they
// use, which leaves items, imports and parameters unused, patterns unreachable or irrefutable, and
// enums and closures that only some families make worth their form; the default build, which has
// every family, keeps these lints.
#![cfg_attr(
    not(feature = "default"),
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
