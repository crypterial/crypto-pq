#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod cpu;

mod ct;

mod encoding;

mod error;

mod hash;

pub mod hazmat;

mod kem;

mod keccak;

mod keys;

mod lms;

mod merkle;

mod mldsa;

mod mlkem;

mod once;

mod primitives;

mod rng;

mod sha2;

mod signature;

mod slhdsa;

mod stateful;

mod wipe;

mod x25519;

mod xmss;

mod xwing;

pub use error::Error;
pub use hash::{
    HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512, HashAlgorithm, Hasher, Hmac,
    HmacAlgorithm, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224,
    SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, Xof, XofAlgorithm,
};
pub use kem::{
    Encapsulation, KemAlgorithm, KemKeyPair, KemPrivateKey, KemPublicKey, ML_KEM_512, ML_KEM_768,
    ML_KEM_1024, X_WING,
};
pub use keys::{KeyFormat, KeyGenOptions};
pub use signature::{
    ML_DSA_44, ML_DSA_65, ML_DSA_87, PreHash, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey,
    SignaturePublicKey, VerifyOptions,
};
pub use stateful::{
    HSS_LMS, StateStore, StatefulKeyGenOptions, StatefulKeyPair, StatefulLoadOptions,
    StatefulParameters, StatefulPrivateKey, StatefulPublicKey, StatefulSignatureAlgorithm, XMSS,
    XMSS_MT,
};

// What the constant-time check of tests/ct.rs needs; it exists only under the crypto_pq_ct cfg.
#[cfg(crypto_pq_ct)]
#[doc(hidden)]
pub mod ct_check {
    pub use crate::ct::{declassify, secret};

    pub fn x25519(scalar: &[u8], u: &[u8]) -> [u8; 32] {
        crate::x25519::x25519(scalar, u)
    }

    pub fn x25519_base(scalar: &[u8]) -> [u8; 32] {
        crate::x25519::x25519_base(scalar)
    }
}
