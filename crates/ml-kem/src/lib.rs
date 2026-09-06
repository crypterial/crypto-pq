//! ML-KEM, the module-lattice-based key encapsulation mechanism of
//! [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203).
//!
//! The three parameter sets are the modules [`ml_kem_512`], [`ml_kem_768`] and
//! [`ml_kem_1024`]. They expose the same API:
//!
//! ```
//! use crypto_pq_ml_kem::ml_kem_768::{generate_keypair, Ciphertext, EncapsulationKey};
//! # struct Rng(u64);
//! # impl rand_core::RngCore for Rng {
//! #     fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
//! #     fn next_u64(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
//! #     fn fill_bytes(&mut self, dest: &mut [u8]) { for c in dest.chunks_mut(8) { let b = self.next_u64().to_le_bytes(); c.copy_from_slice(&b[..c.len()]); } }
//! # }
//! # impl rand_core::CryptoRng for Rng {}
//! # let mut rng = Rng(0x9e3779b97f4a7c15);
//! let (dk, ek) = generate_keypair(&mut rng)?;
//!
//! // The recipient publishes `ek`; the sender parses and uses it.
//! let ek = EncapsulationKey::from_bytes(ek.as_bytes())?;
//! let (secret_sender, ciphertext) = ek.encapsulate(&mut rng);
//!
//! let ciphertext = Ciphertext::from_bytes(ciphertext.as_bytes())?;
//! let secret_recipient = dk.decapsulate(&ciphertext);
//! assert_eq!(secret_sender.as_bytes(), secret_recipient.as_bytes());
//! # Ok::<(), crypto_pq_ml_kem::Error>(())
//! ```
//!
//! Key import runs the checks of FIPS 203 section 7 (length, modulus check on
//! encapsulation keys, hash check on decapsulation keys). Decapsulation never
//! fails: an invalid ciphertext yields the implicit-rejection secret, selected
//! with a mask rather than a branch. Secret material is zeroized on drop.
//!
//! The crate is `no_std`, needs no allocator and contains no `unsafe` code.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(test)]
extern crate std;

mod field;
mod hash;
mod kem;
mod kpke;
mod poly;
mod sample;

use core::fmt;

/// Errors returned when importing keys or ciphertexts, or by key generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The byte string has the wrong length for this parameter set.
    InvalidLength,
    /// The encapsulation key failed the modulus check (FIPS 203, section 7.2).
    InvalidEncapsulationKey,
    /// The decapsulation key failed the hash check (FIPS 203, section 7.3).
    InvalidDecapsulationKey,
    /// A freshly generated key pair failed the pairwise consistency test (FIPS 203, section 7.1).
    PairwiseConsistency,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "invalid length",
            Error::InvalidEncapsulationKey => "encapsulation key failed the modulus check",
            Error::InvalidDecapsulationKey => "decapsulation key failed the hash check",
            Error::PairwiseConsistency => "key pair failed the pairwise consistency test",
        })
    }
}

impl core::error::Error for Error {}

macro_rules! parameter_set {
    (
        $module:ident, $name:literal,
        k = $k:literal, eta1 = $eta1:literal, eta2 = $eta2:literal, du = $du:literal, dv = $dv:literal,
        ek = $ek_len:literal, dk = $dk_len:literal, ct = $ct_len:literal
    ) => {
        #[doc = concat!($name, " (FIPS 203, table 2).")]
        pub mod $module {
            use crate::{kem, Error};
            use core::fmt;
            use rand_core::CryptoRng;
            use subtle::{Choice, ConstantTimeEq};
            use zeroize::Zeroize;

            /// Length in bytes of an encapsulation key.
            pub const ENCAPSULATION_KEY_LEN: usize = $ek_len;
            /// Length in bytes of a decapsulation key.
            pub const DECAPSULATION_KEY_LEN: usize = $dk_len;
            /// Length in bytes of a ciphertext.
            pub const CIPHERTEXT_LEN: usize = $ct_len;
            /// Length in bytes of a shared secret.
            pub const SHARED_SECRET_LEN: usize = 32;

            const K: usize = $k;
            const ETA1: usize = $eta1;
            const ETA2: usize = $eta2;
            const DU: usize = $du;
            const DV: usize = $dv;

            /// Public encapsulation key.
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct EncapsulationKey([u8; ENCAPSULATION_KEY_LEN]);

            /// Secret decapsulation key. Zeroized on drop.
            #[derive(Clone)]
            pub struct DecapsulationKey([u8; DECAPSULATION_KEY_LEN]);

            /// Ciphertext produced by encapsulation.
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct Ciphertext([u8; CIPHERTEXT_LEN]);

            /// Shared secret. Zeroized on drop and compared in constant time.
            #[derive(Clone)]
            pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

            /// ML-KEM.KeyGen (algorithm 19) followed by the pairwise consistency test of
            /// FIPS 203 section 7.1.
            pub fn generate_keypair<R: CryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<(DecapsulationKey, EncapsulationKey), Error> {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                rng.fill_bytes(&mut d);
                rng.fill_bytes(&mut z);
                let (dk, ek) = keypair_from_seed(&d, &z);
                d.zeroize();
                z.zeroize();

                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                let (k_sender, c) = ek.encapsulate_with_seed(&m);
                m.zeroize();
                let k_recipient = dk.decapsulate(&c);
                if bool::from(k_sender.ct_eq(&k_recipient)) {
                    Ok((dk, ek))
                } else {
                    Err(Error::PairwiseConsistency)
                }
            }

            /// ML-KEM.KeyGen_internal (algorithm 16): deterministic key generation from the
            /// seeds `d` and `z`. Both must be uniformly random 32-byte strings.
            pub fn keypair_from_seed(
                d: &[u8; 32],
                z: &[u8; 32],
            ) -> (DecapsulationKey, EncapsulationKey) {
                let mut ek = [0u8; ENCAPSULATION_KEY_LEN];
                let mut dk = [0u8; DECAPSULATION_KEY_LEN];
                kem::keygen::<K>(d, z, ETA1, &mut ek, &mut dk);
                (DecapsulationKey(dk), EncapsulationKey(ek))
            }

            impl EncapsulationKey {
                /// Parses an encoded key, running the type check and the modulus check of
                /// FIPS 203 section 7.2.
                pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                    let bytes: [u8; ENCAPSULATION_KEY_LEN] =
                        bytes.try_into().map_err(|_| Error::InvalidLength)?;
                    if !kem::modulus_check::<K>(&bytes) {
                        return Err(Error::InvalidEncapsulationKey);
                    }
                    Ok(Self(bytes))
                }

                /// The encoded key.
                pub fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_LEN] {
                    &self.0
                }

                /// ML-KEM.Encaps (algorithm 20).
                pub fn encapsulate<R: CryptoRng + ?Sized>(
                    &self,
                    rng: &mut R,
                ) -> (SharedSecret, Ciphertext) {
                    let mut m = [0u8; 32];
                    rng.fill_bytes(&mut m);
                    let out = self.encapsulate_with_seed(&m);
                    m.zeroize();
                    out
                }

                /// ML-KEM.Encaps_internal (algorithm 17): deterministic encapsulation from the
                /// seed `m`, which must be a uniformly random 32-byte string.
                pub fn encapsulate_with_seed(&self, m: &[u8; 32]) -> (SharedSecret, Ciphertext) {
                    let mut c = [0u8; CIPHERTEXT_LEN];
                    let k = kem::encaps::<K>(&self.0, m, ETA1, ETA2, DU, DV, &mut c);
                    (SharedSecret(k), Ciphertext(c))
                }
            }

            impl DecapsulationKey {
                /// Parses an encoded key, running the type check and the hash check of
                /// FIPS 203 section 7.3.
                pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                    let bytes: [u8; DECAPSULATION_KEY_LEN] =
                        bytes.try_into().map_err(|_| Error::InvalidLength)?;
                    if !kem::hash_check::<K>(&bytes) {
                        return Err(Error::InvalidDecapsulationKey);
                    }
                    Ok(Self(bytes))
                }

                /// The encoded key.
                pub fn as_bytes(&self) -> &[u8; DECAPSULATION_KEY_LEN] {
                    &self.0
                }

                /// The encapsulation key embedded in this decapsulation key.
                pub fn encapsulation_key(&self) -> EncapsulationKey {
                    let mut ek = [0u8; ENCAPSULATION_KEY_LEN];
                    ek.copy_from_slice(&self.0[384 * K..384 * K + ENCAPSULATION_KEY_LEN]);
                    EncapsulationKey(ek)
                }

                /// ML-KEM.Decaps (algorithm 21). A ciphertext that was not produced for this
                /// key yields the implicit-rejection secret; there is no error path.
                pub fn decapsulate(&self, c: &Ciphertext) -> SharedSecret {
                    SharedSecret(kem::decaps::<K>(&self.0, &c.0, ETA1, ETA2, DU, DV))
                }
            }

            impl Drop for DecapsulationKey {
                fn drop(&mut self) {
                    self.0.zeroize();
                }
            }

            impl fmt::Debug for DecapsulationKey {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("DecapsulationKey(..)")
                }
            }

            impl Ciphertext {
                /// Parses a ciphertext, running the type check of FIPS 203 section 7.3.
                pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                    let bytes: [u8; CIPHERTEXT_LEN] =
                        bytes.try_into().map_err(|_| Error::InvalidLength)?;
                    Ok(Self(bytes))
                }

                /// The encoded ciphertext.
                pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_LEN] {
                    &self.0
                }
            }

            impl SharedSecret {
                /// The shared secret bytes.
                pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
                    &self.0
                }
            }

            impl ConstantTimeEq for SharedSecret {
                fn ct_eq(&self, other: &Self) -> Choice {
                    self.0.ct_eq(&other.0)
                }
            }

            impl Drop for SharedSecret {
                fn drop(&mut self) {
                    self.0.zeroize();
                }
            }

            impl fmt::Debug for SharedSecret {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("SharedSecret(..)")
                }
            }
        }
    };
}

parameter_set!(
    ml_kem_512,
    "ML-KEM-512",
    k = 2,
    eta1 = 3,
    eta2 = 2,
    du = 10,
    dv = 4,
    ek = 800,
    dk = 1632,
    ct = 768
);
parameter_set!(
    ml_kem_768,
    "ML-KEM-768",
    k = 3,
    eta1 = 2,
    eta2 = 2,
    du = 10,
    dv = 4,
    ek = 1184,
    dk = 2400,
    ct = 1088
);
parameter_set!(
    ml_kem_1024,
    "ML-KEM-1024",
    k = 4,
    eta1 = 2,
    eta2 = 2,
    du = 11,
    dv = 5,
    ek = 1568,
    dk = 3168,
    ct = 1568
);
