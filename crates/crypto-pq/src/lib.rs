//! Post-quantum cryptography, organised by what you need rather than by algorithm name:
//! `crypto_pq::<category>::<algorithm>_<parameter set>`.
//!
//! Each algorithm lives in its own crate and is re-exported here behind a feature, so
//! algorithms you do not enable are not compiled.
//!
//! | Category | Feature  | Modules                                          | Standard |
//! |----------|----------|--------------------------------------------------|----------|
//! | [`kem`]  | `ml-kem` | `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`        | FIPS 203 |
//!
//! ```
//! use crypto_pq::kem::ml_kem_768::{generate_keypair, Ciphertext, EncapsulationKey};
//! # struct Rng(u64);
//! # impl rand_core::RngCore for Rng {
//! #     fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
//! #     fn next_u64(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
//! #     fn fill_bytes(&mut self, dest: &mut [u8]) { for c in dest.chunks_mut(8) { let b = self.next_u64().to_le_bytes(); c.copy_from_slice(&b[..c.len()]); } }
//! # }
//! # impl rand_core::CryptoRng for Rng {}
//! # let mut rng = Rng(0x9e3779b97f4a7c15);
//! let (dk, ek) = generate_keypair(&mut rng)?;
//! let ek = EncapsulationKey::from_bytes(ek.as_bytes())?;
//! let (secret_sender, ciphertext) = ek.encapsulate(&mut rng);
//! let ciphertext = Ciphertext::from_bytes(ciphertext.as_bytes())?;
//! assert_eq!(dk.decapsulate(&ciphertext).as_bytes(), secret_sender.as_bytes());
//! # Ok::<(), crypto_pq::kem::Error>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Key encapsulation mechanisms: establish a shared secret from a public key.
#[cfg(feature = "ml-kem")]
pub mod kem {
    pub use crypto_pq_ml_kem::{ml_kem_1024, ml_kem_512, ml_kem_768, Error};
}
