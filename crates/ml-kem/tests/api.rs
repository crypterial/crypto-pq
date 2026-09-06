//! API behaviour: round trips, input checks, implicit rejection, error reporting.

use crypto_pq_ml_kem::Error;
use rand_core::{CryptoRng, RngCore};

/// xorshift64, seeded. Tests only.
struct TestRng(u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

impl CryptoRng for TestRng {}

macro_rules! api_suite {
    ($module:ident) => {
        mod $module {
            use super::*;
            use crypto_pq_ml_kem::$module::*;

            #[test]
            fn round_trip() {
                let mut rng = TestRng(0x9e3779b97f4a7c15);
                for _ in 0..20 {
                    let (dk, ek) = generate_keypair(&mut rng).unwrap();
                    let (k1, c) = ek.encapsulate(&mut rng);
                    let k2 = dk.decapsulate(&c);
                    assert_eq!(k1.as_bytes(), k2.as_bytes());
                    assert_eq!(dk.encapsulation_key(), ek);
                }
            }

            #[test]
            fn encoded_forms_round_trip() {
                let mut rng = TestRng(1);
                let (dk, ek) = generate_keypair(&mut rng).unwrap();
                let (k, c) = ek.encapsulate(&mut rng);
                let ek2 = EncapsulationKey::from_bytes(ek.as_bytes()).unwrap();
                let dk2 = DecapsulationKey::from_bytes(dk.as_bytes()).unwrap();
                let c2 = Ciphertext::from_bytes(c.as_bytes()).unwrap();
                assert_eq!(ek2, ek);
                assert_eq!(dk2.as_bytes(), dk.as_bytes());
                assert_eq!(dk2.decapsulate(&c2).as_bytes(), k.as_bytes());
            }

            #[test]
            fn tampered_ciphertext_gives_a_different_secret() {
                let mut rng = TestRng(2);
                let (dk, ek) = generate_keypair(&mut rng).unwrap();
                let (k, c) = ek.encapsulate(&mut rng);
                for position in [0, CIPHERTEXT_LEN / 2, CIPHERTEXT_LEN - 1] {
                    let mut bytes = *c.as_bytes();
                    bytes[position] ^= 0x01;
                    let rejected = dk.decapsulate(&Ciphertext::from_bytes(&bytes).unwrap());
                    assert_ne!(rejected.as_bytes(), k.as_bytes());
                    let again = dk.decapsulate(&Ciphertext::from_bytes(&bytes).unwrap());
                    assert_eq!(
                        again.as_bytes(),
                        rejected.as_bytes(),
                        "implicit rejection is deterministic"
                    );
                }
            }

            #[test]
            fn wrong_lengths_are_rejected() {
                assert_eq!(
                    EncapsulationKey::from_bytes(&[0u8; ENCAPSULATION_KEY_LEN - 1]).unwrap_err(),
                    Error::InvalidLength
                );
                assert_eq!(
                    EncapsulationKey::from_bytes(&[0u8; ENCAPSULATION_KEY_LEN + 1]).unwrap_err(),
                    Error::InvalidLength
                );
                assert_eq!(
                    DecapsulationKey::from_bytes(&[0u8; DECAPSULATION_KEY_LEN - 1]).unwrap_err(),
                    Error::InvalidLength
                );
                assert_eq!(
                    Ciphertext::from_bytes(&[0u8; CIPHERTEXT_LEN + 1]).unwrap_err(),
                    Error::InvalidLength
                );
                assert_eq!(
                    Ciphertext::from_bytes(&[]).unwrap_err(),
                    Error::InvalidLength
                );
            }

            #[test]
            fn modulus_check_rejects_a_coefficient_equal_to_q() {
                let mut rng = TestRng(3);
                let (_, ek) = generate_keypair(&mut rng).unwrap();
                let mut bytes = *ek.as_bytes();
                // First 12-bit coefficient := 3329 (0xd01), little-endian bit packing.
                bytes[0] = 0x01;
                bytes[1] = (bytes[1] & 0xf0) | 0x0d;
                assert_eq!(
                    EncapsulationKey::from_bytes(&bytes).unwrap_err(),
                    Error::InvalidEncapsulationKey
                );
                // 3328 (0xd00) is the largest valid coefficient.
                bytes[0] = 0x00;
                assert!(EncapsulationKey::from_bytes(&bytes).is_ok());
            }

            #[test]
            fn hash_check_rejects_a_modified_decapsulation_key() {
                let mut rng = TestRng(4);
                let (dk, _) = generate_keypair(&mut rng).unwrap();
                let mut bytes = *dk.as_bytes();
                let hash_offset = DECAPSULATION_KEY_LEN - 64;
                bytes[hash_offset] ^= 0x80;
                assert_eq!(
                    DecapsulationKey::from_bytes(&bytes).unwrap_err(),
                    Error::InvalidDecapsulationKey
                );
                bytes[hash_offset] ^= 0x80;
                bytes[hash_offset - 1] ^= 0x01;
                assert_eq!(
                    DecapsulationKey::from_bytes(&bytes).unwrap_err(),
                    Error::InvalidDecapsulationKey
                );
            }

            #[test]
            fn secrets_do_not_leak_through_debug() {
                let mut rng = TestRng(5);
                let (dk, ek) = generate_keypair(&mut rng).unwrap();
                let (k, _) = ek.encapsulate(&mut rng);
                assert_eq!(format!("{dk:?}"), "DecapsulationKey(..)");
                assert_eq!(format!("{k:?}"), "SharedSecret(..)");
            }
        }
    };
}

api_suite!(ml_kem_512);
api_suite!(ml_kem_768);
api_suite!(ml_kem_1024);

#[test]
fn errors_display() {
    assert_eq!(Error::InvalidLength.to_string(), "invalid length");
    assert_eq!(
        Error::InvalidEncapsulationKey.to_string(),
        "encapsulation key failed the modulus check"
    );
    assert_eq!(
        Error::InvalidDecapsulationKey.to_string(),
        "decapsulation key failed the hash check"
    );
    assert_eq!(
        Error::PairwiseConsistency.to_string(),
        "key pair failed the pairwise consistency test"
    );
}
