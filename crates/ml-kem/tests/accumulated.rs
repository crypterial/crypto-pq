//! Accumulated randomized test for ML-KEM-768, cross-checked against an independent
//! implementation of the final standard: the procedure and the expected hashes are those
//! of `TestAccumulated` in Go's `crypto/mlkem` (src/crypto/mlkem/mlkem_test.go).
//!
//! A SHAKE-128 stream with empty input supplies, per iteration, the 64-byte key seed
//! (d || z), a 32-byte encapsulation seed and a random ciphertext. The encapsulation key,
//! the ciphertext, the shared secret and the implicit-rejection secret of the random
//! ciphertext are absorbed into a second SHAKE-128, whose output is compared after 100
//! and after 10 000 iterations.

use crypto_pq_ml_kem::ml_kem_768::*;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

const AFTER_100: &str = "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415";
const AFTER_10_000: &str = "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc";

fn digest(acc: &Shake128) -> String {
    let mut out = [0u8; 32];
    acc.clone().finalize_xof().read(&mut out);
    hex::encode(out)
}

#[test]
fn ml_kem_768_matches_go_crypto_mlkem_over_10_000_random_vectors() {
    let mut stream = Shake128::default().finalize_xof();
    let mut acc = Shake128::default();
    let mut seed = [0u8; 64];
    let mut m = [0u8; 32];
    let mut random_ct = [0u8; CIPHERTEXT_LEN];

    for i in 1..=10_000 {
        stream.read(&mut seed);
        let (d, z) = seed.split_at(32);
        let (dk, ek) = keypair_from_seed(d.try_into().unwrap(), z.try_into().unwrap());
        acc.update(ek.as_bytes());

        stream.read(&mut m);
        let (k, c) = ek.encapsulate_with_seed(&m);
        acc.update(c.as_bytes());
        acc.update(k.as_bytes());
        assert_eq!(dk.decapsulate(&c).as_bytes(), k.as_bytes(), "iteration {i}");

        stream.read(&mut random_ct);
        let rejected = dk.decapsulate(&Ciphertext::from_bytes(&random_ct).unwrap());
        acc.update(rejected.as_bytes());

        if i == 100 {
            assert_eq!(digest(&acc), AFTER_100);
        }
    }
    assert_eq!(digest(&acc), AFTER_10_000);
}
