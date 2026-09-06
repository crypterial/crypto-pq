# crypto-pq-ml-kem

ML-KEM (FIPS 203) in pure Rust. `no_std`, no allocator, no `unsafe`.

Parameter sets: `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`, all with the same API.

```rust
use crypto_pq_ml_kem::ml_kem_768::{generate_keypair, Ciphertext, EncapsulationKey};

let (dk, ek) = generate_keypair(&mut rng)?;
let ek = EncapsulationKey::from_bytes(ek.as_bytes())?;
let (secret, ciphertext) = ek.encapsulate(&mut rng);
let ciphertext = Ciphertext::from_bytes(ciphertext.as_bytes())?;
assert_eq!(dk.decapsulate(&ciphertext).as_bytes(), secret.as_bytes());
```

## What is checked

- NIST ACVP vectors for FIPS 203 (final): key generation, encapsulation, decapsulation with
  modified ciphertexts, encapsulation key check, decapsulation key check.
- C2SP/CCTV vectors: every out-of-range coefficient in the modulus check, and the `strcmp`
  edge case in implicit rejection.
- 10 000 accumulated random vectors for ML-KEM-768, checked against the hashes published
  by Go's `crypto/mlkem`, an independent implementation of the final standard.
- Exhaustive tests of the two multiply-and-shift reductions over their whole input range.
- FIPS 203 section 7 input checks on import, and the pairwise consistency test after key
  generation.

## What is not done yet

- Third-party audit.
- Side-channel measurement on real hardware. The code avoids secret-dependent branches,
  memory access and division, but that has not been measured.
- SIMD. This is a scalar implementation.

## License

Apache-2.0 OR MIT.
