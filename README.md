# crypto-pq

Post-quantum cryptography. One crate per algorithm, one workspace, one set of rules.

```toml
[dependencies]
crypto-pq = { version = "0.1", features = ["ml-kem"] }
```

```rust
use crypto_pq::kem::ml_kem_768::{generate_keypair, Ciphertext, EncapsulationKey};
```

Paths follow `crypto_pq::<category>::<algorithm>_<parameter set>`. Categories planned: `kem`,
`sig`, `sig_stateful`, `aead`, `hash`, `xof`, `mac`, `kdf`, `rng`, plus the `recommended` and
`cnsa2` presets. Only `kem` ships today.

## Algorithms

| Algorithm | Standard | Standard status | Crate | Implementation status |
|-----------|----------|-----------------|-------|-----------------------|
| ML-KEM | FIPS 203 | Final, August 2024 | `crypto-pq-ml-kem` | Passes NIST ACVP, C2SP/CCTV negative vectors, and 10 000 random vectors cross-checked against Go's `crypto/mlkem`. Not yet audited. |

## Rules

1. Only post-quantum public-key algorithms. Symmetric primitives they need internally
   (SHA-3, SHAKE) come from audited external crates. Hybrid constructions take their
   classical component from an external crate through a trait; no classical public-key
   code lives here.
2. An algorithm is labelled `production` only when its standard is final and its crate
   passes every gate in CI: the official known-answer tests, the exhaustive tests of every
   reduction it uses, and a build for a `no_std` target. Until a third-party audit exists,
   the label stays `not yet audited`.
3. Draft standards and candidates under evaluation live behind `unstable-*` features. Their
   API and output may change in a minor release. The feature name pins the draft revision.
4. Standard parameter sets only. No custom variants, no reduced parameters.
5. `no_std`, no allocator, `#![forbid(unsafe_code)]`, secret-independent control flow and
   memory access, zeroization of secret material.

## Layout

```text
crates/crypto-pq     facade, re-exports each algorithm crate behind a feature
crates/ml-kem        crypto-pq-ml-kem
vectors/             official test vectors, pinned by upstream commit and sha256
```

## Verification

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --release
cargo build -p crypto-pq-ml-kem --target thumbv7em-none-eabihf
(cd vectors && sha256sum -c SHA256SUMS)
```

## License

Apache-2.0 OR MIT, at your option.
