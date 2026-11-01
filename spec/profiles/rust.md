# 23. Rust profile

## 23.1 Public API idiom

1. Crate `crypto-pq`, library `crypto_pq`, `#![no_std]` with `alloc`. Every public operation is a
   synchronous function.
2. Fallible operations return `Result<T, Error>`. `Error` is a `#[non_exhaustive]` enum with one
   variant per code ([16.4.5](../16-naming.md#1645-error-codes)), `Error::code(&self) -> &'static str`, `Display` and
   `core::error::Error`.
3. Operations that can fail because of caller input return `Result` [[D-03](../decisions.md#decision-d-03)], including
   `HashAlgorithm::digest_into`, `Hasher::digest_into`, `XofAlgorithm::digest`, `digest_into`,
   `Xof::update`, `Xof::read`, `Xof::read_into`, `MacAlgorithm::digest`, `digest_into`, `create`,
   `key`, and `Mac::digest_into`. Operations that cannot fail (`HashAlgorithm::digest`,
   `Hasher::update`, `MacKey::create`, `Mac::update`, `verify`) return their value directly.
4. Option structs are `#[non_exhaustive]`, implement `Default`, and are built with chained setters,
   for example `SignOptions::default().with_context(b"app").with_deterministic(true)` [[D-22](../decisions.md#decision-d-22)]. The
   setters are named `with_<field>`. Rationale: a non-exhaustive struct cannot be built with a struct
   expression outside the crate, even with `..Default::default()`; setters let 1.x add options
   without breaking callers ([20.3](../20-versioning.md#203-compatibility-within-1x)).
5. Algorithm values are `pub const` items of `Copy` types.
6. `SecretBytes` [[D-23](../decisions.md#decision-d-23)] is the type of every secret output: `Encapsulation::shared_secret`, the
   result of `decapsulate`, of `KdfAlgorithm::derive`, `extract` and `expand`, and of a private key's
   `export_key`. It dereferences to `[u8]`, implements `AsRef<[u8]>`, does not implement `Clone`,
   prints as redacted, and wipes its bytes on drop. MAC tags, hashes, ciphertexts, public keys and
   signatures are `Vec<u8>`.
7. Key objects: public keys implement `Clone`, `PartialEq`, `Eq`, `Hash` and `Debug` (algorithm only).
   Private keys and `MacKey` implement `Debug` (algorithm only) and neither `Clone` nor `PartialEq`;
   their secrets are wiped on drop. `Mac` implements neither `Clone` nor `Debug`.
8. Thread safety: algorithm values, KEM and signature key objects and `MacKey` are `Send + Sync`.
   `Hasher`, `Xof` and `Mac` are `Send` and take `&mut self` to change state.
9. Stateful keys: `StatefulPrivateKey<S: StateStore>` owns its store. `sign(&mut self, message)` takes
   exclusive access, so [11.13](../11-stateful-signatures.md#1113-concurrency) item 1 cannot arise; the store cannot reach the key that is calling it.
   The trait is `fn read(&mut self) -> Result<Option<Vec<u8>>, Error>` and
   `fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error>`; `&mut T`
   implements it for `T: StateStore`. Any `Err` from the store becomes STATE_PERSIST_FAILED.
10. `StatefulParameters` is `enum { Levels(&[(&str, &str)]), Name(&str) }`.
11. A failure to allocate memory goes to the Rust allocation error handler
    (`alloc::alloc::handle_alloc_error`); it is not reported as an `Error`
    ([6.2](../06-api.md#62-inputs-and-outputs) item 6).

## 23.2 Security mechanics

1. Unsafe code: `#![deny(unsafe_code)]` at the crate root. `#[allow(unsafe_code)]` is permitted only in:
   the operating-system entropy module; the wipe module (volatile writes); the one-time initialization
   module; the CPU modules (feature detection, `core::arch` intrinsics, inline assembly); and the
   valgrind client requests of the `crypto_pq_ct` build. Each unsafe block carries a comment that states
   why it is sound.
2. Constant time: a mask computed from the sign or top bit of a secret value comes from
   `ct::sign_mask`, which puts an optimization barrier on the value, spreads the bit with an
   arithmetic shift and puts a barrier on the mask, so that the compiler can neither read the
   shift as a comparison nor turn the selection that uses the mask into a branch
   [[D-79](../decisions.md#decision-d-79)]; a bit spread by negation passes a barrier before and
   after it. A word of byte masks formed by word arithmetic, as in the word passes of SampleInBall,
   needs no barrier of its own: no single bit decides it, and the secret byte that it is compared
   with passes a barrier first. The barrier `ct::barrier` is an empty inline assembly block on a
   register where Rust has stable inline assembly, `core::hint::black_box` on the other targets
   and under Miri, and the identity on x86-64 and ARM64, whose builds CI checks under valgrind
   ([14.1](../14-security.md#141-constant-time) item 7). It is defined in the CPU module, where
   item 1 permits inline assembly, and the constant-time module re-exports it. `==` on secret
   slices is forbidden; slice bounds checks depend only on public lengths; `match` and `if` never
   take a secret operand.
3. Wiping: zero stores that the compiler cannot remove, then a compiler fence. A buffer is filled with
   zeros and its address goes into an empty assembly block; up to eight values of at most a word, and
   targets without stable inline assembly, get volatile writes. `SecretBytes` and the private key
   types wipe on drop. Secret stack arrays are wiped before the function returns, on every path, and
   arrays that the compiler keeps in registers at opt-level 3 are wiped at the other levels, which
   the build script detects ([D-76](../decisions.md#decision-d-76)). Moves of secret values are
   avoided (secrets live behind a heap pointer, or a function writes them into storage that its owner
   wipes); copies that the compiler makes in registers or spill slots cannot be controlled, which the
   documentation states.
4. DIT: a guard object sets DIT and restores it on drop ([14.2](../14-security.md#142-data-independent-timing-dit)); Rust threads are operating-system
   threads.
5. Entropy without `std`: `getrandom(2)` (Linux, Android, FreeBSD, NetBSD, DragonFly, illumos,
   Solaris), `getentropy` in chunks of 256 bytes (Apple, OpenBSD), `ProcessPrng` from
   `bcryptprimitives.dll` (Windows, linked with `raw-dylib`), `random_get` (WASI preview 1). Every
   other target, including WASI preview 2, returns RNG_FAILURE.
6. Constant-time verification: `RUSTFLAGS="--cfg crypto_pq_ct"` and the `ct` test under valgrind
   memcheck, in the default and `crypto_pq_portable` builds, on x86-64 with the minimum and the stable
   toolchain and on ARM64 with the stable toolchain, and on x86-64 in the `crypto_pq_sse41` build with
   the stable toolchain. The `crypto_pq_ct` build leaves out the instructions valgrind cannot
   execute, AVX-512 among them [[D-44](../decisions.md#decision-d-44)].

## 23.3 Performance mechanics

1. Kernels use `core::arch` intrinsics and inline assembly behind `#[target_feature]`, selected at run
   time by CPUID with XGETBV (x86-64; the AVX-512 state from `sysctl` on macOS) or the hardware
   capabilities (ARM64). The crate is built for the
   baseline target of each architecture; no target CPU flag is needed.
2. `--cfg crypto_pq_portable` removes every kernel and every use of DIT. `--cfg crypto_pq_sse41` caps
   x86-64 detection at SSE4.1 and AES-NI, so that CI runners with AVX2 run the SSE4.1 kernels.
3. Allocation: fixed-size operations allocate only their returned value; the `_into` forms allocate
   nothing. Key objects hold the caches of [14.6](../14-security.md#146-memory).
4. Stack: no operation needs more than 64 KiB of stack.
5. Measurement: a counting global allocator in the benchmark harness.

## 23.4 Build, packaging and platforms

1. Minimum Rust 1.89, edition 2024.
2. No `[dependencies]`. Dev-dependencies are not permitted either: tests use only the standard library
   (vectors are plain text).
3. The published crate contains the sources, `Cargo.toml`, `Cargo.lock`, `LICENSE-APACHE` and
   `LICENSE-MIT`; it is published by crates.io trusted publishing ([20.4](../20-versioning.md#204-release-process)).
   The release packages and verifies the crate with its default features.
4. Cargo features [[D-70](../decisions.md#decision-d-70)]. Each algorithm family is a feature that gates its public
   constants and the API types that they use:

   | feature | public items | needs |
   |---|---|---|
   | `ml-kem` | `ML_KEM_*`; the KEM types | |
   | `frodokem` | `FRODOKEM_*`, `EFRODOKEM_*`; the KEM types | |
   | `ml-dsa` | `ML_DSA_*`; the signature types | |
   | `slh-dsa` | `SLH_DSA_*`, `HASH_SLH_DSA_*`; the signature types | |
   | `lms` | `HSS_LMS`; the stateful types | |
   | `xmss` | `XMSS`, `XMSS_MT`; the stateful types | |
   | `sha2` | `SHA_*`; the hash types | |
   | `sha3` | `SHA3_*`, `SHAKE*`, `CSHAKE*`, `KMAC*`; the hash, XOF and MAC types | |
   | `blake2` | `BLAKE2B_*`, `BLAKE2S_*`, `BLAKE2B_MAC`, `BLAKE2S_MAC`; the hash and MAC types | |
   | `blake3` | `BLAKE3`, `BLAKE3_256`, `BLAKE3_MAC`, `BLAKE3_KDF`; the hash, XOF, MAC and KDF types | |
   | `ascon` | `ASCON_HASH256`, `ASCON_XOF128`, `ASCON_CXOF128`; the hash and XOF types | |
   | `hmac` | `HMAC_SHA_*`; the MAC types | `sha2` |
   | `hkdf` | `HKDF_SHA_*`; the KDF types | `hmac` |
   | `hazmat` | the `hazmat` module ([13](../13-hazmat.md#13-the-hazmat-namespace)), with the operations of the enabled families | |

   Rules:

   1. `default` enables every algorithm family. `hazmat` is not a default feature: a caller enables it
      explicitly. Rationale: hazmat operations take seeds and randomness from the caller, and a reused
      value breaks the scheme ([13](../13-hazmat.md#13-the-hazmat-namespace) item 1); an application that never names the feature cannot
      reach them, so no default build exposes them.
   2. `Error`, `enable_data_independent_timing` and the key formats and options of the enabled
      families are always available with them; `SecretBytes` is available with every family that
      returns it.
   3. The `ml-dsa` and `slh-dsa` features also make public the hash values that [9.1.3](../09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa) approves as a
      pre-hash (`SHA_*`, `SHA3_*`, `SHAKE128`, `SHAKE256`) and their types, so that the pre-hash
      options work whether or not `sha2` or `sha3` is enabled; they compute with the internal cores.
   4. Internal building blocks (Keccak, the SHA-2 cores, AES, the DER, PEM and base64 encodings,
      the entropy source, CPU detection and the CPU kernels) compile whenever an enabled family needs
      them. They are not features.
   5. Features are additive: enabling one never changes the behaviour of an item that another feature
      provides. An item keeps its whole interface in every build that has it; for example
      `BLAKE3_KDF.extract` fails with UNSUPPORTED with or without `hkdf`.
   6. Every combination of features builds. CI builds no feature, each feature alone, and `hazmat`
      with each family whose operations it extends (`ml-kem`, `frodokem`, `ml-dsa`, `slh-dsa`, `lms`,
      `xmss`, `sha3`) with `cargo clippy -D warnings`, on x86-64 and ARM64, and tests the default
      features, every feature, and each family with `hazmat` and the families that its tests also
      use. A build without every family allows only the lints that compiled-out
      code causes (unused items and parameters, unreachable or irrefutable patterns); the default
      build keeps them all.
5. The crate as published provides the whole of Part I; its features select what a build compiles.
   The compliance suite and the checks of Section [18](../18-testing.md) run with every feature, `hazmat` included.
6. API documentation is rustdoc: the crate root has an overview, the feature table and an example
   for each category, and every public item has a doc comment (`missing_docs`). `cargo doc` runs
   without a warning, broken links included, for the default features, every feature and none.

## 23.5 Conformance checklist

A conforming Rust implementation meets each item:

- Part I behaviour.
- Compliance suite: all of `vectors/` in the default, portable and `crypto_pq_ct` builds.
- `cargo fmt --check`, `cargo clippy -D warnings` for every cfg and cross target, with the default
  features and with every feature.
- `cargo clippy -D warnings` with no feature, each feature alone, and `hazmat` with each family whose
  operations it extends ([23.4](#234-build-packaging-and-platforms) item 4).
- `cargo doc` without a warning.
- valgrind constant-time check on x86-64 and ARM64, default and portable, and on x86-64 with
  `crypto_pq_sse41`.
- x86-64 CPU models of [18.2](../18-testing.md#182-cpu-tiers) under emulation, and the AVX-512 tier on native runners, with no
  instruction on a 512-bit register outside BLAKE3's two 512-bit kernels in the library built for
  the baseline target at any optimization level.
