# 23. Rust profile

## 23.1 Public API idiom

1. Crate `crypto-pq`, library `crypto_pq`, `#![no_std]` with `alloc`. Every public operation is a
   synchronous function.
2. Fallible operations return `Result<T, Error>`. `Error` is a `#[non_exhaustive]` enum with one
   variant per code ([16.4.5](../16-naming.md#1645-error-codes)), `Error::code(&self) -> &'static str`, `Display` and
   `core::error::Error`.
3. Operations that can fail because of caller input return `Result` [[D-03](../decisions.md#decision-d-03)], including
   `HashAlgorithm::digest_into`, `Hasher::digest_into`, `XofAlgorithm::digest`, `digest_into`,
   `Xof::update`, `Xof::read`, `Xof::read_into`, `MacAlgorithm::digest`, `digest_into`, `create`, and
   `Mac::digest_into`. Operations that cannot fail (`HashAlgorithm::digest`, `Hasher::update`,
   `Mac::update`, `verify`) return their value directly.
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
   Private keys implement `Debug` (algorithm only) and neither `Clone` nor `PartialEq`; their secrets
   are wiped on drop.
8. Thread safety: algorithm values and KEM and signature key objects are `Send + Sync`. `Hasher`, `Xof`
   and `Mac` are `Send` and take `&mut self` to change state.
9. Stateful keys: `StatefulPrivateKey<S: StateStore>` owns its store. `sign(&mut self, message)` takes
   exclusive access, so [11.13](../11-stateful-signatures.md#1113-concurrency) item 1 cannot arise; the store cannot reach the key that is calling it.
   The trait is `fn read(&mut self) -> Result<Option<Vec<u8>>, Error>` and
   `fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error>`; `&mut T`
   implements it for `T: StateStore`. Any `Err` from the store becomes STATE_PERSIST_FAILED.
10. `StatefulParameters` is `enum { Levels(&[(&str, &str)]), Name(&str) }`.

## 23.2 Security mechanics

1. Unsafe code: `#![deny(unsafe_code)]` at the crate root. `#[allow(unsafe_code)]` is permitted only in:
   the operating-system entropy module; the wipe module (volatile writes); the one-time initialization
   module; the CPU modules (feature detection, `core::arch` intrinsics, inline assembly); and the
   valgrind client requests of the `crypto_pq_ct` build. Each unsafe block carries a comment that states
   why it is sound.
2. Constant time: masks and selections go through an optimization barrier defined in the constant-time
   module, so that the compiler cannot turn them into branches; `==` on secret slices is forbidden;
   slice bounds checks depend only on public lengths; `match` and `if` never take a secret
   operand.
3. Wiping: volatile writes followed by a compiler fence. `SecretBytes` and the private key types wipe on
   drop. Secret stack arrays are wiped before the function returns, on every path. Moves of secret
   values are avoided (secrets live behind a heap pointer or are wiped after the move); copies that the
   compiler makes in registers or spill slots cannot be controlled, which the documentation states.
4. DIT: a guard object sets DIT and restores it on drop ([14.2](../14-security.md#142-data-independent-timing-dit)); Rust threads are operating-system
   threads.
5. Entropy without `std`: `getrandom(2)` (Linux, Android, FreeBSD, NetBSD, DragonFly, illumos,
   Solaris), `getentropy` in chunks of 256 bytes (Apple, OpenBSD), `ProcessPrng` from
   `bcryptprimitives.dll` (Windows, linked with `raw-dylib`), `random_get` (WASI). Every other target
   returns RNG_FAILURE.
6. Constant-time verification: `RUSTFLAGS="--cfg crypto_pq_ct"` and the `ct` test under valgrind
   memcheck, on x86-64 and ARM64, in the default and `crypto_pq_portable` builds, on the minimum and
   stable toolchains. The `crypto_pq_ct` build leaves out the instructions valgrind cannot execute.

## 23.3 Performance mechanics

1. Kernels use `core::arch` intrinsics and inline assembly behind `#[target_feature]`, selected at run
   time by CPUID with XGETBV (x86-64) or the hardware capabilities (ARM64). The crate is built for the
   baseline target of each architecture; no target CPU flag is needed.
2. `--cfg crypto_pq_portable` removes every kernel and every use of DIT.
3. Allocation: fixed-size operations allocate only their returned value; the `_into` forms allocate
   nothing. Key objects hold the caches of [14.6](../14-security.md#146-memory).
4. Stack: no operation needs more than 64 KiB of stack.
5. Measurement: a counting global allocator in the benchmark harness.

## 23.4 Build, packaging and platforms

1. Minimum Rust 1.88, edition 2024.
2. No `[dependencies]`. Dev-dependencies are not permitted either: tests use only the standard library
   (vectors are plain text).
3. The published crate contains the sources, `Cargo.toml`, `Cargo.lock`, `LICENSE-APACHE` and
   `LICENSE-MIT`; it is published by crates.io trusted publishing ([20.4](../20-versioning.md#204-release-process)).

## 23.5 Conformance checklist

- [ ] Part I behaviour.
- [ ] Compliance suite: all of `vectors/` in the default, portable and `crypto_pq_ct` builds.
- [ ] `cargo fmt --check`, `cargo clippy -D warnings` for every cfg and cross target.
- [ ] valgrind constant-time check on x86-64 and ARM64, default and portable.
- [ ] x86-64 CPU models of [18.2](../18-testing.md#182-cpu-tiers) under emulation.
