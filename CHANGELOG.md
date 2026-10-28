# Changelog

All notable changes to the `crypto-pq` crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and its MAJOR.MINOR is the version of
the [crypto-pq specification](spec/00-contents.md) that it implements
([Section 20.1](spec/20-versioning.md)).

## [Unreleased]

Implements specification 1.1 (draft).

### Changed

- Keccak-f[1600] on x86-64 CPUs with AVX-512F and AVX-512VL: a kernel for four states side by side
  and, on the CPUs that run it in less time than the scalar code (AMD Zen 4 and Zen 5, Intel Ice
  Lake Xeon), one for a single state, selected at run time, use the EVEX instructions on 256-bit
  registers only (three-input logic and 64-bit rotations, 32 registers); in a build for the baseline
  target, no code uses a 512-bit register. Sponges squeezed side by side, as in ML-KEM, ML-DSA and
  SLH-DSA, stay in the kernel's vector layout from one block to the next. The kernels serve SHA-3,
  SHAKE, cSHAKE, KMAC and the Keccak of ML-KEM, ML-DSA, SLH-DSA and FrodoKEM. The AVX2 kernels and
  the portable code stay their twins, and outputs are unchanged.
- Keccak-f[1600] on x86-64 CPUs with AVX2 and without AVX-512: the kernel for up to four states
  loads and stores the lanes of each state four at a time, with transposes, in place of loops over
  the states, so that its state array is indexed with constants only and, at opt-level 3, stays in
  registers. Outputs are unchanged.
- SLH-DSA-SHAKE on x86-64 CPUs with AVX2: F and PRF of up to four nodes, whose input fits one
  block, are padded, permuted and read in the four-state kernel's vector layout, from the parts of
  each message (the public seed shared by all four is broadcast), with no sponge object and no
  copy of the states, and only the output lanes are read back; with AVX-512VL the kernel's rounds
  are the AVX-512VL ones. Other CPUs keep the sponges side by side. Outputs are unchanged.
- ML-KEM key generation hashes the encapsulation key beside the sampling of the matrix: each run
  of entries leaves a slot in the group of sponges for the blocks of the key that the rows of t
  encoded so far complete. ML-KEM-1024 with groups of four samples a first row of four and then
  runs of three; ML-KEM-512 samples all four entries in one group where the CPU's group has four,
  and then hashes the key. Outputs are unchanged.
- An ML-KEM encapsulation key decoded from bytes is hashed beside the sampling of its matrix, in
  the slot that runs of one entry less than the group of sponges leave. On Neoverse N2, which
  permutes three states at a time and the rest one by one, the runs are chosen so that the hash
  takes the third or sixth state of a call, except beside the last entry of ML-KEM-1024, where it
  takes the second. Its modulus check is ByteEncode_12(ByteDecode_12(ek)) = ek in the CPU's
  kernels, as FIPS 203 states it, and elsewhere one loop over the whole key. Outputs and the keys
  accepted are unchanged.
- ML-KEM-512 encryption samples y, e1 and e2 in two permutation calls in place of three: e1[1]
  and then e2 are squeezed beside the sponges of y and e1[0]. Outputs are unchanged.
- ML-KEM on x86-64 with AVX2: the sampling of the matrix reads its 12-bit candidates from the
  Keccak lanes in place, without a copy into a byte buffer, and the NTT and inverse NTT take the
  layers within each block of 32 coefficients four blocks at a time, so that four independent
  butterflies are in flight. The inverse stores each block, transposed, in its output first, so
  that the compiler keeps no block of secret coefficients on the stack. Outputs are unchanged.
- Keccak-f[1600] on Arm Neoverse N2: one state takes scalar rounds whose rotations fold into the
  operands of EOR and BIC, and three states take two in vector registers with the SHA3 instructions
  beside one in general registers, in place of the portable code. Other Arm cores keep the kernels
  they had. Outputs are unchanged.
- One-shot SHA-3, SHAKE, cSHAKE and KMAC on Apple cores have one copy of the kernel for a start
  from zero and one for the precomputed state of cSHAKE and KMAC, so that LLVM no longer joins the
  two starts through a copy of the state on the stack. A state permuted or absorbed alone is loaded
  into one half of each vector register by plain loads. Outputs are unchanged.
- BLAKE3-MAC on x86-64 with AVX2 or SSE4.1: a message of at most 64 bytes is hashed by the one-block
  kernel from the key's bytes, so that no converted copy of the key is stored. Outputs are
  unchanged.
- The minimum supported Rust version is 1.89, the first in which the AVX-512 target features and
  intrinsics are stable.

### Fixed

- Secret buffers on the stack are wiped before each function returns, on every path, as
  specification 14.5 requires ([decision D-76](spec/decisions.md#decision-d-76)): the SHA-2 message
  schedules, the buffers of the Keccak, BLAKE2, BLAKE3 and NTT kernels on x86-64, copies of partial
  lanes and words, the base64 buffers of private keys, and the chain values of SLH-DSA, LMS and
  XMSS. Secrets that were returned by value, such as KEM shared secrets, ML-KEM and ML-DSA
  polynomials, the chaining values and outputs of BLAKE3, and the key states of one-shot HMAC,
  HKDF and KMAC, are written into storage that their owner wipes. ML-DSA signing wipes w1 and the
  products with s1 and s2 of rejected attempts.
  In builds below opt-level 3, where the compiler keeps the register arrays of the kernels in
  memory, those arrays are wiped too; a build script reads the opt-level for this. Copies that the
  compiler makes in registers and spill slots remain, as the documentation states. Outputs are
  unchanged.
- Keccak-f[1600] in builds below opt-level 3: the arrays of theta and of rho and pi in the rounds
  of the portable code, of the AVX2 kernel for four states and of the ARM64 kernel with the SHA3
  instructions, which the compiler kept on the stack, are wiped before each round returns, and the
  temporaries in which it built some of them are no longer made. At opt-level 3 the machine code is
  unchanged. Outputs are unchanged.

## [1.0.1] - 2026-10-26

Implements specification 1.0, as 1.0.0 does. The API and every output are unchanged.

### Changed

- FrodoKEM: matrix A and its products with the secret matrices use CPU kernels selected at run
  time, each with its portable twin: on ARM64, AES-128 rows with the ARMv8 AES instructions
  (eight blocks in flight) and the products with NEON; on x86-64, AES-128 rows with AES-NI and,
  on AVX2 CPUs, four SHAKE128 rows at a time and the products with AVX2. Noise sampling and the
  SHAKE128 rows of the portable code run on whole blocks. Outputs are unchanged.
- BLAKE3, BLAKE3-256, BLAKE3-MAC and BLAKE3-KDF hash several chunks, and several parents, at a
  time with CPU kernels selected at run time, each with its portable twin: NEON on ARM64, AVX2 or
  SSE4.1 on x86-64. The extended output is computed several blocks at a time. Outputs are
  unchanged.
- Ascon on ARM64: the scalar kernel runs on Apple cores only, where it takes less time than the
  portable code; other cores, such as Neoverse N2, on which the portable code takes less time,
  run it. Outputs are unchanged.

## [1.0.0] - 2026-10-23

The first release that implements specification 1.0.

### Added

- Key encapsulation: ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (FIPS 203); FrodoKEM-976 and
  FrodoKEM-1344 and their ephemeral eFrodoKEM forms, each with AES or SHAKE
  (ISO/IEC 18033-2:2006/Amd 2:2026).
- Signatures: ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) and the 12 SLH-DSA sets (FIPS 205), in
  pure and pre-hash (HashML-DSA, HashSLH-DSA) modes, with hedged or deterministic signing and a
  context string; the 12 HashSLH-DSA values of RFC 9909.
- Stateful hash-based signatures: HSS/LMS (RFC 8554, RFC 9858) and XMSS and XMSS^MT (RFC 8391), with
  the parameter sets of NIST SP 800-208, an application-provided `StateStore`, an authenticated tree
  cache, a `reserve` option and erasure of the secrets when a key is exhausted.
- Hash functions and XOFs: SHA-2 (FIPS 180-4); SHA-3, SHAKE and cSHAKE (FIPS 202, NIST SP 800-185);
  BLAKE2b and BLAKE2s (RFC 7693); BLAKE3; Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128
  (NIST SP 800-232).
- MACs: HMAC with SHA-2 (FIPS 198-1), KMAC128 and KMAC256, BLAKE2b-MAC, BLAKE2s-MAC and BLAKE3-MAC.
- KDFs: HKDF with SHA-2 (RFC 5869) and BLAKE3-KDF.
- Key formats: raw, DER (SubjectPublicKeyInfo and PKCS #8) and PEM for ML-KEM, ML-DSA and SLH-DSA
  keys and for HSS/LMS and XMSS public keys; raw for FrodoKEM.
- One Cargo feature per algorithm family, all enabled by default, and the opt-in `hazmat` feature
  with the deterministic operations for known-answer and interoperability tests.
- `no_std` with `alloc`, no dependencies, Rust 1.88 or later.
- CPU-specific code for x86-64 (AVX2, SSE4.1, SHA-NI, AES-NI) and ARM64 (NEON, AES, SHA-2, SHA-3,
  SHA-512), selected at run time, with portable code on every target.
- Constant-time code for secret data, checked in CI with valgrind memcheck on x86-64 and ARM64, and
  the ARM64 data-independent timing mode (DIT) around asymmetric secret operations.
- `SecretBytes` for every secret output, wiped on drop; private keys wiped on drop.
- Pairwise consistency tests at key generation (on by default) and in the ML-KEM and FrodoKEM
  private-key import checks, and verification of every stateful signature before its release.
- Operating-system randomness only, with `Error::RngFailure` on targets without a source.
- `enable_data_independent_timing()`, which extends DIT to MACs and KDFs.

### Usage requirements

These rules are part of the API contract:

- **Pre-hash policy** ([9.1.3](spec/09-signatures.md)). HashML-DSA and HashSLH-DSA accept only
  SHA-2, SHA-3, SHAKE128 and SHAKE256, and only a function with at least the collision strength of
  the signature (128, 192 or 256 bits by category). SHA-224, SHA-512/224 and SHA3-224 are never
  accepted. Signing with a refused pre-hash fails with `Error::InvalidOption`; verification returns
  `false`. The policy is fixed, and only the hazmat functions skip the strength rule.
- **No external μ** ([9.1.5](spec/09-signatures.md)). No public function accepts μ, the message
  representative or a precomputed digest in place of the message. Only the hazmat test functions
  take the message representative, for the ACVP test groups.
- **State store contract** ([11.6](spec/11-stateful-signatures.md)). `StateStore::update` must be an
  atomic compare-and-swap and must make the new record durable before it returns `true`. The record
  contains secrets and must be protected like a private key. It must never be restored from a copy
  or a backup, cloned, or used by two key objects or processes at once; compare-and-swap cannot
  detect a rollback of the storage itself.
- **eFrodoKEM usage limit** ([8.2.6](spec/08-key-encapsulation.md)). An eFrodoKEM public key must be
  used for fewer than 2^8 ciphertexts. The crate does not enforce the limit and never chooses an
  eFrodoKEM set by default.
- **Hazmat** ([13](spec/13-hazmat.md)). The `hazmat` operations are for test vectors only; a seed
  or randomness must never be reused with a different key, message or ciphertext.
- **One key, one mode** ([9.1.2](spec/09-signatures.md)). Each ML-DSA or SLH-DSA key is used with
  only one of the hedged and deterministic variants, and only one of the pure and pre-hash modes.

[1.0.1]: https://github.com/crypterial/crypto-pq/tree/rust-v1.0.1
[1.0.0]: https://github.com/crypterial/crypto-pq/tree/rust-v1.0.0
