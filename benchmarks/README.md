# Benchmarks

This folder describes how crypto-pq is timed and holds its times for each release. The times of
2.0.0 are in [`results-2.0.0.md`](results-2.0.0.md). Performance never justifies weakening a rule
of the specification (principle P11).

## What is timed

The time of one operation, in nanoseconds, single-threaded, for each row: an operation of one
parameter set with one input length. The rows are grouped in eight categories:

| category | rows |
|---|---|
| 1 Keccak | SHA-3, SHAKE, cSHAKE, KMAC, Keccak-256 |
| 2 ML-DSA | key generation, signing (deterministic and hedged), verification |
| 3 ML-KEM | key generation, encapsulation, decapsulation |
| 4 SHA-2, HMAC, HKDF, LMS, XMSS | hashes, MACs, key derivation, stateful signatures |
| 5 SLH-DSA | key generation, signing, verification |
| 6 BLAKE2, BLAKE3 | hashes, MACs, extendable output, key derivation |
| 7 Ascon | Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 |
| 8 FrodoKEM | key generation, encapsulation, decapsulation |

Operations on keys are timed with a key object made before the timing, and also with a fresh key,
imported from bytes inside every call: the encapsulation of ML-KEM and FrodoKEM, the
decapsulation of FrodoKEM and the verification of ML-DSA, SLH-DSA, HSS/LMS and XMSS. A fresh-key
row is the import and the operation together, as an application that holds the key as bytes runs
them.

Some rows include a check that the specification requires, and the results mark them:

- signing with HSS/LMS, XMSS and XMSS^MT verifies each one-time signature before it is released
  ([D-13](../spec/decisions.md#decision-d-13), [D-63](../spec/decisions.md#decision-d-63)), and so
  does the key generation of HSS and XMSS^MT with more than one level, which signs the key of each
  lower tree;
- FrodoKEM key generation through the public API runs its pairwise test, and so does the import of
  a FrodoKEM private key, which a fresh-key decapsulation includes.

Key generation is timed through `hazmat` from a seed, which runs no pairwise test, unless the row
says otherwise; ML-KEM and FrodoKEM also have rows of key generation through the public API, with
the operating system's randomness, with and without the pairwise test
(`KeyGenOptions::with_self_test`).

## Rows

A row is named by the algorithm, then the operation or the length of the input:

- `64B`, `1KiB`, `16KiB`, or a number of bytes: a one-call hash or MAC of that input;
  `in64B/out1KiB` and `64>1024`: the lengths of the input and of the output;
- `stream64/<length>`: a hash of that input in updates of 64 bytes;
- `hmac-<hash>/key+64B`: an HMAC of 64 bytes in one call, the key set up inside it;
  `hmac-<hash>/reused/<length>`: an HMAC under a key set up once (`MacKey`);
- `hkdf-<hash>/rfc1` to `rfc3`: the lengths of the test cases of RFC 5869 Appendix A;
  `tls-okm32` and `tls-okm64`: an input key of 32 bytes, a salt of the hash's length and an output
  of 32 or 64 bytes;
- `blake2b-mac`, `blake2s-mac`: a keyed BLAKE2 in one call, with keys of 64 and 32 bytes;
  `blake3-keyed`: a keyed BLAKE3; `blake3-derive/<length>`: `derive_key` under one context;
  `blake3-derive2ctx/<length>`: two derivations in turn under two contexts;
- `keygen`, `sign`, `verify`: with a key object; `signh`: hedged ML-DSA signing; `fresh` (ML-DSA
  and ML-KEM), `verify-fresh`, `encaps-fresh`, `decaps-fresh`: with a fresh key;
  `keygen+sign1`: key generation and the first signature of a multi-level key;
- `keygen-selftest` (FrodoKEM), `keygen [self-test]` (ML-KEM): key generation through the public
  API with the pairwise test; `keygen-public` and `keygen` of the `kc` rows (ML-KEM): the same
  without it; `keygen [seeded]`: through `hazmat` from a seed;
- `encaps` and `encaps-fresh`, and `fresh` of the ML-KEM `kem` rows, take their randomness from
  the caller through `hazmat`; `fresh-public` and `fresh` of the ML-KEM `kem2` rows draw it from
  the operating system.

ML-KEM is timed in three programs, `kc`, `kem` and `kem2`, each in a process of its own, and the
results list the rows of each under its name.

## Processors

The runs use GitHub's hosted runners with the images `ubuntu-24.04` (x86-64) and
`ubuntu-24.04-arm` (ARM64). A runner's processor is drawn by GitHub, so each job prints its model,
and the rows are grouped by processor model. The runs of November 2026 drew these processors:

| processor | microarchitecture |
|---|---|
| AMD EPYC 7763 | Zen 3 |
| AMD EPYC 9V74 | Zen 4 |
| AMD EPYC 9V45 | Zen 5 |
| Intel Xeon Platinum 8370C | Ice Lake |
| Intel Xeon Platinum 8573C | Emerald Rapids |
| Intel Xeon 6975P-C | Granite Rapids |
| Arm Neoverse N2 | Neoverse N2 |

A job can also be limited to some processor models: it prints its processor and ends without
timing on any other. A result table covers only the processors that its runs measured, and gives
the number of runners of each. RISC-V runs the portable code and is checked for correctness only
([D-105](../spec/decisions.md#decision-d-105-revised-by-d-120)); it is not timed.

## How

- On each runner, before any timing, the library's tests run on the runner's processor.
- One binary per architecture is built once, with Rust 1.99.0 in release mode, one codegen unit,
  and every function at a 64-byte boundary (`-C llvm-args=-align-all-functions=6`), and the same
  binary runs on every runner of that architecture.
- Each program is one process pinned to one CPU. It times its rows in rounds; a sample runs enough
  calls to last a fixed time.
- For each runner, a row's time is the median over its rounds; for each processor, the median over
  its runners.
- The program of BLAKE2, BLAKE3, Ascon and FrodoKEM runs in six processes on each runner: one over
  every row, then five passes over the rows again. Their times come from the first.

The timing harness is not in this repository.

## Timing the crate yourself

The crate's own benchmark times every family:

```sh
cd rust
cargo bench --locked --all-features --bench bench
RUSTFLAGS="--cfg crypto_pq_portable" cargo bench --locked --all-features --bench bench
```

Each case runs in batches until one second has passed and prints its iterations and the mean time
per operation in microseconds; the second command times the portable code. The `rust benchmark`
job of CI runs both on GitHub's x86-64 and ARM64 runners.
