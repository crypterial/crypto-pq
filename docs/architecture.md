# crypto-pq architecture

Decided 2026-10-02. Individual decisions and their dates are in `decisions.md`.

## Goal

Post-quantum cryptography in five languages: Rust, Python, TypeScript, Go and Zig. Each
language has its own complete implementation, written from scratch by the lab. All five follow
one specification and pass one shared set of test vectors, so a developer who switches language
finds the same names, the same behaviour and the same bytes.

## Rules

1. **No external dependencies.**
   - Nothing third-party ships in any package or runs inside a user's program.
   - Each implementation contains its own SHA-3/SHAKE, SHA-2, HMAC, encodings and helpers.
   - The language and its standard library are used only to reach the operating system
     (randomness, memory), never for a cryptographic algorithm.
   - Building and publishing use the official toolchains.
   - Test-only tools that never ship (test frameworks, fuzzers, sanitizers, constant-time
     checkers) and official test vectors are allowed.
2. **Only standardized algorithms, or constructions proven in production by major vendors.**
3. **Options instead of fixed choices**, with safe defaults. Behaviour is fixed only where safety
   requires it.
4. **The same keywords in every language**; only the casing follows each language.

## Scope

| Family | Basis | Parameter sets | Options |
|---|---|---|---|
| ML-KEM | FIPS 203 | 512, 768, 1024 | |
| ML-DSA | FIPS 204 | 44, 65, 87 | HashML-DSA, external μ, deterministic signing |
| SLH-DSA | FIPS 205 | all 12 | HashSLH-DSA, deterministic signing |
| LMS/HSS | SP 800-208, RFC 8554 | the SP 800-208 sets | |
| XMSS, XMSS^MT | SP 800-208, RFC 8391 | the SP 800-208 sets | |
| X-Wing | shipped in production by Apple (CryptoKit, OS 26), Google (Go 1.26, BoringSSL) and libsodium; wire format unchanged since draft 05 | one | |

- **Later:** `seal`/`open` on HPKE with ML-KEM or X-Wing. Go, Apple and BoringSSL run it in
  production, but it needs an AEAD and a KDF written in-house.
- **Out until final and proven:** FN-DSA, HQC, composite ML-KEM and ML-DSA, and the additional
  signature candidates.

Defaults: ML-KEM-768 (FIPS 203 §8) and ML-DSA-65; hedged signing; a self-test after key
generation, which can be switched off.

## Repository

```text
crypterial/crypto-pq        the only source repository
├── spec/                   the contract: names, operations, key formats, errors, vector format
├── vectors/                official vectors (NIST ACVP, C2SP) and the lab's own, pinned by SHA-256
├── rust/                   → crates.io  crypto-pq
├── python/                 → PyPI       crypto-pq
├── typescript/             → npm        crypto-pq
├── go/                     → generated read-only mirror crypterial/crypto-pq-go
├── zig/                    → generated read-only mirror crypterial/crypto-pq-zig
└── docs/
```

- **Why Go and Zig get mirrors:** Go modules want plain `vX.Y.Z` tags and a short module path,
  and Zig wants `build.zig.zon` at the repository root. CI regenerates both mirrors and tags them
  with the release version.
- **`crypto-pq-py` and `crypto-pq-ts`** are archived after the first release from this
  repository. Their registry trusted-publisher settings move here first.

## The contract (`spec/`)

- **Vocabulary:** one set of words, cased per language (table in `decisions.md`).
  `generateKeyPair`, `encapsulate`, `decapsulate`, `sign`, `verify`, `exportKey`,
  `importPrivateKey` and `importPublicKey`, plus the fields `publicKey`, `privateKey`,
  `sharedSecret` and `ciphertext`.
- **Key formats:**
  - Format names follow WebCrypto: `raw-public`, `raw-seed`, `raw-private`, `spki`, `pkcs8`,
    `jwk`.
  - Private keys export as `raw-seed` by default, as RFC 9935, 9881 and 9964 recommend or
    require.
  - Import always runs the standard's checks.
- **Errors:** 14 stable codes, the same string in every language: `INVALID_LENGTH`,
  `INVALID_ENCODING`, `UNKNOWN_ALGORITHM`, `ALGORITHM_MISMATCH`, `INVALID_PUBLIC_KEY`,
  `INVALID_PRIVATE_KEY`, `INVALID_CONTEXT`, `INVALID_OPTION`, `RNG_FAILURE`, `SELF_TEST_FAILED`,
  `KEY_EXHAUSTED`, `STATE_PERSIST_FAILED`, `STATE_CONFLICT`, `UNSUPPORTED`. `verify` returns a
  boolean everywhere.
- **Stateful signatures** (LMS, XMSS):
  - Verification is available everywhere.
  - Signing needs a caller-supplied state store that confirms persistence before any signature
    leaves the library. This is fixed, because reusing an index breaks security.
- **Vector format:** one JSON layout for every family. Each implementation's test runner reads
  it through its public API.

## Randomness, per language

| Language | Source |
|---|---|
| Rust | Its own per-OS code, because stable Rust has no randomness API: `getrandom(2)` on Linux, `CCRandomGenerateBytes` on Apple, `ProcessPrng` on Windows, `crypto.getRandomValues` imported from the host under WASM. This is the only `unsafe` code, small and reviewed line by line. |
| Python | `os.urandom` |
| TypeScript | `crypto.getRandomValues` (browsers, Node, Deno, Bun) |
| Go | `crypto/rand` (the operating system's generator; failure is fatal by Go's design) |
| Zig | the operating system's random source, reached through Zig's OS layer, never `std.crypto` |

## Verification

- **Shared vectors.** Every implementation passes the same vectors: NIST ACVP for every family,
  C2SP Wycheproof for ML-KEM and ML-DSA, C2SP CCTV for ML-KEM, and the accumulated ML-KEM-768
  test in `vectors/SOURCES.md`.
- **Cross-language checks.** Keys, ciphertexts and signatures produced by each language are
  consumed by every other one, in CI, in every format.
- **Constant time.**
  - Rust, Go and Zig avoid secret-dependent branches, memory indices and divisions, and are
    checked on the compiled output: a binary-level checker, Valgrind-based secret tainting, and
    statistical timing as a signal only.
  - TypeScript and Python are written in the same style, but their runtimes (JIT, garbage
    collector, interpreter) cannot guarantee constant time. Their documentation says so on the
    first page, and so does the documentation's note on wiping secrets.
- **Fuzzing** of every decoder and importer.

## Versions and releases

- **Numbering:** the same MAJOR.MINOR in all five languages means the same features; PATCH is
  independent per language. The first designed release is 0.2.0 everywhere. Pre-releases use
  alpha, beta and rc, spelled the way each registry expects (`0.2.0-rc.1`, `0.2.0rc1`).
- **Publishing:** crates.io, PyPI and npm use trusted publishing from this repository's CI. Go
  and Zig are released by tagging their mirrors.

## Order of work

1. `spec/` and the shared vector format.
2. SHA-3 and SHAKE in all five languages, checked against the NIST vectors.
3. ML-KEM in all five.
4. SHA-2 and HMAC, then ML-DSA and SLH-DSA.
5. LMS/HSS and XMSS.
6. X25519, then X-Wing.
7. HPKE `seal`/`open`.
8. Third-party audit, then 1.0.
