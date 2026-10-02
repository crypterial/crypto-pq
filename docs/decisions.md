# crypto-pq decisions

Newest first. The reasoning behind the current design is in `architecture.md`.

## 2026-10-02

- **Implementation model:** every language gets its own complete implementation, written from
  scratch, against one specification and one shared vector suite.
- **Languages:** Rust, Python, TypeScript, Go and Zig, the five for which the `crypto-pq` name
  was reserved on 2026-09-06.
- **Repository:** this repository is the only source. `crypto-pq-go` and `crypto-pq-zig` become
  generated read-only mirrors; `crypto-pq-py` and `crypto-pq-ts` are archived after the first
  release from here.
- **Versions:** the same MAJOR.MINOR in every language, PATCH independent. The first designed
  release is 0.2.0.
- **Prototype withdrawn:**
  - crates.io 0.1.1 of `crypto-pq` and `crypto-pq-ml-kem` carries a withdrawal notice; yanking
    0.1.0 and 0.1.1 is pending.
  - PyPI 0.0.2 only holds the name. The npm 0.0.1 placeholder is prepared and awaits
    publishing.
  - The prototype code left this repository's main branch; it remains in history at tags
    `v0.1.0` and `v0.1.1`.

## 2026-09-29

**Rules:**
1. No external dependencies, with the boundary described in `architecture.md`.
2. Only standardized algorithms, or constructions proven in production by major vendors.
3. Options instead of fixed choices, with safe defaults.
4. The same keywords in every language.

**Scope:**
- **In:** ML-KEM, ML-DSA, SLH-DSA, LMS/HSS, XMSS/XMSS^MT, and X-Wing as an option.
- **Later:** HPKE `seal`/`open`.
- **Out:** FN-DSA, HQC and composites, until they are final and proven.

**Defaults:** ML-KEM-768, ML-DSA-65, hedged signing, a self-test after key generation.

**Keys:** `raw-seed` is the default private-key format; import always validates.

**Stateful signing:** only through a state store that confirms persistence first.

**Licence:** Apache-2.0 OR MIT for every package.

## Vocabulary

| Concept | Rust, Python | TypeScript | Go | Zig |
|---|---|---|---|---|
| algorithm | `ML_KEM_768` | `ML_KEM_768` | `ML_KEM_768` | `ml_kem_768` |
| make keys | `generate_key_pair` | `generateKeyPair` | `GenerateKeyPair` | `generateKeyPair` |
| key pair fields | `public_key`, `private_key` | `publicKey`, `privateKey` | `PublicKey`, `PrivateKey` | `public_key`, `private_key` |
| KEM | `encapsulate`, `decapsulate` | `encapsulate`, `decapsulate` | `Encapsulate`, `Decapsulate` | `encapsulate`, `decapsulate` |
| KEM result | `shared_secret`, `ciphertext` | `sharedSecret`, `ciphertext` | `SharedSecret`, `Ciphertext` | `shared_secret`, `ciphertext` |
| signatures | `sign`, `verify` | `sign`, `verify` | `Sign`, `Verify` | `sign`, `verify` |
| keys in and out | `export_key`, `import_private_key`, `import_public_key` | `exportKey`, `importPrivateKey`, `importPublicKey` | `ExportKey`, `ImportPrivateKey`, `ImportPublicKey` | `exportKey`, `importPrivateKey`, `importPublicKey` |
| errors | `Error` with `code()` (Rust), `CryptoPQError` with `.code` (Python) | `CryptoPQError` with `code` | `*cryptopq.Error` with `Code` | an error set (`error.InvalidLength`) plus `code()` |

Zig follows its own style guide (functions camelCase, values and fields snake_case). The method
name `import` is avoided because it is reserved in Python.
