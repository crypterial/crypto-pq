# 16. Naming and vocabulary

## 16.1 Keywords

Every public item has one canonical keyword, written in this document in lower camel case (for
example `generateKeyPair`, `selfTest`). Each language spells the keyword in its own casing ([16.3](#163-casing)) and
MUST NOT use a different word for it (P4). A language MAY add an item that only its idiom needs (for
example the `_into` forms, Zig `deinit`); such items are listed in its profile.

## 16.2 Algorithm constants

1. A constant is derived from the `name` string of Section [5](05-algorithms.md): letters are upper-cased, and each `-`,
   `/`, `^` and space becomes `_`. Examples: `ML-KEM-768` → `ML_KEM_768`; `SLH-DSA-SHA2-128s` →
   `SLH_DSA_SHA2_128S`; `HSS/LMS` → `HSS_LMS`; `XMSS^MT` → `XMSS_MT`; `SHA3-256` → `SHA3_256`;
   `SHA-512/224` → `SHA_512_224`; `BLAKE2b-512` → `BLAKE2B_512`; `HKDF-SHA-256` → `HKDF_SHA_256`;
   `HMAC-SHA-256` → `HMAC_SHA_256`; `cSHAKE128` → `CSHAKE128`; `Ascon-Hash256` → `ASCON_HASH256`;
   `FrodoKEM-976-AES` → `FRODOKEM_976_AES`; `eFrodoKEM-976-AES` → `EFRODOKEM_976_AES`;
   `BLAKE3-256` → `BLAKE3_256`.
2. Exception to item 1: the prefix `HashSLH-DSA` becomes `HASH_SLH_DSA`, following the RFC 9909
   identifiers `id-hash-slh-dsa-…-with-…`: `HashSLH-DSA-SHA2-128s-with-SHA256` →
   `HASH_SLH_DSA_SHA2_128S_WITH_SHA256`.
3. Zig uses the same words in lower case: `ml_kem_768`, `sha3_256`, `hss_lms`, `xmss_mt`,
   `efrodokem_976_aes`, `hash_slh_dsa_sha2_128s_with_sha256`.
4. Stateful parameter names (LMS, LM-OTS, XMSS and XMSS^MT set names) are strings, spelled exactly as
   in [5.3](05-algorithms.md#53-stateful-hash-based-signatures) in every language.

## 16.3 Casing

| element | Rust | Go | Zig | TypeScript | Python |
|---|---|---|---|---|---|
| algorithm constants | `SCREAMING_CASE` | `SCREAMING_CASE` | `snake_case` | `SCREAMING_CASE` | `SCREAMING_CASE` |
| functions and methods | `snake_case` | `PascalCase` | `camelCase` | `camelCase` | `snake_case` |
| fields, properties, options | `snake_case` | `PascalCase` | `snake_case` | `camelCase` | `snake_case` |
| type names | identical in every language (`PascalCase`) | | | | |
| error codes | enum variant `PascalCase`, `code()` gives the string | constant `SCREAMING_CASE` of type `ErrorCode` | error set member `PascalCase` | string literal | `ErrorCode` member `SCREAMING_CASE` |
| format names | `KeyFormat::Raw`, `Der`, `Pem` | `RAW`, `DER`, `PEM` | `.raw`, `.der`, `.pem` | `"raw"`, `"der"`, `"pem"` | `KeyFormat.RAW` etc., or the strings |

## 16.4 Name map

The tables list every public name.

### 16.4.1 Types

| keyword | Rust | Go | Zig | TypeScript | Python |
|---|---|---|---|---|---|
| HashAlgorithm, Hasher | same | same | same | same | same |
| XofAlgorithm, Xof | same | same | same | same | same |
| MacAlgorithm, Mac | same | same | same | same | same |
| KdfAlgorithm | same | same | same | same | same |
| KemAlgorithm, KemPublicKey, KemPrivateKey, KemKeyPair, Encapsulation | same | same | same | same | same |
| SignatureAlgorithm, SignaturePublicKey, SignaturePrivateKey, SignatureKeyPair | same | same | same | same | same |
| StatefulSignatureAlgorithm, StatefulPublicKey, StatefulPrivateKey, StatefulKeyPair | same | same | same | same | same |
| StateStore | trait | interface | struct with vtable | interface | Protocol |
| KeyFormat | enum | string type | enum | string union | StrEnum |
| PreHash | type | interface | union | union of HashAlgorithm and XofAlgorithm | union |
| StatefulParameters [[D-56](decisions.md#decision-d-56)] | enum `Name`, `Levels` | struct `Name`, `Levels` | union `name`, `levels` | string or list of pairs | string or sequence of pairs |
| HssLevel | pair `(&str, &str)` | struct `Lms`, `Ots` | struct `lms`, `ots` | pair | pair |
| options: HashOptions, XofOptions, MacOptions, KdfOptions, KeyGenOptions, SignOptions, VerifyOptions, StatefulKeyGenOptions, StatefulLoadOptions [[D-55](decisions.md#decision-d-55)] | structs | structs | structs | interfaces | keyword arguments |
| error | `Error` | `*Error` with `Code ErrorCode` | `Error` set | `CryptoPQError` with `code` | `CryptoPQError` with `code` |
| secret byte container [[D-23](decisions.md#decision-d-23), [D-57](decisions.md#decision-d-57)] | `SecretBytes` | none | `SharedSecret` (KEM) | none | `bytearray` results |

### 16.4.2 Operations

| keyword | Rust | Go | Zig | TypeScript | Python |
|---|---|---|---|---|---|
| name | `name()` | `Name()` | `name` field | `name` | `name` |
| digestSize | `digest_size()` | `DigestSize()` | `digest_size` field | `digestSize` | `digest_size` |
| digest | `digest` | `Digest` | `digest` (writes `out`) | `digest` | `digest` |
| digestInto | `digest_into` | `DigestInto` | (the Zig `digest`) | none | none |
| create | `create` | `Create` | `create` | `create` | `create` |
| update | `update` | `Update` | `update` | `update` | `update` |
| read | `read` | `Read` | `read` (writes `out`) | `read` | `read` |
| readInto | `read_into` | `ReadInto` | (the Zig `read`) | none | none |
| configure | `configure` | `Configure` | `configure` | `configure` | `configure` (keyword arguments) |
| verify | `verify` | `Verify` | `verify` | `verify` | `verify` |
| derive, deriveInto | `derive`, `derive_into` | `Derive`, `DeriveInto` | `derive` (writes `out`) | `derive` | `derive` |
| extract, extractInto | `extract`, `extract_into` | `Extract`, `ExtractInto` | `extract` | `extract` | `extract` |
| expand, expandInto | `expand`, `expand_into` | `Expand`, `ExpandInto` | `expand` | `expand` | `expand` |
| prkSize [[D-24](decisions.md#decision-d-24)] | `prk_size()` | `PrkSize()` | `prk_size` field | `prkSize` | `prk_size` |
| publicKeySize, ciphertextSize, sharedSecretSize, signatureSize | `public_key_size()` etc. | `PublicKeySize()` etc. | fields `public_key_size` etc. | `publicKeySize` etc. | `public_key_size` etc. |
| generateKeyPair | `generate_key_pair` | `GenerateKeyPair` | `generateKeyPair` | `generateKeyPair` | `generate_key_pair` |
| importPublicKey, importPrivateKey | `import_public_key`, `import_private_key` | `ImportPublicKey`, `ImportPrivateKey` | `importPublicKey`, `importPrivateKey` | same as keyword | `import_public_key`, `import_private_key` |
| exportKey | `export_key` | `ExportKey` | `exportKey` | `exportKey` | `export_key` |
| encapsulate, decapsulate | `encapsulate`, `decapsulate` | `Encapsulate`, `Decapsulate` | same as keyword | same | same |
| sign | `sign` | `Sign` | `sign` | `sign` | `sign` |
| publicKey (of a private key) | `public_key()` | `PublicKey()` | `publicKey()` | `publicKey` | `public_key` |
| algorithm (of a key) | `algorithm()` | `Algorithm()` | `algorithm` field | `algorithm` | `algorithm` |
| equals (public keys) | `==` (`PartialEq`) | `Equal` | `eql` | `equals` | `==` |
| loadPrivateKey | `load_private_key` | `LoadPrivateKey` | `loadPrivateKey` | `loadPrivateKey` | `load_private_key` |
| remainingSignatures | `remaining_signatures()` | `RemainingSignatures()` | `remainingSignatures()` | `remainingSignatures()` | `remaining_signatures()` |
| exportTreeCache | `export_tree_cache` | `ExportTreeCache` | `exportTreeCache` | `exportTreeCache` | `export_tree_cache` |
| store read, update | `read`, `update` | `Read`, `Update` | vtable `read`, `update` | `read`, `update` | `read`, `update` |
| enableDataIndependentTiming | `enable_data_independent_timing` | `EnableDataIndependentTiming` | `enableDataIndependentTiming` | `enableDataIndependentTiming` | `enable_data_independent_timing` |
| release resources | `Drop` | none | `deinit` | none | none |

### 16.4.3 Options and result fields

| keyword | Rust | Go | Zig | TypeScript | Python |
|---|---|---|---|---|---|
| selfTest | `self_test` | `SelfTest` [[D-19](decisions.md#decision-d-19)] | `self_test` | `selfTest` | `self_test` |
| context, deterministic, preHash | `context`, `deterministic`, `pre_hash` | `Context`, `Deterministic`, `PreHash` | `context`, `deterministic`, `pre_hash` | `context`, `deterministic`, `preHash` | `context`, `deterministic`, `pre_hash` |
| salt, personalization, customization, length, xof, info | snake_case | PascalCase | snake_case | camelCase | snake_case |
| parameters, stateStore, reserve, treeCache | `parameters` (argument), store (argument), `reserve`, `tree_cache` | `Parameters`, `StateStore`, `Reserve`, `TreeCache` | arguments `parameters`, `store`; `reserve`, `tree_cache` | `parameters`, `stateStore`, `reserve`, `treeCache` | `parameters`, `state_store`, `reserve`, `tree_cache` |
| publicKey, privateKey (key pair) | `public_key`, `private_key` | `PublicKey`, `PrivateKey` | `public_key`, `private_key` | `publicKey`, `privateKey` | `public_key`, `private_key` |
| sharedSecret, ciphertext | `shared_secret`, `ciphertext` | `SharedSecret`, `Ciphertext` | `shared_secret`, `ciphertext()` | `sharedSecret`, `ciphertext` | `shared_secret`, `ciphertext` |

### 16.4.4 Hazmat

| keyword | Rust (`crypto_pq::hazmat`) | Go (`cryptopq.Hazmat`) | Zig (`crypto_pq.hazmat`) | TypeScript (`crypto-pq/hazmat`) | Python (`crypto_pq.hazmat`) |
|---|---|---|---|---|---|
| generateKemKeyPair | `generate_kem_key_pair` | `GenerateKemKeyPair` | `generateKemKeyPair` | `generateKemKeyPair` | `generate_kem_key_pair` |
| generateSignatureKeyPair | `generate_signature_key_pair` | `GenerateSignatureKeyPair` | `generateSignatureKeyPair` | `generateSignatureKeyPair` | `generate_signature_key_pair` |
| generateStatefulKeyPair | `generate_stateful_key_pair` | `GenerateStatefulKeyPair` | `generateStatefulKeyPair` | `generateStatefulKeyPair` | `generate_stateful_key_pair` |
| encapsulate, sign, verify | `encapsulate`, `sign`, `verify` | `Encapsulate`, `Sign`, `Verify` | same as keyword | same | same |
| configureCshake | `configure_cshake` | `ConfigureCshake` | `configureCshake` | `configureCshake` | `configure_cshake` |
| signInternal, verifyInternal | `sign_internal`, `verify_internal` | `SignInternal`, `VerifyInternal` | `signInternal`, `verifyInternal` | `signInternal`, `verifyInternal` | `sign_internal`, `verify_internal` |

### 16.4.5 Error codes

| code | Rust | Go | Zig | TypeScript, Python |
|---|---|---|---|---|
| INVALID_LENGTH | `Error::InvalidLength` | `INVALID_LENGTH` | `error.InvalidLength` | `"INVALID_LENGTH"`, `ErrorCode.INVALID_LENGTH` |
| INVALID_ENCODING | `Error::InvalidEncoding` | `INVALID_ENCODING` | `error.InvalidEncoding` | as the code |
| ALGORITHM_MISMATCH | `Error::AlgorithmMismatch` | `ALGORITHM_MISMATCH` | `error.AlgorithmMismatch` | as the code |
| INVALID_PUBLIC_KEY | `Error::InvalidPublicKey` | `INVALID_PUBLIC_KEY` | `error.InvalidPublicKey` | as the code |
| INVALID_PRIVATE_KEY | `Error::InvalidPrivateKey` | `INVALID_PRIVATE_KEY` | `error.InvalidPrivateKey` | as the code |
| INVALID_CONTEXT | `Error::InvalidContext` | `INVALID_CONTEXT` | `error.InvalidContext` | as the code |
| INVALID_OPTION | `Error::InvalidOption` | `INVALID_OPTION` | `error.InvalidOption` | as the code |
| RNG_FAILURE | `Error::RngFailure` | `RNG_FAILURE` | `error.RngFailure` | as the code |
| SELF_TEST_FAILED | `Error::SelfTestFailed` | `SELF_TEST_FAILED` | `error.SelfTestFailed` | as the code |
| KEY_EXHAUSTED | `Error::KeyExhausted` | `KEY_EXHAUSTED` | `error.KeyExhausted` | as the code |
| STATE_PERSIST_FAILED | `Error::StatePersistFailed` | `STATE_PERSIST_FAILED` | `error.StatePersistFailed` | as the code |
| STATE_CONFLICT | `Error::StateConflict` | `STATE_CONFLICT` | `error.StateConflict` | as the code |
| UNSUPPORTED | `Error::Unsupported` | `UNSUPPORTED` | `error.Unsupported` | as the code |

## 16.5 Packages

| language | package | import | hazmat |
|---|---|---|---|
| Rust | crate `crypto-pq` | `crypto_pq` | `crypto_pq::hazmat` |
| Go | module `github.com/crypterial/crypto-pq-go` | package `cryptopq` | the value `cryptopq.Hazmat` |
| Zig | package `crypto_pq` | `@import("crypto_pq")` | `crypto_pq.hazmat` |
| TypeScript | npm `crypto-pq` (registration pending) | `crypto-pq` (ES modules only) | `crypto-pq/hazmat` |
| Python | PyPI `crypto-pq` | `crypto_pq` | `crypto_pq.hazmat` |
