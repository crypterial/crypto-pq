# 16. Naming and vocabulary

## 16.1 Keywords

Every public item has one canonical keyword, written in this document in lower camel case (for
example `generateKeyPair`, `selfTest`). The implementation spells the keyword in the casing of its
language ([16.3](#163-casing)) and MUST NOT use a different word for it (P4). It MAY add an item that only the idiom of
its language needs (for example the Rust `_into` forms); such items are listed in its profile and in
[16.4](#164-name-map).

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
3. Stateful parameter names (LMS, LM-OTS, XMSS and XMSS^MT set names) are strings, spelled exactly as
   in [5.3](05-algorithms.md#53-stateful-hash-based-signatures).

## 16.3 Casing

| element | Rust |
|---|---|
| algorithm constants | `SCREAMING_CASE` |
| functions and methods | `snake_case` |
| fields, properties, options | `snake_case` |
| type names | `PascalCase`, identical to the keyword |
| error codes | enum variant `PascalCase`; `code()` gives the string |
| format names | `KeyFormat::Raw`, `Der`, `Pem` |

## 16.4 Name map

The tables list every public name: the keyword and its Rust form. "same" means that the Rust name
is the keyword.

### 16.4.1 Types

| keyword | Rust |
|---|---|
| HashAlgorithm, Hasher | same |
| XofAlgorithm, Xof | same |
| MacAlgorithm, Mac | same |
| KdfAlgorithm | same |
| KemAlgorithm, KemPublicKey, KemPrivateKey, KemKeyPair, Encapsulation | same |
| SignatureAlgorithm, SignaturePublicKey, SignaturePrivateKey, SignatureKeyPair | same |
| StatefulSignatureAlgorithm, StatefulPublicKey, StatefulPrivateKey, StatefulKeyPair | same |
| StateStore | trait |
| KeyFormat | enum |
| PreHash | type |
| StatefulParameters | enum `Name`, `Levels` |
| HssLevel | pair `(&str, &str)` |
| options: HashOptions, XofOptions, MacOptions, KdfOptions, KeyGenOptions, SignOptions, VerifyOptions, StatefulKeyGenOptions, StatefulLoadOptions | structs |
| error | `Error` |
| secret byte container [[D-23](decisions.md#decision-d-23)] | `SecretBytes` |

### 16.4.2 Operations

| keyword | Rust |
|---|---|
| name | `name()` |
| digestSize | `digest_size()` |
| digest | `digest` |
| digestInto | `digest_into` |
| create | `create` |
| update | `update` |
| read | `read` |
| readInto | `read_into` |
| configure | `configure` |
| verify | `verify` |
| derive, deriveInto | `derive`, `derive_into` |
| extract, extractInto | `extract`, `extract_into` |
| expand, expandInto | `expand`, `expand_into` |
| prkSize [[D-24](decisions.md#decision-d-24)] | `prk_size()` |
| publicKeySize, ciphertextSize, sharedSecretSize, signatureSize | `public_key_size()` etc. |
| generateKeyPair | `generate_key_pair` |
| importPublicKey, importPrivateKey | `import_public_key`, `import_private_key` |
| exportKey | `export_key` |
| encapsulate, decapsulate | `encapsulate`, `decapsulate` |
| sign | `sign` |
| publicKey (of a private key) | `public_key()` |
| algorithm (of a key) | `algorithm()` |
| equals (public keys) | `==` (`PartialEq`) |
| loadPrivateKey | `load_private_key` |
| remainingSignatures | `remaining_signatures()` |
| exportTreeCache | `export_tree_cache` |
| store read, update | `read`, `update` |
| enableDataIndependentTiming | `enable_data_independent_timing` |
| release resources | `Drop` |

### 16.4.3 Options and result fields

| keyword | Rust |
|---|---|
| selfTest | `self_test` |
| context, deterministic, preHash | `context`, `deterministic`, `pre_hash` |
| salt, personalization, customization, length, xof, info | snake_case |
| parameters, stateStore, reserve, treeCache | `parameters` (argument), store (argument), `reserve`, `tree_cache` |
| publicKey, privateKey (key pair) | `public_key`, `private_key` |
| sharedSecret, ciphertext | `shared_secret`, `ciphertext` |

### 16.4.4 Hazmat

| keyword | Rust (`crypto_pq::hazmat`) |
|---|---|
| generateKemKeyPair | `generate_kem_key_pair` |
| generateSignatureKeyPair | `generate_signature_key_pair` |
| generateStatefulKeyPair | `generate_stateful_key_pair` |
| encapsulate, sign, verify | `encapsulate`, `sign`, `verify` |
| configureCshake | `configure_cshake` |
| signInternal, verifyInternal | `sign_internal`, `verify_internal` |

### 16.4.5 Error codes

| code | Rust |
|---|---|
| INVALID_LENGTH | `Error::InvalidLength` |
| INVALID_ENCODING | `Error::InvalidEncoding` |
| ALGORITHM_MISMATCH | `Error::AlgorithmMismatch` |
| INVALID_PUBLIC_KEY | `Error::InvalidPublicKey` |
| INVALID_PRIVATE_KEY | `Error::InvalidPrivateKey` |
| INVALID_CONTEXT | `Error::InvalidContext` |
| INVALID_OPTION | `Error::InvalidOption` |
| RNG_FAILURE | `Error::RngFailure` |
| SELF_TEST_FAILED | `Error::SelfTestFailed` |
| KEY_EXHAUSTED | `Error::KeyExhausted` |
| STATE_PERSIST_FAILED | `Error::StatePersistFailed` |
| STATE_CONFLICT | `Error::StateConflict` |
| UNSUPPORTED | `Error::Unsupported` |

## 16.5 Package

| item | Rust |
|---|---|
| package | crate `crypto-pq` |
| import | `crypto_pq` |
| hazmat | `crypto_pq::hazmat` |
