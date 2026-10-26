# 6. Common API model

This section defines the operations of every category in language-neutral form. Section [16](16-naming.md) gives the
Rust spelling of every name; Part II gives the Rust types.

## 6.1 Algorithm values

1. Every algorithm and parameter set of Section [5](05-algorithms.md) is a public, immutable algorithm value of its
   category type (`HashAlgorithm`, `XofAlgorithm`, `MacAlgorithm`, `KdfAlgorithm`, `KemAlgorithm`,
   `SignatureAlgorithm`, `StatefulSignatureAlgorithm`).
2. Every algorithm value has a `name`, the exact string of Section [5](05-algorithms.md). Names are ASCII.
3. An algorithm value MUST NOT be reassignable or mutable by the caller.
4. `configure(options)` ([6.5](#65-configuration)) returns a new algorithm value of the same category with the options
   applied. It never changes the value it is called on, and the returned value holds no reference to
   the caller's buffers.

## 6.2 Inputs and outputs

1. Byte-string inputs MAY be empty unless a rule of this document requires a length. An
   implementation MUST process every input up to the largest buffer its platform can represent; in
   particular inputs longer than 2^32 bytes MUST be processed correctly on 64-bit platforms.
2. An implementation MUST NOT modify a caller's input, except where Section [11.6](11-stateful-signatures.md#116-state-store-contract) transfers ownership
   of a state record.
3. Operations return new byte strings. The `_into` forms (Section [16.4](16-naming.md#164-name-map)) write into a caller buffer
   instead. A caller buffer of the wrong length fails with INVALID_LENGTH, and the buffer is left
   unchanged.
4. Aliasing [[D-04](decisions.md#decision-d-04)]: when an output buffer overlaps any input of the same call, the result MUST be
   identical to the result of the same call with every input copied before the first output byte is
   written. No error is raised for overlap.
5. Errors, not panics [[D-03](decisions.md#decision-d-03)]: an implementation MUST report every misuse that caller input can cause
   with one of the error codes of Section [7](07-errors.md). It MUST NOT panic, abort, throw a language exception other
   than the crypto-pq error, or invoke undefined behaviour because of caller input. This includes
   wrong buffer lengths, `update` after `read` on an XOF, and MAC keys of an unaccepted length. An
   implementation MAY abort on the violation of an internal invariant that no caller input can reach.
6. Failure to allocate memory is reported in the language's own way (Part II); it is not one of the 13
   codes.
7. A value of the wrong type (for example a string where bytes are expected) is refused by the type
   checking of the language; it is not one of the 13 codes.

## 6.3 Options

1. Each operation that takes options takes them as one options argument. Every option has a
   default. An absent option has its default value.
2. For byte-string options, an empty value is the same as an absent value.
3. A numeric option outside its allowed range fails with INVALID_OPTION.
4. An option that the algorithm or operation does not take fails with INVALID_OPTION when it holds a
   non-default value; the default value is accepted. Examples: a salt for SHA-256, an `info` for
   `extract`, a `salt` for `expand`.

## 6.4 Operations by category

### 6.4.1 Hash

| operation | inputs | output | errors |
|---|---|---|---|
| `ALG.digest(data)` | data | `digestSize` bytes | none |
| `ALG.digestInto(data, out)` | data, out | writes `out` | INVALID_LENGTH if `len(out) ≠ digestSize` |
| `ALG.create()` | | a `Hasher` | none |
| `Hasher.update(data)` | data | | none |
| `Hasher.digest()` | | `digestSize` bytes; the hasher keeps its state and accepts further `update` calls | none |
| `Hasher.digestInto(out)` | out | writes `out` | INVALID_LENGTH |
| `ALG.configure(options)` | `salt`, `personalization` | a `HashAlgorithm` | INVALID_OPTION ([12.1](12-symmetric-primitives.md#121-hash-functions)) |
| `ALG.digestSize`, `ALG.name` | | integer, string | |

### 6.4.2 XOF

| operation | inputs | output | errors |
|---|---|---|---|
| `ALG.digest(data, length)` | data, length | `length` bytes | INVALID_LENGTH ([12.8](12-symmetric-primitives.md#128-limits)) |
| `ALG.digestInto(data, out)` | data, out | writes `out` | INVALID_LENGTH ([12.8](12-symmetric-primitives.md#128-limits)) |
| `ALG.create()` | | an `Xof` | none |
| `Xof.update(data)` | data | | UNSUPPORTED after any `read` ([12.2](12-symmetric-primitives.md#122-xof-streaming)) |
| `Xof.read(length)` | length | the next `length` bytes of the output stream | INVALID_LENGTH ([12.8](12-symmetric-primitives.md#128-limits)) |
| `Xof.readInto(out)` | out | writes the next `len(out)` bytes | INVALID_LENGTH ([12.8](12-symmetric-primitives.md#128-limits)) |
| `ALG.configure(options)` | `customization` | an `XofAlgorithm` | INVALID_OPTION ([12.3](12-symmetric-primitives.md#123-cshake), [12.4](12-symmetric-primitives.md#124-ascon)) |
| `ALG.name` | | string | |

### 6.4.3 MAC

| operation | inputs | output | errors |
|---|---|---|---|
| `ALG.digest(key, data)` | key, data | `digestSize` bytes | INVALID_LENGTH for an unaccepted key length ([12.6](12-symmetric-primitives.md#126-mac-algorithms)) |
| `ALG.digestInto(key, data, out)` | key, data, out | writes `out` | INVALID_LENGTH |
| `ALG.verify(key, data, tag)` | key, data, tag | boolean | never; any invalid input gives `false` ([12.6](12-symmetric-primitives.md#126-mac-algorithms) item 6) |
| `ALG.create(key)` | key | a `Mac` | INVALID_LENGTH for an unaccepted key length |
| `Mac.update(data)` | data | | none |
| `Mac.digest()` | | `digestSize` bytes; the object keeps its state | none |
| `Mac.digestInto(out)` | out | writes `out` | INVALID_LENGTH |
| `Mac.verify(tag)` | tag | boolean | never |
| `ALG.configure(options)` | `length` (HMAC, KMAC, BLAKE2-MAC), `customization`, `xof`, `salt`, `personalization` | a `MacAlgorithm` | INVALID_OPTION ([6.5](#65-configuration), [12.6](12-symmetric-primitives.md#126-mac-algorithms)) |
| `ALG.digestSize`, `ALG.name` | | integer (the configured tag length), string | |

### 6.4.4 KDF

| operation | inputs | output | errors |
|---|---|---|---|
| `ALG.derive(ikm, length, {salt, info})` | | `length` bytes | INVALID_LENGTH, INVALID_OPTION ([12.7](12-symmetric-primitives.md#127-kdf-algorithms)) |
| `ALG.deriveInto(ikm, out, {salt, info})` | | writes `out` | same |
| `ALG.extract(ikm, {salt})` | | `prkSize` bytes | INVALID_OPTION if `info` is given; UNSUPPORTED for `BLAKE3_KDF` |
| `ALG.extractInto(ikm, prk, {salt})` | | writes `prk` | INVALID_LENGTH if `len(prk) ≠ prkSize`; as above |
| `ALG.expand(prk, length, {info})` | | `length` bytes | INVALID_LENGTH, INVALID_OPTION if `salt` is given; UNSUPPORTED for `BLAKE3_KDF` |
| `ALG.expandInto(prk, out, {info})` | | writes `out` | same |
| `ALG.prkSize`, `ALG.name` | | integer, string | |

### 6.4.5 KEM

| operation | output | errors |
|---|---|---|
| `ALG.generateKeyPair({selfTest = true})` | `KemKeyPair {publicKey, privateKey}` | RNG_FAILURE, SELF_TEST_FAILED |
| `ALG.importPublicKey(data, format)` | `KemPublicKey` | INVALID_LENGTH, INVALID_ENCODING, ALGORITHM_MISMATCH, INVALID_PUBLIC_KEY, UNSUPPORTED ([10.6](10-key-formats.md#106-import-order)) |
| `ALG.importPrivateKey(data, format)` | `KemPrivateKey` | INVALID_LENGTH, INVALID_ENCODING, ALGORITHM_MISMATCH, INVALID_PRIVATE_KEY, UNSUPPORTED, RNG_FAILURE ([8.1.4](08-key-encapsulation.md#814-private-key-import)) |
| `publicKey.encapsulate()` | `Encapsulation {sharedSecret, ciphertext}` | RNG_FAILURE |
| `privateKey.decapsulate(ciphertext)` | shared secret | INVALID_LENGTH for a ciphertext of the wrong length only |
| `key.exportKey(format)` | bytes | UNSUPPORTED ([10.7](10-key-formats.md#107-export)) |
| `privateKey.publicKey`, `key.algorithm` | key object, algorithm value | |
| `ALG.publicKeySize`, `ALG.ciphertextSize`, `ALG.sharedSecretSize`, `ALG.name` | integers, string | |

### 6.4.6 Signature

| operation | output | errors |
|---|---|---|
| `ALG.generateKeyPair({selfTest = true})` | `SignatureKeyPair {publicKey, privateKey}` | RNG_FAILURE, SELF_TEST_FAILED |
| `ALG.importPublicKey(data, format)` | `SignaturePublicKey` | as for KEM ([10.6](10-key-formats.md#106-import-order)) |
| `ALG.importPrivateKey(data, format)` | `SignaturePrivateKey` | as for KEM ([10.6](10-key-formats.md#106-import-order)) |
| `privateKey.sign(message, {context = empty, deterministic = false, preHash = none})` | signature of `signatureSize` bytes | INVALID_OPTION, INVALID_CONTEXT, RNG_FAILURE ([9.1](09-signatures.md#91-rules-common-to-ml-dsa-and-slh-dsa)) |
| `publicKey.verify(signature, message, {context = empty, preHash = none})` | boolean | never ([9.1.6](09-signatures.md#916-verification)) |
| `key.exportKey(format)`, `privateKey.publicKey`, `key.algorithm` | | as for KEM |
| `ALG.publicKeySize`, `ALG.signatureSize`, `ALG.name` | integers, string | |

### 6.4.7 Stateful signature

| operation | output | errors |
|---|---|---|
| `ALG.generateKeyPair({parameters, stateStore, reserve = 1})` | `StatefulKeyPair {publicKey, privateKey}` | INVALID_OPTION, RNG_FAILURE, STATE_PERSIST_FAILED, STATE_CONFLICT, SELF_TEST_FAILED ([11.5.3](11-stateful-signatures.md#1153-key-generation)) |
| `ALG.loadPrivateKey(stateStore, {reserve = 1, treeCache = none})` | `StatefulPrivateKey` | INVALID_OPTION, INVALID_PRIVATE_KEY, ALGORITHM_MISMATCH, INVALID_ENCODING, STATE_PERSIST_FAILED, SELF_TEST_FAILED ([11.9](11-stateful-signatures.md#119-loading)) |
| `ALG.importPublicKey(data, format)` | `StatefulPublicKey` | INVALID_LENGTH, INVALID_ENCODING, ALGORITHM_MISMATCH, INVALID_PUBLIC_KEY |
| `privateKey.sign(message)` | signature | STATE_CONFLICT, KEY_EXHAUSTED, RNG_FAILURE, STATE_PERSIST_FAILED, SELF_TEST_FAILED ([11.5](11-stateful-signatures.md#115-signing)) |
| `privateKey.remainingSignatures()` | unsigned 64-bit integer | none |
| `privateKey.exportTreeCache()` | bytes ([11.10](11-stateful-signatures.md#1110-tree-cache)) | STATE_CONFLICT while the key is signing; KEY_EXHAUSTED for an exhausted key |
| `publicKey.verify(signature, message)` | boolean | never |
| `publicKey.exportKey(format)`, `privateKey.publicKey`, `key.algorithm`, `ALG.name` | | |

A stateful private key has no `exportKey` and cannot be imported ([11.1](11-stateful-signatures.md#111-model)). There is no size accessor for
stateful algorithms because sizes depend on the parameters.

### 6.4.8 State store

| operation | output | meaning |
|---|---|---|
| `store.read()` | bytes, or absent | the state record last written, or absent if none was ever written |
| `store.update(previous, next)` | boolean | atomic compare-and-swap; Section [11.6](11-stateful-signatures.md#116-state-store-contract) |

### 6.4.9 Process

| operation | output | meaning |
|---|---|---|
| `enableDataIndependentTiming()` | boolean | Section [14.2](14-security.md#142-data-independent-timing-dit) |

## 6.5 Configuration

| algorithm | options taken | limits | otherwise |
|---|---|---|---|
| BLAKE2b hashes | `salt`, `personalization` | each 0..16 bytes | INVALID_OPTION |
| BLAKE2s hashes | `salt`, `personalization` | each 0..8 bytes | INVALID_OPTION |
| `CSHAKE128`, `CSHAKE256` | `customization` | any length | |
| `ASCON_CXOF128` | `customization` | 0..256 bytes | INVALID_OPTION |
| `HMAC_SHA_224`, `HMAC_SHA_256`, `HMAC_SHA_384`, `HMAC_SHA_512` | `length` | 4 to the hash output size (28, 32, 48, 64) [[D-33](decisions.md#decision-d-33)] | INVALID_OPTION |
| `KMAC128`, `KMAC256` | `length`, `customization`, `xof` | `length` 4..2^32−1 [[D-02](decisions.md#decision-d-02)] | INVALID_OPTION |
| `BLAKE2B_MAC` | `length`, `salt`, `personalization` | `length` 1..64; salt and personalization 0..16 | INVALID_OPTION |
| `BLAKE2S_MAC` | `length`, `salt`, `personalization` | `length` 1..32; salt and personalization 0..8 | INVALID_OPTION |
| every other algorithm, including SHA-2, SHA-3, SHAKE, Ascon-Hash256, Ascon-XOF128, BLAKE3 (all four) | none | | a non-default option gives INVALID_OPTION |

The cSHAKE function-name string N is set only through `hazmat.configureCshake` (Section [13](13-hazmat.md)), because
SP 800-185 §3.3 reserves N for functions defined by NIST.

## 6.6 Concurrency

1. Algorithm values, KEM and signature key objects, and stateful public keys MUST be safe for
   concurrent use from several threads.
2. A `Hasher`, `Xof` or `Mac` object is a sequence of calls. Two threads MUST NOT use one such object at
   the same time; doing so is a caller error.
3. Stateful private keys follow Section [11.13](11-stateful-signatures.md#1113-concurrency).
4. No operation waits for another thread. No operation creates threads in 1.1.

## 6.7 Lifetime, equality and printing

1. A key object holds its secrets until it is destroyed. Destruction wipes them ([14.5](14-security.md#145-wiping)). The language
   mechanism is in Part II.
2. Public keys of the same algorithm compare equal when their raw encodings are equal. Private keys
   have no equality operation.
3. Printing, formatting or debugging a private key, a `Mac`, a `Hasher`, an `Xof` or an error MUST NOT
   reveal secret bytes. A private key prints only its algorithm name.
