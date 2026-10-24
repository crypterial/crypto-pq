# 8. Key encapsulation

## 8.1 ML-KEM

### 8.1.1 Key generation

1. `generateKeyPair` MUST draw d and z, 32 bytes each, from the entropy source ([14.3](14-security.md#143-entropy)) and compute the
   keys with ML-KEM.KeyGen_internal (FIPS 203 §6.1, Algorithm 16), as ML-KEM.KeyGen does (FIPS 203
   §7.1, Algorithm 19).
2. The private key object MUST keep the 64-byte seed d || z so that it can be exported (RFC 9935 §7).
3. With `selfTest = true` (the default), the implementation MUST run the pairwise consistency test of
   [14.4](14-security.md#144-self-tests) before returning the key pair.

### 8.1.2 Encapsulation

1. `encapsulate` MUST draw the 32-byte message m from the entropy source and run ML-KEM.Encaps (FIPS 203
   §7.2, Algorithm 20).
2. The input checks of FIPS 203 §7.2 (the encapsulation key type check and modulus check) MUST be
   performed when the public key object is created (import, [10.6](10-key-formats.md#106-import-order)). A key object is immutable, so the
   checks need not be repeated per call.

### 8.1.3 Decapsulation

1. `decapsulate` MUST run ML-KEM.Decaps (FIPS 203 §7.3, Algorithm 21) with implicit rejection.
2. A ciphertext whose length is not `ciphertextSize` fails with INVALID_LENGTH (the ciphertext type
   check of FIPS 203 §7.3). No other failure is possible.
3. The decapsulation key checks of FIPS 203 §7.3 MUST be performed when the private key object is
   created ([8.1.4](#814-private-key-import)).
4. The re-encryption comparison MUST examine every byte, and the choice between K′ and K̄ MUST be made
   by constant-time selection ([14.1](14-security.md#141-constant-time)).

### 8.1.4 Private key import

| form | checks, in order | failure |
|---|---|---|
| seed (64 bytes) | none beyond the length; the keys are computed with ML-KEM.KeyGen_internal | |
| expanded key only (768k + 96 bytes) | (1) the hash check of FIPS 203 §7.3: H(ek) equals the stored h; (2) the modulus check of FIPS 203 §7.2 on the embedded ek; (3) the same check on the first 384k bytes (the encoding of the secret vector ŝ): every 12-bit coefficient is less than q, checked without a secret-dependent branch and with only the overall result declassified [[D-61](decisions.md#decision-d-61)]; (4) the range check of the secret vector: every coefficient of s = NTT^−1(ŝ) (FIPS 203 §4.3, Algorithm 10) lies in [−η1, η1] modulo q, the values that SamplePolyCBD_η1 gives in K-PKE.KeyGen (FIPS 203 Algorithms 8 and 13), checked without a secret-dependent branch and with only the overall result declassified [[D-74](decisions.md#decision-d-74)]; (5) a pairwise consistency test [[D-06](decisions.md#decision-d-06)]: encapsulate under the embedded ek with fresh randomness, decapsulate with the key, and compare the two shared secrets in constant time | INVALID_PRIVATE_KEY; RNG_FAILURE if the entropy source fails |
| both (PKCS#8 `both`) | the seed consistency check of RFC 9935 §8: the expanded key computed from the seed equals the given expanded key, compared in constant time | INVALID_PRIVATE_KEY |
| any PKCS#8 form with a `publicKey` field | the field equals the public key of the imported private key | INVALID_PRIVATE_KEY |

Rationale for checks (4) and (5): an expanded key with a modified secret vector and an unchanged H(ek)
passes the FIPS 203 checks but decapsulates wrongly (RFC 9935 Appendix C.4, second example). Check (4)
refuses, on every import, each such key whose secret vector key generation cannot produce; check (5)
detects the others, which decapsulate almost every ciphertext wrongly. Their results are declassified because the
import fails on them.

### 8.1.5 Raw private key export

The raw export of an ML-KEM private key is the 64-byte seed when the key object holds it, and the
expanded key otherwise (a key imported in expanded-only form).

## 8.2 FrodoKEM

### 8.2.1 Algorithms

1. The eight algorithm values of [5.1](05-algorithms.md#51-key-encapsulation) implement FrodoKEM and eFrodoKEM as standardized in ISO/IEC
   18033-2:2006/Amd 2:2026. The public algorithm text is [FRODO-DRAFT]: key generation §7.1,
   encapsulation §7.2, decapsulation §7.3, variants §8, parameters §9; matrix A from AES-128 §6.7.1 or
   SHAKE128 §6.7.2.
2. The shared secret has len_sec/8 bytes: 24 for the 976 sets and 32 for the 1344 sets.
   `sharedSecretSize` MUST report it per algorithm.

### 8.2.2 Randomness

| draw | standard sets (976 / 1344) | ephemeral sets (976 / 1344) |
|---|---|---|
| key generation: s, seedSE, z | 24 + 48 + 16 = 88 / 32 + 64 + 16 = 112 | 24 + 24 + 16 = 64 / 32 + 32 + 16 = 80 |
| encapsulation: u, salt | 24 + 48 = 72 / 32 + 64 = 96 | u only: 24 / 32 |

All draws come from the entropy source ([14.3](14-security.md#143-entropy)). The hazmat functions take these bytes, in this order,
as their seed and randomness (Section [13](13-hazmat.md)).

### 8.2.3 Constant time and memory

1. Matrix A is derived from the public seedA. Its generation MAY run in variable time.
2. Every computation on s, S, E, S′, E′, E″, u, seedSE, k, the decoded message, the re-encryption, the
   comparison of B′ || C with B″ || C″ (every byte, no early exit) and the selection of k′ or s (by
   mask) MUST be constant time. Error sampling MUST use the arithmetic comparison against the CDF
   table of [FRODO-DRAFT] §6.5, with no secret-dependent branch or index.
3. Key objects MUST NOT cache matrix A (P8). A public key object MAY cache pkh.
4. The AES variants compute matrix A with the implementation's AES-128 code ([4.3](04-scope.md#43-internal-components)): the AES instructions
   or the bitsliced code of [14.1](14-security.md#141-constant-time) item 3. That code MUST be constant time even though matrix A
   is public, because the same constant-time code serves every AES use [[D-50](decisions.md#decision-d-50)].

### 8.2.4 Keys and import

1. The public key is pk = seedA || b ([FRODO-DRAFT] §7.1). Every byte string of the right length is a
   valid public key; a wrong length fails with INVALID_LENGTH.
2. The private key is sk = s || seedA || b || S^T || pkh ([FRODO-DRAFT] §7.1). There is no seed form;
   export always returns sk.
3. Private import MUST check, in order: the exact length (INVALID_LENGTH); pkh equals
   SHAKE256(seedA || b) truncated to len_sec/8 bytes (INVALID_PRIVATE_KEY); every entry of S^T, a
   signed 16-bit integer ([FRODO-DRAFT] §7.1.1), lies in the support S_χ = {−d, …, d} of the error
   distribution ([FRODO-DRAFT] §6.5), d = 10 for n = 976 and 6 for n = 1344 (§9.1, Table 1), checked
   without a secret-dependent branch and with only the overall result declassified
   (INVALID_PRIVATE_KEY) [[D-74](decisions.md#decision-d-74)]; a pairwise consistency test as in [8.1.4](#814-private-key-import) (5) (INVALID_PRIVATE_KEY, or
   RNG_FAILURE) [[D-47](decisions.md#decision-d-47)].

### 8.2.5 Formats

FrodoKEM supports the `raw` format only. `der` and `pem` fail with UNSUPPORTED for import and export
of both public and private keys. Rationale: no X.509 or PKCS#8 encoding of FrodoKEM is published as an
RFC at the date of this document.

### 8.2.6 eFrodoKEM usage limit

An eFrodoKEM public key MUST NOT be used for 2^8 or more ciphertexts ([FRODO-DRAFT] §8). The library
cannot count ciphertexts across processes and does not enforce the limit [[D-29](decisions.md#decision-d-29)]. The public
documentation MUST state the limit, and crypto-pq MUST NOT choose an eFrodoKEM set by default.
