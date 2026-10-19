# 9. Signatures

## 9.1 Rules common to ML-DSA and SLH-DSA

### 9.1.1 Context

The `context` option is a byte string of 0 to 255 bytes (FIPS 204 §5.2 and §5.4; FIPS 205 §10.2 and
§10.3). `sign` with a longer context fails with INVALID_CONTEXT. `verify` with a longer context returns
`false`.

### 9.1.2 Hedged and deterministic signing

1. Signing is hedged by default: ML-DSA draws rnd, 32 bytes (FIPS 204 §3.4 and §5.2), and SLH-DSA draws
   addrnd, n bytes (FIPS 205 §9.2 and §10.2.1), from the entropy source for every signature.
2. `deterministic = true` selects the deterministic variant: ML-DSA uses rnd = 0^32 (FIPS 204 §3.4);
   SLH-DSA uses opt_rand = PK.seed (FIPS 205 §9.2).
3. The public documentation SHOULD advise using one key for only one of the hedged and deterministic
   variants, and for only one of the pure and pre-hash modes (FIPS 205 §9.1 and §10.2).

### 9.1.3 Pre-hash (HashML-DSA and HashSLH-DSA)

1. The `preHash` option selects HashML-DSA (FIPS 204 §5.4, Algorithms 4 and 5) or HashSLH-DSA
   (FIPS 205 §10.2.2 and §10.3, Algorithms 23 and 25). Its value is one of the hash or XOF algorithm
   values below. Absent means the pure mode.
2. Only these functions are accepted, with these output lengths and DER object identifiers
   (2.16.840.1.101.3.4.2.x, encoded `06 09 60 86 48 01 65 03 04 02 xx`):

   | function | output used | xx | collision strength (bits) |
   |---|---|---|---|
   | SHA-256 | 32 | 01 | 128 |
   | SHA-384 | 48 | 02 | 192 |
   | SHA-512 | 64 | 03 | 256 |
   | SHA-224 | 28 | 04 | 112 |
   | SHA-512/224 | 28 | 05 | 112 |
   | SHA-512/256 | 32 | 06 | 128 |
   | SHA3-224 | 28 | 07 | 112 |
   | SHA3-256 | 32 | 08 | 128 |
   | SHA3-384 | 48 | 09 | 192 |
   | SHA3-512 | 64 | 0A | 256 |
   | SHAKE128 | 32 | 0B | 128 |
   | SHAKE256 | 64 | 0C | 256 |

3. Strength policy: the pre-hash MUST give at least the collision strength of the signature: λ for
   ML-DSA (128, 192, 256), 8n bits for SLH-DSA (128, 192, 256) (FIPS 204 §5.4; FIPS 205 §10.2.2,
   which also states that SHA-256 and SHAKE128 are appropriate only for category 1). The resulting
   permitted sets are:

   | signature strength | permitted pre-hash |
   |---|---|
   | 128 (ML-DSA-44, SLH-DSA-\*-128\*) | SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
   | 192 (ML-DSA-65, SLH-DSA-\*-192\*) | SHA-384, SHA-512, SHA3-384, SHA3-512, SHAKE256 |
   | 256 (ML-DSA-87, SLH-DSA-\*-256\*) | SHA-512, SHA3-512, SHAKE256 |

   SHA-224, SHA-512/224 and SHA3-224 are therefore never permitted.
4. Every other value (BLAKE2, BLAKE3, Ascon, cSHAKE, any configured algorithm value, a MAC) is refused.
5. `sign` with a refused pre-hash fails with INVALID_OPTION; `verify` returns `false`. The policy is
   fixed and has no option to disable it (P3: fixed because it is critical for security). Only
   `hazmat.sign` and `hazmat.verify` skip the strength rule of item 3, for test vectors; they still
   apply items 2 and 4.

### 9.1.4 Message representative

- Pure mode: M′ = 0x00 || u8(len(ctx)) || ctx || M (FIPS 204 §5.2, Algorithm 2; FIPS 205 §10.2.1,
  Algorithm 22).
- Pre-hash mode: M′ = 0x01 || u8(len(ctx)) || ctx || OID || PH(M), where OID is the 11-byte DER
  encoding of [9.1.3](#913-pre-hash-hashml-dsa-and-hashslh-dsa) (FIPS 204 §5.4, Algorithm 4; FIPS 205 §10.2.2, Algorithm 23).

Example: for the message M = `616263` (ASCII "abc") and an empty context, pure mode gives
M′ = `00 00 616263`. Pre-hash mode with SHA-256 gives
M′ = `01 00 0609608648016503040201 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`,
that is the OID of [9.1.3](#913-pre-hash-hashml-dsa-and-hashslh-dsa) followed by SHA-256(M).

### 9.1.5 No external μ

The public API exposes no interface that accepts μ, M′ or a pre-computed digest in place of the
message (the ExternalMu-ML-DSA interface of RFC 9881 Appendix D). The only exception is the test-only
`hazmat.signInternal` and `hazmat.verifyInternal` (Section [13](13-hazmat.md)), which take M′ so that the ACVP
internal-interface groups can run [[D-65](decisions.md#decision-d-65)]; μ is accepted nowhere. Rationale: a caller-supplied μ
bypasses the binding of the public key (tr) and the context; the pre-hash modes cover the use cases
with a checked hash.

### 9.1.6 Verification

`verify` returns `true` only for a valid signature. It returns `false` for every invalid input
([7.2](07-errors.md#72-results-that-are-not-errors)). It runs ML-DSA.Verify or HashML-DSA.Verify (FIPS 204 §5.3 and §5.4) or slh_verify or
hash_slh_verify (FIPS 205 §10.3).

### 9.1.7 Self-test

With `selfTest = true` (the default), `generateKeyPair` MUST sign a fixed message with hedged signing
in the algorithm's own mode, and verify the signature before returning ([14.4](14-security.md#144-self-tests)) [[D-69](decisions.md#decision-d-69)]: pure mode for
the `ML_DSA_*` and `SLH_DSA_*` values, and pre-hash mode with the fixed pre-hash of [9.4](#94-hashslh-dsa-algorithm-values) for the
`HASH_SLH_DSA_*` values.

## 9.2 ML-DSA

1. Key generation draws ξ, 32 bytes, from the entropy source and runs ML-DSA.KeyGen_internal (FIPS 204
   §6.1, Algorithm 6). The private key object keeps ξ for export (RFC 9881 §6).
2. Signing runs ML-DSA.Sign_internal (FIPS 204 §6.2, Algorithm 7). The number of rejection-loop
   iterations and the rejection decisions MAY be declassified; every other value derived from the
   private key MUST be handled in constant time.
3. Private import:

   | form | checks | failure |
   |---|---|---|
   | seed (32 bytes) | none beyond the length | |
   | expanded key only (2560, 4032, 4896 bytes) | the key is rebuilt: s1 and s2 are decoded and every coefficient MUST lie in [−η, η]; t = A·s1 + s2 is recomputed from ρ; pk = pkEncode(ρ, t1); tr = H(pk, 64); the encoding skEncode(ρ, K, tr, s1, s2, t0) MUST equal the input byte for byte (FIPS 204 §7.2, Algorithms 24 and 25), compared in constant time | INVALID_PRIVATE_KEY |
   | both | the expanded key computed from the seed equals the given expanded key (RFC 9881 §8.2) | INVALID_PRIVATE_KEY |
   | PKCS#8 with `publicKey` | equal to the derived public key | INVALID_PRIVATE_KEY |

4. Raw private export is the 32-byte seed when held, else the expanded key.

## 9.3 SLH-DSA

1. Key generation draws SK.seed, SK.prf and PK.seed, n bytes each, from the entropy source (FIPS 205
   §10.1, Algorithm 21) and runs slh_keygen_internal (FIPS 205 §9.1, Algorithm 18).
2. Signing runs slh_sign_internal (FIPS 205 §9.2, Algorithm 19).
3. Private import accepts exactly 4n bytes, SK.seed || SK.prf || PK.seed || PK.root (FIPS 205 §9.1;
   RFC 9909 §7). The implementation MUST recompute the root of the top hypertree layer from SK.seed and
   PK.seed and compare it with PK.root (INVALID_PRIVATE_KEY on mismatch; the result is declassified).
4. Raw private export is the 4n-byte key.

## 9.4 HashSLH-DSA algorithm values

1. The twelve `HASH_SLH_DSA_*_WITH_*` values [[D-07](decisions.md#decision-d-07)] identify HashSLH-DSA with the pre-hash fixed by
   RFC 9909 §3 and §4:

   | SLH-DSA set | fixed pre-hash | OID (2.16.840.1.101.3.4.3.x) |
   |---|---|---|
   | SHA2-128s, SHA2-128f | SHA-256 | 35, 36 |
   | SHA2-192s, SHA2-192f | SHA-512 | 37, 38 |
   | SHA2-256s, SHA2-256f | SHA-512 | 39, 40 |
   | SHAKE-128s, SHAKE-128f | SHAKE128 (32-byte output) | 41, 42 |
   | SHAKE-192s, SHAKE-192f | SHAKE256 (64-byte output) | 43, 44 |
   | SHAKE-256s, SHAKE-256f | SHAKE256 (64-byte output) | 45, 46 |

2. `sign` and `verify` with these values always use hash_slh_sign and hash_slh_verify with the fixed
   pre-hash. The `preHash` option MAY be absent or equal to the fixed function; any other value fails
   `sign` with INVALID_OPTION and makes `verify` return `false`. The same rule applies to
   `hazmat.sign` and `hazmat.verify` ([13](13-hazmat.md) item 3) [[D-07](decisions.md#decision-d-07)]. `context` and `deterministic` apply as in
   [9.1](#91-rules-common-to-ml-dsa-and-slh-dsa).
3. Their key generation, sizes and raw formats are those of the matching `SLH_DSA_*` value, and their
   signatures are byte-identical to those of `SLH_DSA_*.sign` with the same pre-hash, context and
   randomness (for example with `deterministic = true`). Their DER and PEM
   encodings use the OIDs above. A DER or PEM key with a pure SLH-DSA OID imported through a
   `HASH_SLH_DSA_*` value, or the reverse, fails with ALGORITHM_MISMATCH (RFC 9909 §8).
4. Note: for the `SLH_DSA_*` and `ML_DSA_*` values the `preHash` option remains available (FIPS 204
   §5.4, FIPS 205 §10.2.2). A key object does not record how its encoding was obtained [[D-08](decisions.md#decision-d-08)].
   Applications that use X.509 need to avoid the `preHash` option with keys identified by the pure
   OIDs (RFC 9909 §8; RFC 9881 §8.3 forbids HashML-DSA in X.509 altogether).
