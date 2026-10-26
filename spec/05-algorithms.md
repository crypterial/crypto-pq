# 5. Algorithm catalogue

Each table lists the algorithm values of crypto-pq 1.1, their `name` strings, the authoritative
standard and the sizes. All sizes are in bytes and are normative: an implementation MUST report and
enforce exactly these sizes.

## 5.1 Key encapsulation

| constant | name | standard | category | public key | private key (raw) | ciphertext | shared secret |
|---|---|---|---|---|---|---|---|
| `ML_KEM_512` | `ML-KEM-512` | FIPS 203 | 1 | 800 | seed 64; expanded 1632 | 768 | 32 |
| `ML_KEM_768` | `ML-KEM-768` | FIPS 203 | 3 | 1184 | seed 64; expanded 2400 | 1088 | 32 |
| `ML_KEM_1024` | `ML-KEM-1024` | FIPS 203 | 5 | 1568 | seed 64; expanded 3168 | 1568 | 32 |
| `FRODOKEM_976_AES` | `FrodoKEM-976-AES` | ISO/IEC 18033-2 Amd 2 | 3 | 15632 | 31296 | 15792 | 24 |
| `FRODOKEM_976_SHAKE` | `FrodoKEM-976-SHAKE` | same | 3 | 15632 | 31296 | 15792 | 24 |
| `FRODOKEM_1344_AES` | `FrodoKEM-1344-AES` | same | 5 | 21520 | 43088 | 21696 | 32 |
| `FRODOKEM_1344_SHAKE` | `FrodoKEM-1344-SHAKE` | same | 5 | 21520 | 43088 | 21696 | 32 |
| `EFRODOKEM_976_AES` | `eFrodoKEM-976-AES` | same (ephemeral) | 3 | 15632 | 31296 | 15744 | 24 |
| `EFRODOKEM_976_SHAKE` | `eFrodoKEM-976-SHAKE` | same (ephemeral) | 3 | 15632 | 31296 | 15744 | 24 |
| `EFRODOKEM_1344_AES` | `eFrodoKEM-1344-AES` | same (ephemeral) | 5 | 21520 | 43088 | 21632 | 32 |
| `EFRODOKEM_1344_SHAKE` | `eFrodoKEM-1344-SHAKE` | same (ephemeral) | 5 | 21520 | 43088 | 21632 | 32 |

ML-KEM parameters (FIPS 203 §8, Table 2): k = 2, 3, 4; η1 = 3, 2, 2; η2 = 2; (du, dv) = (10, 4),
(10, 4), (11, 5). Encapsulation key 384k + 32; expanded decapsulation key 768k + 96; ciphertext
32(du·k + dv). The seed is d || z (FIPS 203 §6.1, Algorithm 16; RFC 9935 §6).

FrodoKEM parameters (FrodoKEM specification as referenced by the ISO amendment; public text
[FRODO-DRAFT] §9.1): q = 2^16; n = 976 or 1344; n̄ = 8; B = 3 or 4; d = 10 or 6; len_A = 128;
len_sec = 192 or 256; SHAKE256 for hashing; AES-128 or SHAKE128 for matrix A ([FRODO-DRAFT] §6.7).
The ephemeral (eFrodoKEM) sets have a seedSE of len_sec bits and no salt; the standard sets have a
seedSE of 2·len_sec bits and a salt of 2·len_sec bits ([FRODO-DRAFT] §8). ISO object identifiers
(arc 1.0.18033.2.2.7, [FRODO-CERT] §3): 1 FrodoKEM-976-SHAKE, 2 FrodoKEM-1344-SHAKE,
3 eFrodoKEM-976-SHAKE, 4 eFrodoKEM-1344-SHAKE, 5 FrodoKEM-976-AES, 6 FrodoKEM-1344-AES,
7 eFrodoKEM-976-AES, 8 eFrodoKEM-1344-AES. These identifiers are recorded for reference; crypto-pq
1.1 defines no DER encoding for FrodoKEM ([10.1](10-key-formats.md#101-formats)).

## 5.2 Signatures

| constant | name | standard | category | public key | private key (raw) | signature |
|---|---|---|---|---|---|---|
| `ML_DSA_44` | `ML-DSA-44` | FIPS 204 | 2 (λ = 128) | 1312 | seed 32; expanded 2560 | 2420 |
| `ML_DSA_65` | `ML-DSA-65` | FIPS 204 | 3 (λ = 192) | 1952 | seed 32; expanded 4032 | 3309 |
| `ML_DSA_87` | `ML-DSA-87` | FIPS 204 | 5 (λ = 256) | 2592 | seed 32; expanded 4896 | 4627 |
| `SLH_DSA_SHA2_128S` | `SLH-DSA-SHA2-128s` | FIPS 205 | 1 | 32 | 64 | 7856 |
| `SLH_DSA_SHA2_128F` | `SLH-DSA-SHA2-128f` | FIPS 205 | 1 | 32 | 64 | 17088 |
| `SLH_DSA_SHA2_192S` | `SLH-DSA-SHA2-192s` | FIPS 205 | 3 | 48 | 96 | 16224 |
| `SLH_DSA_SHA2_192F` | `SLH-DSA-SHA2-192f` | FIPS 205 | 3 | 48 | 96 | 35664 |
| `SLH_DSA_SHA2_256S` | `SLH-DSA-SHA2-256s` | FIPS 205 | 5 | 64 | 128 | 29792 |
| `SLH_DSA_SHA2_256F` | `SLH-DSA-SHA2-256f` | FIPS 205 | 5 | 64 | 128 | 49856 |
| `SLH_DSA_SHAKE_128S` | `SLH-DSA-SHAKE-128s` | FIPS 205 | 1 | 32 | 64 | 7856 |
| `SLH_DSA_SHAKE_128F` | `SLH-DSA-SHAKE-128f` | FIPS 205 | 1 | 32 | 64 | 17088 |
| `SLH_DSA_SHAKE_192S` | `SLH-DSA-SHAKE-192s` | FIPS 205 | 3 | 48 | 96 | 16224 |
| `SLH_DSA_SHAKE_192F` | `SLH-DSA-SHAKE-192f` | FIPS 205 | 3 | 48 | 96 | 35664 |
| `SLH_DSA_SHAKE_256S` | `SLH-DSA-SHAKE-256s` | FIPS 205 | 5 | 64 | 128 | 29792 |
| `SLH_DSA_SHAKE_256F` | `SLH-DSA-SHAKE-256f` | FIPS 205 | 5 | 64 | 128 | 49856 |
| `HASH_SLH_DSA_SHA2_128S_WITH_SHA256` | `HashSLH-DSA-SHA2-128s-with-SHA256` | FIPS 205 §10.2.2, RFC 9909 | 1 | 32 | 64 | 7856 |
| `HASH_SLH_DSA_SHA2_128F_WITH_SHA256` | `HashSLH-DSA-SHA2-128f-with-SHA256` | same | 1 | 32 | 64 | 17088 |
| `HASH_SLH_DSA_SHA2_192S_WITH_SHA512` | `HashSLH-DSA-SHA2-192s-with-SHA512` | same | 3 | 48 | 96 | 16224 |
| `HASH_SLH_DSA_SHA2_192F_WITH_SHA512` | `HashSLH-DSA-SHA2-192f-with-SHA512` | same | 3 | 48 | 96 | 35664 |
| `HASH_SLH_DSA_SHA2_256S_WITH_SHA512` | `HashSLH-DSA-SHA2-256s-with-SHA512` | same | 5 | 64 | 128 | 29792 |
| `HASH_SLH_DSA_SHA2_256F_WITH_SHA512` | `HashSLH-DSA-SHA2-256f-with-SHA512` | same | 5 | 64 | 128 | 49856 |
| `HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128` | `HashSLH-DSA-SHAKE-128s-with-SHAKE128` | same | 1 | 32 | 64 | 7856 |
| `HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128` | `HashSLH-DSA-SHAKE-128f-with-SHAKE128` | same | 1 | 32 | 64 | 17088 |
| `HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256` | `HashSLH-DSA-SHAKE-192s-with-SHAKE256` | same | 3 | 48 | 96 | 16224 |
| `HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256` | `HashSLH-DSA-SHAKE-192f-with-SHAKE256` | same | 3 | 48 | 96 | 35664 |
| `HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256` | `HashSLH-DSA-SHAKE-256s-with-SHAKE256` | same | 5 | 64 | 128 | 29792 |
| `HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256` | `HashSLH-DSA-SHAKE-256f-with-SHAKE256` | same | 5 | 64 | 128 | 49856 |

ML-DSA parameters (FIPS 204 §4, Table 1): (k, ℓ) = (4, 4), (6, 5), (8, 7); η = 2, 4, 2; τ = 39, 49, 60;
γ1 = 2^17, 2^19, 2^19; γ2 = (q−1)/88, (q−1)/32, (q−1)/32; ω = 80, 55, 75; q = 8380417.

SLH-DSA parameters (FIPS 205 §11, Table 2):

| set | n | h | d | h′ | a | k | lg w | m |
|---|---|---|---|---|---|---|---|---|
| 128s | 16 | 63 | 7 | 9 | 12 | 14 | 4 | 30 |
| 128f | 16 | 66 | 22 | 3 | 6 | 33 | 4 | 34 |
| 192s | 24 | 63 | 7 | 9 | 14 | 17 | 4 | 39 |
| 192f | 24 | 66 | 22 | 3 | 8 | 33 | 4 | 42 |
| 256s | 32 | 64 | 8 | 8 | 14 | 22 | 4 | 47 |
| 256f | 32 | 68 | 17 | 4 | 9 | 35 | 4 | 49 |

The SHA2 sets use the functions of FIPS 205 §11.2 (SHA-256 for category 1; SHA-256 and SHA-512 for
categories 3 and 5); the SHAKE sets use FIPS 205 §11.1.

## 5.3 Stateful hash-based signatures

| constant | name | standard |
|---|---|---|
| `HSS_LMS` | `HSS/LMS` | RFC 8554; NIST SP 800-208 §4; additional parameter sets RFC 9858; X.509 RFC 9802 |
| `XMSS` | `XMSS` | RFC 8391 §4.1; NIST SP 800-208 §5; X.509 RFC 9802 |
| `XMSS_MT` | `XMSS^MT` | RFC 8391 §4.2; NIST SP 800-208 §5 and §7.2; X.509 RFC 9802 |

LM-OTS types (RFC 8554 §4.1, RFC 9858 §3 and SP 800-208 §4):

| type code | name | hash | n | w | p |
|---|---|---|---|---|---|
| 0x01 | `LMOTS_SHA256_N32_W1` | SHA-256 | 32 | 1 | 265 |
| 0x02 | `LMOTS_SHA256_N32_W2` | SHA-256 | 32 | 2 | 133 |
| 0x03 | `LMOTS_SHA256_N32_W4` | SHA-256 | 32 | 4 | 67 |
| 0x04 | `LMOTS_SHA256_N32_W8` | SHA-256 | 32 | 8 | 34 |
| 0x05 | `LMOTS_SHA256_N24_W1` | SHA-256/192 | 24 | 1 | 200 |
| 0x06 | `LMOTS_SHA256_N24_W2` | SHA-256/192 | 24 | 2 | 101 |
| 0x07 | `LMOTS_SHA256_N24_W4` | SHA-256/192 | 24 | 4 | 51 |
| 0x08 | `LMOTS_SHA256_N24_W8` | SHA-256/192 | 24 | 8 | 26 |
| 0x09 | `LMOTS_SHAKE_N32_W1` | SHAKE256/256 | 32 | 1 | 265 |
| 0x0A | `LMOTS_SHAKE_N32_W2` | SHAKE256/256 | 32 | 2 | 133 |
| 0x0B | `LMOTS_SHAKE_N32_W4` | SHAKE256/256 | 32 | 4 | 67 |
| 0x0C | `LMOTS_SHAKE_N32_W8` | SHAKE256/256 | 32 | 8 | 34 |
| 0x0D | `LMOTS_SHAKE_N24_W1` | SHAKE256/192 | 24 | 1 | 200 |
| 0x0E | `LMOTS_SHAKE_N24_W2` | SHAKE256/192 | 24 | 2 | 101 |
| 0x0F | `LMOTS_SHAKE_N24_W4` | SHAKE256/192 | 24 | 4 | 51 |
| 0x10 | `LMOTS_SHAKE_N24_W8` | SHAKE256/192 | 24 | 8 | 26 |

LMS types (RFC 8554 §5.1, RFC 9858 §4 and SP 800-208 §4): type codes 0x05 to 0x18, named
`LMS_{SHA256|SHAKE}_M{32|24}_H{5|10|15|20|25}`. Codes 0x05-0x09 are SHA256_M32 H5..H25,
0x0A-0x0E SHA256_M24 H5..H25, 0x0F-0x13 SHAKE_M32 H5..H25, 0x14-0x18 SHAKE_M24 H5..H25. m equals the
n of the LM-OTS type of the same hash.

XMSS parameter sets (SP 800-208 §5; code points of RFC 8391 §5.3 and SP 800-208 §5): the
SHA-512 and SHAKE128 sets of RFC 8391 are not approved by SP 800-208 and are not provided.

| OID | name | n | h |
|---|---|---|---|
| 0x00000001-0x00000003 | `XMSS-SHA2_10_256`, `XMSS-SHA2_16_256`, `XMSS-SHA2_20_256` | 32 | 10, 16, 20 |
| 0x0000000D-0x0000000F | `XMSS-SHA2_10_192`, `XMSS-SHA2_16_192`, `XMSS-SHA2_20_192` | 24 | 10, 16, 20 |
| 0x00000010-0x00000012 | `XMSS-SHAKE256_10_256`, `XMSS-SHAKE256_16_256`, `XMSS-SHAKE256_20_256` | 32 | 10, 16, 20 |
| 0x00000013-0x00000015 | `XMSS-SHAKE256_10_192`, `XMSS-SHAKE256_16_192`, `XMSS-SHAKE256_20_192` | 24 | 10, 16, 20 |

XMSS^MT parameter sets (RFC 8391 §5.4, SP 800-208 §5), each with (h, d) in the order 20/2, 20/4, 40/2, 40/4, 40/8, 60/3, 60/6, 60/12:

| OIDs | family | n |
|---|---|---|
| 0x00000001-0x00000008 | `XMSSMT-SHA2_{h}/{d}_256` | 32 |
| 0x00000021-0x00000028 | `XMSSMT-SHA2_{h}/{d}_192` | 24 |
| 0x00000029-0x00000030 | `XMSSMT-SHAKE256_{h}/{d}_256` | 32 |
| 0x00000031-0x00000038 | `XMSSMT-SHAKE256_{h}/{d}_192` | 24 |

All XMSS and XMSS^MT sets use w = 16, so len = 2n + 3. The n = 24 sets use the 4-byte padding prefix of
SP 800-208 §5.

Sizes:

| item | size |
|---|---|
| HSS public key | 28 + m (60 for m = 32, 52 for m = 24) |
| LMS signature | 12 + n(p + 1) + m·h |
| HSS signature | 4 + Σ(LMS signature of each level) + (L − 1) × (24 + m) |
| XMSS public key, XMSS^MT public key | 4 + 2n (68 or 52) |
| XMSS signature | 4 + n + (len + h)·n (n = 32: 2500, 2692, 2820 for h = 10, 16, 20; n = 24: 1492, 1636, 1732) |
| XMSS^MT signature | ⌈h/8⌉ + n + (d·len + h)·n (n = 32: 4963, 9251, 5605, 9893, 18469, 8392, 14824, 27688; n = 24: 2955, 5403, 3437, 5885, 10781, 5144, 8816, 16160, in the (h, d) order above) |
| capacity N | HSS 2^(Σ h_l); XMSS and XMSS^MT 2^h |

## 5.4 Hash functions

| constant | name | output | standard |
|---|---|---|---|
| `SHA_224` | `SHA-224` | 28 | FIPS 180-4 §6.3 |
| `SHA_256` | `SHA-256` | 32 | FIPS 180-4 §6.2 |
| `SHA_384` | `SHA-384` | 48 | FIPS 180-4 §6.5 |
| `SHA_512` | `SHA-512` | 64 | FIPS 180-4 §6.4 |
| `SHA_512_224` | `SHA-512/224` | 28 | FIPS 180-4 §6.6 |
| `SHA_512_256` | `SHA-512/256` | 32 | FIPS 180-4 §6.7 |
| `SHA3_224` | `SHA3-224` | 28 | FIPS 202 §6.1 |
| `SHA3_256` | `SHA3-256` | 32 | FIPS 202 §6.1 |
| `SHA3_384` | `SHA3-384` | 48 | FIPS 202 §6.1 |
| `SHA3_512` | `SHA3-512` | 64 | FIPS 202 §6.1 |
| `BLAKE2B_160`, `BLAKE2B_256`, `BLAKE2B_384`, `BLAKE2B_512` | `BLAKE2b-160` ... `BLAKE2b-512` | 20, 32, 48, 64 | RFC 7693; parameter block [BLAKE2] §2.5 |
| `BLAKE2S_128`, `BLAKE2S_160`, `BLAKE2S_224`, `BLAKE2S_256` | `BLAKE2s-128` ... `BLAKE2s-256` | 16, 20, 28, 32 | RFC 7693; [BLAKE2] §2.5 |
| `ASCON_HASH256` | `Ascon-Hash256` | 32 | NIST SP 800-232 §5.1 |
| `BLAKE3_256` | `BLAKE3-256` | 32 | [BLAKE3] §2 (hash mode) |

## 5.5 Extendable-output functions

| constant | name | standard |
|---|---|---|
| `SHAKE128` | `SHAKE128` | FIPS 202 §6.2 |
| `SHAKE256` | `SHAKE256` | FIPS 202 §6.2 |
| `CSHAKE128` | `cSHAKE128` | NIST SP 800-185 §3 |
| `CSHAKE256` | `cSHAKE256` | NIST SP 800-185 §3 |
| `ASCON_XOF128` | `Ascon-XOF128` | NIST SP 800-232 §5.2 |
| `ASCON_CXOF128` | `Ascon-CXOF128` | NIST SP 800-232 §5.3 |
| `BLAKE3` | `BLAKE3` | [BLAKE3] §2 (extended output) |

## 5.6 Message authentication codes

| constant | name | key | default tag | standard |
|---|---|---|---|---|
| `HMAC_SHA_224` | `HMAC-SHA-224` | any length | 28 | FIPS 198-1 (truncation §5); RFC 2104 |
| `HMAC_SHA_256` | `HMAC-SHA-256` | any length | 32 | same |
| `HMAC_SHA_384` | `HMAC-SHA-384` | any length | 48 | same |
| `HMAC_SHA_512` | `HMAC-SHA-512` | any length | 64 | same |
| `KMAC128` | `KMAC128` | any length | 32 | NIST SP 800-185 §4 |
| `KMAC256` | `KMAC256` | any length | 64 | NIST SP 800-185 §4 |
| `BLAKE2B_MAC` | `BLAKE2b-MAC` | 1..64 | 64 | RFC 7693 §2.5 (keyed) |
| `BLAKE2S_MAC` | `BLAKE2s-MAC` | 1..32 | 32 | RFC 7693 §2.5 (keyed) |
| `BLAKE3_MAC` | `BLAKE3-MAC` | exactly 32 | 32 | [BLAKE3] §2 (keyed_hash) |

## 5.7 Key derivation functions

| constant | name | PRK size | standard |
|---|---|---|---|
| `HKDF_SHA_256` | `HKDF-SHA-256` | 32 | RFC 5869 |
| `HKDF_SHA_384` | `HKDF-SHA-384` | 48 | RFC 5869 |
| `HKDF_SHA_512` | `HKDF-SHA-512` | 64 | RFC 5869 |
| `BLAKE3_KDF` | `BLAKE3-KDF` | 32 | [BLAKE3] §2 (derive_key) |
