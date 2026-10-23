# 12. Symmetric primitives

## 12.1 Hash functions

1. SHA-2 follows FIPS 180-4 §6 and SHA-3 follows FIPS 202 §6.1.
2. `Hasher.digest()` returns the digest of everything absorbed so far and leaves the hasher able to
   absorb more; `digest()` called twice without an `update` between returns the same value.
3. BLAKE2b and BLAKE2s follow RFC 7693 in sequential mode (fanout 1, depth 1, leaf length 0, node
   offset 0, node depth 0, inner length 0) with key length 0 and the digest length of the algorithm
   value. `salt` and `personalization` fill the parameter-block fields of [BLAKE2] §2.5, zero-padded on
   the right to 16 bytes (BLAKE2b) or 8 bytes (BLAKE2s). A value padded with zeros is therefore the
   same as the shorter value; an absent value is all zeros.
4. Ascon-Hash256 follows SP 800-232 §5.1. BLAKE3-256 is the BLAKE3 hash mode with a 32-byte output
   ([BLAKE3] §2).

## 12.2 XOF streaming

1. An `Xof` object is absorbing until its first `read` or `readInto` call, and squeezing from then on.
   Any read call, including one for 0 bytes, ends absorbing [[D-01](decisions.md#decision-d-01)].
2. `update` on a squeezing object fails with UNSUPPORTED and leaves the object unchanged.
3. Successive reads return consecutive bytes of the output stream: `read(a)` followed by `read(b)`
   returns the first a + b bytes of `digest(data, a + b)`.
4. `ALG.digest(data, length)` equals `create()`, `update(data)`, `read(length)`.
5. Ascon-XOF128 and Ascon-CXOF128 require an output length L > 0 (SP 800-232 §5.2 and §5.3): the
   one-shot `digest` and `digestInto` with length 0 fail with INVALID_LENGTH [[D-34](decisions.md#decision-d-34)]. A streaming
   `read(0)` is allowed and returns no bytes (SP 800-232 §5.4 defines the streaming interface without
   a total length).
6. SHAKE, cSHAKE and BLAKE3 accept length 0 and return an empty result.

## 12.3 cSHAKE

1. cSHAKE128 and cSHAKE256 follow SP 800-185 §3. `customization` is S, of any length.
2. N, the function-name string, is empty in the public API and is set only through
   `hazmat.configureCshake` (Section [13](13-hazmat.md)), because SP 800-185 §3.3 reserves non-empty N for NIST
   functions.
3. With N and S both empty, cSHAKE is SHAKE (SP 800-185 §3.3), and the implementation MUST return the
   SHAKE output.

## 12.4 Ascon

Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 follow SP 800-232 §5.1 to §5.3, with the byte and bit
ordering of SP 800-232. The Ascon-CXOF128 `customization` is Z, at most 256 bytes (2048 bits,
SP 800-232 §5.3); a longer value fails `configure` with INVALID_OPTION.

## 12.5 BLAKE3

1. BLAKE3 follows [BLAKE3] at the pinned revision ([21.1](21-references.md#211-normative-references)). It runs single-threaded in 1.0.
2. `BLAKE3_256` is the hash mode with a 32-byte output; `BLAKE3` is the hash mode with extended
   output from offset 0, read as a stream ([12.2](#122-xof-streaming)); `BLAKE3_MAC` is keyed_hash with a 32-byte key and a
   32-byte tag; `BLAKE3_KDF` is derive_key ([12.7.2](#1272-blake3-kdf)).
3. None of the four takes `configure` options.

## 12.6 MAC algorithms

1. HMAC follows FIPS 198-1 and RFC 2104 with the SHA-2 function of the algorithm value. The key can have
   any length, including 0; a key longer than the block size is hashed first (FIPS 198-1 §4). The tag
   is the full hash output by default. `length` ([6.5](06-api.md#65-configuration)) selects a truncated tag of the leftmost
   `length` bytes (FIPS 198-1 §5), from 4 bytes (32 bits, the KMAC minimum of item 2) to the hash
   output size [[D-33](decisions.md#decision-d-33)]; `digestSize` is `length` and `verify` compares exactly `length` bytes. The
   documentation SHOULD advise keys with at least the desired security strength and tags of at least
   64 bits unless a risk analysis supports a shorter one.
2. KMAC128 and KMAC256 follow SP 800-185 §4. The key K and `customization` S can have any length.
   `length` is the tag length in bytes, 4 to 2^32 − 1 [[D-02](decisions.md#decision-d-02)]; L = 8 · `length`. The lower bound is the
   32-bit minimum of SP 800-185 §8.4.2; the documentation SHOULD repeat its advice that tags shorter
   than 64 bits need a careful risk analysis. `xof = true` selects KMACXOF (SP 800-185 §4.3.1, with
   right_encode(0)); the tag still has `length` bytes. `digestSize` is `length`.
3. BLAKE2b-MAC and BLAKE2s-MAC are the keyed mode of RFC 7693 §2.5 (key length kk ≥ 1) with the
   parameters of [12.1](#121-hash-functions) item 3. The key has 1 to 64 bytes (BLAKE2b) or 1 to 32 bytes (BLAKE2s); `length`
   is the tag length, 1 to 64 or 1 to 32, default 64 or 32.
4. BLAKE3-MAC requires a key of exactly 32 bytes.
5. A key of an unaccepted length fails `digest`, `digestInto` and `create` with INVALID_LENGTH
   [[D-03](decisions.md#decision-d-03)]. It never panics.
6. Verification (`ALG.verify(key, data, tag)` and `Mac.verify(tag)`) computes the tag and compares it
   with the given tag over its full length in constant time. It returns `false`, without an error or
   panic, if the key length is not accepted or the tag length is not `digestSize`. `Mac.verify` does not
   consume the object's state.

## 12.7 KDF algorithms

### 12.7.1 HKDF

1. HKDF follows RFC 5869 with the SHA-2 function of the algorithm value. `derive(ikm, L, {salt, info})`
   is `expand(extract(ikm, {salt}), L, {info})`.
2. `extract` (RFC 5869 §2.2): an empty `salt` means HashLen zero bytes. A non-empty `info` fails with
   INVALID_OPTION [[D-42](decisions.md#decision-d-42)]. The output has HashLen (`prkSize`) bytes; `extractInto` requires a buffer of exactly
   that length (INVALID_LENGTH).
3. `expand` (RFC 5869 §2.3): a non-empty `salt` fails with INVALID_OPTION. A PRK shorter than HashLen
   fails with INVALID_LENGTH; a longer PRK is accepted. L MUST be 1 to 255 · HashLen; 0 or a larger
   value fails with INVALID_LENGTH [[D-30](decisions.md#decision-d-30)].
4. Order: INVALID_OPTION before INVALID_LENGTH.

### 12.7.2 BLAKE3-KDF

1. `derive(ikm, L, {info})` is BLAKE3 derive_key with context string = `info` (any bytes, possibly
   empty) and key material = `ikm`. The documentation SHOULD repeat the advice of [BLAKE3] that the
   context string be hard-coded, globally unique and application-specific.
2. A non-empty `salt` fails with INVALID_OPTION. L MUST be 1 to 2^32 − 1 (INVALID_LENGTH) [[D-35](decisions.md#decision-d-35)].
3. `extract`, `extractInto`, `expand` and `expandInto` fail with UNSUPPORTED before any other check:
   BLAKE3 has no extract-then-expand split. `prkSize` is 32.

## 12.8 Limits

| item | allowed | otherwise |
|---|---|---|
| XOF `digest` / `digestInto` length | 0 to 2^32 − 1 (Ascon XOFs: 1 to 2^32 − 1) | INVALID_LENGTH |
| XOF `read` / `readInto` length per call | 0 to 2^32 − 1 | INVALID_LENGTH |
| XOF total output of one object | unbounded, except BLAKE3: 2^64 − 1 bytes | INVALID_LENGTH beyond |
| HMAC `length` | 4 to the hash output size | INVALID_OPTION |
| KMAC `length` | 4 to 2^32 − 1 | INVALID_OPTION |
| BLAKE2b-MAC / BLAKE2s-MAC `length` | 1..64 / 1..32 | INVALID_OPTION |
| BLAKE2 `salt`, `personalization` | 0..16 (b) / 0..8 (s) | INVALID_OPTION |
| Ascon-CXOF128 `customization` | 0..256 | INVALID_OPTION |
| HKDF L | 1 to 255 · HashLen | INVALID_LENGTH |
| BLAKE3-KDF L | 1 to 2^32 − 1 | INVALID_LENGTH |
| MAC keys | HMAC, KMAC: any; BLAKE2b: 1..64; BLAKE2s: 1..32; BLAKE3: 32 | INVALID_LENGTH (`verify`: `false`) |
| signature context | 0..255 | INVALID_CONTEXT (`verify`: `false`) |
| message, data, ikm, info, salt, customization (where unbounded) | platform maximum | |

The 2^32 − 1 bound applies on every platform, so that results do not depend on the platform; on
platforms whose buffers cannot reach it, the platform's allocation limit applies first ([6.2](06-api.md#62-inputs-and-outputs) item 6).
