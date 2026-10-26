# 7. Errors

## 7.1 Error codes

Every failure is reported with exactly one of the following 13 codes. Section [16.4.5](16-naming.md#1645-error-codes) gives their Rust
form. There is no other public error code in 1.1.

| code | condition |
|---|---|
| `INVALID_LENGTH` | A byte input, length argument or output buffer has a length that the operation does not accept: a raw key of the wrong size; a KEM ciphertext of the wrong size in `decapsulate`; a hazmat seed or randomness of the wrong size; an XOF or KDF output length outside its range ([12.8](12-symmetric-primitives.md#128-limits)); a PRK shorter than `prkSize` in `expand`; an `extractInto` buffer of the wrong size; an unaccepted MAC key length; a `digestInto`, `readInto` or other caller buffer of the wrong size. |
| `INVALID_ENCODING` | DER, PEM or base64 that is malformed or not in the form that this document requires; a key of the wrong size inside DER or PEM; a tree cache that is malformed, has the wrong version, does not match the stored state, or fails its tag. |
| `ALGORITHM_MISMATCH` | A DER or PEM key whose algorithm identifier is not the one of the algorithm value used to import it (including the identifiers that this document refuses, [10.5](10-key-formats.md#105-object-identifiers)); a state record or tree cache whose kind byte is not the kind of the algorithm value. |
| `INVALID_PUBLIC_KEY` | A public key that fails a validity check of its standard: the ML-KEM modulus check (FIPS 203 §7.2); a stateful public key with an unknown type code, OID or length. |
| `INVALID_PRIVATE_KEY` | A private key that fails a validity check ([8.1.4](08-key-encapsulation.md#814-private-key-import), [8.2.4](08-key-encapsulation.md#824-keys-and-import), [9.2](09-signatures.md#92-ml-dsa) item 3, [9.3](09-signatures.md#93-slh-dsa) item 3); a seed and expanded key that do not agree; a PKCS#8 public key that does not match the private key; a state record that is absent, damaged, of an unknown version, or inconsistent ([11.9](11-stateful-signatures.md#119-loading)). |
| `INVALID_CONTEXT` | `sign` with a context longer than 255 bytes. |
| `INVALID_OPTION` | An option value that is not allowed: a pre-hash that is not approved or too weak ([9.1.3](09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa)); an unknown stateful parameter name or an invalid level list; `reserve` of 0; an option that the operation does not take ([6.3](06-api.md#63-options)); an out-of-range numeric option; a hazmat stateful start index equal to or above the capacity ([11.14](11-stateful-signatures.md#1114-deterministic-mode-hazmat) item 4). |
| `RNG_FAILURE` | The operating-system or runtime entropy source failed, returned fewer bytes than requested, or does not exist on the platform ([14.3](14-security.md#143-entropy)). |
| `SELF_TEST_FAILED` | A pairwise consistency test after key generation failed ([14.4](14-security.md#144-self-tests)); a stateful signature failed its verification before release ([11.5](11-stateful-signatures.md#115-signing)); a stored child-root signature failed its verification at load ([11.9](11-stateful-signatures.md#119-loading) item 6). |
| `KEY_EXHAUSTED` | A stateful `sign` or `exportTreeCache` when every index of the key has been used ([11.10](11-stateful-signatures.md#1110-tree-cache), [11.12](11-stateful-signatures.md#1112-exhaustion)). |
| `STATE_PERSIST_FAILED` | The state store's `read` or `update` reported an error (an exception, an error value or an error return). |
| `STATE_CONFLICT` | The state store's `update` returned `false`; `generateKeyPair` found a store that already holds a state; a stateful `sign` or `exportTreeCache` was called while the same key object was already signing ([11.13](11-stateful-signatures.md#1113-concurrency)). |
| `UNSUPPORTED` | An operation that the algorithm does not have: DER or PEM for FrodoKEM; `update` after `read` on an XOF; `extract` or `expand` on `BLAKE3_KDF`. |

## 7.2 Results that are not errors

1. Every verification (`verify` of signatures, stateful signatures and MACs) returns a boolean and
   never fails with an error. Any invalid input, including a signature or tag of the wrong length, a
   context longer than 255 bytes, a pre-hash that `sign` would refuse, a MAC key of an unaccepted
   length, or a wrong algorithm pairing, gives `false`.
2. KEM decapsulation uses implicit rejection (FIPS 203 §6.3, [FRODO-DRAFT] §7.3): a ciphertext of the
   correct length always yields a shared secret, which is pseudorandom when the ciphertext is invalid.

## 7.3 Order of checks

When an input violates several rules, the error reported MUST be the first one in this order [[D-36](decisions.md#decision-d-36)]. The
compliance suite (Section [19](19-conformance.md)) fixes the expected result of each case it contains; this order is the
rule it is generated from.

1. Concurrency: STATE_CONFLICT for a stateful key that is already signing.
2. An operation that the algorithm does not have: UNSUPPORTED ([7.1](#71-error-codes); [10.6](10-key-formats.md#106-import-order) item 1, [12.2](12-symmetric-primitives.md#122-xof-streaming) item 2,
   [12.7.2](12-symmetric-primitives.md#1272-blake3-kdf) item 3).
3. Options: INVALID_OPTION; then, for `sign`, INVALID_CONTEXT.
4. Lengths of raw inputs, length arguments and caller buffers: INVALID_LENGTH.
5. Key import: the order of Section [10.6](10-key-formats.md#106-import-order).
6. State: the order of Section [11.9](11-stateful-signatures.md#119-loading); KEY_EXHAUSTED.
7. Work: RNG_FAILURE, STATE_PERSIST_FAILED, STATE_CONFLICT (from `update`), SELF_TEST_FAILED, in the
   order the procedure reaches them.

## 7.4 Error content

An error carries its code and a short English message [[D-49](decisions.md#decision-d-49)]. The message MUST NOT contain secret data and
SHOULD NOT contain caller data. Errors raised by the caller's state store are wrapped as
STATE_PERSIST_FAILED; the original error MAY be attached as a cause where the language supports it.
