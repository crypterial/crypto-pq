# 4. Scope

## 4.1 Included

crypto-pq 1.0 provides the algorithms of Section [5](05-algorithms.md) in seven categories: key encapsulation mechanisms
(KEM), signatures, stateful hash-based signatures, hash functions, extendable-output functions (XOF),
message authentication codes (MAC) and key derivation functions (KDF). It also provides public and
private key encoding (raw, DER, PEM) for the algorithms that have a standard encoding.

## 4.2 Excluded

| excluded | reason |
|---|---|
| X-Wing, X25519, X25519MLKEM768, composite signatures, any hybrid | P12: not post-quantum only. |
| RSA, ECDSA, EdDSA, (EC)DH and every other classical asymmetric algorithm | P12. |
| FN-DSA (FIPS 206) | P2: no final standard (no public draft) at the date of this document. |
| HQC | P2: no final standard. |
| Classic McEliece | P11: although it is in ISO/IEC 18033-2:2006/Amd 2:2026, the German BSI advised on 2026-10-01 against its use in new developments, because published key-recovery estimates fall below the claimed security. Excluded until the position is settled. |
| FrodoKEM-640 and eFrodoKEM-640 | Not in ISO/IEC 18033-2:2006/Amd 2:2026 (no ISO object identifier); see [8.2](08-key-encapsulation.md#82-frodokem) [[D-28](decisions.md#decision-d-28)]. |
| HPKE (RFC 9180) with post-quantum KEMs | P2: the post-quantum HPKE profiles are drafts. |
| AEAD (AES-GCM, ChaCha20-Poly1305, Ascon-AEAD128) | Deferred to crypto-pq 1.1. There is no AEAD category and no `DECRYPTION_FAILED` error in 1.0. |
| SHA-1, MD5 | Not quantum-resistant at their sizes and not needed by any included algorithm. |
| TupleHash and ParallelHash (SP 800-185); HMAC and HKDF over SHA-3 | Not in 1.0: no included algorithm uses them, and KMAC is the SHA-3 based MAC. |
| External μ (ExternalMu-ML-DSA) | Not exposed; see [9.1.5](09-signatures.md#915-no-external-μ). |
| JSON Web Key and other key formats | Only raw, DER and PEM (Section [10](10-key-formats.md)). |
| Streaming signatures, multi-threaded operations | Not in 1.0. Multi-threading is a later, opt-in option. |

## 4.3 Internal components

The following are implemented by every language but are not public: Keccak-f[1600], the SHA-2
compression functions, the AES-128 block cipher (used only by the FrodoKEM AES variants), MGF and
WOTS+/LM-OTS internals, DER, PEM and base64 codecs, constant-time helpers, wiping, CPU detection and the
operating-system entropy source.
