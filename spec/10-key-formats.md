# 10. Key formats

## 10.1 Formats

The format argument is one of `raw`, `der` and `pem`. Every other value fails with INVALID_OPTION.

| algorithm | public `raw` | private `raw` export | private `raw` import accepts | `der`/`pem` |
|---|---|---|---|---|
| ML-KEM | ek, 384k + 32 | the 64-byte seed if held, else the expanded key | 64 bytes (seed) or 768k + 96 bytes (expanded), told apart by length | SPKI / PKCS#8 ([10.2](#102-subjectpublickeyinfo), [10.3](#103-pkcs8-oneasymmetrickey)) |
| ML-DSA | pk | the 32-byte seed if held, else the expanded key | 32 bytes (seed) or the expanded size | SPKI / PKCS#8 |
| SLH-DSA, HashSLH-DSA | PK.seed \|\| PK.root, 2n | the 4n-byte key | 4n bytes | SPKI / PKCS#8 |
| FrodoKEM, eFrodoKEM | seedA \|\| b | sk | sk ([8.2.4](08-key-encapsulation.md#824-keys-and-import)) | UNSUPPORTED |
| HSS/LMS | u32(L) \|\| u32(lmsType_0) \|\| u32(otsType_0) \|\| I_0 \|\| T_0[1] (RFC 8554 §6.1) | no export operation | no import operation | SPKI public only |
| XMSS, XMSS^MT | u32(OID) \|\| root \|\| SEED (RFC 8391 §4.1.7, §4.2.2; SP 800-208 Appendix B) | no export operation | no import operation | SPKI public only |

A raw input of any other length fails with INVALID_LENGTH. The HSS/LMS, XMSS and XMSS^MT public keys
have no fixed length: their length follows from the type codes or OID they contain, so a stateful
public key whose length does not match them fails with INVALID_PUBLIC_KEY, in `raw` and inside DER or
PEM alike ([7.1](07-errors.md#71-error-codes)) [[D-62](decisions.md#decision-d-62)].

## 10.2 SubjectPublicKeyInfo

1. `der` for a public key is a DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7): SEQUENCE { SEQUENCE {
   OBJECT IDENTIFIER }, BIT STRING }. The AlgorithmIdentifier parameters MUST be absent (RFC 9935 §3,
   RFC 9881 §2, RFC 9909 §3, RFC 9802 §4 and §5). The BIT STRING has zero unused bits and contains the
   raw public key with no further ASN.1 wrapping.
2. Exact sizes: ML-KEM 822, 1206, 1590; ML-DSA 1334, 1974, 2614; SLH-DSA 2n + 18 for the 9-byte OIDs
   (50, 66, 82); HSS 48 + m (80 for m = 32; RFC 9802 Appendix A); XMSS and XMSS^MT 2n + 21 (85 for n = 32).
3. On import, present parameters (including NULL), a non-zero unused-bits octet, a non-minimal or
   indefinite length, or trailing bytes fail with INVALID_ENCODING.

Example: the SubjectPublicKeyInfo of the SLH-DSA-SHA2-128s public key of `cross/slhdsa.txt` in the
compliance suite ([19.2](19-conformance.md#192-compliance-suite)) has 50 bytes:

```
30 30                                     SEQUENCE, 48 bytes
   30 0b                                  SEQUENCE (AlgorithmIdentifier), 11 bytes
      06 09 60864801650304 0314           OID 2.16.840.1.101.3.4.3.20, no parameters
   03 21 00                               BIT STRING, 33 bytes, no unused bits
      3737cde790fa02ab68ce073866c48903    PK.seed
      e5c358caf763048a6281885051ad69dc    PK.root
```

## 10.3 PKCS#8 OneAsymmetricKey

1. `der` for a private key is a DER OneAsymmetricKey (RFC 5958 §2).
2. Export MUST produce version 0, the algorithm identifier without parameters, the private key, no
   attributes and no public key. The privateKey OCTET STRING contains:
   - ML-KEM and ML-DSA: the CHOICE of RFC 9935 §6 and RFC 9881 §6, in the `seed` form (`80 40` || seed
     for ML-KEM, `80 20` || seed for ML-DSA) when the key object holds the seed, and in the
     `expandedKey` form (an OCTET STRING) otherwise. The `both` form is never exported [[D-31](decisions.md#decision-d-31)].
   - SLH-DSA and HashSLH-DSA: the raw 4n-byte key itself (RFC 9909 §7).
3. Exact sizes of the seed form: ML-KEM 86, ML-DSA 54.
4. Import MUST accept version 0 (v1) and version 1 (v2 of RFC 5958), MUST ignore `attributes`, and
   MUST accept a `publicKey` field only in version 1 (INVALID_ENCODING otherwise). The CHOICE MUST be
   one of its three forms, told apart by the tag (0x80 `seed`, 0x04 `expandedKey`, 0x30 `both`, whose
   members are two universal OCTET STRINGs) and with the exact sizes of RFC 9935 §6 or RFC 9881 §6
   (INVALID_ENCODING otherwise). A present `publicKey` is checked as in [8.1.4](08-key-encapsulation.md#814-private-key-import) and [9.2](09-signatures.md#92-ml-dsa); for SLH-DSA
   and HashSLH-DSA it MUST equal PK.seed || PK.root of the private key (INVALID_PRIVATE_KEY).
5. The DER rules of [10.2](#102-subjectpublickeyinfo) item 3 apply.

Example: the PKCS#8 export of the ML-DSA-44 key of the first key group of `cross/mldsa.txt` ([19.2](19-conformance.md#192-compliance-suite)), in
the seed form, has 54 bytes:

```
30 34                                     SEQUENCE, 52 bytes
   02 01 00                               INTEGER 0 (version)
   30 0b                                  SEQUENCE (AlgorithmIdentifier), 11 bytes
      06 09 60864801650304 0311           OID 2.16.840.1.101.3.4.3.17, no parameters
   04 22                                  OCTET STRING (privateKey), 34 bytes
      80 20                               [0] seed, 32 bytes
         ce56971cde355897421efc0b1046c8bf
         2f537eddbfbc7b9864f6e7ff7a82f2c3
```

## 10.4 PEM

1. `pem` is the textual encoding of RFC 7468 with the label `PUBLIC KEY` for SubjectPublicKeyInfo and
   `PRIVATE KEY` for OneAsymmetricKey.
2. Export MUST produce exactly: `-----BEGIN <label>-----` LF, the base64 encoding (RFC 4648 §4, with
   padding) of the DER in lines of 64 characters, each followed by LF (only the last line can be shorter),
   then `-----END <label>-----` LF. The output is ASCII bytes [[D-05](decisions.md#decision-d-05)].

   Example: the PEM encoding of the SubjectPublicKeyInfo of the example in [10.2](#102-subjectpublickeyinfo). Every line, including
   the last, ends with LF.

   ```
   -----BEGIN PUBLIC KEY-----
   MDAwCwYJYIZIAWUDBAMUAyEANzfN55D6Aqtozgc4ZsSJA+XDWMr3YwSKYoGIUFGt
   adw=
   -----END PUBLIC KEY-----
   ```
3. Import takes bytes [[D-05](decisions.md#decision-d-05)]. It MUST [[D-32](decisions.md#decision-d-32), [D-67](decisions.md#decision-d-67)]:
   - recognise the BEGIN and END boundary lines only where each starts a line, with no leading
     whitespace, and holds only the boundary (`-----BEGIN <label>-----` or `-----END <label>-----`),
     optionally followed by spaces or tabs before the line end (`*WSP` in the grammar of RFC 7468
     §3);
   - ignore any text before the BEGIN line and after the END line (RFC 7468 §2 and §5.2 permit
     explanatory text there), including non-ASCII bytes;
   - ignore whitespace (SP, HT, LF, CR, VT, FF) anywhere inside the base64 body;
   - require exactly one block, whose boundary lines carry exactly the expected label (a
     `PRIVATE KEY` block given to `importPublicKey` fails with INVALID_ENCODING);
   - refuse any other text on a boundary line, a block written on one line, any other text
     between the boundary lines, any non-ASCII byte there, and a second `-----BEGIN ` line;
   - refuse base64 whose length is not a multiple of 4, characters outside the alphabet, misplaced
     padding, or non-zero bits in the unused part of the last group (canonical encoding).
   Every refusal fails with INVALID_ENCODING.
4. Base64 decoding of private keys MUST be constant time: it MUST NOT branch on or index by the
   value of a base64 digit [[D-67](decisions.md#decision-d-67)]. The positions of the boundaries, the whitespace and the padding
   are layout and are public.

## 10.5 Object identifiers

| algorithm | OID | reference |
|---|---|---|
| ML-KEM-512, -768, -1024 | 2.16.840.1.101.3.4.4.1, .2, .3 | RFC 9935 §3 |
| ML-DSA-44, -65, -87 | 2.16.840.1.101.3.4.3.17, .18, .19 | RFC 9881 §2 |
| SLH-DSA-SHA2-128s, -128f, -192s, -192f, -256s, -256f, then SLH-DSA-SHAKE in the same order | 2.16.840.1.101.3.4.3.20 to .31 | RFC 9909 §3 |
| HashSLH-DSA ([9.4](09-signatures.md#94-hashslh-dsa-algorithm-values)) | 2.16.840.1.101.3.4.3.35 to .46 | RFC 9909 §3 |
| HSS/LMS | 1.2.840.113549.1.9.16.3.17 (id-alg-hss-lms-hashsig) | RFC 9708 §3, RFC 9802 §4.1 |
| XMSS | 1.3.6.1.5.5.7.6.34 (id-alg-xmss-hashsig) | RFC 9802 §4.2 |
| XMSS^MT | 1.3.6.1.5.5.7.6.35 (id-alg-xmssmt-hashsig) | RFC 9802 §4.3 |

The HashML-DSA identifiers 2.16.840.1.101.3.4.3.32 to .34 are refused with ALGORITHM_MISMATCH by every
ML-DSA value (RFC 9881 §8.3) [[D-09](decisions.md#decision-d-09)]. Any OID other than the algorithm value's own fails with
ALGORITHM_MISMATCH.

## 10.6 Import order

`importPublicKey` and `importPrivateKey` MUST check in this order and report the first failure:

1. FrodoKEM with `der` or `pem`: UNSUPPORTED, before any parsing.
2. `raw`: the length (INVALID_LENGTH; for stateful public keys see [10.1](#101-formats)).
3. `pem`: the PEM frame, label and base64 (INVALID_ENCODING).
4. `der`, and the DER inside `pem`: the outer structure up to and including the algorithm identifier
   (INVALID_ENCODING); then the OID (ALGORITHM_MISMATCH); then the rest of the structure, the version
   and the sizes inside it (INVALID_ENCODING).
5. The content checks of [8.1.4](08-key-encapsulation.md#814-private-key-import), [8.2.4](08-key-encapsulation.md#824-keys-and-import), [9.2](09-signatures.md#92-ml-dsa) item 3 and [9.3](09-signatures.md#93-slh-dsa) item 3 (INVALID_PUBLIC_KEY,
   INVALID_PRIVATE_KEY), then a PKCS#8 `publicKey` comparison (INVALID_PRIVATE_KEY).

Import of a private key runs with DIT set on ARM64 ([14.2](14-security.md#142-data-independent-timing-dit)) and wipes every intermediate copy ([14.5](14-security.md#145-wiping)).

## 10.7 Export

`exportKey(format)` returns the encoding of [10.1](#101-formats) to [10.4](#104-pem). FrodoKEM with `der` or `pem` fails with
UNSUPPORTED. Exporting a private key runs with DIT set on ARM64 and returns a secret that belongs to
the caller ([14.5](14-security.md#145-wiping) item 2); Part II states how the caller wipes it.
