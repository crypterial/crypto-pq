# 19. Conformance

## 19.1 Definition

An implementation conforms to this specification when:

1. it meets every requirement of Part I and of its profile in Part II;
2. it passes every record of the compliance suite ([19.2](#192-compliance-suite)) in every build mode of its profile, on every
   platform of [18.3](18-testing.md#183-platforms);
3. its constant-time check ([14.1](14-security.md#141-constant-time) item 7) passes for every secret-handling path;
4. its CI runs the checks of Section [18](18-testing.md).

## 19.2 Compliance suite

The compliance suite is the content of the `vectors/` directory, fixed by `vectors/SHA256SUMS`. An
implementation MUST run all of it; a record MUST NOT be skipped. Each file records
its source URL and SHA-256 in the fetch or generation tool that produced it.

| directory | content |
|---|---|
| `acvp/` | NIST ACVP-Server vectors, pinned at commit 975de31eb83d87039ec88934fdc47d8c312b892d |
| `cavp/` | NIST CAVP SHA-2, SHA-3, SHAKE and HMAC response files |
| `wycheproof/` | C2SP Wycheproof vectors (pin: [19.4](#194-official-vector-sets)) |
| `rfc/` | test vectors and examples from RFCs |
| `nist-examples/` | NIST example values for cSHAKE and KMAC |
| `ascon/` | Ascon known-answer tests |
| `blake2/`, `derived/` | BLAKE2 known-answer tests and derived parameter tests |
| `blake3/` | BLAKE3 `test_vectors.json`, pinned ([19.4](#194-official-vector-sets)) |
| `frodokem/` | FrodoKEM known-answer tests ([19.4](#194-official-vector-sets)) |
| `xmss/` | XMSS and XMSS^MT vectors produced by the RFC 8391 reference implementation |
| `cross/` | the cross-check files ([19.3](#193-cross-check-files)) |

## 19.3 Cross-check files

1. The files of `vectors/cross/` define the behaviour that no official vector covers: every error
   case, every option, formats, stateful records, tree caches and the edge cases of Sections [6](06-api.md) to [13](13-hazmat.md).
   They are written by the test-only generator of [18.4](18-testing.md#184-vectors-and-robustness) item 2 and checked in CI.
2. Format: UTF-8 text. A line `[algorithm = <name>]` starts a section for the algorithm value with
   that `name`. In `mldsa.txt` and `slhdsa.txt`, a line `[seed = <hex>]` starts a key group: the
   records up to the next header use the key pair that hazmat key generation derives from that
   seed. Records are separated by blank lines. Each record line is `key = value`. Values are
   lowercase hexadecimal byte strings unless the dictionary below gives another type. An empty value
   is an empty byte string. A long value can continue on following lines that carry no key; the
   continuation lines are concatenated. A runner MUST fail on a key that the dictionary does not
   list.
3. `result` is `ok` (the operation succeeds and its outputs equal the given fields), `true` or
   `false` (a verification result), or one of the 13 error codes (the operation fails with that
   code). A record without `result` lists the outputs of a successful operation.

   Example, two records of `cross/symmetric.txt`:

   ```
   [algorithm = SHA-256]

   name = empty options
   operation = digest
   message = 616263
   salt =
   personalization =
   result = ok
   output = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

   name = salt
   operation = digest
   message = 616263
   salt = 73
   result = INVALID_OPTION
   ```
4. Key dictionary. "text" values are ASCII; "integer" values are decimal; "bool" values are `true`
   or `false`; every other value is hexadecimal bytes.

   | key | type | meaning |
   |---|---|---|
   | `name` | text | the case name, unique within its section |
   | `tcId` | integer | the case number (`kem.txt`, `hss.txt`, `xmss.txt`) |
   | `operation` | text | the operation of the record; see the operation table below |
   | `format` | text | `raw`, `der` or `pem`: the format of `input` (import) or of `output` (export) |
   | `result` | text | item 3 |
   | `mode` | text | `hazmat`: `hazmat.sign` with `randomness` and without the strength rule; `deterministic`: the public `sign` with `deterministic = true` |
   | `preHash` | text | `none`, or the ACVP name of the pre-hash: `SHA2-224`, `SHA2-256`, `SHA2-384`, `SHA2-512`, `SHA2-512/224`, `SHA2-512/256`, `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`, `SHAKE-128`, `SHAKE-256`, naming `SHA_224` … `SHAKE256` |
   | `parameters` | text | an XMSS or XMSS^MT parameter set name ([5.3](05-algorithms.md#53-stateful-hash-based-signatures)); error cases use invalid names on purpose |
   | `lms`, `ots` | text | the HSS levels: LMS and LM-OTS type names, comma-separated, top first, one entry per level |
   | `index` | integer | the start index of hazmat stateful key generation ([11.14](11-stateful-signatures.md#1114-deterministic-mode-hazmat)) |
   | `remaining` | integer | `remainingSignatures()` after the operation |
   | `reserve` | integer | the `reserve` option ([11.11](11-stateful-signatures.md#1111-reserve)) |
   | `length` | integer | the MAC `length` option ([6.5](06-api.md#65-configuration)) |
   | `outputLength` | integer | the requested output length of an XOF, `derive` or `expand` |
   | `xof` | bool | the KMAC `xof` option |
   | `signed` | bool | the key signed `message` once before `exportTreeCache` |
   | `publicVerify` | bool | the result that the public `verify` (with the strength rule) gives for `signature` |
   | `input` | bytes | the main input: the key encoding to import (in `format`), the seed of `generate`, the ciphertext of `decapsulate`, the signature of `verify` and `hazmatVerify`, the state record of `loadPrivateKey` and of stateful `sign` |
   | `output` | bytes | the output of a successful operation; see the operation table |
   | `key` | bytes | the key of the operation: a raw public key (`encapsulate`, `verify`, `hazmatVerify`), a raw private key (`decapsulate`, `sign`, `hazmatSign`, `hazmatSignInternal`), the hazmat seed of the key to export (`exportPublicKey`, `exportPrivateKey`), or a MAC key |
   | `message` | bytes | the message to hash, MAC or sign; for `hazmatSignInternal`, the message representative M′ |
   | `context` | bytes | the signature context |
   | `randomness` | bytes | hazmat randomness: `rnd` or `opt_rand` for signing, the encapsulation randomness |
   | `seed` | bytes | the hazmat key-generation seed |
   | `publicKey`, `publicKeyDer`, `publicKeyPem` | bytes | the public key in `raw`, `der` and `pem` (PEM as its ASCII bytes) |
   | `privateKey`, `privateKeyDer`, `privateKeyPem` | bytes | the private key in `raw` (SLH-DSA), and its `der` and `pem` export |
   | `expandedKey`, `expandedKeyDer`, `expandedKeyPem` | bytes | the expanded private key, raw and as a PKCS#8 `expandedKey` form |
   | `bothKeyDer` | bytes | the PKCS#8 `both` form, which import accepts and export never writes |
   | `ciphertext`, `sharedSecret` | bytes | the encapsulation from `publicKey` with `randomness` |
   | `tamperedCiphertext`, `rejectedSecret` | bytes | a modified ciphertext and the implicit-rejection secret that `decapsulate` returns for it |
   | `signature` | bytes | the signature of `message` |
   | `state`, `stateAfter` | bytes | the state record before and after the operation of the record (`stateAfter`: after signing `message`) |
   | `treeCache` | bytes | a tree cache ([11.10](11-stateful-signatures.md#1110-tree-cache)): exported by `export`, given to `load` |
   | `tag` | bytes | the MAC tag that `verify` checks |
   | `salt`, `personalization`, `customization`, `info` | bytes | the options of the same names |
   | `functionName` | bytes | the cSHAKE N of `hazmat.configureCshake` |
   | `ikm`, `prk` | bytes | the KDF inputs |

   Operations:

   | operation | file | runs | `output` |
   |---|---|---|---|
   | `importPublicKey`, `importPrivateKey` | `errors.txt` | import `input` in `format` | the raw public key of the imported key |
   | `exportPublicKey`, `exportPrivateKey` | `errors.txt` | hazmat key generation from `key`, then export in `format` | the export |
   | `generate` | `errors.txt` | hazmat key generation from `input` (stateful: with `parameters` or `lms`/`ots`, `index`, an empty store) | the raw public key; stateful also `remaining` |
   | `encapsulate` | `errors.txt` | `hazmat.encapsulate` under `key` with `randomness` | `sharedSecret \|\| ciphertext` |
   | `decapsulate` | `errors.txt` | `decapsulate(input)` with the raw private key `key` | the shared secret |
   | `sign` | `errors.txt` | signatures: the public `sign` of `message` with `context`, `preHash` and `deterministic = true` under `key`; stateful: load the state record `input`, then `sign(message)` | the signature |
   | `hazmatSign` | `errors.txt` | `hazmat.sign` under `key` with `randomness`, `context`, `preHash` | the signature |
   | `hazmatSignInternal` | `errors.txt` | `hazmat.signInternal` under `key` with `message` as M′ and `randomness` | the signature |
   | `verify`, `hazmatVerify` | `errors.txt` | verify `input` over `message` under `key` | none; `result` is `true` or `false` |
   | `loadPrivateKey` | `errors.txt` | `loadPrivateKey` from a store holding `input` | the raw public key, and `remaining` |
   | `digest`, `verify` | `symmetric.txt`, `blake3.txt` | the hash, XOF or MAC of the section's algorithm value, configured with the option keys of the record | the digest, XOF output or tag (`verify`: `result` only) |
   | `derive`, `extract`, `expand` | `symmetric.txt`, `blake3.txt` | the KDF operation with `ikm` or `prk`, `salt`, `info`, `outputLength` | the KDF output |
   | `export` | `treecache.txt` | hazmat stateful key generation from `seed` at `index`, a signature of `message` if `signed`, then `exportTreeCache` | `state`, `treeCache`, then as `load` |
   | `load` | `treecache.txt` | `loadPrivateKey` of `state` with `treeCache`; on success a signature of `message` | `publicKey`, `remaining`, `signature` |

   Records without `operation` (`kem.txt`, `mldsa.txt`, `slhdsa.txt`, `hss.txt`, `xmss.txt`) list the
   keys, encodings and signatures that the hazmat functions produce from `seed`, and for stateful
   algorithms the state records before and after one signature; a runner checks every listed field.
5. Files and coverage in 1.0:

   | file | covers |
   |---|---|
   | `errors.txt` | every import, export, encapsulate, decapsulate, sign, verify, generate, load and hazmat error of the asymmetric algorithms; for each HashSLH-DSA value, the refusals of [9.4](09-signatures.md#94-hashslh-dsa-algorithm-values) items 2 and 3 and of [13](13-hazmat.md) item 3 (a `preHash` other than the fixed one, `hazmat.signInternal`, a key with the pure SLH-DSA identifier and the reverse) and a changed signature |
   | `kem.txt` | ML-KEM keys in every form, encapsulation, implicit rejection |
   | `mldsa.txt`, `slhdsa.txt` | for each ML-DSA and SLH-DSA value: keys in every form, pure and pre-hash modes, contexts, hedged and deterministic signatures; in `slhdsa.txt`, for each HashSLH-DSA value: keys in every form with the identifiers of [9.4](09-signatures.md#94-hashslh-dsa-algorithm-values) and a deterministic signature with a context and the fixed pre-hash |
   | `hss.txt`, `xmss.txt` | deterministic stateful key generation, signatures, public keys in every format, and the state record after each step |
   | `treecache.txt` | tree cache export and every load check |
   | `symmetric.txt` | every hash, XOF, MAC and KDF operation, option, limit, streaming order and error |
   | `blake3.txt` | BLAKE3-256, the BLAKE3 XOF, BLAKE3-MAC and BLAKE3-KDF: digests, tags and their verification, derived keys, option and length errors, and the `extract` and `expand` that BLAKE3-KDF refuses |

## 19.4 Official vector sets

Each algorithm MUST pass these sets in every build mode. "Full" means every test group of
the file, including groups that the 1.0 API reaches only through `hazmat`. Groups for interfaces that
crypto-pq does not expose (external μ) are the only permitted omissions and MUST be counted and
reported by the runner. The internal-interface groups of ML-DSA and SLH-DSA run through
`hazmat.signInternal` and `hazmat.verifyInternal` [[D-65](decisions.md#decision-d-65)].

| algorithm | sets |
|---|---|
| ML-KEM | ACVP ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203, full (encapsulation, decapsulation, key checks); Wycheproof `mlkem_*_test`, `mlkem_*_encaps_test`, `mlkem_*_semi_expanded_decaps_test`, `mlkem_*_keygen_seed_test`; RFC 9935 Appendix C (every example key, including the inconsistent keys of C.4, which MUST fail with INVALID_PRIVATE_KEY); `cross/kem.txt`, `cross/errors.txt` |
| FrodoKEM | the official known-answer tests of the reference implementation (PQCrypto-LWEKE, commit e1edeb3af1fae0d5727683bd2f5465280ec2437a) for the eight sets; `cross/errors.txt` |
| ML-DSA | ACVP ML-DSA-keyGen, -sigGen and -sigVer (FIPS 204), full; Wycheproof `mldsa_*_sign_seed_test`, `mldsa_*_sign_noseed_test`, `mldsa_*_verify_test`; RFC 9881 Appendix C; `cross/mldsa.txt`, `cross/errors.txt` |
| SLH-DSA, HashSLH-DSA | ACVP SLH-DSA-keyGen, -sigGen and -sigVer (FIPS 205), full, including the internal groups through `hazmat`; RFC 9909 Appendix C (C.1 public key, C.2 private key, C.3 self-signed certificate); `cross/slhdsa.txt`, `cross/errors.txt` |
| HSS/LMS | ACVP LMS-keyGen, -sigGen and -sigVer; RFC 8554 Appendix F; RFC 9858 test cases; RFC 9802 Appendix A; `cross/hss.txt`, `cross/treecache.txt`, `cross/errors.txt` |
| XMSS, XMSS^MT | vectors of the RFC 8391 reference implementation: the sets in `vectors/xmss/` on every push, and all 44 parameter sets weekly; RFC 9802 Appendices B and C; `cross/xmss.txt`, `cross/treecache.txt`, `cross/errors.txt` |
| SHA-2, SHA-3, SHAKE | CAVP short, long, Monte Carlo and variable-output files; ACVP SHA2, SHA3 and SHAKE (byte-aligned groups, including the Monte Carlo procedures); large-data tests weekly |
| HMAC | CAVP HMAC; ACVP HMAC-SHA2; RFC 4231 |
| cSHAKE, KMAC | ACVP cSHAKE and KMAC; NIST example values; Wycheproof KMAC |
| HKDF | RFC 5869 Appendix A; ACVP KDA-HKDF; Wycheproof HKDF |
| BLAKE2 | RFC 7693 Appendix and the BLAKE2 reference known-answer tests; parameter (salt, personalization, length) tests; data above 4 GiB weekly |
| BLAKE3 | `test_vectors.json` of the BLAKE3 repository at commit f55849f89cd85083c1c9daa2c5de20766f309c00 (SHA-256 dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624): hash, keyed_hash and derive_key at every listed length; `cross/blake3.txt` |
| Ascon | ACVP Ascon (SP 800-232) and the Ascon known-answer tests for Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 |
| all symmetric | `cross/symmetric.txt` |

The Wycheproof pin is commit 7a32593 (the full commit hash is recorded with the vectors).

Schedule [[D-51](decisions.md#decision-d-51)]: the subsets kept in `vectors/` run on every push; the full ACVP sets of ML-KEM,
ML-DSA and SLH-DSA, all 44 XMSS and XMSS^MT sets, and the large-data tests run weekly. Both
are part of the release gate ([19.5](#195-release-gate)).

## 19.5 Release gate

A release MUST NOT be published unless, for the release commit:

1. every CI check passes, and the latest weekly fuzz run and weekly full-vector run passed;
2. the compliance suite passes in every build mode of the package;
3. the constant-time checks pass;
4. the release artifacts are reproducible ([18.5](18-testing.md#185-supply-chain) item 3);
5. the package conforms to this specification ([19.1](#191-definition));
6. an independent review of the changes since the last release is recorded.
