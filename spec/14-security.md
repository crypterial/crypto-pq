# 14. Security requirements

## 14.1 Constant time

1. A branch, a memory address or a variable-latency instruction MUST NOT depend on a secret. This
   covers the native code, the WebAssembly code and the source of the pure backends.
2. Secrets are compared with a constant-time equality that examines every byte and returns a mask or a
   value whose computation has no secret-dependent branch. Secret selections use masks.
3. Table lookups indexed by secret data are forbidden. AES uses hardware AES instructions or a
   bitsliced constant-time implementation; the FrodoKEM sampler uses arithmetic comparisons; base64
   decoding of private keys uses arithmetic character mapping.
4. Lengths of secrets, algorithm identifiers and every public value of [2.2](02-terminology.md#22-terms) MAY influence control
   flow.
5. A value derived from secrets MAY be declassified only where this document allows it: the outcome
   of a validity check that fails the call; values that become public outputs (public keys, roots,
   ciphertexts, signatures, randomizers C and r that are part of a signature); rejection-loop
   decisions of ML-DSA signing; ML-KEM and FrodoKEM matrix generation from public seeds. Each
   declassification MUST be marked in the code so that the checker of [14.1](#141-constant-time) item 7 sees it.
6. Rejection sampling on secret data is permitted only in the form that FIPS 204 specifies for the
   signing loop.
7. Every language MUST verify item 1 mechanically in CI for every secret-handling path, including
   every CPU-specific kernel that the checker can execute:

   | language | method |
   |---|---|
   | Rust | valgrind memcheck with every secret marked undefined through client requests (`--cfg crypto_pq_ct`), on x86-64 and ARM64, in the default and the forced-portable build |
   | Zig (and the C ABI core) | valgrind memcheck with client requests (`-Dct=true`), on x86-64 (x86-64-v3 objects) and ARM64; the C ABI exports checked in the same way |
   | Go | valgrind memcheck with the Go runtime's valgrind support and client requests, on amd64 and arm64, with and without `purego` |
   | TypeScript WebAssembly | the core's valgrind check at source level, plus the WebAssembly branch lint of 26.2 for every secret-handling export |
   | TypeScript pure JavaScript, Python pure | no mechanical guarantee is possible (just-in-time compilers, garbage collectors, arbitrary-precision integers); see item 8 |
   | Python native | the core's checks |

8. The pure JavaScript and pure Python backends cannot guarantee constant time. They MUST follow items
   1 to 6 in their source, the native or WebAssembly backend MUST be the default wherever it loads,
   and the public documentation MUST state the limitation.

## 14.2 Data-independent timing (DIT)

1. On ARM64 processors with FEAT_DIT, the implementation MUST set PSTATE.DIT for the whole duration of:
   KEM key generation, encapsulation and decapsulation; signature key generation and signing; stateful
   key generation, loading, signing and `exportTreeCache`; private-key import and export; and the
   hazmat forms of these. It MUST restore the previous value afterwards; a nested operation leaves a
   bit that was already set to the outer one (P10).
2. MAC and KDF operations run without DIT unless the process has called
   `enableDataIndependentTiming()`. After that call, every later MAC and KDF operation in every thread
   sets DIT as in item 1. The switch cannot be turned off.
3. `enableDataIndependentTiming()` returns `true` only where DIT is supported and will be used, and
   `false` otherwise: on x86-64, RISC-V and other architectures; on ARM64 systems that do not report
   DIT (Windows ARM64 reports no DIT); in WebAssembly and JavaScript; in the Python pure backend; and in
   forced-portable builds that exclude CPU-specific code.
4. DIT detection: Linux and Android read the hardware capability HWCAP_DIT; on Apple systems DIT is
   used where the compilation target guarantees FEAT_DIT (macOS on Apple silicon); other systems,
   including Apple targets whose baseline predates ARMv8.4, are treated as not supporting it. Setting
   DIT on a processor without FEAT_DIT is an undefined instruction and MUST NOT happen.
5. DIT is a property of the operating-system thread. A runtime that can move a task between threads
   (Go) MUST pin the task to its thread for the duration of the bracket (24.2).
6. Verification, public-key import and hash/XOF operations do not set DIT [[D-45](decisions.md#decision-d-45)].

Rationale: DIT costs tens of nanoseconds per call on some ARMv8.4 cores, which is a large share of a
short MAC; attacks that exploit data-dependent prefetching need secrets that can be guessed piece by
piece, which is the case for lattice and hash-based private keys and not for keys mixed by a hash
(P10). The cost exists only on ARMv8.4 and later cores; other processors are unaffected.

## 14.3 Entropy

1. Every random value comes from the operating system or the runtime's cryptographic random source,
   requested for the operation that uses it. There is no user-space generator, no seeding by the
   caller (except hazmat), and no fallback.
2. Failure, a short read, or the absence of a source on the platform fails with RNG_FAILURE. Where the
   only entropy interface that P1 permits terminates the process on failure instead of returning an
   error (Go, 24.2 item 6), that termination conforms: it is not caused by caller input ([6.2](06-api.md#62-inputs-and-outputs) item 5)
   and no operation continues without fresh randomness.
3. Sources (Part II gives the details): `getrandom(2)` on Linux and Android and the BSD and illumos
   systems that provide it; `getentropy` (in chunks of at most 256 bytes) on Apple systems and
   OpenBSD; `ProcessPrng` on Windows; `random_get` on WASI; `crypto.getRandomValues` (in chunks of at
   most 65536 bytes) in JavaScript; Go's `crypto/rand.Read` and Python's `os.urandom`, which are used
   for operating-system access only (P1).
4. A source can block until the operating system has initialized its pool at boot; this is an
   operating-system property, not a crypto-pq wait (P7).

## 14.4 Self-tests

1. Pairwise consistency tests run at key generation when `selfTest` is true (the default): KEM keys
   encapsulate and decapsulate under fresh randomness and compare the secrets; signature keys sign a
   fixed message and verify it. Failure wipes the keys and fails with SELF_TEST_FAILED.
2. The import checks of [8.1.4](08-key-encapsulation.md#814-private-key-import) and [8.2.4](08-key-encapsulation.md#824-keys-and-import) include a pairwise consistency test that cannot be disabled.
3. Stateful signatures are verified before release ([11.5](11-stateful-signatures.md#115-signing)) and cannot be disabled.
4. Backends built from the core (TypeScript WebAssembly, Python native) MUST run a known-answer test
   of each module the first time it is loaded, synchronously [[D-27](decisions.md#decision-d-27)]:
   - If the module cannot be loaded on the platform (it is absent, or the runtime cannot instantiate
     it) and the backend was chosen automatically, the implementation uses its pure backend and
     records the reason. If the caller selected that backend explicitly, every operation fails with
     SELF_TEST_FAILED.
   - If the module loads but its known-answer test fails, every operation that uses the module fails
     with SELF_TEST_FAILED, whether the backend was chosen automatically or selected explicitly. There is no
     fallback to the pure backend in that case: a module that computes wrong results indicates
     corruption or a defect, not a platform limit.
5. crypto-pq 1.0 is not a validated module and runs no power-on self-tests beyond item 4.

## 14.5 Wiping

1. Every secret MUST be overwritten with zeros when it is no longer needed, by writes that the
   compiler and runtime cannot remove (volatile stores or an equivalent barrier). This covers key
   objects when destroyed, seeds, expanded keys, noise and mask vectors, one-time signature secrets,
   chain values derived from secrets, shared secrets inside the library, HMAC pads, PRKs, state record
   copies, decoded PEM and DER buffers of private keys, and stack buffers. It applies on success and on
   every error path.
2. Values returned to the caller belong to the caller. Each language MUST give the caller a way to
   wipe returned secrets (Part II).
3. Where a language cannot guarantee wiping (garbage collectors that copy, immutable byte strings), the
   implementation MUST still wipe every buffer it controls, and the public documentation MUST state the
   limitation.

## 14.6 Memory

1. No heap bloat (P8): operations of fixed size SHOULD NOT allocate on the heap where the language
   allows it, and a cache MUST NOT grow with use.
2. Permitted caches: the expanded matrix and the NTT forms of the secrets in ML-KEM and ML-DSA key
   objects; the authenticated nodes of the trees a stateful key currently uses (at most
   (2^(min(h,15)+1) − 1) · n bytes per held tree). FrodoKEM key objects MUST NOT cache matrix A.
3. Stack: every operation of the core MUST use at most 64 KiB of stack in every build mode, checked by
   a test. The other implementations SHOULD respect the same bound.

## 14.7 Fault countermeasures

crypto-pq 1.0 includes: the key-generation pairwise tests ([14.4](#144-self-tests)), the import consistency tests ([8.1.4](08-key-encapsulation.md#814-private-key-import),
[8.2.4](08-key-encapsulation.md#824-keys-and-import), [9.2](09-signatures.md#92-ml-dsa), [9.3](09-signatures.md#93-slh-dsa)), and verification before release of stateful signatures ([11.5](11-stateful-signatures.md#115-signing)). Verifying an SLH-DSA
signature before release is not an effective countermeasure (RFC 9909 §9), and this document does
not require it.

## 14.8 Security considerations

This section is informative. It collects the limits that this document states and the duties that it
leaves to callers and deployments. The sections cited define the rules.

1. **Pure backends.** The pure JavaScript and pure Python backends follow the source rules of [14.1](#141-constant-time)
   but cannot guarantee constant time; the native or WebAssembly backend is the default wherever it
   loads ([14.1](#141-constant-time) item 8, [14.4](#144-self-tests) item 4).
2. **WebAssembly.** WebAssembly gives no timing guarantee. The WebAssembly backend relies on the
   constant-time checks of the core and on the branch lint of 26.2 item 1.
3. **Wiping.** Garbage collectors that copy, immutable byte strings and compiler register spills can
   leave copies of secrets that an implementation cannot wipe ([14.5](#145-wiping) item 3; [23.2](profiles/rust.md#232-security-mechanics) item 3, 24.2 item 3,
   26.2 item 3, 27.2 item 3). Secrets returned to the caller belong to the caller ([14.5](#145-wiping) item 2).
4. **DIT.** DIT is used only on ARM64 processors that report FEAT_DIT. It is not available on other
   architectures, in WebAssembly, JavaScript or pure Python, on Windows ARM64, or in forced-portable
   builds ([14.2](#142-data-independent-timing-dit) item 3). MAC and KDF operations use DIT only after `enableDataIndependentTiming()`
   ([14.2](#142-data-independent-timing-dit) item 2).
5. **Entropy.** All randomness comes from the entropy source ([14.3](#143-entropy)). Whether that source is an
   approved random bit generator in the sense of SP 800-90 depends on the platform ([11.15](11-stateful-signatures.md#1115-statement-of-conformance-to-sp-800-208) item 1). In
   Go, a failing source terminates the process, and under `GODEBUG=fips140` the bytes come from the
   Go runtime's DRBG ([14.3](#143-entropy) item 2, 24.2 item 6).
6. **Stateful signatures.** The security of HSS/LMS, XMSS and XMSS^MT keys depends on the state store
   contract of [11.6](11-stateful-signatures.md#116-state-store-contract): atomic and durable updates, protection like a private key, and no restore, clone
   or concurrent use. Compare-and-swap cannot detect a rollback of the storage itself ([11.6](11-stateful-signatures.md#116-state-store-contract) item 8).
   Reserved and skipped indices are lost by design ([11.9](11-stateful-signatures.md#119-loading), [11.11](11-stateful-signatures.md#1111-reserve) item 3).
7. **SP 800-208 in software.** A software library cannot meet the module requirements of SP 800-208
   §8.1: a hardware module validated at FIPS 140 level 3, an entropy source inside the module boundary
   and no export of private keying material. crypto-pq claims neither SP 800-208 nor FIPS 140
   validation ([11.15](11-stateful-signatures.md#1115-statement-of-conformance-to-sp-800-208)), and crypto-pq 1.0 is not a validated module ([14.4](#144-self-tests) item 5).
8. **eFrodoKEM.** An eFrodoKEM public key is limited to fewer than 2^8 ciphertexts. The library does
   not enforce the limit ([8.2.6](08-key-encapsulation.md#826-efrodokem-usage-limit)).
9. **Pre-hash and X.509.** A key object does not record whether its encoding used a pure or a
   pre-hash OID; applications that use X.509 keep keys with pure OIDs in pure mode ([9.4](09-signatures.md#94-hashslh-dsa-algorithm-values) item 4). One
   key is best used with only one of the hedged and deterministic variants and only one of the pure
   and pre-hash modes ([9.1.2](09-signatures.md#912-hedged-and-deterministic-signing) item 3).
10. **Hazmat.** Reusing a seed or randomness with a different key, message or ciphertext breaks the
    scheme ([13](13-hazmat.md) item 1). Hazmat stateful keys do not conform to SP 800-208 ([11.14](11-stateful-signatures.md#1114-deterministic-mode-hazmat)).
11. **Short outputs.** SHA-224, SHA-512/224, SHA3-224, BLAKE2b-160, BLAKE2s-128, BLAKE2s-160,
    BLAKE2s-224 and truncated MAC tags are below the quantum-resistant collision sizes. They exist for
    interoperability, are never a default and are never accepted as a pre-hash ([9.1.3](09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa)). Tags shorter
    than 64 bits need a risk analysis ([12.6](12-symmetric-primitives.md#126-mac-algorithms) items 1 and 2).
12. **BLAKE3-KDF.** The context string is best hard-coded, globally unique and application-specific
    ([12.7.2](12-symmetric-primitives.md#1272-blake3-kdf) item 1).
13. **Faults.** The countermeasures of [14.7](#147-fault-countermeasures) cover key generation, key import and stateful signing.
    They do not detect every fault; for example, verifying an SLH-DSA signature before release is not
    effective (RFC 9909 §9).
