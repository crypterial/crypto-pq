# Appendix A. Decision log

Each entry records a decision that this specification makes where the standards or the design
principles of Section [3](03-principles.md) left a choice open. Each entry gives the decision, the sections that apply it,
and its rationale. The criteria are, in order: security, the standards, simplicity.

## Decision D-01

Any `read` of an XOF, including `read(0)`, ends absorbing; a
later `update` fails with UNSUPPORTED ([12.2](12-symmetric-primitives.md#122-xof-streaming)). Rationale: one state transition with no special case is
the simplest rule to implement and to test.

## Decision D-02

The KMAC `length` option is 4 to 2^32 − 1 bytes for KMAC and
KMACXOF ([6.5](06-api.md#65-configuration), [12.6](12-symmetric-primitives.md#126-mac-algorithms)). Rationale: 32 bits is the minimum of SP 800-185 §8.4.2; one upper bound that every
platform can represent, including 32-bit ones, keeps results identical.

## Decision D-03

Caller input never causes a panic. Wrong buffer sizes, `update`
after `read`, and MAC keys of an unaccepted length return errors; MAC verification returns `false`
([6.2](06-api.md#62-inputs-and-outputs), [12.6](12-symmetric-primitives.md#126-mac-algorithms)). The Rust signatures follow from it ([23.1](profiles/rust.md#231-public-api-idiom)). Rationale: a panic
on input is a denial-of-service vector in servers; one error model is easier to audit.

## Decision D-04

An output buffer that overlaps an input gives the same result as
non-overlapping buffers; no error ([6.2](06-api.md#62-inputs-and-outputs) item 4). Rationale: refusing overlap would add a failure mode
that Rust cannot even express; computing as if inputs were copied gives the correct output
with no new error.

## Decision D-05

PEM export returns ASCII bytes, and PEM import takes bytes
([10.4](10-key-formats.md#104-pem)). Rationale: one byte-string type for `exportKey` and the import operations in every
format.

## Decision D-06

Importing an ML-KEM expanded key without its seed runs a
pairwise consistency test with fresh randomness ([8.1.4](08-key-encapsulation.md#814-private-key-import)). Rationale: the FIPS 203 checks accept a key
with a modified secret vector (RFC 9935 Appendix C.4); fresh randomness prevents a key crafted to pass
one fixed test message.

## Decision D-07

Twelve algorithm values `HASH_SLH_DSA_*_WITH_*` represent the
RFC 9909 HashSLH-DSA identifiers (OIDs 35 to 46) with their fixed pre-hash ([9.4](09-signatures.md#94-hashslh-dsa-algorithm-values)). Rationale: RFC 9909
§8 binds a key to either pure or pre-hash use through its OID; an algorithm value per OID makes that
binding explicit, uses the existing API, and follows the rule that constants are named after the
standard. The fixed pre-hash also binds `hazmat.sign` and `hazmat.verify` ([13](13-hazmat.md) item 3), so that no
interface of crypto-pq produces a signature under these values with another hash.

## Decision D-08

The `SLH_DSA_*` and `ML_DSA_*` values keep the `preHash` option,
and key objects do not record whether they were imported from DER ([9.4](09-signatures.md#94-hashslh-dsa-algorithm-values) item 4). Rationale: FIPS 204
and FIPS 205 permit pre-hashing with any key; enforcing the X.509 binding would add hidden state to
keys. The RFC 9909 binding is available through [D-07](#decision-d-07). To be reviewed if users need enforcement.

## Decision D-09

DER or PEM keys with the HashML-DSA OIDs (.32 to .34) fail with
ALGORITHM_MISMATCH ([10.5](10-key-formats.md#105-object-identifiers)). Rationale: RFC 9881 §8.3 forbids them in X.509.

## Decision D-10

State record version 2, holding the signed child roots and a
claimed or signed status per level ([11.7](11-stateful-signatures.md#117-state-record-version-2)). Rationale: SP 800-208 §8.1 (footnote 9) requires each root
to be signed only once; storing the signatures removes the re-signing after every load, and the
claimed status makes the use of a parent leaf durable before it signs.

## Decision D-11

Fresh random I and SEED per child LMS tree, a random C per LMS
signature, and a random S_XMSS per XMSS^MT tree, stored in the state record; one SK_PRF per XMSS^MT key
([11.4](11-stateful-signatures.md#114-randomness-d-11)). Rationale: SP 800-208 §6.1 and §6.2 and RFC 9802 §8. Random per-tree secrets cannot be
re-derived, so they are stored, which the version 2 record does. One SK_PRF per key is allowed by
SP 800-208 §7.2 for a single module.

## Decision D-12

When a load finds a level claimed but not signed, the key skips
to the next child tree at that level, losing the indices below it ([11.9](11-stateful-signatures.md#119-loading) item 4). Rationale: re-signing
after a crash would use a parent one-time key a second time (with a new random C, on a new message);
skipping never does. The loss is bounded by one subtree and happens only after a crash in the middle
of a transition.

## Decision D-13

Every newly computed one-time signature, the message
signature and every child-root signature, is verified before it is released or stored ([D-63](#decision-d-63)); a failure gives SELF_TEST_FAILED and the index stays spent
([11.5](11-stateful-signatures.md#115-signing)). Rationale: a faulty one-time signature can reveal secret chain values, so it is never
released; an existing error code fits the meaning. (SP 800-208 §8.1 footnote 9 addresses a different
fault, a changed child root, which the sign-once rule of [D-10](#decision-d-10) makes harmless.)

## Decision D-14

Version 1 state records are refused with
INVALID_PRIVATE_KEY and left unchanged ([11.8](11-stateful-signatures.md#118-state-record-version-1)). They are not migrated by recomputing
the current child-root signatures once. Rationale: the recomputation signs every current
child root again, and a fault during it can yield a different root signed by a one-time key that
already signed the original root in every released signature (the grafting fault that SP 800-208
§8.1 footnote 9 guards against); the parent-signature check cannot detect it, because the signature
over the faulty root is valid. A migrated key would also keep deterministically derived child trees,
contrary to SP 800-208 §6.

## Decision D-15

Hazmat stateful keys use the deterministic derivation of the
reference implementations, marked by a flag in the state record ([11.14](11-stateful-signatures.md#1114-deterministic-mode-hazmat)). Rationale: test vectors of
RFC 8554, RFC 9858 and RFC 8391 need deterministic keys; the flag keeps them distinguishable from
conforming keys.

## Decision D-16

The project claims that it implements the SP 800-208 algorithms
and signing requirements, never SP 800-208 or FIPS 140 validation ([11.15](11-stateful-signatures.md#1115-statement-of-conformance-to-sp-800-208)). Rationale: SP 800-208 §8.1
requires a validated hardware module, which a software library cannot be.

## Decision D-17

The tree cache format stays at version 1; child-tree roots in a
cache are checked against the state record, and a cache holds exactly one entry per current level,
top first ([11.10](11-stateful-signatures.md#1110-tree-cache)). Rationale: the format already carries every needed field and its tag. Defining the entries fixes every byte of the `exportTreeCache` output, which
the compliance suite tests.

## Decision D-18

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-19

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-20

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-21

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-22

Rust option structs are `#[non_exhaustive]` with `Default` and
`with_*` setters ([23.1](profiles/rust.md#231-public-api-idiom)). Rationale: a non-exhaustive struct cannot be built with a struct expression
outside its crate, even with `..Default::default()`; setters keep 1.x additions non-breaking.

## Decision D-23

Rust returns secret outputs as `SecretBytes`, which wipes its bytes
on drop ([23.1](profiles/rust.md#231-public-api-idiom)). Rationale: a returned secret is then wiped when the caller drops it, with no
further action by the caller ([14.5](14-security.md#145-wiping) item 2).

## Decision D-24

The PRK size accessor is `prkSize` (`prk_size()` in Rust)
([16.4.2](16-naming.md#1642-operations)). Rationale: P4.

## Decision D-25

The hazmat key-generation functions are
`generateKemKeyPair`, `generateSignatureKeyPair` and `generateStatefulKeyPair`, and
the stateful one takes algorithm, seed, index, then the arguments of `generateKeyPair` ([13](13-hazmat.md),
[16.4.4](16-naming.md#1644-hazmat)). Rationale: P4; Rust cannot overload a single name.

## Decision D-26

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-27

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-28

FrodoKEM is the eight ISO sets; FrodoKEM-640 and eFrodoKEM-640
are excluded ([4.2](04-scope.md#42-excluded), [5.1](05-algorithms.md#51-key-encapsulation)). Rationale: P2; the ISO amendment assigns no identifier to the 640 sets.

## Decision D-29

The eFrodoKEM limit of fewer than 2^8 ciphertexts per public key
is documented, not enforced ([8.2.6](08-key-encapsulation.md#826-efrodokem-usage-limit)). Rationale: a library cannot count encapsulations made by other
processes or copies of a public key; a partial counter would suggest a guarantee it cannot give.

## Decision D-30

HKDF output length 0 fails with INVALID_LENGTH ([12.7.1](12-symmetric-primitives.md#1271-hkdf)).
Rationale: an empty key is never useful and usually a caller bug.

## Decision D-31

PKCS#8 export writes version 0, no public key, and the seed form
when the seed is known, otherwise the expanded form; never `both` ([10.3](10-key-formats.md#103-pkcs8-oneasymmetrickey)). Rationale: RFC 9935 §7 and
RFC 9881 recommend keeping and exporting the seed; the seed form is the smallest and needs no
consistency check on import.

## Decision D-32

PEM import ignores text before the BEGIN line and
after the END line, tolerates whitespace inside the block, and refuses any other text inside the
block, a second block and non-canonical base64 ([10.4](10-key-formats.md#104-pem)). Rationale: RFC 7468 §2 permits data before the
encapsulation boundary and requires that parsers do not malfunction on it, and §5.2 describes
explanatory text around the block; inside the block, strict parsing removes ambiguity between
implementations.

## Decision D-33

HMAC accepts keys of any length, including empty, and
takes a `length` option for a truncated tag of 4 bytes up to the hash output size, with the full
output as the default ([6.5](06-api.md#65-configuration), [12.6](12-symmetric-primitives.md#126-mac-algorithms)). Rationale: FIPS 198-1 §5 standardizes truncation, so P3 makes it an
option with a safe default; the 32-bit minimum and the option name match KMAC and BLAKE2-MAC. FIPS
198-1 and RFC 4231 test keys shorter than the output; key and tag strength advice belongs in the
documentation.

## Decision D-34

One-shot Ascon-XOF128 and Ascon-CXOF128 with length 0 fail with
INVALID_LENGTH; a streaming `read(0)` is allowed ([12.2](12-symmetric-primitives.md#122-xof-streaming)). Rationale: SP 800-232 §5.2 and §5.3 require
L > 0 for the function; §5.4 defines streaming without a total length.

## Decision D-35

Per-call output lengths of XOFs and BLAKE3-KDF are at most
2^32 − 1 bytes ([12.8](12-symmetric-primitives.md#128-limits)). Rationale: one bound representable on every platform keeps results identical;
larger single outputs have no use case.

## Decision D-36

A fixed order of checks decides which error is reported when
several apply ([7.3](07-errors.md#73-order-of-checks), [10.6](10-key-formats.md#106-import-order), [11.9](11-stateful-signatures.md#119-loading)). Rationale: the compliance suite can fix one expected result for an
input only with a defined order.

## Decision D-37

Hazmat key generation runs no pairwise self-test ([13](13-hazmat.md)).
Rationale: hazmat reproduces vectors; the public `generateKeyPair` keeps the test on by default.

## Decision D-38

HSS allows 1 to 8 levels with one hash function and size and a
total height of at most 60 ([11.2](11-stateful-signatures.md#112-parameters)). Rationale: RFC 8554 §6 allows 1 to 8 levels; 60 bounds every count
in 64 bits and covers every SP 800-208 XMSS^MT height.

## Decision D-39

When a key is exhausted the public key still verifies, and
`sign` fails with KEY_EXHAUSTED without signing; its only store access is the retry of a pending
erasure write ([11.5.2](11-stateful-signatures.md#1152-procedure), [11.12](11-stateful-signatures.md#1112-exhaustion)). `exportTreeCache` on an exhausted key also fails with KEY_EXHAUSTED
([11.10](11-stateful-signatures.md#1110-tree-cache) item 6). Rationale: refusing needs no write, and the retry completes the erasure of [D-54](#decision-d-54); an
exhausted key has erased the secrets that key the cache tag and has no tree left to use.

## Decision D-40

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-41

The state record keeps a truncated SHA-256 checksum, not a MAC
([11.7](11-stateful-signatures.md#117-state-record-version-2)). Rationale: a MAC cannot stop a rollback by whoever controls the store, which is the real
threat; the checksum detects damage.

## Decision D-42

HKDF `extract` and `expand` refuse a misplaced `info` or `salt`
with INVALID_OPTION ([12.7.1](12-symmetric-primitives.md#1271-hkdf)). Rationale: silent ignoring of an option hides caller bugs.

## Decision D-43 (revised by D-66)

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-44

Revised for specification 1.1 on 2026-10-26, 2026-10-28 and 2026-11-01; specification 1.0, which
1.0.0 and 1.0.1 implement, said that crypto-pq contains no AVX-512 code. On x86-64 processors with
AVX-512F and AVX-512VL, whose opmask and ZMM state the operating system saves (XCR0 bits 1, 2 and 5
to 7, or the `hw.optional.avx512f` and `hw.optional.avx512vl` sysctl values on macOS), the
Keccak-f[1600] kernel on four states uses the EVEX instructions on 256-bit registers only, and so
does the kernel on one state on the processors that run it in less time than the scalar kernel, by a
table of families and models: AMD families 19h and 1Ah and Intel's Ice Lake Xeon; other processors
run one state with the scalar kernel. On the same processors, the kernel that hashes eight lanes of
SHA-256 side by side, for the chains and trees of LMS and XMSS and the SHA-2 hashes of SLH-DSA,
keeps one lane in each element of a 256-bit register and uses rotations and three-input logic for
Ch, Maj and the sigma functions. In a build for the baseline target, no code uses a 512-bit register
but BLAKE3's sixteen-lane and four-input kernels below. The Keccak round takes theta in the form that
each vendor's cores run in less time. Sponges squeezed side by side keep their states in the vector
layout of the kernel from one block to the next. The tier is detected at run time, and the AVX2
kernels and the portable code stay its twins ([15.3](15-platforms.md#153-cpu-specific-code)).
valgrind cannot execute AVX-512, so the constant-time check's build leaves the tier out
([14.1](14-security.md#141-constant-time) item 7), and its kernels are constant time by
construction: logic, rotations, shifts, additions, shuffles, blends, broadcasts and loads and stores
at addresses that depend on public lengths only, each on Intel's list of data-operand-independent
timing instructions or a floating-point-domain logic, move, unpack, shuffle, insert or blend
instruction of [D-75](#decision-d-75), with no branch, address or variable-latency instruction that
depends on the data; which kernel runs depends only on the processor. CI runs them on native runners
([18.2](18-testing.md#182-cpu-tiers)). On the same processors, BLAKE2b, BLAKE2s and BLAKE3 take the
tier for one message: the rotations of their AVX2 row forms that take two shifts and an OR become
one VPRORD or VPRORQ (BLAKE2b by 63, BLAKE2s by 12 and 7, BLAKE3 every rotation), on 128-bit and
256-bit registers, written as inline assembly in the AVX2 code, so that the compiler places no value
in a 512-bit register. BLAKE3 keeps the message in registers and moves its words to the next round's
order with shuffles, unpacks and blends, in the form of the blake3 crate's assembly for one input: as
two VPERMT2D a round on two registers, a block of a 1 KiB hash took 50.7 ns on Granite Rapids, 61.2 on
Emerald Rapids and 63.4 on Zen 4, against 46.2, 55.7 and 62.2 for that assembly in rscrypto. On
the processors of a table of families, AMD family 1Ah, these kernels for one message give way to the
portable code in general registers, which takes less time there; their kernels for several messages
stay. BLAKE2b and BLAKE2s keep their AVX2 forms on the other AMD processors with AVX-512, where
VPRORD and VPRORQ take two cycles. On the processors of a third table, AMD families 19h and 1Ah and
Intel's Ice Lake Xeon, Sapphire Rapids, Emerald Rapids and Granite Rapids (family 6, models 6Ah, 6Ch,
8Fh, CFh and ADh), BLAKE3 hashes sixteen chunks or parents, and computes sixteen blocks of its
extended output, side by side in 512-bit registers: each of zmm0 to zmm15 holds one state word of the
sixteen inputs, zmm16 to zmm31 hold the message words, and every rotation is one VPRORD. There eight
take 256-bit registers in the same way, and two to four the row form of
[D-84](#decision-d-84), on 512-bit registers for three or four and on 256-bit registers for two.
These kernels are the only functions built with AVX-512F. Each is one block of inline assembly, of
the instructions of this tier's kernels, that ends by zeroing zmm16 to zmm31 and with VZEROUPPER. The
other processors with AVX-512 run the eight-lane AVX2 kernel there. The minimum Rust version is
1.89, the first in which these target features and intrinsics are stable
([15.2](15-platforms.md#152-supported-platforms)). Rationale: sixteen more registers, three-input
logic and 64-bit rotations take fewer instructions per Keccak round than AVX2 does, and 256-bit
registers keep the clock at which the core runs AVX2 code. On the processors of the third table, the
512-bit BLAKE3 kernels of the blake3 crate and rscrypto hashed 16 KiB in 0.43 (Zen 5), 0.68 (Zen 4),
0.56 (Emerald Rapids) and 0.55 (Granite Rapids) of the time of the eight-lane AVX2 kernel, close to
what their instruction counts predict for each core, so no clock cost showed; Sapphire Rapids, whose
core Emerald Rapids revises, was not measured. On Ice Lake Xeon they took 0.70, a fifth more than
the count predicts, and the processor stayed out of the table until this crate's own sixteen-lane
kernel took 0.56 to 0.58 of the time of its eight-lane kernel for 16 KiB and 64 KiB, in three runs,
and a copy of the kernel in the same process 0.63 to 0.73, in two; what separates the two copies
there was not established. For SHA-256 on eight lanes, the block of one lane takes 18 to 22 ns on the
Zen 4, Zen 5, Ice Lake, Emerald Rapids and Granite Rapids processors measured, against 20 to 59 ns with
the SHA extensions on two lanes and 31 to 44 ns with AVX2. AMD processors with the SHA extensions
run SHA-256 lanes with them instead: with the SHA-NI rounds of specification 1.1, LMS, XMSS and
SLH-DSA-SHA2 took 0.5 to 6 percent less time on Zen 4 and Zen 5 than with the eight-lane kernel, and
7 to 14 percent more on Emerald Rapids.

## Decision D-45

Hash and XOF operations never set DIT ([14.2](14-security.md#142-data-independent-timing-dit)). Rationale: P10
covers asymmetric secrets and, by the switch, MAC and KDF; hashes and XOFs have no key, and
keyed uses go through MAC or KDF values.

## Decision D-46

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-47

FrodoKEM private import runs a pairwise consistency test after
the pkh check ([8.2.4](08-key-encapsulation.md#824-keys-and-import)). Rationale: the same reasoning as [D-06](#decision-d-06): a modified S^T passes the pkh check.

## Decision D-48

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-49

Errors carry a code and an English message with no secret data;
store errors are wrapped as STATE_PERSIST_FAILED with the cause attached where possible ([7.4](07-errors.md#74-error-content)).
Rationale: diagnosable without leaking.

## Decision D-50

The AES-128 code used by FrodoKEM, the AES instructions or the bitsliced code, is constant time
although its FrodoKEM inputs are public ([8.2.3](08-key-encapsulation.md#823-constant-time-and-memory)). Rationale: constant-time AES code serves every use, with public or
secret keys; no variable-time AES code exists in the code base.

## Decision D-51

Subsets of the official vectors run on every push and the full
sets weekly; both gate the release ([19.4](19-conformance.md#194-official-vector-sets)). Rationale: full ACVP and XMSS sets take too long for every
push.

## Decision D-52

Stateful `generateKeyPair` returns the key pair only after the
initial state record, with every first child tree signed and verified, is stored with
`update(absent, record)` ([11.5.3](11-stateful-signatures.md#1153-key-generation)). Rationale: no public key exists without a durable
state.

## Decision D-53

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-54

When a stateful key is exhausted, its secrets are erased from
the stored record and from memory ([11.12](11-stateful-signatures.md#1112-exhaustion)). Rationale: an exhausted key has no legitimate use for its
secrets; erasing them removes the reuse risk after a rollback.

## Decision D-55

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-56

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-57

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-58

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-59

Withdrawn on 2026-10-23: it concerned implementations in other languages, which are no longer part of crypto-pq.

## Decision D-60

A failure after a successful claim write (a failed verification
of a child-root signature, or a failed signed write) moves the in-memory index past the subtree of
the topmost claimed level, exactly as a reload of the claim would ([11.5.2](11-stateful-signatures.md#1152-procedure) step 3.5). Rationale: a
retry that rebuilt the claimed trees would draw new randomness and make a parent leaf sign a second,
different root, which SP 800-208 §8.1 forbids even if the first signature was never released.
Treating the failure as a crash needs no extra state and keeps the key object and a reload in
agreement; the cost is the indices of one subtree, and only after a fault or a store failure.

## Decision D-61

Importing an ML-KEM expanded key without its seed checks that
the encoding of the secret vector ŝ is canonical (every coefficient below q) in addition to the
FIPS 203 checks and the pairwise test ([8.1.4](08-key-encapsulation.md#814-private-key-import)). Rationale: FIPS 203 does not check ŝ, and a
non-canonical encoding can pass a pairwise test where the arithmetic reduces mod q, yet it is not a
valid key and would be exported unchanged; the check is cheap, constant time and declassifies only
its result.

## Decision D-62

A stateful public key whose length does not match its type codes
or OID fails with INVALID_PUBLIC_KEY in every format, not with INVALID_LENGTH or INVALID_ENCODING
([10.1](10-key-formats.md#101-formats)). Rationale: the length of these keys is defined by their content, so a length mismatch is a
content error; one code for every format keeps the compliance results identical.

## Decision D-63

Verification before release ([11.5.2](11-stateful-signatures.md#1152-procedure) step 7)
covers the one-time signatures computed in the call, that is the message signature and any child-root
signature produced at a transition; the stored child-root signatures are copied byte for byte and are
not verified again on every signature. Rationale: [D-13](#decision-d-13) stops a faulty one-time signature from leaving
the key, and only a newly computed one-time signature can carry such a fault; the stored ones were
verified when computed and again at load ([11.9](11-stateful-signatures.md#119-loading) item 6). Verifying them again on every signature was
measured to cost about 2.5 times the signing time of XMSS^MT-20/4 with no security gain.

## Decision D-64

Three readings of Section [11](11-stateful-signatures.md) are fixed.
(1) A hazmat key generated at index i builds and signs, at every level, the tree that is current for
i, and stores next = i; it does not build tree 0 of the lower levels first. (2) A tree cache entry whose tree
number is not t_l(i) for the loaded index i is stale and is ignored, and the tree is rebuilt; an
entry that is malformed, duplicated, out of order, or for a level that the key does not have gives
INVALID_ENCODING ([11.10](11-stateful-signatures.md#1110-tree-cache) items 3 and 4). (3) An empty tree cache means no cache ([6.3](06-api.md#63-options) item 2).
Rationale: (1) avoids building trees that are never used and keeps the deterministic test-vector
bytes defined by the index alone; (2) keeps an old cache harmless ([11.10](11-stateful-signatures.md#1110-tree-cache) item 5) while a damaged
cache is refused; (3) follows from the exact cache contents of [11.10](11-stateful-signatures.md#1110-tree-cache) item 1.

## Decision D-65

`hazmat` gains `signInternal` and
`verifyInternal` for ML-DSA (FIPS 204 Algorithms 7 and 8) and SLH-DSA (FIPS 205 Algorithms 19 and 20).
They take the message representative M′ and, for signing, the randomness, and exist only so that the
ACVP internal-interface groups can run. External μ stays unsupported (Section [9](09-signatures.md)). Rationale: the ACVP
internal groups are part of the official conformance evidence for both standards, and the internal
algorithms cannot be reached through the pure or pre-hash interfaces.

## Decision D-66 (revised by D-71)

The package follows SemVer; its MAJOR.MINOR equals the version of
this specification it implements (1.0.x implements SPEC 1.0), and PATCH is independent of the
specification. A release is a signed annotated tag `rust-vX.Y.Z` (`rust-v1.0.0`) ([20.1](20-versioning.md#201-versions),
[20.4](20-versioning.md#204-release-process)). Rationale: tying MAJOR.MINOR to the specification states which version of
this document a release implements, and patch releases need no new specification.

## Decision D-67

A PEM block is recognised only when the BEGIN and
END boundary lines each start a line (no leading whitespace) and hold nothing but the boundary,
optionally followed by spaces or tabs as the RFC 7468 grammar allows (`*WSP` before the line end);
any other text on a boundary line, or a block written on one line, gives INVALID_ENCODING. Text before the BEGIN line and after the END line is ignored ([D-32](#decision-d-32)). Decoding
a private key does not branch on or index by the value of a base64 digit; the positions of boundaries,
whitespace and padding are layout and are public. Rationale: RFC 7468 §2 and §5; one exact rule leaves no choice to
an implementation, and the layout carries no secret.

## Decision D-68

`hazmat` stateful key generation requires a start
index below the key's capacity N; an index of N or more gives INVALID_OPTION. Rationale: a key that
starts exhausted can never sign, and exhaustion is reached through signing in the tests.

## Decision D-69

The key-generation self-test of [9.1.7](09-signatures.md#917-self-test) signs
and verifies a fixed message in the algorithm's own mode: pure for `ML_DSA_*` and `SLH_DSA_*`, pre-hash
with the fixed hash for `HASH_SLH_DSA_*`; signing is hedged. Rationale: the self-test checks the key in
the way it will be used; a `HASH_SLH_DSA_*` key is never used for pure signing.

## Decision D-70

The Rust crate has one Cargo feature per algorithm family, all of them in the default set, and an
opt-in `hazmat` feature ([23.4](profiles/rust.md#234-build-packaging-and-platforms) item 4). Rationale: a user can build only the
algorithms that an application uses, with less code to compile and review, while the default build
stays the whole of Part I; `hazmat` takes caller seeds and randomness, so only a build that names it
contains it.

## Decision D-71

The repository `crypterial/crypto-pq` holds this specification, the compliance suite and the Rust
package, and the release tag of [D-66](#decision-d-66-revised-by-d-71) sits on a commit of its default branch
([17](17-implementation-conventions.md) item 8, [20.4](20-versioning.md#204-release-process)). Rationale: the specification, the tests that define its behaviour
and the package that implements it change together in one history.

## Decision D-72

Revised for specification 1.1 on 2026-10-28; specification 1.0, which 1.0.0 and 1.0.1 implement,
said that verification runs the same code. SampleInBall (FIPS 204 Algorithm 29) runs in constant
time in every attempt of ML-DSA signing: neither the positions nor the signs of the challenge decide
a branch, a memory address or the number of steps ([14.1](14-security.md#141-constant-time) item 5).
The only value derived from the challenge stream that is declassified is whether fewer than τ of the
128 candidate bytes of the first SHAKE256 block fit, so that a further block is read; for a uniform
stream its probability is 2^−87.7 for τ = 60, 2^−140.3 for τ = 49 and 2^−202.9 for τ = 39.
Verification of a signature that is an input of the call, whose c̃ is public
([2.2](02-terminology.md#22-terms), [14.1](14-security.md#141-constant-time) item 4), may sample the
challenge by plain rejection, as FIPS 204 Algorithm 29 is written; a verification of a signature
that the implementation has not output, such as the pairwise test of key generation
([14.4](14-security.md#144-self-tests)), runs the constant-time form. Rationale: the challenge c̃ of
a rejected attempt is never output, so it is a secret, and only the decision to reject is public. A
signature under verification is public as a whole, c̃ with it, so its challenge carries nothing that
the signature does not; the pairwise test's signature is never output, so its challenge stays a
secret. Side channels on the challenges of rejected attempts are a demonstrated threat:
[KARABULUT21] recovers their signs, and [ZHOU25] recovers the private key from rejected challenges
together with the rejected responses. The declassified bit is expected fewer than 2^−23 times in
2^64 attempts, and no fixed amount of stream avoids it entirely.

## Decision D-73

At load, a child tree that is current for the loaded index and is built from the secrets of its
level record has the root that the record stores; a mismatch fails with INVALID_PRIVATE_KEY
before any parent signature is verified ([11.9](11-stateful-signatures.md#119-loading) item 6). A tree taken from a tree cache keeps
the rule of [11.10](11-stateful-signatures.md#1110-tree-cache) item 4 (INVALID_ENCODING). Rationale: the record is the only source of a child
root, so a root that its own secrets do not give means a damaged or inconsistent record, for
example a lower level whose LM-OTS type was changed, which keeps every length; that is the meaning of
INVALID_PRIVATE_KEY ([7.1](07-errors.md#71-error-codes)), and the top root already follows the same rule ([11.9](11-stateful-signatures.md#119-loading) item 3).
SELF_TEST_FAILED stays for a parent signature that does not verify a root that matches.

## Decision D-74

Importing a KEM private key that holds no seed refuses every secret that key generation cannot
produce: every coefficient of s = NTT^−1(ŝ) of an ML-KEM expanded key lies in [−η1, η1], and every
entry of the S^T of a FrodoKEM key lies in the support {−d, …, d} of χ ([8.1.4](08-key-encapsulation.md#814-private-key-import) check (4),
[8.2.4](08-key-encapsulation.md#824-keys-and-import) item 3). Both checks examine every coefficient without a secret-dependent branch and
declassify only their result, the outcome of a validity check that fails the call ([14.1](14-security.md#141-constant-time) item 5).
The pairwise tests of [D-06](#decision-d-06) and [D-47](#decision-d-47) stay: they also check that the secret belongs to the
public key. Rationale: a pairwise test with fresh randomness can accept a key that is wrong for
some ciphertexts and refuse it on the next import; a FrodoKEM key with the top bit of one entry of
S^T flipped passes it for about 2^−8 of the encapsulations. The range checks give the same result
every time. A secret changed within the range is left to the pairwise test, which one changed entry
of S^T passes for about 2^−24 (n = 976) or 2^−32 (n = 1344) of the encapsulations. The cost is one
inverse NTT per polynomial of ŝ and one pass over S^T.

## Decision D-75

On x86-64, the following floating-point-domain logic, move, unpack, shuffle, insert and blend
instructions, which LLVM emits for the integer intrinsics of the kernels, count as on Intel's list
of data-operand-independent timing instructions ([14.1](14-security.md#141-constant-time) item 1), in their VEX and their legacy SSE
encodings. Each of these gives the result of an integer instruction on the list: VANDPS, VANDNPS and
VORPS as VPAND, VPANDN and VPOR; VUNPCKLPS, VUNPCKHPS, VUNPCKLPD and VUNPCKHPD as VPUNPCKLDQ,
VPUNPCKHDQ, VPUNPCKLQDQ and VPUNPCKHQDQ; VMOVLHPS as VPUNPCKLQDQ, and VMOVHLPS as VPUNPCKHQDQ with
its two sources swapped; VBLENDPS as VPBLENDD with the same immediate, and VBLENDPD as VPBLENDD with
each bit of its immediate doubled. In the legacy SSE encoding, which VPBLENDD and the three-operand
VPUNPCKHQDQ do not have, BLENDPS and BLENDPD give the result of PBLENDW with each bit of the
immediate repeated two or four times, and MOVHLPS that of VPUNPCKHQDQ with the destination as its
second source. Each of these moves 32-bit or 64-bit elements or their sign bits, selected by an
immediate or by sign bits, as an instruction on the list does for other elements or sources, though
no integer instruction gives its result for every operand: VSHUFPS and VSHUFPD, which fill the low
half of each 128-bit lane with elements of the first source and the high half with elements of the
second, picked by an immediate, as VPSHUFD picks those of one source, whose result VSHUFPS gives
when both sources are one register; VINSERTPS, which writes a 32-bit element of a register or of
memory at the position its immediate gives and zeroes the elements the immediate names, as VPINSRD
writes one from a general register or memory; VBLENDVPS and VBLENDVPD, which select each 32-bit or
64-bit element by its sign bit in a mask register, as VPBLENDVB selects each byte; and VMOVMSKPS and
VMOVMSKPD, which gather the sign bits of the 32-bit or 64-bit elements into a general register, as
VPMOVMSKB gathers those of the bytes. An instruction on the list counts whatever its domain, as
VMOVSD, VPERM2F128 and VINSERTF128 do, and in its VEX and its legacy SSE encoding where the list
names one of them: VXORPS, VMOVAPS and VMOVUPS as XORPS, MOVAPS and MOVUPS, and the legacy MOVSD of
opcodes 10h and 11h as VMOVSD (the MOVSD of the list, opcode A5h, is the string move). No other
floating-point instruction counts. Rationale: none of these instructions does arithmetic or reads
its operands as numbers.

## Decision D-76

A secret array is a stack buffer in the sense of [14.5](14-security.md#145-wiping) item 1 when the
code addresses its memory: it is indexed with a run-time value, passed by reference to a function
that is not inlined, or copied with a run-time length. Such an array is wiped before the function
returns, on every path. Scratch that a block, a round or a chain step uses belongs to the operation,
which wipes it once at the end. An array of vector or general registers that the code indexes only
with constants holds register values, as a scalar variable does, also where it is larger than the
register file, such as a Keccak state, and a value that the compiler spills is a copy that the
compiler makes ([14.5](14-security.md#145-wiping) item 3). At opt-level 3, where the compiler
unrolls the loops over such an array and keeps it in registers, the implementation does not wipe it,
since the address that a wipe takes would keep the array in memory for its whole life and store
every secret value in it. At the other opt-levels, 2 among them, the compiler keeps some of these
arrays in memory, and the implementation wipes them before the function returns, as it does a stack
buffer. A build script reads the opt-level of the profile and of RUSTFLAGS, the last one named
winning; a build in which it reads none wipes, and an opt-level given to the compiler by another
way, such as `cargo rustc --`, is not seen. Secret values are not moved by value: a function that
computes a secret writes it into storage that its owner wipes. An object that the API returns by
value, such as a keyed MAC, is moved once into the caller's storage; that copy, as the caller's own
moves of the object, is a copy that the compiler makes. A function that holds a secret buffer does
not panic: the lengths it depends on are checked before any secret is computed, so the wipe at its
end runs on every path that returns. Rationale: keeping such an array in memory, with or without a
wipe, cost 2 to 7 percent of SHA-3, ML-KEM and SLH-DSA in the measurements for this decision, and
the spill slots remain either way; a wipe per block of the four-state Keccak cost about 3 percent of
SHA3-256, where one wipe per operation cost nothing measurable.

## Decision D-77

`MacAlgorithm` gains `key`, which checks a key as `create` does and returns a `MacKey`, a key
object that holds the keyed state `create` sets up; `MacKey.create` returns a `Mac` in that state
([12.6](12-symmetric-primitives.md#126-mac-algorithms) item 7). For HMAC that state is the two
states after the inner and the outer key block, for KMAC the state after the key, for BLAKE2 the
chaining value and the key block, and for BLAKE3 the key. A `MacKey` is safe for concurrent use
([6.6](06-api.md#66-concurrency) item 1), has no `Clone`, like `Mac`, and wipes its keyed state when
it is destroyed ([6.7](06-api.md#67-lifetime-equality-and-printing) item 1,
[14.5](14-security.md#145-wiping)); `create` copies that state into the new `Mac` in place at
opt-levels 2 and 3; at the others the compiler may stage it on the stack [[D-76](#decision-d-76)].
`Mac` itself is unchanged. Rationale: a protocol that tags many messages under one key, and the
reused-key rows of the rival comparison, paid the key setup for every message: two compressions
for HMAC and a permutation for KMAC (keyed BLAKE2
compresses its key block as the first block of each message, with a key object too). The other
Rust MAC crates key once and reuse the keyed state, and ring and aws-lc-rs do it with a key object,
as WebCrypto does with CryptoKey. A `Mac.reset` that put back a state saved
inside the `Mac` was measured first and rejected: the saved state grew every `Mac` from 336 to 448
bytes on 64-bit targets, and a build of main with only that growth made one-shot BLAKE2 MACs take
2 to 5 percent more time on Haswell, and KMAC up to 1.5 percent. A key object leaves `Mac`, and so
every one-shot MAC, as it was. An API addition is a MINOR version change
([20.1](20-versioning.md#201-versions)).

## Decision D-78

On Intel x86-64 processors of family 6 with Golden Cove or later cores that run without the AVX-512
tier, by a table of models (8Fh, 97h, 9Ah, AAh, ACh, ADh, AEh, B5h, B7h, BAh, BDh, BFh, C5h, C6h,
CCh, CFh, D5h and E5h), BLAKE3's one-shot hash, keyed hash and key derivation, of inputs and
contexts of at most one chunk with at most 64 bytes of output, use the earlier AVX2 row form, which
loads each half step's message words from the block, and the one-shot path that calls it; longer
inputs, contexts and outputs and the incremental hasher keep the row form that holds the message in
registers ([15.3](15-platforms.md#153-cpu-specific-code) item 2). The table reads the CPUID vendor
string and the family and model of leaf 1, with the extended fields, once at detection; which form
runs depends otherwise only on the public lengths, never on the data or the key. The constant-time
and SSE4.1 builds leave the table out, so that their checks run the same kernels on every runner.
Both forms are tested against the reference code on every processor with AVX2. Rationale: with
AVX-512 hidden, as on the client processors of these cores, the earlier form took 1.2 and 2.3
percent less time for 64 bytes on Emerald Rapids and Granite Rapids and 0.6 percent less for 1 KiB
on both, while on Haswell its kernels took 5 percent more for 1 KiB and on AMD Zen 3 1.1 percent
more, so other processors keep the newer form; the models not measured are of the same core line.

## Decision D-79

A mask that the implementation computes from the sign or top bit of a secret value, to select or
to subtract with it, comes from one helper, `ct::sign_mask`: an optimization barrier on the value
([23.2](profiles/rust.md#232-security-mechanics) item 2), the arithmetic shift that spreads the
bit, and a barrier on the mask. The first barrier keeps the compiler, which may know the range of
the value from the code around it, from reading the shift as a comparison; the second keeps it
from knowing that the mask is 0 or all ones. The FrodoKEM noise sign, bit 0 of the sample, is
spread by a negation between two barriers in the same way. Without the barriers, LLVM rewrote the
masked reductions of ML-DSA and ML-KEM, such as `a + (q & (a >> 31))`, as a choice between two
values, which targets without a conditional move compute with a conditional branch on the secret
value ([14.1](14-security.md#141-constant-time) item 1): RISC-V without the Zicond extension, and
s390x at its baseline z10, which has no load-on-condition. The barrier is an empty inline
assembly block that takes the value in a register and returns it, which emits no instruction, on
the targets where Rust has stable inline assembly (RISC-V, LoongArch and s390x), and
`core::hint::black_box` on the others and under Miri. On x86-64 and ARM64 it is the identity: there
the compiler chooses with a conditional move or select instruction, and CI checks these builds
mechanically under valgrind
([14.1](14-security.md#141-constant-time) item 7); ML-DSA Decompose and the byte equality of
SampleInBall keep their `black_box` forms there. The masks covered are those of the ML-DSA and
ML-KEM reductions to [0, q), the ML-DSA reduction to the centered representative, the ML-KEM
subtraction of q (in additions, subtractions, decoding, noise sampling and the compression of the
message), the sign masks of ML-DSA Decompose, the constant-time equality of byte strings (with
the FrodoKEM decapsulation choice), the byte equality of ML-DSA SampleInBall and the FrodoKEM
noise sign. On the targets other than x86-64 and ARM64, SampleInBall runs its passes on the bytes
of 64-bit words, eight lanes an operation, instead of a byte equality for each lane: the mask of a
lane is the top bit of its byte in !(((x & 0x7F..) + 0x7F..) | x | 0x7F..), set only where that
byte of x is zero, spread over the byte by a subtraction that borrows from no other byte. No single
bit of the word decides it, so the compiler sees no choice between two values that it could make a
select or a branch, and the rule does not apply; the secret byte that a step seeks passes the
barrier once, before it is spread over the word. Constant items and the public twiddle factors use
twins of the reductions without the barrier, since inline assembly cannot run in constant
evaluation.

Rationale: on riscv64gc, at opt-levels 1, 2, 3, s and z, ML-DSA signing (MakeHint and the
addition of polynomials), ML-DSA key generation from a seed, the import of expanded ML-DSA keys
and the ML-KEM check of expanded decapsulation keys branched on secret coefficients; on s390x
(z10) the norm checks of ML-DSA signing and the ML-KEM noise sampler branched at opt-levels 1, 2
and 3. rust-v1.0.0 and rust-v1.0.1 have the same flaw. On WebAssembly, Decompose, whose masks
already passed `black_box`, compiled to selects, which a runtime may compile to a branch where
the host has no conditional move. A barrier on the mask alone does not suffice: given the range
of the value, the compiler forms the mask before the barrier as a choice between two constants,
which on s390x and on 32-bit x86 at opt-level s became a branch in the equality of byte strings;
and without the barrier on the mask, it turns the and with the shifted mask in Decompose into a
select. The rule therefore applies to every such mask, whether or not a scan of the current
compiler shows a branch. With the barriers, a scan of the machine code at opt-levels 1, 2, 3, s
and z on riscv64gc, riscv32imac, i686, armv7, wasm32 and s390x (z10) finds no branch or select on
secret data, and the x86-64 and ARM64 objects at opt-levels 3 and z, in the default, portable and
constant-time builds, are equal to those before, function by function. The word passes of
SampleInBall, scanned in the same way, have none either: their branches and selects test step and
loop counters, lengths, tau, the shift amounts of 64-bit words on 32-bit targets, and the
declassified test for another block of the stream; with them ML-DSA signing executes 16 to 30
percent fewer instructions on armv7 and i686 (counted under QEMU) and 33 to 40 percent fewer on
wasm32 (wasmtime fuel). Code size: at opt-level 3
the riscv64gc, s390x and i686 builds have 0.3, 0.9 and 1.2 percent fewer instructions; at
opt-level z riscv64gc and i686 have 0.07 and 0.05 percent more, and s390x 0.03 percent fewer. The
barrier itself emits no instruction except on WebAssembly and under Miri, where `black_box`
stores the value. No timing was taken on these targets.

## Decision D-80

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-81

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-82

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-83

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-84

On x86-64, BLAKE3's `hash_many` and extended output compute two to four inputs or blocks in the row
form, in which each 128-bit lane of a register holds one row of one input's state, and not with one
word of every input in each register. On the processors of the third table of
[D-44](#decision-d-44), three or four take 512-bit registers and two take 256-bit registers, in the
kernels that D-44 describes, while five to eight stay on eight lanes. With AVX2 alone, three or four
take 256-bit registers, two to each set of state registers, `hash_many` in the register plan of the
blake3 crate's assembly for four inputs, except on the cores of another table, which keep four lanes
on 128-bit registers: AMD family 17h below model 30h (Zen 1 and Zen+), where a 256-bit instruction
runs as two operations of 128 bits, Intel's cores of the Atom line alone (family 6, models AFh, B6h,
BEh and DDh), and processors of other vendors. Both tables read the CPUID vendor string and the
family and model of leaf 1 once at detection, and which form runs depends otherwise only on the
public lengths, never on the data or the key. Every instruction of these kernels is on Intel's list
of data-operand-independent timing instructions, or counts as on it by [D-75](#decision-d-75), and
each form is tested against the portable code on the native runners of
[18.2](18-testing.md#182-cpu-tiers).

Rationale: a block in the row form takes the latency of one compression, whose chain of dependent
instructions is as long on any register width, so that four inputs in one 512-bit register take the
time of one input, while the eight-lane form takes its full latency with lanes empty. llvm-mca 19
models 169 cycles a block on Sapphire Rapids and Ice Lake Xeon, on two inputs or on four, against 285
and 283 on eight lanes, and on Zen 4 225 on two and 233 on four against 296. In one process on one
runner, the kernels before this decision took 1.69 (Emerald Rapids), 2.07 (Ice Lake Xeon), 1.12 (Zen
4) and 1.15 (Zen 5) times the time here for 4 KiB, and 1.26, 1.25, 1.06 and 1.43 for 2 KiB. With AVX2
they took 1.31 for 4 KiB on Zen 3, and 1.27 on Zen 4 with AVX-512 hidden. The blake3 crate's register
plan took 1478 ns for 4 KiB on Zen 3 against 1651 for the row form that first replaced the 128-bit
kernel, which reads the message from memory, though llvm-mca 19 models them at 267 and 255 cycles a
block: the measurement decided, and what the model misses was not established. On Zen 1 and Zen+,
where no runner exists, llvm-mca 19 models that plan at 466 cycles a block against 377 for four lanes
on 128-bit registers. The cores of the Atom line were neither modelled nor measured.

## Decision D-85

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-86

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-87

Keccak-256 is a hash function of the crate, `KECCAK_256`, in the `sha3` feature: KECCAK[512](M, 256)
in the terms of FIPS 202 §5.2, with 32 bytes of output, the function that the Keccak submission to
the SHA-3 competition defines at this capacity. It differs from SHA3-256 only in the domain bits that
FIPS 202 §6.1 adds, so its padding starts with the byte `01` where SHA3-256's starts with `06`, and it
runs on the code and the kernels of SHA-3. It has no NIST identifier, so it is refused as a pre-hash,
and no MAC or KDF takes it.

Rationale: FIPS 202 did not take this padding, but Keccak-256 is the hash of Ethereum, for its
addresses, its transactions and its state, so software for that chain needs it, and AWS-LC ships it
as `EVP_keccak256`. Its security rests on the permutation, the rate and the sponge of SHA3-256.

No standard publishes vectors for it. `tools/keccak_vectors.py` derives `derived/keccak256.txt` with
its own Keccak-f[1600], written from FIPS 202 §3, which must agree with hashlib's SHA3-256 under the
padding of SHA-3 and with three published digests under the padding of Keccak. RustCrypto's sha3 0.10.9
and tiny-keccak 2.0.2 give the same values for each of the 284 messages.

## Decision D-88

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-89

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-90

`MacAlgorithm::digest_into` is inlined into its callers, as a hint, and it reaches BLAKE2 and BLAKE3
by calls of their own functions. HMAC and KMAC stay behind one function out of line on x86-64 and
riscv64, and all of the MAC on ARM64: called from code inlined in another crate, the functions of
this crate that they call would be exported, and the other callers in this crate would reach them
through the GOT.

This is a form of the portable code that the target chooses at compile time, not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code). Which path runs depends only on public lengths.
With this crate at opt-level 3 and the application at 1, on x86-64, ARM64 and riscv64, what the
application's crate compiles of this one is drop glue and `Debug`. The forms that this decision gave
WebAssembly are withdrawn by [D-105](#decision-d-105).

Rationale: a test of the kind and of a key of a constant length took 3 to 6 percent of a MAC of a
block. In bench run 42350709458, on x86-64, the time before over the time here for keyed BLAKE3 of at
most a block was 1.03 on Zen 5, 1.02 on Emerald Rapids and Ice Lake, 1.01 on Zen 4 and 1.00 on Zen 3.
The machine code of x86-64, ARM64 and riscv64 differed from that before, function by function, only
in the MAC entries.

## Decision D-91

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-92

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-93

On x86-64 processors of the AVX-512 tier of [15.3](15-platforms.md#153-cpu-specific-code) item 2,
the message schedule of the AVX2 kernel of SHA-512, which SHA-384, SHA-512/224 and SHA-512/256
share, computes each sigma function with the instructions of AVX-512VL on 256-bit registers: two
VPRORQ rotations, a VPSRLQ shift and a VPTERNLOGQ three-input XOR, in place of 7 and 9 instructions
of AVX2. The kernel tests the tier once for each block or pair of blocks. The rounds and the rest of
the schedule are as before, and other processors run the AVX2 form.

The instructions work on registers only, with no branch or memory access that depends on the data,
as in the other AVX-512 kernels of [D-44](#decision-d-44). The build for the constant-time check
under valgrind leaves the tier out, as it does for those kernels.

Rationale: the rotations and logic of the schedule share their ports with the scalar rounds on
Intel's cores. The 8 instructions saved of each step's 22 are 9 percent of the instructions of a
lone block, 2636 against 2903, and 5 percent of a pair's, 4637 against 4904. In bench run
42362652467, in one process where the copies run in turn, the time before over the time here, as a
geometric mean over the 40 rows of SHA-384, SHA-512, HMAC and HKDF, was 1.066 and 1.074 for the two
copies here on Ice Lake, 1.058 on Emerald Rapids, 1.050 on Granite Rapids, 1.037 on Zen 5 and 1.036
on Zen 4. On Zen 3, which has no AVX-512 and runs the AVX2 form, it was 1.005 and 1.006, and a copy
of the code before took 0.972 to 1.021 of the time of the other, by row. SLH-DSA over SHA2 at the
192-bit and 256-bit levels took 0.2 to 2.7 percent less time in the five classes with AVX-512.

Rows that rivals led over those 40 rows in these five classes went from 4 of 200 to 0 in one copy
and 2 in the other. On Ice Lake, SHA-384 and SHA-512 of nothing were at 1.055 and 1.054 against
aws-lc-rs in the first copy and at 0.946 and 0.940 in the second, with the same machine code,
against 0.951 and 0.953 before. The place of the code decides the hashes of nothing. Intel's cores with AVX-512 other than Ice Lake, Emerald Rapids and Granite Rapids
were not measured.

The test of the tier and both forms are in one function out of line, which grows from 415 to 759
lines of assembly. It is the machine code measured, and every other function of x86-64 is the
machine code before. The machine code of ARM64, i686, armv7, riscv64 and WebAssembly is the same as
before, function by function. A test compares the state and the stored schedule of both forms on
random pairs of blocks and on lone blocks, and CI fails unless a runner with AVX-512 ran it.

## Decision D-94

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-95

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-96

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-97

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-98

On x86-64, the one-call digest and MAC of BLAKE2b in the AVX2 and AVX-512VL kernels put the 16
bytes that end a key or a final block, when those are not a whole number of 16-byte pieces, in both
halves of their vector with one instruction in inline assembly, and store the vector with one
32-byte store. The 16 bytes are made in registers from the bytes that end the input, as before.
Before, the vector was the same 16 bytes twice to the compiler, which stored its halves with two
16-byte stores.

This is CPU-specific code under [15.3](15-platforms.md#153-cpu-specific-code), in the kernels of
x86-64. Which path runs depends only on the lengths, which are public.

Rationale: the rounds read each vector of the message with one 32-byte load, and a load of bytes
that two stores wrote cannot take its value from them: it waits until both reach the cache. In a
MAC, the final block is stored after the rounds of the key block, so its stores reach the cache
only after those rounds retire, and the rounds of the final block wait for them. In bench run
42388218855, a BLAKE2b MAC of 63 bytes took 280.6 ns against 270.1 for 64 bytes on Zen 3, where
blake2-rfc took 277.1 and 274.3. Lengths whose pieces are all whole, as 16, 64 and 128 bytes, did
not pay this. Intel's cores run the AVX-512VL kernel, Zen 3 and Zen 4 the AVX2 one, and Zen 5 the
portable code. Under QEMU, the AVX2 kernel runs 1 or 2 instructions fewer for a digest of at most a
block, 1 to 3 more for one of 255 or 256 bytes, 2 to 6 more for a MAC of 1 to 256 bytes and 2 fewer
for a MAC of no data, as the registers that the compiler gives the rest of the function moved.

In bench runs 42428878012 and 42430044275, in one process where the copies run in turn, two copies
of the code here and two of the code before, the time before over the time here, each the geometric
mean of its two copies of the median over the processes, as a geometric mean over the 12 rows of
BLAKE2b and its MAC whose input ends in a partial piece, was 1.057 on Ice Lake, 1.088 on Emerald
Rapids, 1.089 on Granite Rapids, 1.029 on Zen 3, 1.021 on Zen 4 and 1.000 on Zen 5, whose machine
code is the same. Over the other 12 rows of BLAKE2b it was 1.000 to 1.004 in each class, and over
the 55 rows of BLAKE2s and BLAKE3, whose code is the same, 0.996 to 1.000. A digest of 63 bytes now
takes as long as one of 64 on Zen 3, 136.2 ns against 135.8, and 2.4 to 3.7 ns more on Intel's
cores, where it took 13 to 19 ns more. On Zen 4 a MAC of 63 bytes takes as long as one of 64, 225.1
ns against 226.7, but a digest of 63 bytes still takes 19.2 ns more than one of 64, against 23.5
before: a wait that this change does not remove. The BLAKE2b MAC of 63 bytes on Zen 3, which
blake2-rfc led by 1.3 percent, now leads it by 2.4 percent, and rivals lead none of the rows of
BLAKE2b in these six classes.

Against both copies of the code before, beyond the spread of the rows of BLAKE2s and BLAKE3 of the
same class, seven rows take more time here, all in the AVX2 kernel, which has one form for Zen 3
and Zen 4. On Zen 3 a digest of 16 bytes, which runs one instruction fewer than before, with other
registers, takes 1.3 percent more, 136.8 and 136.9 ns against 135.0 and 135.1. On Zen 4 a digest of
1 byte takes 1.3 percent more, 125.0 ns against 123.3 and 123.6, MACs of 64 and 128 bytes 0.8 and
0.9 percent more, and a BLAKE2b-256 digest of 64 bytes and digests of 1 KiB and 16 KiB 0.6 to 0.8
percent more. The rounds of these rows run the instructions before, with other registers and stack
offsets, and on Zen 3 the last five take as long as before, 0.999 to 1.003. On the other rows with
a partial piece, the ratio above is 1.006 to 1.044 on Zen 4 and 1.014 to 1.048 on Zen 3. Rivals
lead none of the seven rows: the rival that leads the others on each still takes 1.6 to 20.7
percent more time than the code here.

The vector holds bytes of the key or the data, and it is cleared with the rest of the message at
the end, as before. The instruction takes registers only and touches no memory, stack or flags; it
is emitted by the macro of the other instructions of the module. The reference answers of BLAKE2
for inputs of 0 to 255 bytes, keyed and unkeyed, and the self-test of RFC 7693 pass on x86-64 under
QEMU with AVX2, and the unit tests compare the one-call digest and MAC with the compression of
padded blocks. In the bench runs, before any timing, the output of every row agrees with those of
the rivals, on Intel's cores through the AVX-512VL kernel. The machine code of ARM64, armv7, i686,
riscv64 and WebAssembly is the same as before, function by function, and on x86-64 only the
one-call digests of BLAKE2b of both kernels change. With this crate at opt-level 3 and the
application at 1, on all six, what the application's crate compiles of this one is drop glue,
`Debug` and, on armv7, `MacAlgorithm::digest_into`, as before.

## Decision D-99

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-100

Withdrawn on 2026-11-14 by [D-105](#decision-d-105): it concerned WebAssembly or 32-bit targets, which
crypto-pq no longer supports.

## Decision D-101

On an ARM64 core with LAZY, Neoverse N2 by the implementer and part numbers of MIDR_EL1, a call of
BLAKE2b that compresses two or more blocks (a MAC's key block, the whole blocks and the final block,
those there are) runs them in one loop of inline assembly, out of line: the sixteen words of the
state in sixteen general registers, words 0 to 8 of the block in nine more, and each of the other
seven words of a round loaded from the block where a G function adds it. The chaining value goes
from one block to the next in the registers of the state, and its copy in memory, stored after each
block, is read back for the next block's final XOR. A call that compresses one block keeps the
compiled rounds, and so do BLAKE2s, other cores and other targets. Which path runs depends only on
the number of blocks, which the lengths give, and the lengths are public.

This is CPU-specific code under [15.3](15-platforms.md#153-cpu-specific-code), and the portable
compression is its twin. The kernel test compares them on random inputs for every form of call, a
key block or none, zero to three whole blocks and a final block or none, in the build of the
constant-time check (`--cfg crypto_pq_ct`), which takes LAZY on every core.

The assembly runs ADD, EOR and ROR, with or without a rotated operand, in the rounds, ADDS and ADC
on the counter, and LDR, LDP, STR and STP at immediate offsets from the addresses it is given. Its
conditional branches, B.NE after SUBS and CBNZ, test the counts of blocks only. The data-processing
instructions are on Arm's data-independent-timing list, and no address depends on the data. Nothing
secret goes to the stack: the words of the blocks and of the state stay in registers, and the
assembly stores only the chaining value, into the caller's h as before, and the counters, counts and
positions of the runs it works through, which are public. Where pointers have 32 bits (the ILP32 ABI
of ARM64), the layout that the assembly reads fails its assertions at compile time; the other
assembly of this module, which takes addresses in 64-bit registers, does not support that ABI
either.

Rationale: compiled from Rust, the rounds of a block keep the sixteen message words beside the
sixteen words of the state, more values than there are registers, and LLVM stores some of them to
the stack and loads them back in every block. Under QEMU, in the build of the constant-time check, a
block takes 1476 instructions here against 1528 before. A digest of 255 bytes runs 3203 against
3253, one of 1 KiB 12015 against 12375 and one of 16 KiB 189135 against 195735, and a MAC of 1, 64
and 127 bytes 3191, 3173 and 3227 against 3239, 3221 and 3275. A digest of one block runs the code
before, and 1 to 3 more instructions in its caller.

In bench run 42556051228, in one process where four copies of crypto-pq run in turn (this code, the
code with every call on the assembly, and two copies of the code before), the time before over the
time here on Neoverse N2, the time before the geometric mean of its two copies and each copy's time
the median over five processes, as a geometric mean over six jobs, was 1.007 for a digest of 255
bytes, 1.026 for 1 KiB, 1.025 for 16 KiB, 1.009 to 1.012 for the MACs of 1 to 128 bytes, 1.028 for a
MAC of 1 KiB and 1.027 for one of 16 KiB, and 1.001 for the MAC of 0 bytes. For the eleven digests
of one block it was 0.997 to 0.999, and 0.996 to 1.000 by job, while the two copies of the code
before, the same machine code at other places, differed by up to 0.5 percent in a job; with every
call on the assembly it was 0.990 to 0.997. BLAKE2s and BLAKE3, whose machine code is unchanged,
gave 0.999 as geometric means over their rows. dryoc, which led the digest of 16 KiB by 1.1 percent,
takes 1.5 percent more time than this code.

In bench run 42553148391, with every call on the assembly and an earlier form of the function that
fills the runs, the time before over the time here on Neoverse N2 was 1.007 for a digest of 255
bytes, 1.026 for 1 KiB and 16 KiB and 1.010 to 1.029 for the MACs of 1 byte to 16 KiB, but 0.988 to
0.997 for the eleven digests of one block, although under QEMU those of 0, 31, 64, 127 and 128 bytes
ran 3 to 5 fewer instructions than before; the MAC of 0 bytes, also one block, took 1.4 percent less
time. A call that compresses one block therefore keeps the compiled rounds.

Given the assembly of one block inside a loop in Rust, LLVM copied it into each path of the loop. A
first form of the loop in assembly, in bench run 42547091038, was called once for each run of
blocks, the key block, the whole blocks and the final block, and loaded every message word from the
block: the digests of 1 KiB and 16 KiB took 3.6 percent less time than before, but one of 255 bytes
2.2 to 2.8 percent more and the MACs of up to 127 bytes 0.6 to 1.5 percent more.

The machine code of 32-bit Arm, x86-64, 32-bit x86, RISC-V and WebAssembly is unchanged, function by
function. On ARM64 the rounds compiled from Rust are unchanged, the three callers that reach them
change, and the assembly is new. In a crate that depends on crypto-pq, built at a lower opt-level,
the functions of crypto-pq that are compiled in the crate are those before.

## Decision D-102

On an ARM64 core with LAZY, a BLAKE3 hash of at most a block with an output of at most 32 bytes, a
hash, a keyed hash or the last compression of `derive_key`, takes the message words from the
caller's slice, and a key given in bytes into the words of the state, and writes the output words
into the caller's output: the scalar kernel keeps no copy of the block, the key or the output in
memory. The words after a message of less than a block are zeros, and the word that takes its last
bytes is built from them; an output of less than 32 bytes takes its
whole words, then the bytes left from the register of the next word. Other cores, longer inputs and
other targets are unchanged.

This is CPU-specific code under [15.3](15-platforms.md#153-cpu-specific-code), and the portable
digest is its twin. The kernel test compares them with random keys, in words and in bytes, random
flags, inputs of 0 to 64 bytes and outputs of 1 to 32 bytes, in the build of the constant-time check
(`--cfg crypto_pq_ct`), which takes LAZY on every core. Which path runs depends only on the lengths
of the input and of the output, which are public. The words of the key, the message and the state
are arrays indexed with constants only, register values under [D-76](#decision-d-76), wiped below
opt-level 3, and the last bytes of a partial output come from a register, not from an array of them.

Rationale: a keyed hash and `derive_key` copied the key's words to the stack, with two stores of 16
bytes, and the rounds loaded them four bytes at a time right after; a message of less than a block
went into a block of zeros on the stack, and the output into a buffer of 32 bytes, both wiped after.
In bench run 42564427681, in one process where four copies of crypto-pq run in turn (this code, the
code with the last bytes of a partial output written through an array, and two copies of the code
before), the time before over the time here on Neoverse N2, the time before the geometric mean of
its two copies and each copy's time the median over five processes, as a geometric mean over six
jobs, was 1.039, 1.089, 1.090, 1.084, 1.040, 1.088 and 1.013 for hashes of 0, 1, 4, 8, 32, 63 and 64
bytes, 1.096, 1.135, 1.135, 1.127, 1.087, 1.143 and 1.065 for keyed hashes of these lengths, and
1.021 for `derive_key` of 32 bytes and 1.016 with two contexts in turn. Inputs of 1 KiB and more and
extended output gave 0.998 to 1.005, with the same machine code. The two copies of the code before
differed by up to 0.34 percent in a job. On the hashes and keyed hashes of at most 64 bytes,
ab-blake3, the nearest rival there, with its hash of one block or of one chunk, took 1.147 to 1.190
times the time here, against 1.016 to 1.148 times the time before. The code with the array took
keyed hashes 0.3 to 1.0 percent more time than here, through the register allocation of the kernel,
and hashes, whose machine code is the same, the same time.

In bench run 42562857052, with the key's words read from its bytes and the code before otherwise,
keyed hashes of at most a block took 3.6 to 4.8 percent less time than before and hashes the same:
the copy of the key, two stores read back at once as eight loads, and its wipe took that time. Under
QEMU, in the build of the constant-time check, a hash of 1 byte runs 1010 instructions here against
1050 before, one of 63 bytes 1055 against 1044, and keyed 1024 against 1073 and 1069 against 1067;
the words of a short message, built in registers, take more instructions than a copy, and less time.

In the same run, BLAKE2 on ARM64 with the whole words of a short last block copied in a function of
their own, out of line, took more time on Neoverse N2: BLAKE2b of 16 and 31 bytes 0.5
and 0.2 percent less, but of 63, 65, 100, 127 and 255 bytes 0.7 to 1.9 percent more, and BLAKE2s and
its MAC of 31 to 127 bytes up to 3.1 percent more. On Apple M3, in one process, BLAKE2s of 16 and 33
bytes took 3.5 and 3.9 percent more. BLAKE2 keeps the loop on ARM64.

The machine code of 32-bit Arm, x86-64, 32-bit x86, RISC-V and WebAssembly is unchanged, function by
function. On ARM64 the scalar digest changes and takes 1189 instructions against 922, the digest of
a key in bytes is new, with its own copy of the rounds (1186 instructions), and the MAC and KDF
dispatchers, which copied the key, change; the keyed MAC now reaches the kernel by a tail call. In a
crate that depends on crypto-pq, built at a lower opt-level, the functions of crypto-pq that are
compiled in the crate are those before.

## Decision D-103

On x86-64 with the SHA extensions, the SHA-224 and SHA-256 engine of `Hasher` and `Mac` keeps its
state, from the first compression of a stream to the digest, in the order of the registers of the
rounds, the words f, e, b, a, h, g, d and c, and the digest kernel stores the digest from that
order. A digest of another size, from a `Mac` truncated or a `Hasher` read into a shorter output,
goes through a copy of the state in the order of the words, out of line, which it wipes. An update
whose bytes leave the block unfilled is buffered in a function with no frame: fewer than 32 bytes in
line, with two moves of the largest of 16, 8, 4 and 2 bytes that fits or one move of a byte, at the
start of the buffer when it is empty; 32 bytes or more through memcpy, as the last call of the
function. The blocks go to the kernel from another function. In a build without AVX, the loop of the
kernel over the blocks is in assembly, from a 64-byte boundary: the instructions of the loop of
`compress256_sha`, the kernel of the other engines, in their order. The one-shot digests, the
SHA-256 of ML-DSA, SLH-DSA, LMS and XMSS, the other engines and the other targets are unchanged.

This is CPU-specific code under [15.3](15-platforms.md#153-cpu-specific-code). The order is a
permutation of the state's words, held in the same array, which the engine's drop wipes as before.
Whether the state is in that order depends only on the CPU's features and on whether a block was
compressed, and the moves of a short update only on its length and on that of the buffer, which are
public. The assembly reads the blocks and the round constants and writes only the registers it
names, with no branch but the loop's, on the number of blocks. The kernel's registers are register
values under [D-76](#decision-d-76), wiped below opt-level 3. The test compares the engine with
`Sha256` on 400 streams of random messages in random pieces, with the initial values of SHA-224 and
SHA-256, copies taken halfway and continued, and digests of 1 to 32 bytes: under qemu-x86_64 with
the SHA extensions, 380 of them go through a kept state at opt-levels 3, 2 and 0, and in a build
with AVX (`-C target-cpu=x86-64-v3`) at 3 and 0, and none on a model without them. CI runs the tests
of that build on its x86-64 runners, which have the SHA extensions.

Rationale: in a stream of updates, each call took the state from the order of the words to the order
of the rounds and back, two shuffles on the path from a block to the next, and the dispatch of the
kernel, a call with its own frame; an update of less than a block called memcpy from a function with
a frame. In bench run 42586796772, in one process where four copies of crypto-pq run in turn (this
code, the code with the loop of the kernel for a kept state 32 bytes past a 64-byte boundary, and
two copies of the code before), the time before over the time here, the time before the geometric
mean of its two copies, each ratio taken within one process and the median over the processes of a
class, on Zen 3, Zen 4, Zen 5, Ice Lake, Emerald Rapids and Granite Rapids (70, 40, 35, 10, 15 and
10 processes), was 1.414, 1.531, 1.121, 1.205, 1.213 and 1.111 for a SHA-256 of 1 KiB in updates of
1 byte; over the six classes, 1.129 to 1.181 in updates of 8 bytes, 1.046 to 1.219 of 16, 1.032 to
1.065 of 32, 1.021 to 1.061 of 64 and 1.022 to 1.065 for 16 KiB in updates of 64 bytes, SHA-224
alike, and 1.017 to 1.038 in updates of 100 bytes; 1.000 to 1.048 for an update of 16 bytes and the
digest, 1.015 to 1.030 of 64, 1.011 to 1.033 of 65 and 1.011 to 1.019 of 129; 1.002 to 1.025 for
HMAC-SHA-256 of 64 bytes under a key set up once, 0.999 to 1.004 of 1 KiB and 1.000 of 16 KiB. The
one-shot digests, with the same machine code, gave 0.996 to 1.018. The two copies of the code before
differed by up to 2.8 percent on a one-shot digest, 1.7 percent on an update of 16 bytes and 0.9
percent on the other rows. RustCrypto's sha2, whose update the caller's crate compiles in line, took
0.652 to 0.996 times the time here on updates of 1 byte and 0.955 on Zen 3 on updates of 8 bytes; on
the other rows, the rival that leads each took more time than this code. In bench run 42572122614,
where every update of less than a block went through memcpy, the SHA-256 of 1 KiB in updates of 1
byte gave 1.141 on Zen 3 and 1.371 on Zen 4.

On Ice Lake, where SHA256MSG1 and SHA256MSG2 are 6 and 12 uops, HMAC-SHA-256 of 16 KiB under a key
set up once took 2.5 percent more time than before with the loop of the kernel in the order LLVM
gave it, the instructions of the loop of `compress256_sha` with each SHA256MSG2 between the two
SHA256RNDS2 of the next quarter (bench run 42572122614), and 2.0 percent more in the order of
`compress256_sha` (bench run 42581716106), both with the loop 16 bytes past a 64-byte boundary,
where the loop of `compress256_sha` is at one in these builds, which align functions to 64 bytes;
from a boundary, the same time. With the loop 32 bytes past a boundary, the SHA-256 of 1 KiB and of
16 KiB in updates of 64 bytes took 0.9 percent more time than from one, 1.2 and 1.3 percent less
than before. The directive that aligns the loop also aligns the function, so the loop is at a
boundary in any build. In builds with AVX, with x86-64-v3 or icelake-server as the target CPU, LLVM
gives the kernel's loop the order of that of `compress256_sha` (128 and 127 instructions), and the
rounds stay in Rust there.

On Zen 3, an update of 16 bytes into an empty buffer, then the digest, took 4.3 percent more time
than before with the bytes moved in line to `bytes[len..]` (bench run 42581716106): the address of
the stores waited on the load of the length, and the loads of the digest on the stores; to the start
of the buffer, 0.8 percent less (bench run 42586796772). An update of 63 bytes moved in line, in
four stores of 16 bytes that leave two of the 16-byte loads of the digest with no store that holds
all their bytes, took 3.0 and 1.9 percent more time on Zen 3 and Zen 4 (bench run 42581716106).
Through memcpy, in two stores of 32 bytes where the CPU has AVX, it takes on Zen 4 the same time,
and on Zen 3, in each process, about the same time or 2 percent more: 2 percent more in 18 of 70
processes, 15 of them in both copies of this code, which points to the placement of the data in the
process, 0.4 percent more as the median and 0.7 percent as the geometric mean of the processes
(bench run 42586796772), against 0.4 percent less as the median of 20 processes in bench run
42572122614, with the same stores in the same order.

The machine code of ARM64, 32-bit Arm, 32-bit x86, RISC-V and WebAssembly is unchanged, function by
function. On x86-64, in the build of the benchmark, the update and the buffering of blocks of the
engine, its kernels for a state in the order of the words and for a kept state, the digest of a kept
state and its copy for a digest of another size are new; the dispatchers of the update and the
digest of a hasher, the creation of a SHA-256 hasher and of a MAC and the copy of an HMAC-SHA-256
state change; the other 218 functions of crypto-pq in that build are the same. Under QEMU, with the
EPYC-Milan model, the SHA-256 of 16 bytes in one update runs 455.8 instructions here against 471.2
before, of 63 bytes 622.6 against 634.4, of 64 bytes 644.0 against 648.6 and of 1 KiB 4209 against
4443; that of 1 KiB in updates of 1 byte 49157 against 75547, of 8 bytes 9353 against 12447 and of
256 bytes 6598 against 8030.

## Decision D-104

The update of `Hasher` and `Mac` for SHA-384, SHA-512, SHA-512/224 and SHA-512/256, and for SHA-224 and SHA-256 where their engine is not that of
[D-103](#decision-d-103), on x86-64 outside SGX and the portable build, is a function of its own,
out of line as that of D-103. An update whose bytes leave the buffer unfilled is buffered there with
no frame: fewer than 32 bytes in line, as in D-103, and 32 bytes or more through memcpy, as the last
call, after the length is set, or on ARM64 in line, in moves of 16 bytes from the start of the bytes
and one move of their last 16. Into an empty buffer, the bytes go to its start and its length is that of the update, so that the stores do not
wait on the load of the length: below 32 bytes, as in D-103, and from 32 for SHA-512 on ARM64. Whole
buffers into an empty one, a block or, for SHA-512 on x86-64, two, go to the kernel as the last
call, on x86-64 through a function of their own. Any other update fills the buffer, compresses it
with the whole buffers after it and keeps the rest, without the tests that the paths before it
decide, in another function, so that the update has no frame on its other paths. The SHA-2 of ML-DSA, SLH-DSA, LMS,
XMSS and HKDF keeps the update it had, in line in it, and the one-shot digests are unchanged.

The paths depend only on the length of the update and on that of the buffer, which are public, and
the bytes move as before into the same buffer, which the engine's drop wipes. The moves on ARM64
write the bytes of the update and no other, each once but for those of the last 16 that the moves of
16 bytes also cover, and a constant assertion bounds the buffers they serve to 128 bytes, so that no
move needs a check of its index. On x86-64, where the buffer of SHA-512 holds two blocks, a buffered
update only raises the length and writes the bytes it then covers, so the second block holds bytes
only while the length reaches into it, as before. The tests compare this update with that of the
engine on 400 streams of SHA-512, SHA-384 and SHA-512/256 messages in random pieces of 1 to 300
bytes, with empty updates between some of them and a copy taken halfway that goes on with its own
bytes, and on messages in pieces of each of 25 sizes from 1 to 512 bytes, around the moves and the
buffers, from an empty buffer and after one byte, for SHA-256 and SHA-512; the test of D-103, on 400
streams of SHA-224 and SHA-256, now runs this update on the other targets, and that of the wipe of
the second block of SHA-512's buffer after each piece runs through both updates. The tests pass
natively on ARM64 at opt-levels 3 and 0 and in the portable build; under qemu-x86_64 with the SHA
extensions at opt-levels 3, 2 and 0, with AVX2 alone and with neither, and in a build for x86-64-v3;
under qemu-i386, qemu-arm and wasmtime; and in CI.

Rationale: before, each update of these engines went through the update of the engine, which has a
frame and calls memcpy for the bytes it buffers, in an update of a few bytes as in one of a block.

On Neoverse N2, in bench run 42620714496, measured as in D-103 (40 processes), this code gave 1.619
for a SHA-256 of 1 KiB in updates of 1 byte, 1.457 of 8 bytes, 1.115 of 16, 1.143 of 32, 1.002 of 64
and 1.004 of 100, 1.000 for 16 KiB in updates of 64 bytes, 0.998 to 1.022 for one update of 16 to
129 bytes and the digest and 1.008 for HMAC-SHA-256 of 64 bytes under a key set up once; 1.442 for a
SHA-512 of 1 KiB in updates of 1 byte, 1.272 of 8 bytes, 1.084 of 16, 1.041 of 32, 1.008 of 64,
SHA-384, SHA-512/224 and SHA-512/256 alike, and 1.008 of 100, 1.007 for 16 KiB in updates of 64
bytes, 0.999 to 1.004 for one update of 16 to 257 bytes and 1.004 for HMAC-SHA-512 of 64 bytes. In
bench run 42623847135, with the same machine code in another of the four copies, the same rows gave
1.610, 1.455, 1.113, 1.143, 1.002, 1.006, 1.000, 0.999 to 1.034 and 1.003, and 1.427, 1.266, 1.082,
1.040, 1.008, 1.011, 1.007, 1.000 to 1.004 and 1.002.

On x86-64, in bench run 42629267787, on Zen 3, Zen 4, Zen 5, Ice Lake and Emerald Rapids (55, 35,
15, 20 and 25 processes), a SHA-512 of 1 KiB in updates of 1 byte gave 1.117 to 1.630 over the five
classes, of 8 bytes 1.055 to 1.203, of 16 bytes 1.071 to 1.100, of 32 bytes 1.009 to 1.034 and of 64
bytes 1.003 to 1.015, SHA-384, SHA-512/224 and SHA-512/256 alike, of 100 bytes 1.002 to 1.008; 16
KiB in updates of 64 bytes gave 1.004 to 1.018, one update of 16 to 257 bytes and the digest 0.997
to 1.008, HMAC-SHA-512 of 64 bytes under a key set up once 1.003 to 1.007, and HMAC-SHA-384 and
HMAC-SHA-512 of 1 KiB and 16 KiB 0.999 to 1.010. The machine code of SHA-224 and SHA-256 there is
the same as before, and their rows gave 0.992 to 1.004. Under i686, on Zen 3, Zen 4, Zen 5 and Ice
Lake, a SHA-256 of 1 KiB in updates of 1 byte gave 1.735 to 3.419, of 8 bytes 1.242 to 1.370 and of
16 bytes 1.100 to 1.211, and a SHA-512 1.530 to 3.082, 1.121 to 1.231 and 1.062 to 1.112. Under
32-bit Arm on Neoverse N2 (20 processes), the same rows gave 1.120, 1.033 and 1.019, and 1.080,
1.015 and 1.012, and no row gave less than 1.000.

On ARM64, `HashAlgorithm::create` builds every kind of hasher in one tail of stores that its arms
share, which writes the length of SHA-512's buffer in four stores, of 1, 1, 4 and 2 bytes, where
another arm keeps a byte of its own, so the first load of the length in an update waits for the four
to be written to the cache. With the bytes of 32 or more into an empty buffer moved to its start and
the length taken from the update, a SHA-512 of 63 bytes in one update and the digest gave 1.002
against 0.992 through `bytes[len..]` (bench run 42606782608) and 1.007 against 0.995 (bench run
42613729950). Built by a function of its own, which stores the length whole, the hasher of SHA-512
gave 1.015 to 1.035 for one update of 16 to 257 bytes in bench run 42620714496, but the path of
SHA-256 through `create` changed, and the rows of SHA-256 gave up to 0.6 percent less than this
code. With the hashers of SHA-256 and SHA-512 each built by a function of its own, bench run
42623847135 gave 1.044 to 1.133 for one update of SHA-256 of 16 to 129 bytes and 1.016 to 1.038 of
SHA-512, but 0.993 and 0.992 for SHA-256 and SHA-224 of 1 KiB in updates of 64 bytes, 0.990 to 0.993
on each of the 8 runners: about 5 ns more per hasher than this code, for 16 updates as for 256, in
fewer instructions. Its cause is not known, and the hashers are built as before.

Through memcpy, a SHA-256 of 1 KiB in updates of 32 bytes took 3.6 percent more time on Neoverse N2
than with the moves in line (bench run 42601946382). On x86-64, a path of its own for 32 bytes or
more into an empty buffer moved the code of the shorter updates, and a SHA-256 of 1 KiB in updates
of 1 byte took 3.3 to 10.6 percent more time than before (bench run 42606782608); for SHA-512 alone,
up to 3.2 percent less time in updates of 1 byte and up to 1.6 percent more in updates of 8 bytes
(bench run 42620714496). On 32-bit targets it kept a register on the stack, an instruction more on
each short update. On 32-bit Arm, the moves in line of fewer than 32 bytes run 1.1 percent more
instructions than memcpy for a SHA-256 of 1 KiB in updates of 1 byte, under QEMU, and with them a
SHA-256 of 1 KiB in updates of 32 and 100 bytes gave 0.998 and 0.999 on Neoverse N2 (bench run
42606782608), against 1.007 and 1.002 through memcpy in the same copy of bench run 42613729950. On
x86-64, the detection of the CPU's features at the first call, in line in the path of whole buffers,
gave the update of SHA-512 a frame on every path; out of line, an update of 16 to 64 bytes runs 6 or
7 fewer instructions. Through the update of the engine, an update that fills the buffer ran 8 to 10
more instructions, on tests that the paths before it decide: on ARM64, a SHA-256 of 1 KiB in updates
of 100 bytes ran 2.2 percent more instructions than before, and gave 0.997 and 0.998 on Neoverse N2
in both copies of bench runs 42606782608 and 42613729950, against 1.004 to 1.006 with this code in
bench runs 42620714496 and 42623847135; on i686, a SHA-256 of 1 KiB in updates of 32 or 100 bytes
ran 0.16 percent more instructions than before, and on 32-bit Arm a SHA-512 of 1 KiB in updates of
64 or 100 bytes 0.04 and 0.06 percent more.

Some rows gave less than 1.000. On Zen 3, a SHA-512 of 16 bytes in one update and the digest gave
0.997, 0.996 to 0.998 on the 11 runners, 0.65 ns more than before, and of 128 bytes 0.998, 0.80 ns
more, where the two copies of the code before differed by 0.1 and 0.4 percent, in both copies of
bench runs 42620714496 and 42629267787, with each form of the update measured, though this code runs
26 fewer instructions for 16 bytes. Its cause is not known. The same path takes 197 ns less for 1
KiB in updates of 16 bytes on Zen 3, the one-shot digest of a message in one piece is unchanged, and
this code stays on Zen 3. On Ice Lake and Emerald Rapids, rows of SHA-224 and SHA-256, whose machine
code is the same as before, gave 0.992 to 0.998, as placement moves them: in the same run, the other
copy, with the same code of SHA-256, gave 0.923 for HMAC-SHA-256 of 64 bytes under a key set up once
on Ice Lake. Under i686 on Zen 5, one update of SHA-256 of 16 to 129 bytes gave 0.957 to 0.974 in
the copy of this code and 0.989 to 1.045 in that of the code without the function for updates that
fill the buffer; in bench run 42613729950, the same machine code in these two copies gave 0.955 to
0.975 and 0.990 to 1.045. Under i686 on Zen 4, with one runner, one update of SHA-256 of 63 to 129
bytes gave 0.989 to 0.995, where this code runs 0.05 to 0.26 percent fewer instructions than before.
Under i686 on Ice Lake, with one runner, where the two copies of the code before differed by up to
7.6 percent, the one-shot digests, whose source is unchanged, gave 0.986 to 0.994, and other rows
0.989 to 0.999.

The machine code of WebAssembly is unchanged, function by function, and that of ARM64 is the code of
bench runs 42620714496 and 42623847135. On x86-64, the update of the SHA-512 engine, out of line
before, gives way to this update, the function for the updates that fill the buffer and the call of
the kernel for whole buffers, and the other functions of crypto-pq in a build of the counts below
are the same. Under QEMU, counting the instructions run in crypto-pq, in memcpy and memset and in
the loop that calls them, with the Neoverse N2 model a SHA-256 of 16 bytes in one update runs 454.5
instructions here against 471.5 before, of 129 bytes 851.5 against 890.5, of 1 KiB in updates of 1
byte 46595 against 67651, of 8 bytes 8739 against 11203 and of 100 bytes 4082 against 4084, and a
SHA-512 of 16 bytes 882.5 against 899.5 and of 1 KiB in updates of 16 bytes 8100 against 9444. With
the EPYC-Milan model, a SHA-512 of 16 bytes runs 3481 against 3507, of 257 bytes 8742 against 8847
and of 1 KiB in updates of 16 bytes 26367 against 28159, and SHA-256 the same as before. On i686, a
SHA-256 of 1 KiB in updates of 1 byte runs 165236 against 189317, of 32 bytes 68341 against 68389
and of 100 bytes 66123 against 66114; on 32-bit Arm 96151 against 109447, 40855 against 41255 and
39673 against 39856.

## Decision D-105

crypto-pq builds for 64-bit targets only. A build for WebAssembly, or for a target whose pointers
are not 64 bits wide, stops with a compile error ([15.2](15-platforms.md#152-supported-platforms)),
and CI builds and tests no such target ([18.3](18-testing.md#183-platforms)). Every other 64-bit
target keeps the portable code, big-endian s390x among them, and the CPU-specific code is that of
x86-64 and ARM64, as before. The forms of the portable code that only the removed targets took are
gone, with the configuration `crypto_pq_pairs` of the build script, and so are the decisions that
chose them: D-80 to D-83, D-85, D-86, D-88, D-89, D-91, D-92, D-94 to D-97, D-99 and D-100 are
withdrawn, and D-79, D-84, D-90, D-102 and D-104 lose their text on those targets. Of D-88, the wipe
of the other targets without stable inline assembly and of Miri stays: each value of four bytes or
more takes a volatile store of its own.

P9 and 15.2 of SPEC 1.0 keep every platform that works working, 32-bit ones included, so the change
cannot come in a 1.x release (Section 20.3 item 1 of SPEC 1.0). The draft begun as SPEC 1.1 is
therefore SPEC 2.0, and the first release that implements it is 2.0.0
([20.1](20-versioning.md#201-versions)); the decisions before this one that name specification 1.1
mean this draft. Every format that 1.0.x writes, 2.0 reads
([20.3](20-versioning.md#203-compatibility-within-2x) item 4). WebAssembly and 32-bit targets stay
on 1.0.x.

Rationale: the work on performance is for x86-64 and ARM64 processors and is judged on them, and
RISC-V runs the portable code, checked for correctness only. A WebAssembly runtime compiles the
module again for the processor that runs it, so a form chosen for WebAssembly is chosen for that
runtime's compiler rather than for a processor, and the 32-bit targets took forms of their own,
since a 64-bit word does not fit one of their registers. Those forms took sixteen decisions and
parts of five more, and the tests of 32-bit Arm under emulation took more than an hour in one CI
job. On the targets that stay, the removed code was compiled only for the removed targets or for
their tests: built with one codegen unit, the library's machine code is the same as before, function
by function, on x86-64 and ARM64 with and without `crypto_pq_portable` and on riscv64. With the
sixteen units of Cargo's default, x86-64 is the same too; on ARM64 and riscv64, rustc puts some
functions in other units, as a change anywhere in the crate can, and LLVM gives about fifty
functions on ARM64 and seven on riscv64 other code.
