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
the targets where Rust has stable inline assembly (32-bit ARM, 32-bit x86, RISC-V, LoongArch and
s390x), and `core::hint::black_box` on the others, WebAssembly among them, and under Miri. On
x86-64 and ARM64 it is the identity: there the compiler chooses with a conditional move or select
instruction, and CI checks these builds mechanically under valgrind
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

On 32-bit x86 with SSE2, Keccak-f[1600] holds the same lane of two states as a pair of 64-bit
words, and `keccak::permute_all` permutes the states of a group two at a time; a state alone runs
beside the zero state, whose permutation is public. Each operation of a round on a pair is the
same operation on both words, which LLVM's SLP vectorizer turns into one SSE2 instruction for
both states. build.rs sets `crypto_pq_pairs` where the target architecture is x86 and the
target features include sse2, as they do on every i686 target; the other 32-bit targets keep the
bit-interleaved lanes, and 64-bit targets and WebAssembly the plain lanes. The pair form is
portable code, Rust without intrinsics or assembly that is correct on any target: the target's
features choose at compile time between two forms of the portable code, as its pointer width
chooses between the plain and the bit-interleaved lanes. It is not CPU-specific code under
[15.3](15-platforms.md#153-cpu-specific-code), needs no run-time detection or twin, and stays in
the builds that force the portable code. Three details of the form keep the vectorizer at work:
the two arrays of pairs stay in memory, behind `core::hint::black_box`, with a compiler fence
before each plane, so that the stores of each plane give the vectorizer its starting points; each
rotation shifts the lane and the lane XOR an opaque zero, since from one value LLVM forms a funnel
shift, which SSE2 lacks, and its cost kept the whole round scalar; and each round computes the
column parities from its input lanes. Every index and shift amount is a constant, so the form has
no branch or memory access that depends on the data, and the arrays of pairs are wiped after the
permutation.

Rationale: on i686, counted under QEMU, a block of SHA3-256 executes 8841 instructions, against
12170 with the bit-interleaved lanes. ML-KEM key generation executes 34 to 39 percent fewer
instructions, encapsulation with a reused key 17 to 20 percent and with an imported key 29 to 40
percent fewer, and decapsulation 13 to 15 percent fewer; ML-DSA key generation executes 42 to 47
percent fewer, verification with a reused key 13 to 17 percent and with an imported key 41 to 46
percent fewer, and signing 16 to 18 percent fewer. Adding each plane of a round to the parities
of the next round as it is written, as the 64-bit form does, took 5 percent more instructions
per block of SHA3-256. A scan of the i686 machine code at opt-levels 1, 2, 3, s and z finds no
branch or select on secret data, and the objects of x86-64, ARM64, armv7 and wasm32 are equal to
those before, function by function. No timing was taken on this target.

## Decision D-81

On 32-bit Arm, Ascon-p[12] holds each 64-bit word of the state bit-interleaved, its even bits in the
low 32-bit half and its odd bits in the high half, so that a rotation of a word is a rotation of
each half, the halves swapped for an odd amount, which Arm takes as the rotated operand of an EOR;
the 64-bit rotation took two shifts and an ORR a half. Each word of input enters the state, and each
word of output leaves it, through a fixed exchange of bit groups, so that the permutation converts
nothing, and the start states are held interleaved at compile time. Other targets hold the words
whole: on 32-bit x86 the interleaved words took more instructions than the whole words, and the
other 32-bit targets, on which they were not counted, keep the form of the 64-bit ones.

The form is portable code, Rust without intrinsics or assembly that is correct on any target, which
the target's architecture chooses at compile time. It is not CPU-specific code under
[15.3](15-platforms.md#153-cpu-specific-code), needs no run-time detection or twin, and stays in the
builds that force the portable code. Every index, shift and rotation amount is a constant, so the
form has no branch or memory access that depends on the data.

Rationale: counted under QEMU, Ascon-Hash256 of 0, 64 and 1024 bytes, Ascon-XOF128 of 0 bytes to 32
and of 64 bytes to 1024, and Ascon-CXOF128 of 0 and 64 bytes to 32 execute 26.5 to 28.5 percent
fewer instructions on armv7; on i686 the interleaved words took 2.5 to 4.3 percent more instructions
than the whole words. In bench run 41403058064, on Neoverse N2 in 32-bit mode, Ascon-Hash256 of 64
bytes and 1 KiB and Ascon-XOF128 and Ascon-CXOF128 of 1 KiB took 0.72 times the time before with a
one-shot digest that also absorbed the blocks a word at a time; the digest here, which keeps its
loop over both kinds of block, executes 0.6 to 2.1 percent more instructions than that one. A scan
of the armv7 machine code at opt-levels 1, 2, 3, s and z finds no new branch, select, table or
division in the Ascon functions, and on x86-64, ARM64, i686 and wasm32 they are equal to those
before, function by function.

## Decision D-82

On 32-bit x86 with SSE2, BLAKE2b holds the words of each row of its state in pairs, those of
columns 0 and 2 and those of columns 1 and 3, so that each operation of the G function on a pair is
the same operation on both words, which LLVM's SLP vectorizer turns into one SSE2 instruction. The
diagonal step takes the same pairs, four of them with their words swapped. build.rs sets
`crypto_pq_pairs`, the configuration of [D-80](#decision-d-80), for both forms; BLAKE2s, whose words
are 32 bits, keeps its form there, as the other targets keep theirs. The details of D-80 keep the
vectorizer at work here too: the pairs stay in memory, behind `core::hint::black_box`, and each
rotation shifts the word and the word XOR an opaque zero. A compiler fence before the columns and
before the diagonals of each round makes each half load and store its own pairs: over a whole round
LLVM kept more values than the eight SSE2 registers hold, and spilled them.

On 32-bit x86, BLAKE3 compresses each block of a chain in a call of its own, in place in the
chaining value. With the rounds inlined into the loop over the blocks, the seven general registers
held little of the state: its words stayed in memory, changed by 60 read-modify-write instructions
per block, each waiting for the store of the one before. Compressed alone, a block has 3 of them.
The whole blocks of an extended output go from the registers of their compression straight into the
output: stored as words and then copied as bytes, they were loaded back with wider loads than their
stores, which a store cannot forward. Other targets keep the form before.

Both forms are portable code, Rust without intrinsics or assembly that is correct on any target,
which the target's architecture and features choose at compile time. They are not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code), need no run-time detection or twin, and stay in
the builds that force the portable code. Every index and shift amount is a constant, so neither form
has a branch or memory access that depends on the data, and the pairs are wiped after each
compression.

Rationale: on i686, counted under QEMU one instruction at a time, BLAKE2b-512 of 0 bytes to 1 KiB
and its MAC of 64 bytes execute 53 to 57 percent fewer instructions. BLAKE3 of 1 KiB executes 1.8
percent more, its extended output of 1 KiB from 64 bytes 1.5 percent fewer, and BLAKE2s, BLAKE3 of 0
and 64 bytes and its MAC of 64 bytes as many as before. In bench run 41610095005, on 13 runners (Zen
3, Zen 4, Zen 5 and Granite Rapids), with every function aligned to 64 bytes and to 128, the time
before over the time here was 1.14 to 2.06 for BLAKE2b and its MAC, 1.05 to 1.31 for BLAKE3 and its
MAC of 1 KiB and 16 KiB, and 1.05 to 1.41 for its extended output of 1 KiB and 16 KiB. BLAKE2s, and
BLAKE3 of up to 64 bytes, were at 0.986 to 1.03. The lowest, on Zen 3, were BLAKE2s-256 of 0 and 64
bytes, whose machine code, the bench harness's included, is the same as before, and BLAKE3 key
derivation of 64 bytes, at 64 bytes of alignment: at 128 it was 1.012. A scan of the i686 machine
code at opt-levels 1, 2, 3, s and z finds no branch, select, table or division on secret data, and
the code of x86-64, ARM64, armv7 and wasm32 is the same as before, function by function.

## Decision D-83

On 32-bit x86 with SSE2, the message schedule of SHA-512, which SHA-384, SHA-512/224 and SHA-512/256
share, computes its words two at a time: words t and t + 1, for t even, from the pairs of words at
t, t + 1, t + 9 and t + 14 (mod 16), so that each operation of a step is the same operation on both
words of a pair, which LLVM's SLP vectorizer turns into one SSE2 instruction. A 64-bit word alone
takes two general registers there, and each of its rotations two double shifts. build.rs sets
`crypto_pq_pairs`, the configuration of [D-80](#decision-d-80), for the form; the rounds keep
theirs, as SHA-256 and the other targets keep their schedules. The details of D-80 keep the
vectorizer at work here too: the sixteen words stay in memory, behind `core::hint::black_box`, and
each rotation shifts the word and the word XOR an opaque zero. The eight steps of a schedule are
written out, so that every index is a constant: as a loop over the steps, the schedule stayed
scalar.

The form is portable code, Rust without intrinsics or assembly that is correct on any target, which
the target's architecture and features choose at compile time. It is not CPU-specific code under
[15.3](15-platforms.md#153-cpu-specific-code), needs no run-time detection or twin, and stays in the
builds that force the portable code. Every index and shift amount is a constant, so the form has no
branch or memory access that depends on the data, and the words are wiped after the last block.

Rationale: on i686, counted under QEMU one instruction at a time, a block of SHA-512 executes 8272
instructions, against 10007 before. SHA-512 of 0 bytes and 1 KiB, HMAC-SHA-512 of 64 bytes and
HKDF-SHA-512 of 32 bytes execute 16.2 to 17.2 percent fewer instructions. A scan of the i686 machine
code at opt-levels 1, 2, 3, s and z finds no branch, select, table or division on secret data, and
the code of x86-64, ARM64, armv7 and wasm32 is the same as before, function by function.
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

On WebAssembly, `hash_many` runs the last two inputs one after the other, not side by side as on the
other targets, and the whole blocks of an extended output go from the registers of their compression
straight into the output, as on 32-bit x86 ([D-82](#decision-d-82)). Both are forms of the portable
code that the target chooses at compile time, not CPU-specific code under
[15.3](15-platforms.md#153-cpu-specific-code), and neither depends on the data.

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

On WebAssembly, in bench run 42094485113, the side-by-side form took 1.29 (Zen 3), 1.33 (Zen 4), 1.10
(Zen 5) and 1.02 (Neoverse N2) times the time here for 2 KiB under wasmtime, and 1.34, 1.02, 1.04 and
1.03 under Node.js; what the runtimes do to it was not established. For 16 KiB of extended output, the
words stored and then copied took 1.06, 1.09, 1.10 and 1.05 times the time here under wasmtime, and
1.08, 1.07, 1.11 and 1.13 under Node.js.

## Decision D-85

On WebAssembly, the compressions of SHA-2 run the rounds of the first group of sixteen ahead of a
loop over the other groups, so that each pass of the loop holds a group's schedule and its rounds in
one block. A hash of a single block runs that form inline, with its words in registers. Any other
padding block, an HMAC key block and the blocks of a one-shot input of under four take one copy of it
out of line, with the block's words in memory, which are wiped after each call at every optimization
level. Longer inputs and streaming updates run it in a loop of their own. Streaming updates copy what
they buffer as loads and stores, with no `memory.copy`, which is a call into the runtime. Other
targets keep the form before.

The form is portable code, Rust without intrinsics or assembly that is correct on any target, which
the target chooses at compile time. It is not CPU-specific code under
[15.3](15-platforms.md#153-cpu-specific-code), needs no run-time detection or twin, and stays in the
builds that force the portable code. Which path runs depends only on public lengths, and every index
and shift amount is a constant, so the form has no branch or memory access that depends on the data.

Rationale: Cranelift, the compiler of wasmtime, places each pure value right before its first use.
Under the `if` of a loop over all four groups, the schedule ran as a block of its own ahead of the
rounds; peeled, each word of the schedule lands next to the round that reads it. In bench run
42113245037, the time before over the time here, as a geometric mean over the 23 rows of SHA-224,
SHA-256, HMAC and HKDF, was 1.06 (Zen 3), 1.07 (Zen 4), 1.11 (Zen 5), 1.14 (Granite Rapids) and 1.12
(Neoverse N2) under wasmtime, and 1.10, 1.16 and 1.04 (Zen 3, Zen 4, Neoverse N2) under Node.js. The
rows that rivals led over those rows and the LMS, HSS, XMSS and XMSS^MT rows over SHA-2 went from 31
to 7 under wasmtime on Granite Rapids, where 7 XMSS-192 rows stay behind RustCrypto, and from 22 to 0
on Zen 5. The lowest rows were the hashes of 0 bytes, at 0.955 under Node.js on Neoverse N2 and 0.972
under wasmtime on Zen 3, which place decides: the same source at another place in the module was at
1.05 and 0.995 there. Out of line, as the other padding blocks, those rows held at 0.95 to 0.96 on
Neoverse N2 at each place measured.

SHA-384 and SHA-512 took the same form in bench run 42308429929. The time before over the time here,
as a geometric mean over the 40 rows of SHA-384, SHA-512, HMAC and HKDF, was 1.13 (Emerald Rapids),
1.12 (Neoverse N2), 1.07 (Zen 4), 1.06 (Zen 5) and 1.01 (Zen 3) under wasmtime, and 1.09, 1.04, 1.05,
1.06, 1.15 and 1.11 (Emerald Rapids, Ice Lake, Neoverse N2, Zen 3, Zen 4, Zen 5) under Node.js. Over
the 22 rows of XMSS and XMSS^MT it was 1.03 to 1.18. The rows that rivals led over all of SHA-2 and its
signatures went from 40 to 6 in the eleven classes measured, where 6 XMSS-192 rows stay behind
RustCrypto under wasmtime on Emerald Rapids. One class loses: under wasmtime on Zen 3, for the hashes
of a single block of SHA-384 and SHA-512, this ratio is 0.92 to 0.93, with each rival there still
behind by 5 percent or more. A WebAssembly module has one form for every CPU, and the ten other
classes gain 3 to 16 percent on these rows.

Outside WebAssembly the code is the same as before, function by function, on x86-64, ARM64, armv7 and
i686. A scan of the wasm32 code at opt-levels 1, 2, 3, s and z finds no select in these functions, and
at opt-level 3 the only branch of the copy out of line is its loop counter.

## Decision D-86

A BLAKE3 hash of at most a block, keyed or not, on WebAssembly and on 32-bit Arm takes the message
words straight from the input into locals and writes the output from locals, with no block in memory
to fill, read and wipe. On both targets the dispatch of a keyed hash is inlined, and the full HMAC of
a truncated output stays out of line, with the frame it needs. On WebAssembly the last compression
of `derive_key` is out of line too.

On 32-bit Arm, a BLAKE2 digest or MAC of at most a block of data runs one function of the same form,
which holds both, with its one copy of the rounds, and the block counter of BLAKE2s's whole blocks
takes 64 bits, its full range. On WebAssembly, BLAKE2 kept its form before, until
[D-89](#decision-d-89).

These are forms of the portable code that the target chooses at compile time, not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code). Which path runs depends only on public lengths.
The words are arrays indexed by constants only, so [D-76](#decision-d-76) treats them as register
values at opt-level 3, whose spills are copies that the compiler makes, and they are wiped at other
levels; a partial output word, in a buffer with a run-time length, is wiped on every path.

Rationale: the buffers took more than their stores, since each read of a word came right after its
store. In bench run 42297409561, the time before over the time here for BLAKE3, as a median over the
13 classes of CPU and runtime under wasmtime and Node.js, was 1.058 for an empty message, 1.040 for
64 bytes, 1.081 and 1.046 keyed, 1.104 for `derive_key` and 1.112 with two contexts in turn. In bench
run 42302165419, on armv7 on Neoverse N2, it was 1.170 and 1.162 for BLAKE3, 1.175 and 1.160 keyed,
1.039 to 1.093 for BLAKE2 digests of one block and 1.043 to 1.161 for its MACs, and 0.994 to 1.012
for the rows of many blocks.

BLAKE2 stayed out of WebAssembly here because of one compiler. Its 16 words of state, 16 of message and 8
of chaining value in locals took Cranelift 166 stack slots against 37 for BLAKE2b, most of them for
one store and one reload. In that run, for BLAKE2b of one block, the time before over the time here
was 1.01 to 1.24 under Node.js and 1.05 to 1.12 under wasmtime on Ice Lake, Emerald Rapids and
Neoverse N2, but 0.70 to 0.86 under wasmtime on Zen 3, Zen 4 and Zen 5. Why those cores take these
slots so badly was not established. The state in memory and a block out of line each left 142 to 163
slots, so no form was found then that holds for both runtimes; [D-89](#decision-d-89) has one.

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

On WebAssembly, a digest of Keccak of at least a block in one call copies what follows the whole blocks
into a block in memory, pads it there, and absorbs it in the loop over the whole blocks, so that one
copy of the rounds runs every block of the call. That block is a stack buffer, wiped before the
function returns, as the state is. A digest of less than a block keeps the form that takes its lanes as
arguments, and streaming updates keep the loop over the blocks. On the same target the zero state, the
zero block and the wipes of values of four bytes and more are stores of a word each, with no
`memory.fill`, which is a call into the runtime. A tail of under 128 bytes goes into the block with no
`memory.copy`. On the other targets without stable inline assembly, and under Miri, `wipe` takes the
same stores; these targets are not measured, and CI runs this path on them.

The form is portable code that the target chooses at compile time, not CPU-specific code under
[15.3](15-platforms.md#153-cpu-specific-code). Which path runs, and how many bytes each copy takes,
depend only on public lengths.

Rationale: with a copy of the rounds of its own for the last block, a digest of a block or two took
more time than the instructions it runs. In bench run 42329884751, the time before over the time
here for Keccak-256 of 136 bytes was 1.24 (Ice Lake), 1.13 (Zen 3), 1.07 (Emerald Rapids), 1.07 (Zen
4), 1.05 (Neoverse N2) and 1.00 (Zen 5) under wasmtime, and 1.01 to 1.04 under Node.js on Emerald
Rapids, Neoverse N2, Zen 3 and Zen 5. At 1 KiB, as a median over the rows of SHA-3, SHAKE, cSHAKE,
KMAC and Keccak-256, it was 1.07, 1.03, 1.07, 1.03, 1.01 and 1.01 under wasmtime in that order.
Hashes of less than a block take the same code as before. At 16 KiB no class loses more than 2
percent, except under Node.js on Zen 4, where the one job there measured long rows at 0.96; the loop
of V8 has 621 instructions on ARM64 here and 655 before, so the bench of the release has to confirm
that class on more jobs. Over the 33 rows of the sponge in eleven classes, rows that rivals led went
from 7 to 3, and rows ahead by 3 percent or more from 315 to 319.

## Decision D-89

On WebAssembly, each block of a BLAKE2 digest or MAC of more than a block takes a call of one
function, with the chaining value in memory and the message words read from the input ahead of the
state. A key block and the tail of a message, padded in a block in memory that is wiped before the
function returns, take the same function. A digest or MAC of at most a block, with an output of 4 or
8 words, takes the message straight from its slice into the rounds: a whole block, half a block or
nothing with the zero words folded away, and any other length through words in memory, which are
wiped. The zero block, the zero words of BLAKE2b and the wipes of its state are stores, with no
`memory.fill`, and the tail goes into its block with no `memory.copy`. Streaming updates call the
compression for each block, with the words in memory, which are wiped. `HashAlgorithm::digest_into`
and `digest_unchecked` are inlined into their callers on WebAssembly, and what they call for BLAKE2 is
not generic: a generic function would be compiled in the crate of the caller, at the opt-level of
that crate, while the wipes of [D-76](#decision-d-76) follow the opt-level of this one.

On WebAssembly and 32-bit Arm, the compression copies the message words into locals ahead of the
state. On 32-bit Arm, the chains of BLAKE3 run one at a time, and the whole blocks of an extended
output go straight into the output, as on 32-bit x86 and WebAssembly.

These are forms of the portable code that the target chooses at compile time, not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code). Which path runs depends only on public lengths.
The words and the state of the rounds are arrays indexed by constants only, so
[D-76](#decision-d-76) treats them as register values at opt-level 3, and they are wiped at other
levels; what a call takes the address of is wiped on every path.

Rationale: under Cranelift, the compiler of wasmtime, a value live through the rounds holds a spill
slot that the values of the rounds cannot share, and regalloc2 looks at only ten slots before it
opens a new one. In a loop with the chaining value in locals, each spill took a slot of its own: 157
for BLAKE2b against 37 in this form. A loop with the chaining value in memory took as few slots, but
the values of the loop took the slots that a byte of displacement reaches, with 8047 bytes of code
for BLAKE2s against 7588 here and 7562 in p3-blake2s, and in bench run 42333112013 it took 3 percent
more time than here on Ice Lake. That core decodes 16 bytes a cycle outside its cache of
micro-operations, which fits the difference; the cause was not measured directly.

In bench run 42337573871, the time before over the time here, as a median over the rows of 1 KiB and
16 KiB and over the rows of at most a block, was 1.47 and 1.20 (Zen 3), 1.51 and 1.12 (Zen 4), 1.14
and 1.18 (Zen 5), 1.06 and 1.20 (Ice Lake), 1.03 and 1.14 (Granite Rapids) and 1.00 and 1.16
(Neoverse N2) under wasmtime, and 1.00 and 1.23 (Neoverse N2), 0.97 and 1.21 (Zen 3), 0.97 and 1.27
(Zen 5) and 1.02 and 1.15 (Emerald Rapids) under Node.js. The rows that rivals led went from 141 to
26 of 170 in those ten classes.

Under wasmtime on Zen cores, one process can take 1.5 to 2.5 times the time of another on the same
code with the same input, on all the rows of one function; the cause was not measured. In that run
this took long rows before this change, of BLAKE2s in 6 of 10 processes on Zen 3 and 2 of 4 on Zen 4
and of BLAKE2b in 2 of 4 on Zen 5, and here BLAKE2b in 1 of 4 on Zen 5 and no other row. The median
of 1.14 holds that process: the same form without the change of `digest_into` below had none, and a
median of 1.33.

Out of line, `HashAlgorithm::digest_into` was one more call, with its frame, on every digest of a
caller's buffer. With the arms of BLAKE2 in `digest_unchecked`, LLVM stopped inlining it, as
`#[inline]` is a hint. In that run this took `blake3/0` and `blake3/64` 3 to 10 percent more time
under wasmtime and 1 to 5 percent more under Node.js. With the attribute on WebAssembly they take at
most 1.1 percent more than before the arms of BLAKE2. After that run the digests of at most a block
were made not generic, which is 14 more instructions on ARM64 for BLAKE2s, of 1152 for an empty
message, and 5 fewer for BLAKE2b. With this crate at opt-level 3 and the application at 1, on x86-64,
ARM64, i686, armv7, riscv64 and WebAssembly, what the application's crate compiles of this one is drop
glue and `Debug`.

A module has one form for every CPU, and this one has costs. Long rows under Node.js take 3 percent
more on Zen 3, Zen 4 and Zen 5, where the median of the leading rival over this code goes from 1.02
to 1.04 down to about 1.00, while rows of at most a block there take 17 to 22 percent less. On
Neoverse N2 under wasmtime a block takes 2 percent more than in the loop with the chaining value in
memory. With the chaining value in locals, in bench run 42329048951, long rows took 24 to 56 percent
more than that loop under wasmtime on Zen cores, and under Node.js 2 percent less on Neoverse N2,
Zen 4 and Zen 5 and 3 percent more on Zen 3, so that form does not hold for both runtimes.

LLVM's Reassociate adds the values of an expression by rank, and a load ranks by its place in the
block. A word read in the rounds had the higher rank through the first rounds, and went into `a + b
+ x` after `b`, one more step on the longest chain of dependencies, in 32 of the 160 sums of BLAKE2s.
Read ahead of the state, it goes in first. In bench run 42329048951 that took 1 percent less time on
armv7 on Neoverse N2. On i686 it gave nothing on long rows and took up to 1 percent more on short
ones, and an A/B on one ARM64 core gave no gain, so these targets, x86-64 and riscv64 keep the form
before.

On armv7, BLAKE3 executes fewer instructions with its chains one at a time: 2341 against 2589 for an
extended output of 128 bytes from 64, 16019 against 17219 for 1024 bytes, 31398 against 32117 for a
hash of 2 KiB and 63681 against 63804 for 4 KiB. In bench run 42329048951, on armv7 on Neoverse N2,
the median of the time before over the time here was 1.00 over the rows of 1 KiB and 16 KiB and 1.03
over the others, and the rows that rivals led went from 12 to 1 of 36. That row is `derive_key`
against rscrypto, which keeps the last context's key in a `thread_local`.

The machine code of x86-64, ARM64, i686 and riscv64 is the same as before, function by function.

## Decision D-90

On WebAssembly, the public entries of digests, extended outputs, MACs and key derivation are inlined
into their callers, where a constant algorithm leaves one arm. What is inlined checks lengths and
routes, and each arm is a call of a function that is neither generic nor inlined: the code that holds
a message, a key or a state stays compiled in this crate, at its opt-level, which the wipes of
[D-76](#decision-d-76) follow. A message of Keccak shorter than a block from the zero state takes one
function for each rate, with one call of the rounds for each number of whole lanes, so that no lane
is tested at run time. cSHAKE and KMAC, which start from a state of their own, keep the tests.

On the other targets `MacAlgorithm::digest_into` is inlined too, as a hint, and it reaches BLAKE2 and
BLAKE3 by calls of their own functions. HMAC and KMAC stay behind one function out of line on x86 and
riscv64, and all of the MAC on ARM64: called from code inlined in another crate, the functions of this
crate that they call would be exported, and the other callers in this crate would reach them through
the GOT, on 32-bit x86 with their arguments on the stack.

These are forms of the portable code that the target chooses at compile time, not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code). Which path runs depends only on public lengths.
With this crate at opt-level 3 and the application at 1, on x86-64, ARM64, i686, armv7, riscv64 and
WebAssembly, what the application's crate compiles of this one is drop glue, `Debug` and, on armv7,
`MacAlgorithm::digest_into`, which checks lengths and routes.

Rationale: a dispatcher out of line took about 50 instructions of each call on WebAssembly, a test
of the kind and of a key of a constant length 3 to 6 percent of a MAC of a block, and the tests of
the lanes 2 percent of a digest of SHA-3. Instructions on ARM64 under wasmtime, before and here:
SHA3-256 of 64 bytes 5354 and 5145 (libcrux 5164), keyed BLAKE3 of nothing 1116 and 1046 and of 64
bytes 1124 and 1057 (ab-blake3 1118 and 1147), `derive_key` of 32 bytes 2228 and 2157 (ab-blake3
2228), the BLAKE2s MAC of 64 bytes 2788 and 2736 (rscrypto 3182).

In bench run 42350709458, the time before over the time here, as a median per class:

- SHA-3 and SHAKE of 64 bytes: 1.06 (Zen 5), 1.06 (Zen 4), 1.05 (Zen 3), 1.04 (Neoverse N2) and 1.04
  (Granite Rapids) under wasmtime, and 1.05 (Granite Rapids, Ice Lake, Neoverse N2, Zen 3), 1.04 (Zen
  4) and 1.03 (Zen 5) under Node.js.
- BLAKE3 of at most a block, keyed or not, and `derive_key`: 1.06 (Zen 4, Neoverse N2, Zen 3), 1.04
  (Zen 5, Granite Rapids) under wasmtime, and 1.03 (Neoverse N2), 1.02 (Granite Rapids, Zen 3, Zen 5),
  1.01 (Zen 4) and 1.00 (Ice Lake) under Node.js. Rows of these that rivals led went from 12 to 5 of
  55, and rows ahead by 3 percent or more from 23 to 36.
- On x86-64, keyed BLAKE3 of at most a block: 1.03 on Zen 5, 1.02 on Emerald Rapids and Ice Lake, 1.01
  on Zen 4 and 1.00 on Zen 3; on i686, 1.01 to 1.07 by row.

Over all rows of BLAKE2 and BLAKE3 in those eleven classes, rows that rivals led went from 44 to 33 of
330, and of Keccak from 4 to 3 of 275.

In one process, where the copies run in turn, no row of BLAKE2 and BLAKE3 took more than 2 percent
more, except BLAKE2b of nothing under Node.js on Ice Lake, at 0.97, with crypto-pq ahead of the rivals
by 19 percent. Rows measured in separate processes, as SHA-2, HMAC and HKDF are here, moved by up to 11
percent on code that did not change: SHA-224 in updates of 64 bytes under wasmtime on Zen 3 took 0.89
to 0.91.

A module holds what it calls. In test modules with one family and its rivals, the size went from
318157 to 141131 bytes for BLAKE3 and from 325329 to 199380 for BLAKE2. Each rate of Keccak in use
adds about 3.5 KB of functions for its first block: from 310969 to 317376 bytes with two rates.

The machine code of x86-64, ARM64, i686, armv7 and riscv64 differs, function by function, only in the
MAC entries.

## Decision D-91

On 32-bit Arm, the loops over the whole blocks of BLAKE2 read the message words of each block after
the state, where [D-89](#decision-d-89) reads them ahead of it. They take every block of an
incremental hash or MAC but the last, and every block of a digest or MAC of more than a block in one
call but, for BLAKE2s, its key block and last block. Those blocks, and digests and MACs of at most a
block, keep the order of D-89.

This is a form of the portable code that the target chooses at compile time, not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code). Which path runs depends only on public lengths.
The words and the state are arrays indexed by constants only, so [D-76](#decision-d-76) treats them
as register values at opt-level 3, and they are wiped at other levels.

Rationale: in bench run 42357880614, on armv7 on Neoverse N2, the time with the words after the
state on every path over the time in the order of D-89, as a median over 20 processes, was 0.993 and
0.992 for BLAKE2s of 1 KiB and 16 KiB, 0.993 and 0.982 for its MAC, and 0.999 for BLAKE2b of both
lengths, keyed or not. In that order, rows of at most a block took 1.010 to 1.020 for BLAKE2s and
0.995 to 0.998 for BLAKE2b; the rounds of a lone block are not changed here. The cause was not
measured. In bench run 42362652467, over 20 processes, this form took 0.994 and 0.992 for BLAKE2s,
0.993 and 0.992 for its MAC, 0.999 for BLAKE2b and 1.000 to 1.002 for rows of at most a block,
while a copy of the code before took 0.999 to 1.000 of the time of the other. The time of the
leading rival over the time here was 0.991 for BLAKE2s of 1 KiB, against 0.984 before, 0.996 for
16 KiB, against 0.988, and 0.992 for its MAC of 16 KiB, against 0.984.

The two loops, `whole_blocks` of BLAKE2s and `all_blocks` of BLAKE2b, are the machine code measured
in the first run, and every other function of armv7 is the machine code before. The machine code of
x86-64, ARM64, i686, riscv64 and WebAssembly is the same as before, function by function.

## Decision D-92

On 32-bit Arm and WebAssembly, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 of data given in one
call take the padded last block through a permutation of its own after the loop over the whole
blocks, where before it was the last step of that loop. The output words, and the wipe of the state
at the end at every opt-level, are as before. ARM64, where the same form took more time, riscv64 and
x86-64 without AVX2, where it was not measured, and 32-bit x86, which has a digest of its own, keep
the code before.

This is a form of the portable code that the target chooses at compile time, not CPU-specific code
under [15.3](15-platforms.md#153-cpu-specific-code). Which path runs depends only on public lengths.

Rationale: in bench run 42362652467, in one process where the copies run in turn, the time here over
the time before, as a median over the processes, for Ascon-Hash256 of 1 KiB, was 0.984 on armv7 on
Neoverse N2; 0.963 (Ice Lake), 0.974 (Neoverse N2), 0.988 (Zen 3), 0.991 (Zen 5), 0.997 (Granite
Rapids) and 1.012 (Zen 4) under wasmtime; and 0.980 (Zen 3), 0.989 (Zen 5), 0.993 (Ice Lake, Zen 4)
and 0.998 (Emerald Rapids, Neoverse N2) under Node.js. Over the 15 rows of Ascon in these 13
classes, rows that rivals led went from 2 to 1 of 195, and rows ahead by 3 percent or more from 90
to 122. The two rows led before, Ascon-Hash256 and Ascon-CXOF128 of nothing under wasmtime on
Neoverse N2, where the time of the leading rival over the time before was 0.985 and 0.989, are at
1.006 and 0.998.

Under Node.js on Zen 3, outputs of 1 KiB and 16 KiB took 1.004 to 1.007, and Ascon-XOF128 of 64
bytes to 16 KiB, where the time of the leading rival over the time before was 0.993, is at 0.986,
the one row led here. Under wasmtime on Zen 4, inputs of 1 KiB and 16 KiB took 1.011 to 1.013, and
under Node.js on Zen 5, Ascon-CXOF128 of 64 bytes to 32 took 1.036, with crypto-pq still ahead of
the rivals there by 8.6 percent. A WebAssembly module has one form for every CPU
([D-85](#decision-d-85)). In the same processes, a copy of the code before took 0.990 to 1.004 of
the time of the other, by row, the widest on inputs of nothing. On ARM64 on Neoverse N2, the same
form took 0.995 to 1.014 of the time, by row. The cause was not measured.

The function grows from 2372 to 3419 lines of assembly on armv7 and from 2444 to 3461 on
WebAssembly. It is the machine code measured, and every other function of these targets is the
machine code before. The machine code of x86-64, ARM64, i686 and riscv64 is the same as before,
function by function.

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
against 0.951 and 0.953 before. As in [D-85](#decision-d-85), the place of the code decides the
hashes of nothing. Intel's cores with AVX-512 other than Ice Lake, Emerald Rapids and Granite Rapids
were not measured.

The test of the tier and both forms are in one function out of line, which grows from 415 to 759
lines of assembly. It is the machine code measured, and every other function of x86-64 is the
machine code before. The machine code of ARM64, i686, armv7, riscv64 and WebAssembly is the same as
before, function by function. A test compares the state and the stored schedule of both forms on
random pairs of blocks and on lone blocks, and CI fails unless a runner with AVX-512 ran it.
