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

crypto-pq 1.0 contains no AVX-512 code ([15.3](15-platforms.md#153-cpu-specific-code)). Rationale: P13;
the AVX2 kernels run on AVX-512 processors, and the AVX-512 work is not yet verified for release.

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

The AES-128 core used by FrodoKEM is constant time although its
FrodoKEM inputs are public ([8.2.3](08-key-encapsulation.md#823-constant-time-and-memory)). Rationale: one AES core serves later AEAD use with secret keys; no
variable-time AES core exists in the code base.

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

SampleInBall (FIPS 204 Algorithm 29) runs in constant time in every
attempt of ML-DSA signing: neither the positions nor the signs of the challenge decide a branch, a
memory address or the number of steps ([14.1](14-security.md#141-constant-time) item 5). The only
value derived from the challenge stream that is declassified is whether fewer than τ of the 128
candidate bytes of the first SHAKE256 block fit, so that a further block is read; for a uniform stream
its probability is 2^−87.7 for τ = 60, 2^−140.3 for τ = 49 and 2^−202.9 for τ = 39. Verification
runs the same code. Rationale: the challenge c̃ of a rejected attempt is never output, so it is a
secret, and only the decision to reject is public. Side channels on the challenges of rejected
attempts are a demonstrated threat: [KARABULUT21] recovers their signs, and [ZHOU25] recovers the
private key from rejected challenges together with the rejected responses. The declassified bit is
expected fewer than 2^−23 times in 2^64 attempts, and no fixed amount of stream avoids it entirely.

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
