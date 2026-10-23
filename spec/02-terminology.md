# 2. Conventions and terminology

## 2.1 Requirement keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

## 2.2 Terms

| term | meaning |
|---|---|
| implementation | A crypto-pq library package built to this specification. Part II profiles the Rust implementation, the crate `crypto-pq`. |
| algorithm value | A public constant that names one algorithm or parameter set, for example `ML_KEM_768`. |
| category | One of: hash, XOF, MAC, KDF, KEM, signature, stateful signature. |
| key object | A public-key or private-key value created by key generation or import. |
| caller input | Every argument and option that the caller passes, including byte strings, lengths, option values, stored state and tree caches. |
| secret | Any value from which a private key, a shared secret, a MAC key, a KDF input key or output, or an internal value derived from them can be learned. |
| public | Any value that is not secret, including public keys, ciphertexts, signatures, messages, lengths and algorithm identifiers. |
| declassify | To state, in code and in the constant-time checker, that a value derived from secrets is allowed to become public (for example the result of a validity check that fails the call). |
| state record | The byte string that a stateful private key writes to its state store (Section [11.7](11-stateful-signatures.md#117-state-record-version-2)). |
| state store | The caller's object that persists the state record (Section [11.6](11-stateful-signatures.md#116-state-store-contract)). |
| tree cache | The byte string of public Merkle tree nodes exported by a stateful private key (Section [11.10](11-stateful-signatures.md#1110-tree-cache)). |
| hazmat | The namespace of deterministic, caller-randomness operations intended for test vectors only (Section [13](13-hazmat.md)). |
| entropy source | The operating-system or runtime source of random bytes ([14.3](14-security.md#143-entropy)). |
| DIT | Data-independent timing: the PSTATE.DIT bit of ARM64 processors with FEAT_DIT ([14.2](14-security.md#142-data-independent-timing-dit)). |
| capacity | The number N of signatures that a stateful key can produce ([11.3](11-stateful-signatures.md#113-levels-indices-and-trees) item 2). |
| maintainers | The people responsible for crypto-pq and for this document. |
| runner | A test program that runs the records of the compliance suite against an implementation ([19.3](19-conformance.md#193-cross-check-files)). |
| kernel | Code written for a specific CPU feature set, selected at run time ([15.3](15-platforms.md#153-cpu-specific-code)). |
| portable code | Code that uses no CPU-specific instructions. The portable twin of a kernel is the portable code that computes the same result. |
| build mode | A configuration in which the implementation is compiled and tested, for example with CPU-specific code or forced-portable; the profile lists them. |
| conforming | Passing every requirement of Part I, the applicable Part II profile, and the compliance suite of Section [19](19-conformance.md). |

## 2.3 Notation

- Byte strings are written in hexadecimal. `a || b` is concatenation. `x[i..j]` is the bytes of `x`
  from offset `i` (inclusive) to `j` (exclusive). `len(x)` is the length in bytes.
- `u8(v)`, `u16(v)`, `u32(v)` and `u64(v)` are the unsigned integer `v` encoded in 1, 2, 4 and 8 bytes,
  big-endian. Every multi-byte integer in a format defined by this document is big-endian.
- Sizes are in bytes unless stated as bits. Ranges `a..b` are inclusive.
- "Fails with E" means that the operation returns or raises the error with code `E` (Section [7](07-errors.md)) and
  produces no other result.
- Section numbers of cited standards are written as, for example, FIPS 203 §7.2.

## 2.4 Normative and informative text

Sections [1](01-introduction.md) to [23](profiles/rust.md) are normative except Sections [1.5](01-introduction.md#15-how-to-read-this-document) and [14.8](14-security.md#148-security-considerations) and text marked "Note", "Rationale"
or "Example", which are informative. Appendices A and B are informative.
