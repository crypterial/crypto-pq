# 3. Principles

## 3.1 Design principles

The following design principles are binding on every part of crypto-pq. Every later section applies
them; [Appendix B](principles-review.md) checks the document against each one.

| id | principle |
|---|---|
| P1 | **Zero third-party code.** Nothing third-party is shipped or runs at run time; all of the code is the project's own. The language and its standard library are used only for operating-system and runtime access (entropy, foreign-function interface, memory), never for any cryptographic algorithm, including hash functions and constant-time comparison; standard-library cryptography is excluded. Official toolchains build and publish; GitHub's own actions run CI. Test-only tools that never ship (test frameworks, fuzzers, sanitizers, constant-time checkers) and official test vectors are allowed. |
| P2 | **Standardized or proven only.** Only algorithms that are standardized, or used in production by major vendors and proven there, are implemented. No drafts. |
| P3 | **Options, not fixed choices.** Where a standard offers alternatives, they are exposed as options with a safe default. Behaviour is fixed only where it is critical or mandatory for security (for example the reuse rules of stateful signatures). |
| P4 | **Same keywords everywhere.** Every public item has one keyword, used alike in this specification, the API, the documentation and the compliance suite, and adapted only to the casing and idiom of the implementation language. One product name, "crypto-pq". |
| P5 | **Language-neutral specification.** Part I specifies the behaviour without reference to a programming language, and the compliance suite tests it. Rust is the implementation: a complete implementation written from scratch, with its profile in Part II. |
| P6 | **Thoroughness.** Everything related to a change is considered, to avoid side effects. |
| P7 | **Never asynchronous.** No asynchronous API, no asynchronous or lazy initialization, no run-time download, no waiting at use. CPU detection runs once and synchronously. |
| P8 | **No heap bloat.** Prefer caller buffers and the stack; no large caches; memory is measured when a change adds buffers. |
| P9 | **Universal.** Every platform and runtime that works MUST keep working. CPU-specific code exists only for x86-64, ARM64 and RISC-V, always with run-time detection and a portable twin; every other architecture runs the portable code, which MUST stay correct, including 32-bit and big-endian. Trade-offs are judged per CPU class, not on one machine. |
| P10 | **Data-independent timing.** On ARM64, DIT is always set around asymmetric secret operations. MAC and KDF operations run without DIT unless the process calls the one-way, process-wide switch `enable_data_independent_timing()`, which returns true only where DIT is active. |
| P11 | **Security first, then standards, then speed.** A check is never weakened to gain speed. |
| P12 | **Post-quantum only.** Every asymmetric algorithm is post-quantum. No hybrid with a classical algorithm and no classical asymmetric algorithm, so X-Wing and X25519 are not part of the library. Symmetric primitives stay, at quantum-resistant sizes. |
| P13 | **Production first.** The first release requires exact conformance to the standards, a final algorithm set and the security requirements of Section [14](14-security.md); performance work that they do not need follows the release. |
| P14 | **Wording.** Text published by the project uses precise, professional terms. It may describe crypto-pq as secure and optimized; it never uses informal or promotional words such as "fast", or superlatives such as "fastest" or "most secure". |

Related design decisions that this document applies:

- Hand-written per-ISA acceleration is permitted (CPU instructions are not libraries) and is limited to
  x86-64, ARM64 and RISC-V, with run-time detection and a portable fallback.
- Key objects MAY cache the expanded public matrix and expanded secrets.
- Multi-threading is an additive, opt-in option for later releases; the default is single-threaded and
  outputs never depend on the thread count.

## 3.2 Priority

When two requirements conflict, the order is: security (P11), then conformance to the cited standards,
then simplicity, then performance. A conflict that this document resolves is recorded in [Appendix A](decisions.md); a
remaining tension is listed in [Appendix B](principles-review.md).
