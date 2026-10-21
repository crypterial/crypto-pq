# crypto-pq Specification

| field | value |
|---|---|
| Document | crypto-pq Specification |
| Version | 1.0 |
| Applies to | crypto-pq 1.0.x packages in Rust, Go, Zig, TypeScript and Python ([20.1](20-versioning.md#201-versions)) |
| Status | Release candidate |
| Date | 2026-10-21 |
| Editor | Crypterial Labs |
| License | This document is licensed under the Apache License, Version 2.0, or the MIT license, at your option (`LICENSE-APACHE`, `LICENSE-MIT`). |

## Abstract

crypto-pq is a post-quantum cryptography library implemented independently in five programming
languages (Rust, Go, Zig, TypeScript and Python) with one shared vocabulary. This document is the
contract that every implementation conforms to and is verified against. Part I specifies the
algorithms, the application programming interface (API) model, the byte formats, the error model,
the security requirements, the conformance test suite and the release rules that are common to every
language. Part II adds one profile per language that tightens Part I for that language and never
contradicts it. The appendices are informative: a decision log and a review of the document against the
project principles.

## Contents

Part I. Common specification (normative)

1. [Introduction](01-introduction.md)
2. [Conventions and terminology](02-terminology.md)
3. [Principles](03-principles.md)
4. [Scope](04-scope.md)
5. [Algorithm catalogue](05-algorithms.md)
6. [Common API model](06-api.md)
7. [Errors](07-errors.md)
8. [Key encapsulation](08-key-encapsulation.md)
9. [Signatures](09-signatures.md)
10. [Key formats](10-key-formats.md)
11. [Stateful hash-based signatures](11-stateful-signatures.md)
12. [Symmetric primitives](12-symmetric-primitives.md)
13. [The hazmat namespace](13-hazmat.md)
14. [Security requirements](14-security.md)
15. [Platform, runtime and performance requirements](15-platforms.md)
16. [Naming and vocabulary](16-naming.md)
17. [Implementation conventions](17-implementation-conventions.md)
18. [Testing and continuous integration](18-testing.md)
19. [Conformance](19-conformance.md)
20. [Versioning, compatibility and release](20-versioning.md)
21. [References](21-references.md)

Part II. Language profiles (normative)

22. [Profile rules](22-profile-rules.md)
23. [Rust profile](profiles/rust.md)
24. Go profile
25. Zig profile (including the C ABI core)
26. TypeScript profile (WebAssembly and pure JavaScript)
27. Python profile (native and pure)

The Rust profile is part of this repository; profiles for other languages are maintained with their implementations.

Appendices (informative)

- A. [Decision log](decisions.md)
- B. [Principle conformance review](principles-review.md)

Quick reference

| table | section |
|---|---|
| algorithm values, names and sizes | [5.1](05-algorithms.md#51-key-encapsulation) to [5.7](05-algorithms.md#57-key-derivation-functions) |
| stateful type codes and parameter-set OIDs | [5.3](05-algorithms.md#53-stateful-hash-based-signatures) |
| error codes | [7.1](07-errors.md#71-error-codes); language forms [16.4.5](16-naming.md#1645-error-codes) |
| pre-hash functions and their OIDs | [9.1.3](09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa) |
| key formats per algorithm | [10.1](10-key-formats.md#101-formats) |
| key object identifiers | [10.5](10-key-formats.md#105-object-identifiers); HashSLH-DSA [9.4](09-signatures.md#94-hashslh-dsa-algorithm-values) |
| state record format | [11.7](11-stateful-signatures.md#117-state-record-version-2) |
| tree cache format | [11.10](11-stateful-signatures.md#1110-tree-cache) |
| limits | [12.8](12-symmetric-primitives.md#128-limits) |
| name map per language | [16.4](16-naming.md#164-name-map) |
| compliance-file keys and operations | [19.3](19-conformance.md#193-cross-language-files) item 4 |
| C ABI identifiers and status codes | 25.5 (Zig profile) |
