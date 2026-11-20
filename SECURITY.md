# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/crypterial/crypto-pq/security/advisories/new)
("Report a vulnerability" on the Security tab). Do not open a public issue for a security bug.

Include the crate version, the target and the features you build with, and a minimal reproduction.
We will acknowledge the report, work with you on a fix, and credit you in the advisory unless you ask
otherwise.

## Supported versions

Security fixes are released as a new PATCH version of the latest MAJOR.MINOR, and only the latest
release is supported. Within 2.x, an upgrade never removes or changes a specified behaviour
([specification Section 20.3](spec/20-versioning.md)).

The crate's MAJOR.MINOR is the version of the crypto-pq specification that it implements: every
2.0.x release implements specification 2.0. Releases are published from signed tags `rust-vX.Y.Z`.

The 1.0.x releases receive no patch. Values that they leave on the stack after operations on
secret values, which 2.0.0 fixes, are listed in
[security/audit-2026-11.md](security/audit-2026-11.md#released-versions). Version 2.0 removes the
WebAssembly and 32-bit targets, so their users stay on 1.0.x, which keeps these residues.

## Scope

The Rust crate `crypto-pq` published from this repository, and the specification and test vectors it
is built and checked against.
