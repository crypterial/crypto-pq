# Security policy

Report vulnerabilities privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue for a security bug.

Include the crate version and a minimal reproduction. We will acknowledge the report, work with
you on a fix, and credit you in the advisory unless you ask otherwise.

## Supported versions

The Rust crate `crypto-pq` is released from a signed tag `rust-vX.Y.Z`. Its MAJOR.MINOR is the
version of the crypto-pq specification it implements, so every 1.0.x release implements
specification 1.0; PATCH counts the releases of the crate.

Security fixes are released as a new PATCH version of the latest MAJOR.MINOR, and only the latest
release is supported. Upgrading to it never removes or changes a specified behaviour within 1.x
(specification Section 20.3). A release candidate (`1.0.0-rc.N`) is supported until the release it
precedes.

## Scope

The Rust crate `crypto-pq` published from this repository, and the specification and test vectors
it is built and checked against. The withdrawn 0.1.x prototype on crates.io is not supported.
Nothing here has had a third-party audit yet.
