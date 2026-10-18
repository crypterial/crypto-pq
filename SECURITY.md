# Security policy

Report vulnerabilities privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue for a security bug.

Include the language, the package version and a minimal reproduction. You will get an
acknowledgement, a fix, and credit in the advisory unless you ask otherwise.

## Supported versions

Each language package is released on its own, from a signed tag `<language>-vX.Y.Z` (for
example `rust-v1.0.0`; the Go mirror also carries `vX.Y.Z`, as Go modules require). Its
MAJOR.MINOR is the version of the crypto-pq specification it implements, so every 1.0.x package
implements specification 1.0; PATCH counts the releases of that package alone.

Security fixes are released as a new PATCH version of the latest MAJOR.MINOR of each package.
Only that latest release is supported; an earlier release is fixed only by upgrading within its
MAJOR.MINOR, which never removes or changes a specified behaviour. A release candidate
(`1.0.0-rc.N`) is supported until the release it precedes. A package that has no 1.0 release yet
is not supported.

## Scope

Everything in this repository and every package published from it. The withdrawn 0.1.x
prototype on crates.io is not supported. Nothing here has had a third-party audit yet.
