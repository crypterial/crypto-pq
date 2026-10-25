# Contributing to crypto-pq

crypto-pq is built to a [specification](spec/00-contents.md): it states what the crate does, and
[`spec/decisions.md`](spec/decisions.md) records why. Contributions follow it.

## Security issues

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes, never in a public
issue. Never paste private keys, state records, seeds or other secrets into an issue.

## Issues

Issues are welcome for bugs, departures from the specification or from a standard, missing test
vectors, performance regressions and documentation errors. A bug report names the crate version,
the target, the enabled features and a minimal reproduction.

An algorithm is in scope only if it is standardized, or used in production by major vendors and
proven there, and only if it is post-quantum when it is asymmetric (principles P2 and P12 of
[Section 3](spec/03-principles.md)). [Section 4.2](spec/04-scope.md#42-excluded) lists what is
excluded and why.

## Pull requests

- A change of behaviour, API or format starts in `spec/`, with its reason in
  `spec/decisions.md`. A correction to a published specification is listed in
  [`spec/VERSIONS.md`](spec/VERSIONS.md).
- The crate has no dependencies and ships no third-party code (principle P1).
- Code that handles secret data has no branch or memory access that depends on a secret, and the
  valgrind constant-time check covers it ([14.1](spec/14-security.md#141-constant-time)).
- A CPU-specific kernel is selected at run time, keeps its portable twin, and has a test that
  compares the two on random inputs ([15.3](spec/15-platforms.md#153-cpu-specific-code)).
- A performance change states its numbers before and after, measured on the same machine.
- Every pull request passes CI: formatting, clippy with warnings denied, the test suites, the
  constant-time check and the specification check (`python3 tools/spec_check.py`).
- A change that users can observe gets a line in [CHANGELOG.md](CHANGELOG.md).

A pull request makes one change and describes what it changes, why, and how it was tested.

## License

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
crypto-pq by you, as defined in the Apache-2.0 license, shall be dual licensed as in
[README.md](README.md#license), without any additional terms or conditions.
