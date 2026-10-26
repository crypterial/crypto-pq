# 18. Testing and continuous integration

## 18.1 Checks

The CI MUST run:

1. the language's standard formatter in check mode;
2. the compiler, linter or static type checker with warnings treated as errors, for every build
   configuration and cross target;
3. a check that every generated file (assembly, generated source) equals the output of its generator;
4. the tests, on the minimum supported and the current toolchain or runtime, and in every build mode
   that the profile names;
5. the tests with CPU-specific code disabled, through the switch that the profile names ([15.3](15-platforms.md#153-cpu-specific-code) item 6);
6. the constant-time check of [14.1](14-security.md#141-constant-time) item 7.

## 18.2 CPU tiers

CI MUST run the tests on processor models, emulated where necessary, that together select every
CPU-specific tier of [15.3](15-platforms.md#153-cpu-specific-code) and the portable code, and on native x86-64 and ARM64 hardware. A test
counts the kernels each model selects and fails if the count differs from the expected one. The
AVX-512 tier, which the emulators do not execute, runs on native runners: CI runs the tests on
several x86-64 runners, each records which of the tier's kernels it selected, and the run fails
unless one selected the four-state kernel and one the one-state kernels. CI also checks that the
library, built for the baseline target at each optimization level, contains no instruction on a
512-bit register [[D-44](decisions.md#decision-d-44)].

## 18.3 Platforms

CI MUST build and test: Linux x86-64 and ARM64, macOS ARM64, Windows x86-64 and ARM64; 32-bit x86;
RISC-V 64 and big-endian s390x under emulation; Linux musl; the minimum and the current toolchain of
[15.2](15-platforms.md#152-supported-platforms).

## 18.4 Vectors and robustness

1. The compliance suite ([19.2](19-conformance.md#192-compliance-suite)) runs on every push in every build mode, and its files MUST be
   unmodified, as checked against `SHA256SUMS`.
2. The cross-check files ([19.3](19-conformance.md#193-cross-check-files)) change only through their generator, which is part of the test
   suite of the Rust implementation. CI MUST run the generator in check mode: it rebuilds every
   record that it generates and fails on any difference from the committed files. The records that it
   does not generate are frozen and fixed by `SHA256SUMS`.
3. Long robustness runs with random inputs to every parser and every public operation run weekly.
4. Large-data tests (inputs of 1 to 8 GiB for SHA-2, SHA-3 and SHAKE; BLAKE2 above 4 GiB) run weekly.

## 18.5 Supply chain

1. Every CI dependency (actions, container images, test tools) is pinned by commit hash, digest or
   version.
2. CI runs only the CI platform's own actions; toolchains are installed from their official
   distributions (P1).
3. Builds of the package are reproducible: two builds on different host architectures produce
   identical bytes.
