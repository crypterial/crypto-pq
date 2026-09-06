# Test vector sources

All files are unmodified copies, pinned by upstream commit and sha256 (see SHA256SUMS).

## acvp/

NIST ACVP-Server, commit 975de31eb83d87039ec88934fdc47d8c312b892d,
`gen-val/json-files/ML-KEM-keyGen-FIPS203/` and `ML-KEM-encapDecap-FIPS203/`.
These target the final FIPS 203 (August 2024) and are the authority for correctness.

## cctv/

C2SP/CCTV, commit 4448f2097b2daa812c91a26141f9f36c2096b9ca, `ML-KEM/` (CC0 1.0).
Only the files that do not depend on key generation are kept:

- `modulus-*.txt.gz`: encapsulation keys with one out-of-range coefficient each, all of
  which must be rejected by the modulus check.
- `strcmp-*.txt`: decapsulation inputs whose implicit-rejection comparison would break
  under a `strcmp`-style early exit.

The collection's `intermediate/`, `unluckysample/` and accumulated vectors were generated
in December 2023 against FIPS 203 ipd (with the A-hat index fix) and do not include the
domain separator byte that the final standard added to K-PKE.KeyGen (`G(d || k)`). They
cannot match a final-standard implementation. This was confirmed on 2026-09-05: with the
byte removed in a throwaway copy of the crate, all 15 CCTV tests passed, including the
10 000 accumulated vectors for every parameter set, while the ACVP key-generation tests
failed; with the byte present the reverse holds.

## Accumulated randomized test

`tests/accumulated.rs` follows `TestAccumulated` from Go's `crypto/mlkem`
(src/crypto/mlkem/mlkem_test.go), an independent implementation of the final standard,
and uses its published hashes for ML-KEM-768 after 100 and 10 000 iterations. No
independent final-standard hashes are published for ML-KEM-512 and ML-KEM-1024.
