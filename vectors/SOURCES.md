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
cannot match a final-standard implementation. This was confirmed on 2026-09-05 with an
implementation of the final standard: with the byte removed, all 15 CCTV tests passed,
including the 10 000 accumulated vectors for every parameter set, while the ACVP
key-generation tests failed; with the byte present the reverse holds.

## Accumulated randomized test

Go's `crypto/mlkem`, an independent implementation of the final standard, publishes
accumulated hashes for ML-KEM-768 (`TestAccumulated` in src/crypto/mlkem/mlkem_test.go).
Every implementation here runs the same procedure and must reproduce them:

- A SHAKE-128 stream with empty input supplies, per iteration, the 64-byte key seed
  (`d || z`), a 32-byte encapsulation seed and a ciphertext-sized random string.
- The encapsulation key, the ciphertext, the shared secret, and the implicit-rejection secret
  of the random ciphertext are absorbed, in that order, into a second SHAKE-128.
- The first 32 bytes of that second SHAKE-128's output, read from a copy so the absorbing
  continues, must equal:
  - after 100 iterations: `1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415`
  - after 10 000 iterations: `8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc`

No independent final-standard hashes are published for ML-KEM-512 and ML-KEM-1024.
