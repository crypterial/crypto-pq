# crypto-pq

Post-quantum cryptography by [Crypterial Labs](https://crypterial.com), written from scratch in
five languages against one specification. **In development: nothing here is usable yet.**

| Language | Package | Status |
|---|---|---|
| Rust | [`crypto-pq`](https://crates.io/crates/crypto-pq) on crates.io | Not started. 0.1.x was a prototype and is withdrawn. |
| Python | [`crypto-pq`](https://pypi.org/project/crypto-pq/) on PyPI | Not started. 0.0.x only holds the name. |
| TypeScript | `crypto-pq` on npm | Not started. |
| Go | `github.com/crypterial/crypto-pq-go` | Not started. |
| Zig | `github.com/crypterial/crypto-pq-zig` | Not started. |

## Rules

- **No external dependencies.** Every implementation is the lab's own code, including SHA-3,
  SHA-2 and every helper. A language's standard library is used only to reach the operating
  system (randomness, memory), never for cryptography.
- **Only standardized algorithms, or constructions proven in production by major vendors:**
  ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS/HSS and XMSS (SP 800-208), and
  X-Wing as an option.
- **One specification, one set of test vectors**, and the same names for the same things in
  every language.
- **Options, not fixed choices:** safe defaults, with behaviour fixed only where safety requires
  it.

## Layout

```text
docs/      architecture and the decision log
vectors/   official test vectors (NIST ACVP, C2SP CCTV), pinned by upstream commit and SHA-256
```

The specification and the five implementations get their own directories as the work lands.

## License

Apache-2.0 OR MIT, at your option.
