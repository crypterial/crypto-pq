# 13. The hazmat namespace

1. The `hazmat` namespace exposes operations that take caller-supplied randomness. They exist for
   known-answer tests and interoperability tests only. Reusing a seed or randomness with a different
   key, message or ciphertext breaks the security of the scheme; the public documentation MUST say so.
2. Operations:

   | operation | inputs | sizes |
   |---|---|---|
   | `hazmat.generateKemKeyPair(algorithm, seed)` | KEM value, seed | ML-KEM 64 (d \|\| z); FrodoKEM 88, 112; eFrodoKEM 64, 80 ([8.2.2](08-key-encapsulation.md#822-randomness)) |
   | `hazmat.encapsulate(publicKey, randomness)` | | ML-KEM 32 (m); FrodoKEM 72, 96; eFrodoKEM 24, 32 |
   | `hazmat.generateSignatureKeyPair(algorithm, seed)` | | ML-DSA 32 (ξ); SLH-DSA and HashSLH-DSA 3n (SK.seed \|\| SK.prf \|\| PK.seed) |
   | `hazmat.sign(privateKey, message, randomness, {context, preHash})` | | ML-DSA 32 (rnd); SLH-DSA n (opt_rand) |
   | `hazmat.verify(publicKey, signature, message, {context, preHash})` | | |
   | `hazmat.signInternal(privateKey, messageRepresentative, randomness)` | `ML_DSA_*` or `SLH_DSA_*` key; M′ of FIPS 204 Algorithm 7 or FIPS 205 Algorithm 19 | randomness as for `hazmat.sign` |
   | `hazmat.verifyInternal(publicKey, signature, messageRepresentative)` | as above; FIPS 204 Algorithm 8 or FIPS 205 Algorithm 20 | |
   | `hazmat.generateStatefulKeyPair(algorithm, seed, index, …)` | the remaining arguments are those of `generateKeyPair` in the language | [11.14](11-stateful-signatures.md#1114-deterministic-mode-hazmat) |
   | `hazmat.configureCshake(algorithm, functionName, customization)` | `CSHAKE128` or `CSHAKE256` | any lengths |

3. A seed or randomness of the wrong length fails with INVALID_LENGTH. `hazmat.sign` and
   `hazmat.verify` apply [9.1.3](09-signatures.md#913-pre-hash-hashml-dsa-and-hashslh-dsa) items 2 and 4 but not the strength rule (item 3). With a
   `HASH_SLH_DSA_*` value they also apply [9.4](09-signatures.md#94-hashslh-dsa-algorithm-values) item 2: a `preHash` other than absent or the fixed
   function fails `hazmat.sign` with INVALID_OPTION and makes `hazmat.verify` return `false`. `hazmat.sign` has no
   `deterministic` option; the randomness argument decides. `configureCshake` with any other
   algorithm fails with INVALID_OPTION. `hazmat.signInternal` and `hazmat.verifyInternal` accept only
   `ML_DSA_*` and `SLH_DSA_*` keys: with a `HASH_SLH_DSA_*` key `signInternal` fails with INVALID_OPTION
   and `verifyInternal` returns `false`, because a pre-hash key is never used through the pure
   internal interface [[D-65](decisions.md#decision-d-65)].
4. Hazmat key generation runs no pairwise self-test, because its purpose is to reproduce vectors
   exactly [[D-37](decisions.md#decision-d-37)]. It MUST still validate its inputs.
5. Hazmat operations follow every constant-time, DIT and wiping rule of Section [14](14-security.md).
6. The positional order of `generateStatefulKeyPair` is algorithm, seed, index, then the arguments of
   the language's `generateKeyPair` [[D-25](decisions.md#decision-d-25)]. Python takes `index` as a keyword-only argument with
   default 0.
