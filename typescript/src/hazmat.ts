// Deterministic operations for test vectors. Production code must not call them: reusing a seed
// or randomness value with a different key, message or ciphertext breaks the scheme, and these
// functions skip the pre-hash strength policy of the public API.
import {
  type Encapsulation,
  KemAlgorithm,
  type KemKeyPair,
  KemPublicKey,
  encapsulateDeterministic,
  keyPairFromSeed as kemKeyPairFromSeed,
} from "./kem.ts";
import {
  type SignOptions,
  SignatureAlgorithm,
  type SignatureKeyPair,
  SignaturePrivateKey,
  SignaturePublicKey,
  type VerifyOptions,
  keyPairFromSeed as signatureKeyPairFromSeed,
  signDeterministic,
  verifyUnchecked,
} from "./signature.ts";
import {
  type HazmatStatefulOptions,
  StatefulSignatureAlgorithm,
  type StatefulKeyPair,
  keyPairFromSeed as statefulKeyPairFromSeed,
} from "./stateful.ts";

export type { HazmatStatefulOptions };

export function generateKeyPair(algorithm: KemAlgorithm, seed: Uint8Array): KemKeyPair;

export function generateKeyPair(algorithm: SignatureAlgorithm, seed: Uint8Array): SignatureKeyPair;

export function generateKeyPair(
  algorithm: KemAlgorithm | SignatureAlgorithm,
  seed: Uint8Array,
): KemKeyPair | SignatureKeyPair {
  if (algorithm instanceof KemAlgorithm) {
    return kemKeyPairFromSeed(algorithm, seed);
  }

  if (algorithm instanceof SignatureAlgorithm) {
    return signatureKeyPairFromSeed(algorithm, seed);
  }

  throw new TypeError("algorithm must be a KemAlgorithm or a SignatureAlgorithm");
}

export function generateStatefulKeyPair(
  algorithm: StatefulSignatureAlgorithm,
  seed: Uint8Array,
  options: HazmatStatefulOptions,
): StatefulKeyPair {
  if (!(algorithm instanceof StatefulSignatureAlgorithm)) {
    throw new TypeError("algorithm must be a StatefulSignatureAlgorithm");
  }

  return statefulKeyPairFromSeed(algorithm, seed, options);
}

export function encapsulate(publicKey: KemPublicKey, randomness: Uint8Array): Encapsulation {
  if (!(publicKey instanceof KemPublicKey)) {
    throw new TypeError("publicKey must be a KemPublicKey");
  }

  return encapsulateDeterministic(publicKey, randomness);
}

// options.deterministic is ignored: the randomness is always the one given.
export function sign(
  privateKey: SignaturePrivateKey,
  message: Uint8Array,
  randomness: Uint8Array,
  options?: SignOptions,
): Uint8Array {
  if (!(privateKey instanceof SignaturePrivateKey)) {
    throw new TypeError("privateKey must be a SignaturePrivateKey");
  }

  return signDeterministic(privateKey, message, randomness, options);
}

export function verify(
  publicKey: SignaturePublicKey,
  signature: Uint8Array,
  message: Uint8Array,
  options?: VerifyOptions,
): boolean {
  if (!(publicKey instanceof SignaturePublicKey)) {
    throw new TypeError("publicKey must be a SignaturePublicKey");
  }

  return verifyUnchecked(publicKey, signature, message, options);
}
