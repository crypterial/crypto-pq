import { bytes, equal, wipe } from "./bytes.ts";
import { type KeyFormat, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import {
  type KeyGenOptions,
  decodeSeedChoice,
  encodeSeedChoice,
  exportPrivate,
  exportPublic,
  importPrivate,
  importPublic,
  mismatch,
  requireKeyLength,
  requireLength,
  selfTest,
} from "./keys.ts";
import * as mlkem from "./mlkem.ts";
import { randomBytes } from "./rng.ts";
import * as xwing from "./xwing.ts";

// The private half of a key as a backend produced it: the expanded encoding when the algorithm
// has one, and the decapsulation bound to the key material, which also reads the cache of its
// public key.
interface Secret {
  readonly expanded: Uint8Array | null;

  decapsulate(ciphertext: Uint8Array, cache: mlkem.PublicCache): Uint8Array;
}

// A new key as a backend makes it: the public key, the secret and what the public key's cache can
// start with. For X-Wing the cache is that of the ML-KEM part.
type NewKey = [Uint8Array, Secret, mlkem.PublicCache];

interface ExpandedForm {
  readonly size: number;

  load(key: Uint8Array): NewKey;
}

export interface KemBackend {
  readonly oid: Uint8Array | null;

  readonly seedSize: number;

  readonly randomnessSize: number;

  readonly publicKeySize: number;

  readonly ciphertextSize: number;

  readonly expanded: ExpandedForm | null;

  fromSeed(seed: Uint8Array): NewKey;

  checkPublicKey(key: Uint8Array): boolean;

  encapsulate(key: Uint8Array, cache: mlkem.PublicCache, randomness: Uint8Array): [Uint8Array, Uint8Array];
}

export interface KemKeyPair {
  readonly publicKey: KemPublicKey;

  readonly privateKey: KemPrivateKey;
}

export interface Encapsulation {
  readonly sharedSecret: Uint8Array;

  readonly ciphertext: Uint8Array;
}

function mlKemSecret(dk: Uint8Array, params: mlkem.Parameters): Secret {
  const secret: mlkem.SecretCache = { s: null };

  return {
    expanded: dk,
    decapsulate: (ciphertext, cache) => mlkem.decapsInternal(dk, secret, cache, ciphertext, params),
  };
}

function mlKem(params: mlkem.Parameters, arc: number): KemBackend {
  return {
    oid: objectIdentifier(`2.16.840.1.101.3.4.4.${arc}`),
    seedSize: 64,
    randomnessSize: 32,
    publicKeySize: params.encapsulationKeySize,
    ciphertextSize: params.ciphertextSize,
    expanded: {
      size: params.decapsulationKeySize,
      load(dk) {
        if (!mlkem.checkDecapsulationKey(dk, params)) {
          throw mismatch("the decapsulation key fails the FIPS 203 checks");
        }

        return [mlkem.publicKeyOf(dk, params), mlKemSecret(dk, params), mlkem.publicCache(mlkem.digestOf(dk, params))];
      },
    },
    fromSeed(seed) {
      const [ek, dk] = mlkem.keygenInternal(seed.subarray(0, 32), seed.subarray(32), params);

      return [ek, mlKemSecret(dk, params), mlkem.publicCache(mlkem.digestOf(dk, params))];
    },
    checkPublicKey: (key) => mlkem.checkEncapsulationKey(key, params),
    encapsulate: (key, cache, randomness) => mlkem.encapsInternal(key, cache, randomness, params),
  };
}

const X_WING_BACKEND: KemBackend = {
  oid: null,
  seedSize: xwing.SEED_SIZE,
  randomnessSize: 64,
  publicKeySize: xwing.PUBLIC_KEY_SIZE,
  ciphertextSize: xwing.CIPHERTEXT_SIZE,
  expanded: null,
  fromSeed(seed) {
    const [pk, key, cache] = xwing.expand(seed);

    return [
      pk,
      { expanded: null, decapsulate: (ciphertext, mlkemCache) => xwing.decapsulate(key, mlkemCache, ciphertext) },
      cache,
    ];
  },
  checkPublicKey: xwing.checkPublicKey,
  encapsulate: xwing.encapsulate,
};

let backendOf: (algorithm: KemAlgorithm) => KemBackend;

let fromSeed: (algorithm: KemAlgorithm, seed: Uint8Array) => KemPrivateKey;

let encapsulateWith: (publicKey: KemPublicKey, randomness: Uint8Array) => Encapsulation;

let cacheOf: (publicKey: KemPublicKey) => mlkem.PublicCache;

let useCache: (publicKey: KemPublicKey, cache: mlkem.PublicCache) => KemPublicKey;

export class KemPublicKey {
  readonly algorithm: KemAlgorithm;

  readonly #key: Uint8Array;

  // What encapsulation derives from the key, filled on first use unless the key's creator supplies
  // part of it.
  #cache = mlkem.publicCache();

  constructor(algorithm: KemAlgorithm, key: Uint8Array) {
    this.algorithm = algorithm;

    this.#key = key;

    Object.freeze(this);
  }

  encapsulate(): Encapsulation {
    return this.#encapsulate(randomBytes(backendOf(this.algorithm).randomnessSize));
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  exportKey(format: KeyFormat): Uint8Array | string {
    return exportPublic(format, backendOf(this.algorithm).oid, this.#key);
  }

  equals(other: KemPublicKey): boolean {
    return (
      typeof other === "object" &&
      other !== null &&
      #key in other &&
      other.algorithm === this.algorithm &&
      equal(other.#key, this.#key)
    );
  }

  #encapsulate(randomness: Uint8Array): Encapsulation {
    const [sharedSecret, ciphertext] = backendOf(this.algorithm).encapsulate(this.#key, this.#cache, randomness);

    randomness.fill(0);

    return Object.freeze({ sharedSecret, ciphertext });
  }

  static {
    encapsulateWith = (publicKey, randomness) => publicKey.#encapsulate(randomness);

    cacheOf = (publicKey) => publicKey.#cache;

    useCache = (publicKey, cache) => {
      publicKey.#cache = cache;

      return publicKey;
    };
  }
}

export class KemPrivateKey {
  readonly algorithm: KemAlgorithm;

  readonly publicKey: KemPublicKey;

  readonly #seed: Uint8Array | null;

  readonly #secret: Secret;

  constructor(algorithm: KemAlgorithm, seed: Uint8Array | null, secret: Secret, publicKey: KemPublicKey) {
    this.algorithm = algorithm;

    this.publicKey = publicKey;

    this.#seed = seed;

    this.#secret = secret;

    Object.freeze(this);
  }

  decapsulate(ciphertext: Uint8Array): Uint8Array {
    const data = bytes(ciphertext, "ciphertext");

    requireLength(data, this.algorithm.ciphertextSize, "ciphertext");

    return this.#secret.decapsulate(data, cacheOf(this.publicKey));
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  // A key without its seed was imported in expanded form, which only ML-KEM has.
  exportKey(format: KeyFormat): Uint8Array | string {
    const seed = this.#seed;

    const raw = seed ?? this.#secret.expanded!;

    return exportPrivate(format, backendOf(this.algorithm).oid, () => encodeSeedChoice(raw, seed !== null), raw);
  }
}

export class KemAlgorithm {
  readonly name: string;

  readonly publicKeySize: number;

  readonly ciphertextSize: number;

  readonly sharedSecretSize = 32;

  readonly #backend: KemBackend;

  constructor(name: string, backend: KemBackend) {
    this.name = name;

    this.publicKeySize = backend.publicKeySize;

    this.ciphertextSize = backend.ciphertextSize;

    this.#backend = backend;

    Object.freeze(this);
  }

  generateKeyPair(options?: KeyGenOptions): KemKeyPair {
    const test = selfTest(options);

    const privateKey = this.#fromSeed(randomBytes(this.#backend.seedSize));

    const publicKey = privateKey.publicKey;

    if (test) {
      const { sharedSecret, ciphertext } = publicKey.encapsulate();

      const decapsulated = privateKey.decapsulate(ciphertext);

      const consistent = equal(decapsulated, sharedSecret);

      wipe(sharedSecret, decapsulated);

      if (!consistent) {
        throw new CryptoPQError("SELF_TEST_FAILED", "the new key pair failed its consistency test");
      }
    }

    return Object.freeze({ publicKey, privateKey });
  }

  importPublicKey(data: Uint8Array | string, format: KeyFormat): KemPublicKey {
    const backend = this.#backend;

    const key = importPublic(format, data, backend.oid);

    requireKeyLength(key, backend.publicKeySize, format, "public key");

    if (!backend.checkPublicKey(key)) {
      throw new CryptoPQError("INVALID_PUBLIC_KEY", "the public key fails the encoding checks");
    }

    return new KemPublicKey(this, key);
  }

  importPrivateKey(data: Uint8Array | string, format: KeyFormat): KemPrivateKey {
    const backend = this.#backend;

    const { octets, raw, publicKey } = importPrivate(format, data, backend.oid);

    if (raw !== null) {
      if (raw.length === backend.seedSize) {
        return this.#fromSeed(raw);
      }

      if (backend.expanded !== null && raw.length === backend.expanded.size) {
        return this.#create(null, ...backend.expanded.load(raw));
      }

      raw.fill(0);

      throw new CryptoPQError("INVALID_LENGTH", "the private key has the wrong length");
    }

    // PKCS#8 input exists only for algorithms with an OID, which all have the expanded form.
    const { seed, expanded } = decodeSeedChoice(octets!, backend.seedSize, backend.expanded!.size);

    octets!.fill(0);

    const [pk, secret, cache] = seed !== null ? backend.fromSeed(seed) : backend.expanded!.load(expanded!);

    const dk = secret.expanded!;

    const agrees = seed === null || expanded === null || equal(expanded, dk);

    if (seed !== null) {
      expanded?.fill(0);
    }

    if (!agrees || (publicKey !== null && !equal(publicKey, pk))) {
      wipe(dk, seed ?? dk);

      throw mismatch(agrees ? "the embedded public key does not match" : "the seed and the expanded key differ");
    }

    return this.#create(seed, pk, secret, cache);
  }

  #fromSeed(seed: Uint8Array): KemPrivateKey {
    return this.#create(seed, ...this.#backend.fromSeed(seed));
  }

  #create(seed: Uint8Array | null, pk: Uint8Array, secret: Secret, cache: mlkem.PublicCache): KemPrivateKey {
    return new KemPrivateKey(this, seed, secret, useCache(new KemPublicKey(this, pk), cache));
  }

  static {
    backendOf = (algorithm) => algorithm.#backend;

    fromSeed = (algorithm, seed) => algorithm.#fromSeed(seed);
  }
}

export function keyPairFromSeed(algorithm: KemAlgorithm, seed: Uint8Array): KemKeyPair {
  const data = bytes(seed, "seed");

  requireLength(data, backendOf(algorithm).seedSize, "seed");

  const privateKey = fromSeed(algorithm, data.slice());

  return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
}

export function encapsulateDeterministic(publicKey: KemPublicKey, randomness: Uint8Array): Encapsulation {
  const data = bytes(randomness, "randomness");

  requireLength(data, backendOf(publicKey.algorithm).randomnessSize, "randomness");

  return encapsulateWith(publicKey, data.slice());
}

export const ML_KEM_512 = new KemAlgorithm("ML-KEM-512", mlKem(mlkem.ML_KEM_512, 1));

export const ML_KEM_768 = new KemAlgorithm("ML-KEM-768", mlKem(mlkem.ML_KEM_768, 2));

export const ML_KEM_1024 = new KemAlgorithm("ML-KEM-1024", mlKem(mlkem.ML_KEM_1024, 3));

export const X_WING = new KemAlgorithm("X-Wing", X_WING_BACKEND);
