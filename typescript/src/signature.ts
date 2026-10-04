import { bytes, concat, equal, wipe } from "./bytes.ts";
import { type KeyFormat, OBJECT_IDENTIFIER, element, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import {
  SHA3_224,
  SHA3_256,
  SHA3_384,
  SHA3_512,
  SHA_224,
  SHA_256,
  SHA_384,
  SHA_512,
  SHA_512_224,
  SHA_512_256,
  SHAKE128,
  SHAKE256,
  type HashAlgorithm,
  type XofAlgorithm,
} from "./hash.ts";
import {
  type KeyGenOptions,
  decodeSeedChoice,
  encodeSeedChoice,
  exportPrivate,
  exportPublic,
  importPrivate,
  importPublic,
  mismatch,
  readOptions,
  requireBool,
  requireKeyLength,
  requireLength,
  selfTest,
} from "./keys.ts";
import * as mldsa from "./mldsa.ts";
import { randomBytes } from "./rng.ts";
import * as slhdsa from "./slhdsa.ts";

const SELF_TEST_MESSAGE = Uint8Array.from("crypto-pq pairwise consistency test", (c) => c.charCodeAt(0));

export interface SignOptions {
  context?: Uint8Array;

  deterministic?: boolean;

  preHash?: HashAlgorithm | XofAlgorithm;
}

export interface VerifyOptions {
  context?: Uint8Array;

  preHash?: HashAlgorithm | XofAlgorithm;
}

export interface SignatureKeyPair {
  readonly publicKey: SignaturePublicKey;

  readonly privateKey: SignaturePrivateKey;
}

interface PreHash {
  readonly oid: Uint8Array;

  readonly strength: number;

  digest(message: Uint8Array): Uint8Array;
}

function preHash(arc: number, strength: number, digest: (message: Uint8Array) => Uint8Array): PreHash {
  return { oid: element(OBJECT_IDENTIFIER, objectIdentifier(`2.16.840.1.101.3.4.2.${arc}`)), strength, digest };
}

// Collision strength in bits of each approved pre-hash; SHAKE128 and SHAKE256 produce 256 and
// 512 bits as FIPS 204 and FIPS 205 require.
const PRE_HASHES = new Map<unknown, PreHash>([
  [SHA_224, preHash(4, 112, (message) => SHA_224.digest(message))],
  [SHA_256, preHash(1, 128, (message) => SHA_256.digest(message))],
  [SHA_384, preHash(2, 192, (message) => SHA_384.digest(message))],
  [SHA_512, preHash(3, 256, (message) => SHA_512.digest(message))],
  [SHA_512_224, preHash(5, 112, (message) => SHA_512_224.digest(message))],
  [SHA_512_256, preHash(6, 128, (message) => SHA_512_256.digest(message))],
  [SHA3_224, preHash(7, 112, (message) => SHA3_224.digest(message))],
  [SHA3_256, preHash(8, 128, (message) => SHA3_256.digest(message))],
  [SHA3_384, preHash(9, 192, (message) => SHA3_384.digest(message))],
  [SHA3_512, preHash(10, 256, (message) => SHA3_512.digest(message))],
  [SHAKE128, preHash(11, 128, (message) => SHAKE128.digest(message, 32))],
  [SHAKE256, preHash(12, 256, (message) => SHAKE256.digest(message, 64))],
]);

// A new key as a backend makes it: the public key, the private key and what the public key's cache
// can start with.
type NewKey = [Uint8Array, Uint8Array, mldsa.PublicCache];

// The caches serve ML-DSA; SLH-DSA keys carry empty ones.
export interface SignatureBackend {
  readonly oid: Uint8Array;

  readonly seedSize: number;

  readonly expandedSize: number | null;

  readonly privateKeySize: number;

  readonly publicKeySize: number;

  readonly signatureSize: number;

  readonly randomnessSize: number;

  readonly strength: number;

  fromSeed(seed: Uint8Array): NewKey;

  fromPrivate(key: Uint8Array): NewKey;

  deterministicRandomness(key: Uint8Array): Uint8Array;

  sign(
    key: Uint8Array,
    cache: mldsa.PublicCache,
    secret: mldsa.SecretCache,
    message: Uint8Array,
    randomness: Uint8Array,
  ): Uint8Array;

  verify(key: Uint8Array, cache: mldsa.PublicCache, message: Uint8Array, signature: Uint8Array): boolean;
}

function mlDsa(params: mldsa.Parameters, arc: number): SignatureBackend {
  return {
    oid: objectIdentifier(`2.16.840.1.101.3.4.3.${arc}`),
    seedSize: 32,
    expandedSize: params.privateKeySize,
    privateKeySize: params.privateKeySize,
    publicKeySize: params.publicKeySize,
    signatureSize: params.signatureSize,
    randomnessSize: 32,
    strength: params.lambda,
    fromSeed: (seed) => mldsa.keygenInternal(seed, params),
    fromPrivate(sk) {
      const checked = mldsa.checkPrivateKey(sk, params);

      if (checked === null) {
        throw mismatch("the private key fails the consistency checks");
      }

      return [checked[0], sk, checked[1]];
    },
    deterministicRandomness: () => new Uint8Array(32),
    sign: (sk, cache, secret, message, randomness) =>
      mldsa.signInternal(sk, cache, secret, message, randomness, params),
    verify: (pk, cache, message, signature) => mldsa.verifyInternal(pk, cache, message, signature, params),
  };
}

function slhDsa(params: slhdsa.Parameters, arc: number): SignatureBackend {
  const n = params.n;

  return {
    oid: objectIdentifier(`2.16.840.1.101.3.4.3.${arc}`),
    seedSize: 3 * n,
    expandedSize: null,
    privateKeySize: params.privateKeySize,
    publicKeySize: params.publicKeySize,
    signatureSize: params.signatureSize,
    randomnessSize: n,
    strength: 8 * n,
    fromSeed(seed) {
      const [sk, pk] = slhdsa.keygenInternal(
        seed.subarray(0, n),
        seed.subarray(n, 2 * n),
        seed.subarray(2 * n),
        params,
      );

      return [pk, sk, mldsa.publicCache()];
    },
    fromPrivate(sk) {
      if (!equal(slhdsa.root(params, sk.subarray(0, n), sk.subarray(2 * n, 3 * n)), sk.subarray(3 * n))) {
        throw mismatch("the private key does not match its public root");
      }

      return [sk.slice(2 * n), sk, mldsa.publicCache()];
    },
    deterministicRandomness: (sk) => sk.slice(2 * n, 3 * n),
    sign: (sk, _cache, _secret, message, randomness) => slhdsa.signInternal(message, sk, randomness, params),
    verify: (pk, _cache, message, signature) => slhdsa.verifyInternal(message, signature, pk, params),
  };
}

function preHashEntry(value: unknown): PreHash | null {
  if (value === undefined) {
    return null;
  }

  const entry = PRE_HASHES.get(value);

  if (entry === undefined) {
    throw new CryptoPQError("INVALID_OPTION", "preHash must be one of the crypto-pq hash functions");
  }

  return entry;
}

function contextOf(value: VerifyOptions | undefined): [Uint8Array, PreHash | null] {
  const { context = new Uint8Array(), preHash } = readOptions(value);

  return [bytes(context, "context"), preHashEntry(preHash)];
}

// A pre-hash must give at least the collision strength of the signature (FIPS 204, 5.4, and
// FIPS 205, 10.2): signing with a weaker one is refused and verification fails closed.
function tooWeak(backend: SignatureBackend, entry: PreHash | null, policy: boolean): boolean {
  return policy && entry !== null && entry.strength < backend.strength;
}

// FIPS 204 and FIPS 205: M' = 0 || |ctx| || ctx || M, or 1 || |ctx| || ctx || OID || PH(M).
function messageRepresentative(message: Uint8Array, context: Uint8Array, entry: PreHash | null): Uint8Array {
  if (entry === null) {
    return concat(Uint8Array.of(0, context.length), context, message);
  }

  return concat(Uint8Array.of(1, context.length), context, entry.oid, entry.digest(message));
}

let backendOf: (algorithm: SignatureAlgorithm) => SignatureBackend;

let fromSeed: (algorithm: SignatureAlgorithm, seed: Uint8Array) => SignatureKeyPair;

let signWith: (
  privateKey: SignaturePrivateKey,
  message: Uint8Array,
  randomness: Uint8Array,
  options: SignOptions | undefined,
) => Uint8Array;

let verifyWith: (
  publicKey: SignaturePublicKey,
  signature: Uint8Array,
  message: Uint8Array,
  options: VerifyOptions | undefined,
) => boolean;

let cacheOf: (publicKey: SignaturePublicKey) => mldsa.PublicCache;

let useCache: (publicKey: SignaturePublicKey, cache: mldsa.PublicCache) => SignaturePublicKey;

export class SignaturePublicKey {
  readonly algorithm: SignatureAlgorithm;

  readonly #key: Uint8Array;

  // What verification derives from the key, filled on first use unless the key's creator supplies
  // part of it.
  #cache = mldsa.publicCache();

  constructor(algorithm: SignatureAlgorithm, key: Uint8Array) {
    this.algorithm = algorithm;

    this.#key = key;

    Object.freeze(this);
  }

  verify(signature: Uint8Array, message: Uint8Array, options?: VerifyOptions): boolean {
    return this.#verify(signature, message, options, true);
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  exportKey(format: KeyFormat): Uint8Array | string {
    return exportPublic(format, backendOf(this.algorithm).oid, this.#key);
  }

  equals(other: SignaturePublicKey): boolean {
    return (
      typeof other === "object" &&
      other !== null &&
      #key in other &&
      other.algorithm === this.algorithm &&
      equal(other.#key, this.#key)
    );
  }

  #verify(signature: Uint8Array, message: Uint8Array, value: VerifyOptions | undefined, policy: boolean): boolean {
    const data = bytes(signature, "signature");

    const text = bytes(message, "message");

    const [context, entry] = contextOf(value);

    const backend = backendOf(this.algorithm);

    if (tooWeak(backend, entry, policy) || context.length > 255 || data.length !== backend.signatureSize) {
      return false;
    }

    return backend.verify(this.#key, this.#cache, messageRepresentative(text, context, entry), data);
  }

  static {
    verifyWith = (publicKey, signature, message, value) => publicKey.#verify(signature, message, value, false);

    cacheOf = (publicKey) => publicKey.#cache;

    useCache = (publicKey, cache) => {
      publicKey.#cache = cache;

      return publicKey;
    };
  }
}

export class SignaturePrivateKey {
  readonly algorithm: SignatureAlgorithm;

  readonly publicKey: SignaturePublicKey;

  readonly #seed: Uint8Array | null;

  readonly #key: Uint8Array;

  // The secret vectors in the NTT domain, decoded on first use.
  readonly #secret: mldsa.SecretCache = { vectors: null };

  constructor(algorithm: SignatureAlgorithm, seed: Uint8Array | null, key: Uint8Array, publicKey: SignaturePublicKey) {
    this.algorithm = algorithm;

    this.publicKey = publicKey;

    this.#seed = seed;

    this.#key = key;

    Object.freeze(this);
  }

  sign(message: Uint8Array, options?: SignOptions): Uint8Array {
    const { deterministic = false } = readOptions(options);

    const backend = backendOf(this.algorithm);

    const randomness = requireBool(deterministic, "deterministic")
      ? backend.deterministicRandomness(this.#key)
      : randomBytes(backend.randomnessSize);

    return this.#sign(message, randomness, options, true);
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  exportKey(format: KeyFormat): Uint8Array | string {
    const backend = backendOf(this.algorithm);

    const key = this.#key;

    const seed = this.#seed;

    if (backend.expandedSize === null) {
      return exportPrivate(format, backend.oid, () => key.slice(), key);
    }

    const raw = seed ?? key;

    return exportPrivate(format, backend.oid, () => encodeSeedChoice(raw, seed !== null), raw);
  }

  #sign(message: Uint8Array, randomness: Uint8Array, value: SignOptions | undefined, policy: boolean): Uint8Array {
    try {
      const text = bytes(message, "message");

      const [context, entry] = contextOf(value);

      const backend = backendOf(this.algorithm);

      if (tooWeak(backend, entry, policy)) {
        throw new CryptoPQError("INVALID_OPTION", "the pre-hash is weaker than the signature algorithm");
      }

      if (context.length > 255) {
        throw new CryptoPQError("INVALID_CONTEXT", "the context must be at most 255 bytes");
      }

      const representative = messageRepresentative(text, context, entry);

      return backend.sign(this.#key, cacheOf(this.publicKey), this.#secret, representative, randomness);
    } finally {
      randomness.fill(0);
    }
  }

  static {
    signWith = (privateKey, message, randomness, value) => privateKey.#sign(message, randomness, value, false);
  }
}

export class SignatureAlgorithm {
  readonly name: string;

  readonly publicKeySize: number;

  readonly signatureSize: number;

  readonly #backend: SignatureBackend;

  constructor(name: string, backend: SignatureBackend) {
    this.name = name;

    this.publicKeySize = backend.publicKeySize;

    this.signatureSize = backend.signatureSize;

    this.#backend = backend;

    Object.freeze(this);
  }

  generateKeyPair(options?: KeyGenOptions): SignatureKeyPair {
    const test = selfTest(options);

    const pair = this.#fromSeed(randomBytes(this.#backend.seedSize));

    if (test) {
      const signature = pair.privateKey.sign(SELF_TEST_MESSAGE, { deterministic: true });

      if (!pair.publicKey.verify(signature, SELF_TEST_MESSAGE)) {
        throw new CryptoPQError("SELF_TEST_FAILED", "the new key pair failed its consistency test");
      }
    }

    return pair;
  }

  importPublicKey(data: Uint8Array | string, format: KeyFormat): SignaturePublicKey {
    const key = importPublic(format, data, this.#backend.oid);

    requireKeyLength(key, this.#backend.publicKeySize, format, "public key");

    return new SignaturePublicKey(this, key);
  }

  importPrivateKey(data: Uint8Array | string, format: KeyFormat): SignaturePrivateKey {
    const backend = this.#backend;

    const { octets, raw, publicKey } = importPrivate(format, data, backend.oid);

    let key: SignaturePrivateKey;

    if (backend.expandedSize === null) {
      key = this.#fromPrivate(requireKeyLength(raw ?? octets!, backend.privateKeySize, format, "private key"));
    } else if (raw !== null) {
      key = this.#importRaw(raw);
    } else {
      key = this.#importChoice(octets!);
    }

    if (publicKey !== null && !equal(publicKey, key.publicKey.exportKey("raw"))) {
      throw mismatch("the embedded public key does not match the private key");
    }

    return key;
  }

  // ML-DSA keeps the seed as its private key; SLH-DSA keeps the expanded 4n-byte key, which
  // contains the seed.
  #fromSeed(seed: Uint8Array): SignatureKeyPair {
    const backend = this.#backend;

    const [pk, key, cache] = backend.fromSeed(seed);

    const kept = backend.expandedSize !== null ? seed : null;

    if (kept === null) {
      seed.fill(0);
    }

    const privateKey = this.#create(kept, key, pk, cache);

    return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
  }

  #fromPrivate(key: Uint8Array): SignaturePrivateKey {
    const [pk, sk, cache] = this.#backend.fromPrivate(key);

    return this.#create(null, sk, pk, cache);
  }

  #create(seed: Uint8Array | null, key: Uint8Array, pk: Uint8Array, cache: mldsa.PublicCache): SignaturePrivateKey {
    return new SignaturePrivateKey(this, seed, key, useCache(new SignaturePublicKey(this, pk), cache));
  }

  #importRaw(raw: Uint8Array): SignaturePrivateKey {
    const backend = this.#backend;

    if (raw.length === backend.seedSize) {
      return this.#fromSeed(raw).privateKey;
    }

    if (raw.length !== backend.privateKeySize) {
      raw.fill(0);
    }

    return this.#fromPrivate(requireLength(raw, backend.privateKeySize, "private key"));
  }

  // PKCS#8 CHOICE: the seed, the expanded key, or both, which must then agree.
  #importChoice(octets: Uint8Array): SignaturePrivateKey {
    const backend = this.#backend;

    const { seed, expanded } = decodeSeedChoice(octets, backend.seedSize, backend.expandedSize);

    octets.fill(0);

    if (seed === null) {
      return this.#fromPrivate(expanded!);
    }

    const [pk, key, cache] = backend.fromSeed(seed);

    if (expanded !== null) {
      const matches = equal(expanded, key);

      expanded.fill(0);

      if (!matches) {
        wipe(seed, key);

        throw mismatch("the seed and the expanded key do not match");
      }
    }

    return this.#create(seed, key, pk, cache);
  }

  static {
    backendOf = (algorithm) => algorithm.#backend;

    fromSeed = (algorithm, seed) => algorithm.#fromSeed(seed);
  }
}

export function keyPairFromSeed(algorithm: SignatureAlgorithm, seed: Uint8Array): SignatureKeyPair {
  const data = bytes(seed, "seed");

  requireLength(data, backendOf(algorithm).seedSize, "seed");

  return fromSeed(algorithm, data.slice());
}

export function signDeterministic(
  privateKey: SignaturePrivateKey,
  message: Uint8Array,
  randomness: Uint8Array,
  options?: SignOptions,
): Uint8Array {
  const data = bytes(randomness, "randomness");

  requireLength(data, backendOf(privateKey.algorithm).randomnessSize, "randomness");

  return signWith(privateKey, message, data.slice(), options);
}

export function verifyUnchecked(
  publicKey: SignaturePublicKey,
  signature: Uint8Array,
  message: Uint8Array,
  options?: VerifyOptions,
): boolean {
  return verifyWith(publicKey, signature, message, options);
}

export const ML_DSA_44 = new SignatureAlgorithm("ML-DSA-44", mlDsa(mldsa.ML_DSA_44, 17));

export const ML_DSA_65 = new SignatureAlgorithm("ML-DSA-65", mlDsa(mldsa.ML_DSA_65, 18));

export const ML_DSA_87 = new SignatureAlgorithm("ML-DSA-87", mlDsa(mldsa.ML_DSA_87, 19));

const SLH_DSA = [...slhdsa.SHA2, ...slhdsa.SHAKE].map((p, i) => new SignatureAlgorithm(p.name, slhDsa(p, 20 + i)));

export const SLH_DSA_SHA2_128S = SLH_DSA[0];

export const SLH_DSA_SHA2_128F = SLH_DSA[1];

export const SLH_DSA_SHA2_192S = SLH_DSA[2];

export const SLH_DSA_SHA2_192F = SLH_DSA[3];

export const SLH_DSA_SHA2_256S = SLH_DSA[4];

export const SLH_DSA_SHA2_256F = SLH_DSA[5];

export const SLH_DSA_SHAKE_128S = SLH_DSA[6];

export const SLH_DSA_SHAKE_128F = SLH_DSA[7];

export const SLH_DSA_SHAKE_192S = SLH_DSA[8];

export const SLH_DSA_SHAKE_192F = SLH_DSA[9];

export const SLH_DSA_SHAKE_256S = SLH_DSA[10];

export const SLH_DSA_SHAKE_256F = SLH_DSA[11];
