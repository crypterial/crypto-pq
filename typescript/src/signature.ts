import { bytes, concat, equal, wipe } from "./bytes.ts";
import { type KeyFormat, OBJECT_IDENTIFIER, element, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import { ML_DSA, SLH_DSA } from "./families.ts";
import type { HashAlgorithm, XofAlgorithm } from "./hash.ts";
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
import { PRE_HASHES, type PreHash, REFUSED_PRE_HASHES } from "./prehash.ts";
import { randomBytes } from "./rng.ts";
import * as slhdsa from "./slhdsa.ts";
import { type Core, type Family, PUBLIC, REJECTED, SECRET, Slot, check } from "./wasm.ts";

const SELF_TEST_MESSAGE = Uint8Array.from("crypto-pq pairwise consistency test", (c) => c.charCodeAt(0));

const PUBLIC_SLOT = 3;

const PRIVATE_SLOT = 4;

const FILL_CACHE = 1;

const DETERMINISTIC = 1;

const HAZMAT = 2;

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

// The randomness of a signature: given (hazmat), fresh from the platform, or the fixed value of
// deterministic signing.
type Randomness = Uint8Array | "fresh" | "deterministic";

// How a key verifies on the backend that made it, after the checks that every backend shares.
interface Verifier {
  verify(
    message: Uint8Array,
    context: Uint8Array,
    entry: PreHash | null,
    signature: Uint8Array,
    policy: boolean,
  ): boolean;
}

// The private half of a key on the backend that made it. raw and key return new arrays: the raw
// private key and whether it is the seed, and the private key itself (the expanded ML-DSA key, or
// SLH-DSA's 4n bytes).
interface Secret {
  raw(): [Uint8Array, boolean];

  key(): Uint8Array;

  sign(
    message: Uint8Array,
    context: Uint8Array,
    entry: PreHash | null,
    randomness: Randomness,
    policy: boolean,
  ): Uint8Array;

  wipe(): void;
}

// A new key as a backend makes it: the public key, how to verify with it and the secret.
type NewKey = [Uint8Array, Verifier, Secret];

// One parameter set on one backend. fromSeed draws the seed when none is given and fills the
// caches at once when asked, for a key pair that tests itself; a seed or private key that it is
// given belongs to the new key afterwards.
interface Engine {
  fromSeed(seed: Uint8Array | null, fill: boolean): NewKey;

  fromPrivate(key: Uint8Array): NewKey;

  importPublic(key: Uint8Array): Verifier;
}

// The TypeScript implementation of one parameter set. The caches serve ML-DSA; SLH-DSA keys carry
// empty ones.
interface Scheme {
  fromSeed(seed: Uint8Array): [Uint8Array, Uint8Array, mldsa.PublicCache];

  fromPrivate(key: Uint8Array): [Uint8Array, Uint8Array, mldsa.PublicCache];

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

interface SignatureSizes {
  readonly seedSize: number;

  readonly expandedSize: number | null;

  readonly privateKeySize: number;

  readonly publicKeySize: number;

  readonly signatureSize: number;

  readonly randomnessSize: number;

  readonly strength: number;
}

export interface SignatureBackend extends SignatureSizes {
  readonly oid: Uint8Array;

  readonly family: Family;

  readonly js: Engine;

  readonly wasm: Engine;
}

// A crypto-pq hash function that FIPS 204 and FIPS 205 do not approve as a pre-hash.
const REFUSED: PreHash = { id: 0, arc: 0, strength: 0, digest: () => new Uint8Array(0) };

function preHashEntry(value: unknown): PreHash | null {
  if (value === undefined) {
    return null;
  }

  const entry = PRE_HASHES.get(value as object) ?? (REFUSED_PRE_HASHES.has(value as object) ? REFUSED : undefined);

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

  const oid = element(OBJECT_IDENTIFIER, objectIdentifier(`2.16.840.1.101.3.4.2.${entry.arc}`));

  return concat(Uint8Array.of(1, context.length), context, oid, entry.digest(message));
}

function jsEngine(scheme: Scheme, sizes: SignatureSizes): Engine {
  const create = (seed: Uint8Array | null, [pk, sk, cache]: [Uint8Array, Uint8Array, mldsa.PublicCache]): NewKey => {
    // The secret vectors in the NTT domain, decoded on first use; the private key signs with the
    // cache of its public key.
    const vectors: mldsa.SecretCache = { vectors: null };

    const secret: Secret = {
      raw: () => [(seed ?? sk).slice(), seed !== null],
      key: () => sk.slice(),
      sign(message, context, entry, randomness) {
        const representative = messageRepresentative(message, context, entry);

        const fixed = randomness === "deterministic" ? scheme.deterministicRandomness(sk) : randomness;

        const value = fixed === "fresh" ? randomBytes(sizes.randomnessSize) : fixed;

        try {
          return scheme.sign(sk, cache, vectors, representative, value);
        } finally {
          value.fill(0);
        }
      },
      wipe: () => wipe(sk, seed ?? sk),
    };

    return [pk, verifierOf(pk, cache), secret];
  };

  const verifierOf = (pk: Uint8Array, cache: mldsa.PublicCache): Verifier => ({
    verify: (message, context, entry, signature) =>
      scheme.verify(pk, cache, messageRepresentative(message, context, entry), signature),
  });

  return {
    fromSeed(seed) {
      const s = seed ?? randomBytes(sizes.seedSize);

      const made = scheme.fromSeed(s);

      // ML-DSA keeps the seed as its private key; SLH-DSA keeps the expanded 4n-byte key, which
      // contains the seed.
      if (sizes.expandedSize === null) {
        s.fill(0);
      }

      return create(sizes.expandedSize === null ? null : s, made);
    },
    fromPrivate: (key) => create(null, scheme.fromPrivate(key)),
    importPublic: (pk) => verifierOf(pk, mldsa.publicCache()),
  };
}

function mlDsa(params: mldsa.Parameters): Scheme {
  return {
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

function slhDsa(params: slhdsa.Parameters): Scheme {
  const n = params.n;

  return {
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

// Keys live as copies of their slots, which every call places in the instance's I/O block. An
// ML-DSA key's caches fill on first use as in TypeScript; the private slot holds its own public
// part. ML-DSA keys keep their seed; SLH-DSA keys keep the 4n-byte private key.
function wasmEngine(family: Family, id: number, sizes: SignatureSizes, invalid: string): Engine {
  const mlDsaKey = sizes.expandedSize !== null;

  const caches = mlDsaKey ? 0x100 : 0;

  const verifierOf = (slot: Slot): Verifier => ({
    verify(message, context, entry, signature, policy) {
      const core = family.core();

      const size = slot.bytes.length;

      return core.run(PUBLIC, [size, signature.length, message.length, context.length], ([key, s, m, c]) => {
        slot.load(core, key);

        core.write(s, signature);

        core.write(m, message);

        core.write(c, context);

        const flags = policy ? 0 : HAZMAT;

        const status = core.x.cpq_sig_verify(
          key,
          size,
          s,
          signature.length,
          m,
          message.length,
          c,
          context.length,
          entry?.id ?? 0,
          flags,
        );

        if (status !== REJECTED) {
          check(status);
        }

        slot.update(core, key);

        return status !== REJECTED;
      });
    },
  });

  const secretOf = (slot: Slot, seeded: boolean): Secret => {
    const size = slot.bytes.length;

    const exported = (which: number, length: number) => {
      const core = family.core();

      return core.run(SECRET, [size, length], ([key, out]) => {
        slot.load(core, key);

        check(core.x.cpq_sig_export_private(key, size, which, out, length));

        return core.read(out, length);
      });
    };

    return {
      raw: () => [seeded ? exported(0, sizes.seedSize) : exported(1, sizes.privateKeySize), seeded],
      key: () => exported(1, sizes.privateKeySize),
      sign(message, context, entry, randomness, policy) {
        const core = family.core();

        const length = randomness === "deterministic" ? 0 : sizes.randomnessSize;

        const regions = [size, message.length, context.length, length, sizes.signatureSize];

        return core.run(SECRET, regions, ([key, m, c, r, signature]) => {
          slot.load(core, key);

          core.write(m, message);

          core.write(c, context);

          if (randomness === "fresh") {
            core.random(r, length);
          } else if (randomness !== "deterministic") {
            core.write(r, randomness);
          }

          const flags = (length === 0 ? DETERMINISTIC : 0) | (policy ? 0 : HAZMAT);

          const status = core.x.cpq_sig_sign(
            key,
            size,
            m,
            message.length,
            c,
            context.length,
            entry?.id ?? 0,
            r,
            length,
            flags,
            signature,
            sizes.signatureSize,
          );

          check(status);

          slot.update(core, key);

          return core.read(signature, sizes.signatureSize);
        });
      },
      wipe: () => slot.bytes.fill(0),
    };
  };

  const importPublic = (pk: Uint8Array): Verifier => {
    const core = family.core();

    const publicSize = core.size(PUBLIC_SLOT, id);

    return core.run(PUBLIC, [publicSize, pk.length], ([publicSlot, input]) => {
      core.write(input, pk);

      check(core.x.cpq_sig_import_public(id, input, pk.length, publicSlot, publicSize));

      return verifierOf(new Slot(core, publicSlot, publicSize, caches));
    });
  };

  // A new key's verifier keeps the public key and imports it when it first verifies: its public
  // slot, which for ML-DSA is the larger part of what key generation copies out of the instance
  // (allocators that clear memory as they hand it out, such as musl's, make that slow), is copied
  // only once it serves. A key pair that tested itself keeps the slot it made, caches filled.
  const deferred = (pk: Uint8Array): Verifier => {
    let verifier: Verifier | null = null;

    return {
      verify: (message, context, entry, signature, policy) =>
        (verifier ??= importPublic(pk)).verify(message, context, entry, signature, policy),
    };
  };

  // The key made in the private slot at key: its public slot, made at public, and the public key,
  // exported at raw.
  const created = (core: Core, at: readonly number[], seeded: boolean, filled: boolean): NewKey => {
    const [key, publicSlot, raw] = at;

    const privateSize = core.size(PRIVATE_SLOT, id);

    const publicSize = core.size(PUBLIC_SLOT, id);

    check(core.x.cpq_sig_public_from_private(key, privateSize, publicSlot, publicSize));

    check(core.x.cpq_sig_export_public(publicSlot, publicSize, raw, sizes.publicKeySize));

    const pk = core.read(raw, sizes.publicKeySize);

    const verifier = filled ? verifierOf(new Slot(core, publicSlot, publicSize, caches)) : deferred(pk);

    return [pk, verifier, secretOf(new Slot(core, key, privateSize, caches | (caches << 1)), seeded)];
  };

  const slots = (core: Core) => [core.size(PRIVATE_SLOT, id), core.size(PUBLIC_SLOT, id), sizes.publicKeySize];

  return {
    fromSeed(seed, fill) {
      const core = family.core();

      try {
        return core.run(SECRET, [...slots(core), sizes.seedSize], (at) => {
          const [key, , , s] = at;

          if (seed === null) {
            core.random(s, sizes.seedSize);
          } else {
            core.write(s, seed);
          }

          check(core.x.cpq_sig_keygen(id, s, sizes.seedSize, fill ? FILL_CACHE : 0, key, core.size(PRIVATE_SLOT, id)));

          return created(core, at, mlDsaKey, fill);
        });
      } finally {
        seed?.fill(0);
      }
    },
    fromPrivate(sk) {
      const core = family.core();

      try {
        return core.run(SECRET, [...slots(core), sk.length], (at) => {
          const [key, , , input] = at;

          core.write(input, sk);

          const status = core.x.cpq_sig_import_private(id, input, sk.length, key, core.size(PRIVATE_SLOT, id));

          check(status, { INVALID_PRIVATE_KEY: invalid });

          return created(core, at, false, false);
        });
      } finally {
        sk.fill(0);
      }
    },
    importPublic,
  };
}

function mlDsaBackend(params: mldsa.Parameters, arc: number, id: number): SignatureBackend {
  const sizes: SignatureSizes = {
    seedSize: 32,
    expandedSize: params.privateKeySize,
    privateKeySize: params.privateKeySize,
    publicKeySize: params.publicKeySize,
    signatureSize: params.signatureSize,
    randomnessSize: 32,
    strength: params.lambda,
  };

  return {
    ...sizes,
    oid: objectIdentifier(`2.16.840.1.101.3.4.3.${arc}`),
    family: ML_DSA,
    js: jsEngine(mlDsa(params), sizes),
    wasm: wasmEngine(ML_DSA, id, sizes, "the private key fails the consistency checks"),
  };
}

function slhDsaBackend(params: slhdsa.Parameters, index: number): SignatureBackend {
  const n = params.n;

  const sizes: SignatureSizes = {
    seedSize: 3 * n,
    expandedSize: null,
    privateKeySize: params.privateKeySize,
    publicKeySize: params.publicKeySize,
    signatureSize: params.signatureSize,
    randomnessSize: n,
    strength: 8 * n,
  };

  return {
    ...sizes,
    oid: objectIdentifier(`2.16.840.1.101.3.4.3.${20 + index}`),
    family: SLH_DSA,
    js: jsEngine(slhDsa(params), sizes),
    wasm: wasmEngine(SLH_DSA, 3 + index, sizes, "the private key does not match its public root"),
  };
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

export class SignaturePublicKey {
  readonly algorithm: SignatureAlgorithm;

  readonly #key: Uint8Array;

  // What verification derives from the key, on the backend that made the key, filled on first use
  // unless the key's creator supplies part of it.
  readonly #verifier: Verifier;

  constructor(algorithm: SignatureAlgorithm, key: Uint8Array, verifier: Verifier) {
    this.algorithm = algorithm;

    this.#key = key;

    this.#verifier = verifier;

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

    const refused = entry === REFUSED || tooWeak(backend, entry, policy);

    if (refused || context.length > 255 || data.length !== backend.signatureSize) {
      return false;
    }

    return this.#verifier.verify(text, context, entry, data, policy);
  }

  static {
    verifyWith = (publicKey, signature, message, value) => publicKey.#verify(signature, message, value, false);
  }
}

export class SignaturePrivateKey {
  readonly algorithm: SignatureAlgorithm;

  readonly publicKey: SignaturePublicKey;

  readonly #secret: Secret;

  constructor(algorithm: SignatureAlgorithm, secret: Secret, publicKey: SignaturePublicKey) {
    this.algorithm = algorithm;

    this.publicKey = publicKey;

    this.#secret = secret;

    Object.freeze(this);
  }

  // The arguments are checked before the randomness is drawn.
  sign(message: Uint8Array, options?: SignOptions): Uint8Array {
    const { deterministic = false } = readOptions(options);

    const randomness = requireBool(deterministic, "deterministic") ? "deterministic" : "fresh";

    return this.#sign(message, randomness, options, true);
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  exportKey(format: KeyFormat): Uint8Array | string {
    const backend = backendOf(this.algorithm);

    const [raw, seed] = this.#secret.raw();

    const octets = backend.expandedSize === null ? () => raw.slice() : () => encodeSeedChoice(raw, seed);

    try {
      return exportPrivate(format, backend.oid, octets, raw);
    } finally {
      raw.fill(0);
    }
  }

  #sign(message: Uint8Array, randomness: Randomness, value: SignOptions | undefined, policy: boolean): Uint8Array {
    try {
      const text = bytes(message, "message");

      const [context, entry] = contextOf(value);

      const backend = backendOf(this.algorithm);

      if (entry === REFUSED) {
        throw new CryptoPQError("INVALID_OPTION", "FIPS 204 and FIPS 205 do not approve this pre-hash");
      }

      if (tooWeak(backend, entry, policy)) {
        throw new CryptoPQError("INVALID_OPTION", "the pre-hash is weaker than the signature algorithm");
      }

      if (context.length > 255) {
        throw new CryptoPQError("INVALID_CONTEXT", "the context must be at most 255 bytes");
      }

      return this.#secret.sign(text, context, entry, randomness, policy);
    } finally {
      if (randomness instanceof Uint8Array) {
        randomness.fill(0);
      }
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

  // Where new keys of this algorithm run, deciding it on first use.
  get backend(): "wasm" | "js" {
    return this.#backend.family.select() === null ? "js" : "wasm";
  }

  generateKeyPair(options?: KeyGenOptions): SignatureKeyPair {
    const test = selfTest(options);

    const pair = this.#pair(this.#engine().fromSeed(null, test));

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

    return new SignaturePublicKey(this, key, this.#engine().importPublic(key));
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

  #engine(): Engine {
    const backend = this.#backend;

    return backend.family.select() === null ? backend.js : backend.wasm;
  }

  #pair(key: NewKey): SignatureKeyPair {
    const privateKey = this.#create(key);

    return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
  }

  #fromPrivate(key: Uint8Array): SignaturePrivateKey {
    return this.#create(this.#engine().fromPrivate(key));
  }

  #create([pk, verifier, secret]: NewKey): SignaturePrivateKey {
    return new SignaturePrivateKey(this, secret, new SignaturePublicKey(this, pk, verifier));
  }

  #importRaw(raw: Uint8Array): SignaturePrivateKey {
    const backend = this.#backend;

    if (raw.length === backend.seedSize) {
      return this.#create(this.#engine().fromSeed(raw, false));
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

    const key = this.#engine().fromSeed(seed, false);

    if (expanded !== null) {
      const sk = key[2].key();

      const matches = equal(expanded, sk);

      wipe(expanded, sk);

      if (!matches) {
        key[2].wipe();

        throw mismatch("the seed and the expanded key do not match");
      }
    }

    return this.#create(key);
  }

  static {
    backendOf = (algorithm) => algorithm.#backend;

    fromSeed = (algorithm, seed) => algorithm.#pair(algorithm.#engine().fromSeed(seed, false));
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

function slhDsaAlgorithm(index: number): SignatureAlgorithm {
  const params = [...slhdsa.SHA2, ...slhdsa.SHAKE][index];

  return new SignatureAlgorithm(params.name, slhDsaBackend(params, index));
}

export const ML_DSA_44 = /* @__PURE__ */ new SignatureAlgorithm(
  "ML-DSA-44",
  /* @__PURE__ */ mlDsaBackend(mldsa.ML_DSA_44, 17, 0),
);

export const ML_DSA_65 = /* @__PURE__ */ new SignatureAlgorithm(
  "ML-DSA-65",
  /* @__PURE__ */ mlDsaBackend(mldsa.ML_DSA_65, 18, 1),
);

export const ML_DSA_87 = /* @__PURE__ */ new SignatureAlgorithm(
  "ML-DSA-87",
  /* @__PURE__ */ mlDsaBackend(mldsa.ML_DSA_87, 19, 2),
);

export const SLH_DSA_SHA2_128S = /* @__PURE__ */ slhDsaAlgorithm(0);

export const SLH_DSA_SHA2_128F = /* @__PURE__ */ slhDsaAlgorithm(1);

export const SLH_DSA_SHA2_192S = /* @__PURE__ */ slhDsaAlgorithm(2);

export const SLH_DSA_SHA2_192F = /* @__PURE__ */ slhDsaAlgorithm(3);

export const SLH_DSA_SHA2_256S = /* @__PURE__ */ slhDsaAlgorithm(4);

export const SLH_DSA_SHA2_256F = /* @__PURE__ */ slhDsaAlgorithm(5);

export const SLH_DSA_SHAKE_128S = /* @__PURE__ */ slhDsaAlgorithm(6);

export const SLH_DSA_SHAKE_128F = /* @__PURE__ */ slhDsaAlgorithm(7);

export const SLH_DSA_SHAKE_192S = /* @__PURE__ */ slhDsaAlgorithm(8);

export const SLH_DSA_SHAKE_192F = /* @__PURE__ */ slhDsaAlgorithm(9);

export const SLH_DSA_SHAKE_256S = /* @__PURE__ */ slhDsaAlgorithm(10);

export const SLH_DSA_SHAKE_256F = /* @__PURE__ */ slhDsaAlgorithm(11);
