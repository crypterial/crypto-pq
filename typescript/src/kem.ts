import { bytes, equal, wipe } from "./bytes.ts";
import { type KeyFormat, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import { ML_KEM, X_WING_HASH } from "./families.ts";
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
import { type Core, type Family, PUBLIC, SECRET, Slot, check } from "./wasm.ts";
import * as xwing from "./xwing.ts";

const PUBLIC_SLOT = 1;

const PRIVATE_SLOT = 2;

const FILL_CACHE = 1;

const PUBLIC_CACHE = 0x100;

const INVALID_PUBLIC_KEY = 4;

// How a key encapsulates on the backend that made it. Without randomness it draws its own; given
// randomness is wiped after use.
interface Encapsulator {
  encapsulate(randomness: Uint8Array | null): [Uint8Array, Uint8Array];
}

// The private half of a key on the backend that made it. raw and expanded return new arrays: the
// raw private key and whether it is the seed (a key imported in expanded form, which only ML-KEM
// has, gives the expanded key), and the expanded key.
interface Secret {
  raw(): [Uint8Array, boolean];

  expanded(): Uint8Array;

  decapsulate(ciphertext: Uint8Array): Uint8Array;

  wipe(): void;
}

// A new key as a backend makes it: the public key, how to encapsulate to it and the secret.
type NewKey = [Uint8Array, Encapsulator, Secret];

// One algorithm on one backend. fromSeed draws the seed when none is given and runs the pairwise
// consistency test of a new key pair when asked; a seed or expanded key that it is given belongs
// to the new key afterwards.
interface Engine {
  fromSeed(seed: Uint8Array | null, test: boolean): NewKey;

  fromExpanded(dk: Uint8Array): NewKey;

  importPublic(key: Uint8Array): Encapsulator | null;
}

interface KemSizes {
  readonly seed: number;

  readonly randomness: number;

  readonly publicKey: number;

  readonly ciphertext: number;

  readonly expanded: number | null;
}

export interface KemBackend extends KemSizes {
  readonly oid: Uint8Array | null;

  readonly family: Family;

  readonly js: Engine;

  readonly wasm: Engine;
}

export interface KemKeyPair {
  readonly publicKey: KemPublicKey;

  readonly privateKey: KemPrivateKey;
}

export interface Encapsulation {
  readonly sharedSecret: Uint8Array;

  readonly ciphertext: Uint8Array;
}

function encapsulator(encapsulate: (randomness: Uint8Array) => [Uint8Array, Uint8Array], size: number): Encapsulator {
  return {
    encapsulate(randomness) {
      const m = randomness ?? randomBytes(size);

      try {
        return encapsulate(m);
      } finally {
        m.fill(0);
      }
    },
  };
}

function pairwise(key: NewKey): NewKey {
  const [sharedSecret, ciphertext] = key[1].encapsulate(null);

  const decapsulated = key[2].decapsulate(ciphertext);

  const consistent = equal(decapsulated, sharedSecret);

  wipe(sharedSecret, decapsulated);

  if (!consistent) {
    throw new CryptoPQError("SELF_TEST_FAILED", "the new key pair failed its consistency test");
  }

  return key;
}

function unexpanded(): CryptoPQError {
  return new CryptoPQError("UNSUPPORTED", "X-Wing has no expanded private key");
}

// The cache of a public key lives with it and is shared with the private key it belongs to.
function mlKemJs(params: mlkem.Parameters): Engine {
  const publicOf = (ek: Uint8Array, cache: mlkem.PublicCache) =>
    encapsulator((m) => mlkem.encapsInternal(ek, cache, m, params), 32);

  const secretOf = (seed: Uint8Array | null, dk: Uint8Array, cache: mlkem.PublicCache): Secret => {
    const secret: mlkem.SecretCache = { s: null };

    return {
      raw: () => [(seed ?? dk).slice(), seed !== null],
      expanded: () => dk.slice(),
      decapsulate: (ciphertext) => mlkem.decapsInternal(dk, secret, cache, ciphertext, params),
      wipe: () => wipe(dk, seed ?? dk),
    };
  };

  return {
    fromSeed(seed, test) {
      const s = seed ?? randomBytes(64);

      const [ek, dk] = mlkem.keygenInternal(s.subarray(0, 32), s.subarray(32), params);

      const cache = mlkem.publicCache(mlkem.digestOf(dk, params));

      const key: NewKey = [ek, publicOf(ek, cache), secretOf(s, dk, cache)];

      return test ? pairwise(key) : key;
    },
    fromExpanded(dk) {
      if (!mlkem.checkDecapsulationKey(dk, params)) {
        throw mismatch("the decapsulation key fails the FIPS 203 checks");
      }

      const ek = mlkem.publicKeyOf(dk, params);

      const cache = mlkem.publicCache(mlkem.digestOf(dk, params));

      return [ek, publicOf(ek, cache), secretOf(null, dk, cache)];
    },
    importPublic: (key) => (mlkem.checkEncapsulationKey(key, params) ? publicOf(key, mlkem.publicCache()) : null),
  };
}

// The cache of an X-Wing key is that of its ML-KEM part.
const X_WING_JS: Engine = {
  fromSeed(seed, test) {
    const s = seed ?? randomBytes(xwing.SEED_SIZE);

    const [pk, key, cache] = xwing.expand(s);

    const secret: Secret = {
      raw: () => [s.slice(), true],
      expanded() {
        throw unexpanded();
      },
      decapsulate: (ciphertext) => xwing.decapsulate(key, cache, ciphertext),
      wipe: () => wipe(s, key.dk, key.scalar),
    };

    const newKey: NewKey = [pk, encapsulator((eseed) => xwing.encapsulate(pk, cache, eseed), 64), secret];

    return test ? pairwise(newKey) : newKey;
  },
  fromExpanded() {
    throw unexpanded();
  },
  importPublic(key) {
    const cache = mlkem.publicCache();

    return xwing.checkPublicKey(key) ? encapsulator((eseed) => xwing.encapsulate(key, cache, eseed), 64) : null;
  },
};

// Keys live as copies of their slots, which every call places in the instance's I/O block: a key's
// caches fill on first use as in TypeScript, and the private slot holds its own public part.
function kemWasm(family: Family, id: number, sizes: KemSizes): Engine {
  const encapsulatorOf = (slot: Slot): Encapsulator => ({
    encapsulate(randomness) {
      const core = family.core();

      const size = slot.bytes.length;

      try {
        return core.run(SECRET, [size, sizes.randomness, sizes.ciphertext, 32], ([key, r, ciphertext, shared]) => {
          slot.load(core, key);

          if (randomness === null) {
            core.random(r, sizes.randomness);
          } else {
            core.write(r, randomness);
          }

          check(core.x.cpq_kem_encapsulate(key, size, r, sizes.randomness, ciphertext, sizes.ciphertext, shared, 32));

          slot.update(core, key);

          return [core.read(shared, 32), core.read(ciphertext, sizes.ciphertext)];
        });
      } finally {
        randomness?.fill(0);
      }
    },
  });

  const secretOf = (slot: Slot, seeded: boolean): Secret => {
    const size = slot.bytes.length;

    const exported = (which: number, length: number) => {
      const core = family.core();

      return core.run(SECRET, [size, length], ([key, out]) => {
        slot.load(core, key);

        check(core.x.cpq_kem_export_private(key, size, which, out, length));

        return core.read(out, length);
      });
    };

    return {
      raw: () => [seeded ? exported(0, sizes.seed) : exported(1, sizes.expanded!), seeded],
      expanded: () => exported(1, sizes.expanded!),
      decapsulate(ciphertext) {
        const core = family.core();

        return core.run(SECRET, [size, ciphertext.length, 32], ([key, input, shared]) => {
          slot.load(core, key);

          core.write(input, ciphertext);

          check(core.x.cpq_kem_decapsulate(key, size, input, ciphertext.length, shared, 32));

          slot.update(core, key);

          return core.read(shared, 32);
        });
      },
      wipe: () => slot.bytes.fill(0),
    };
  };

  // The key made in the private slot at key: its public slot, made at public, and the public key,
  // exported at raw.
  const created = (core: Core, at: readonly number[], seeded: boolean): NewKey => {
    const [key, publicSlot, raw] = at;

    const privateSize = core.size(PRIVATE_SLOT, id);

    const publicSize = core.size(PUBLIC_SLOT, id);

    check(core.x.cpq_kem_public_from_private(key, privateSize, publicSlot, publicSize));

    check(core.x.cpq_kem_export_public(publicSlot, publicSize, raw, sizes.publicKey));

    const pk = core.read(raw, sizes.publicKey);

    const encapsulator = encapsulatorOf(new Slot(core, publicSlot, publicSize, PUBLIC_CACHE));

    return [pk, encapsulator, secretOf(new Slot(core, key, privateSize, PUBLIC_CACHE), seeded)];
  };

  const slots = (core: Core) => [core.size(PRIVATE_SLOT, id), core.size(PUBLIC_SLOT, id), sizes.publicKey];

  return {
    fromSeed(seed, test) {
      const core = family.core();

      try {
        return core.run(SECRET, [...slots(core), sizes.seed, sizes.randomness], (at) => {
          const [key, , , s, r] = at;

          const privateSize = core.size(PRIVATE_SLOT, id);

          if (seed === null) {
            core.random(s, sizes.seed);
          } else {
            core.write(s, seed);
          }

          check(core.x.cpq_kem_keygen(id, s, sizes.seed, test ? FILL_CACHE : 0, key, privateSize));

          if (test) {
            core.random(r, sizes.randomness);

            check(core.x.cpq_kem_self_test(key, privateSize, r, sizes.randomness));
          }

          return created(core, at, true);
        });
      } finally {
        seed?.fill(0);
      }
    },
    fromExpanded(dk) {
      const core = family.core();

      try {
        return core.run(SECRET, [...slots(core), dk.length], (at) => {
          const [key, , , input] = at;

          core.write(input, dk);

          const status = core.x.cpq_kem_import_private(id, input, dk.length, key, core.size(PRIVATE_SLOT, id));

          check(status, { INVALID_PRIVATE_KEY: "the decapsulation key fails the FIPS 203 checks" });

          return created(core, at, false);
        });
      } finally {
        dk.fill(0);
      }
    },
    importPublic(pk) {
      const core = family.core();

      const publicSize = core.size(PUBLIC_SLOT, id);

      return core.run(PUBLIC, [publicSize, pk.length], ([publicSlot, input]) => {
        core.write(input, pk);

        const status = core.x.cpq_kem_import_public(id, input, pk.length, publicSlot, publicSize);

        if (status === INVALID_PUBLIC_KEY) {
          return null;
        }

        check(status);

        return encapsulatorOf(new Slot(core, publicSlot, publicSize, PUBLIC_CACHE));
      });
    },
  };
}

function mlKem(params: mlkem.Parameters, arc: number, id: number): KemBackend {
  const sizes: KemSizes = {
    seed: 64,
    randomness: 32,
    publicKey: params.encapsulationKeySize,
    ciphertext: params.ciphertextSize,
    expanded: params.decapsulationKeySize,
  };

  return {
    ...sizes,
    oid: objectIdentifier(`2.16.840.1.101.3.4.4.${arc}`),
    family: ML_KEM,
    js: mlKemJs(params),
    wasm: kemWasm(ML_KEM, id, sizes),
  };
}

function xWing(): KemBackend {
  const sizes: KemSizes = {
    seed: xwing.SEED_SIZE,
    randomness: 64,
    publicKey: xwing.PUBLIC_KEY_SIZE,
    ciphertext: xwing.CIPHERTEXT_SIZE,
    expanded: null,
  };

  return { ...sizes, oid: null, family: X_WING_HASH, js: X_WING_JS, wasm: kemWasm(X_WING_HASH, 3, sizes) };
}

let backendOf: (algorithm: KemAlgorithm) => KemBackend;

let fromSeed: (algorithm: KemAlgorithm, seed: Uint8Array) => KemPrivateKey;

let encapsulateWith: (publicKey: KemPublicKey, randomness: Uint8Array) => Encapsulation;

export class KemPublicKey {
  readonly algorithm: KemAlgorithm;

  readonly #key: Uint8Array;

  // What encapsulation derives from the key, on the backend that made the key, filled on first use
  // unless the key's creator supplies part of it.
  readonly #encapsulator: Encapsulator;

  constructor(algorithm: KemAlgorithm, key: Uint8Array, encapsulator: Encapsulator) {
    this.algorithm = algorithm;

    this.#key = key;

    this.#encapsulator = encapsulator;

    Object.freeze(this);
  }

  encapsulate(): Encapsulation {
    return this.#encapsulate(null);
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

  #encapsulate(randomness: Uint8Array | null): Encapsulation {
    const [sharedSecret, ciphertext] = this.#encapsulator.encapsulate(randomness);

    return Object.freeze({ sharedSecret, ciphertext });
  }

  static {
    encapsulateWith = (publicKey, randomness) => publicKey.#encapsulate(randomness);
  }
}

export class KemPrivateKey {
  readonly algorithm: KemAlgorithm;

  readonly publicKey: KemPublicKey;

  readonly #secret: Secret;

  constructor(algorithm: KemAlgorithm, secret: Secret, publicKey: KemPublicKey) {
    this.algorithm = algorithm;

    this.publicKey = publicKey;

    this.#secret = secret;

    Object.freeze(this);
  }

  decapsulate(ciphertext: Uint8Array): Uint8Array {
    const data = bytes(ciphertext, "ciphertext");

    requireLength(data, this.algorithm.ciphertextSize, "ciphertext");

    return this.#secret.decapsulate(data);
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  exportKey(format: KeyFormat): Uint8Array | string {
    const [raw, seed] = this.#secret.raw();

    try {
      return exportPrivate(format, backendOf(this.algorithm).oid, () => encodeSeedChoice(raw, seed), raw);
    } finally {
      raw.fill(0);
    }
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

    this.publicKeySize = backend.publicKey;

    this.ciphertextSize = backend.ciphertext;

    this.#backend = backend;

    Object.freeze(this);
  }

  // Where new keys of this algorithm run, deciding it on first use.
  get backend(): "wasm" | "js" {
    return this.#backend.family.select() === null ? "js" : "wasm";
  }

  generateKeyPair(options?: KeyGenOptions): KemKeyPair {
    const test = selfTest(options);

    const privateKey = this.#create(this.#engine().fromSeed(null, test));

    return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
  }

  importPublicKey(data: Uint8Array | string, format: KeyFormat): KemPublicKey {
    const backend = this.#backend;

    const key = importPublic(format, data, backend.oid);

    requireKeyLength(key, backend.publicKey, format, "public key");

    const found = this.#engine().importPublic(key);

    if (found === null) {
      throw new CryptoPQError("INVALID_PUBLIC_KEY", "the public key fails the encoding checks");
    }

    return new KemPublicKey(this, key, found);
  }

  importPrivateKey(data: Uint8Array | string, format: KeyFormat): KemPrivateKey {
    const backend = this.#backend;

    const { octets, raw, publicKey } = importPrivate(format, data, backend.oid);

    if (raw !== null) {
      if (raw.length === backend.seed) {
        return this.#create(this.#engine().fromSeed(raw, false));
      }

      if (backend.expanded !== null && raw.length === backend.expanded) {
        return this.#create(this.#engine().fromExpanded(raw));
      }

      raw.fill(0);

      throw new CryptoPQError("INVALID_LENGTH", "the private key has the wrong length");
    }

    // PKCS#8 input exists only for algorithms with an OID, which all have the expanded form.
    const { seed, expanded } = decodeSeedChoice(octets!, backend.seed, backend.expanded!);

    octets!.fill(0);

    const engine = this.#engine();

    const key = seed !== null ? engine.fromSeed(seed, false) : engine.fromExpanded(expanded!);

    let agrees = true;

    if (seed !== null && expanded !== null) {
      const dk = key[2].expanded();

      agrees = equal(expanded, dk);

      wipe(dk, expanded);
    }

    if (!agrees || (publicKey !== null && !equal(publicKey, key[0]))) {
      key[2].wipe();

      throw mismatch(agrees ? "the embedded public key does not match" : "the seed and the expanded key differ");
    }

    return this.#create(key);
  }

  #engine(): Engine {
    const backend = this.#backend;

    return backend.family.select() === null ? backend.js : backend.wasm;
  }

  #create([pk, encapsulator, secret]: NewKey): KemPrivateKey {
    return new KemPrivateKey(this, secret, new KemPublicKey(this, pk, encapsulator));
  }

  static {
    backendOf = (algorithm) => algorithm.#backend;

    fromSeed = (algorithm, seed) => algorithm.#create(algorithm.#engine().fromSeed(seed, false));
  }
}

export function keyPairFromSeed(algorithm: KemAlgorithm, seed: Uint8Array): KemKeyPair {
  const data = bytes(seed, "seed");

  requireLength(data, backendOf(algorithm).seed, "seed");

  const privateKey = fromSeed(algorithm, data.slice());

  return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
}

export function encapsulateDeterministic(publicKey: KemPublicKey, randomness: Uint8Array): Encapsulation {
  const data = bytes(randomness, "randomness");

  requireLength(data, backendOf(publicKey.algorithm).randomness, "randomness");

  return encapsulateWith(publicKey, data.slice());
}

export const ML_KEM_512 = /* @__PURE__ */ new KemAlgorithm("ML-KEM-512", /* @__PURE__ */ mlKem(mlkem.ML_KEM_512, 1, 0));

export const ML_KEM_768 = /* @__PURE__ */ new KemAlgorithm("ML-KEM-768", /* @__PURE__ */ mlKem(mlkem.ML_KEM_768, 2, 1));

export const ML_KEM_1024 = /* @__PURE__ */ new KemAlgorithm(
  "ML-KEM-1024",
  /* @__PURE__ */ mlKem(mlkem.ML_KEM_1024, 3, 2),
);

export const X_WING = /* @__PURE__ */ new KemAlgorithm("X-Wing", /* @__PURE__ */ xWing());
