import { bytes, concat, equal, readUint32, readUint64, uint32, uint64, wipe } from "./bytes.ts";
import { type KeyFormat, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import { exportPublic, importPublic, mismatch, readOptions, requireLength } from "./keys.ts";
import * as lms from "./lms.ts";
import { sha256 } from "./primitives.ts";
import { randomBytes } from "./rng.ts";
import * as xmss from "./xmss.ts";

const VERSION = 1;

const HSS_KIND = 1;

const XMSS_KIND = 2;

const XMSS_MT_KIND = 3;

// Both methods answer synchronously: a signature may only exist once its index is stored. Each
// blob holds the secret seed, so update gets copies: previous is wiped when the call returns, and
// next belongs to the store.
export interface StateStore {
  read(): Uint8Array | null;

  update(previous: Uint8Array | null, next: Uint8Array): boolean;
}

export type StatefulParameters = string | readonly (readonly [string, string])[];

export interface StatefulLoadOptions {
  reserve?: number | bigint;
}

export interface StatefulKeyGenOptions extends StatefulLoadOptions {
  parameters: StatefulParameters;

  stateStore: StateStore;
}

export interface StatefulKeyPair {
  readonly publicKey: StatefulPublicKey;

  readonly privateKey: StatefulPrivateKey;
}

interface Signer {
  readonly publicKey: Uint8Array;

  sign(index: bigint, message: Uint8Array): Uint8Array;
}

// The decoded content of a state blob: the parameter set, the secret seed and the next index.
interface State<P> {
  readonly parameters: P;

  readonly seed: Uint8Array;

  readonly index: bigint;
}

export interface StatefulBackend<P> {
  readonly kind: number;

  readonly oid: Uint8Array;

  parameters(value: unknown): P;

  seedSize(parameters: P): number;

  capacity(parameters: P): bigint;

  encode(parameters: P, seed: Uint8Array, index: bigint): Uint8Array;

  decode(state: unknown): State<P>;

  signer(parameters: P, seed: Uint8Array): Signer;

  checkPublicKey(key: Uint8Array): boolean;

  verify(key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

function option(message: string): CryptoPQError {
  return new CryptoPQError("INVALID_OPTION", message);
}

// How many indices one store update claims, so that the store is written once per that many
// signatures. Indices claimed but unused when the key is dropped are skipped, never reused.
function reserveOption(options: StatefulLoadOptions | undefined): bigint {
  const { reserve = 1 } = readOptions(options);

  if (typeof reserve === "bigint" ? reserve >= 1n : Number.isSafeInteger(reserve) && reserve >= 1) {
    return BigInt(reserve);
  }

  throw option("reserve must be a positive integer");
}

// A thenable means the store has not finished, and a signature must not exist before its index is
// stored; without this check a Promise would read as a refusal or as damaged state.
function synchronous(value: unknown): void {
  const object = (typeof value === "object" && value !== null) || typeof value === "function";

  if (object && typeof (value as { then?: unknown }).then === "function") {
    throw new TypeError("stateStore methods must return their result, not a promise");
  }
}

// State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
// first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused. The body is
// a temporary copy of the seeds, so it is wiped once sealed.
function seal(body: Uint8Array): Uint8Array {
  const state = concat(body, sha256(body).subarray(0, 16));

  wipe(body);

  return state;
}

function unseal(state: unknown, kind: number): Uint8Array {
  if (!(state instanceof Uint8Array) || state.length < 18) {
    throw mismatch("the state store holds no valid key");
  }

  const body = state.subarray(0, state.length - 16);

  if (!equal(sha256(body).subarray(0, 16), state.subarray(state.length - 16)) || body[0] !== VERSION) {
    throw mismatch("the stored key state is damaged or unsupported");
  }

  if (body[1] !== kind) {
    throw new CryptoPQError("ALGORITHM_MISMATCH", "the stored key belongs to another algorithm");
  }

  return body.subarray(2);
}

const HSS_BACKEND: StatefulBackend<readonly lms.Level[]> = {
  kind: HSS_KIND,
  oid: objectIdentifier("1.2.840.113549.1.9.16.3.17"),
  parameters(value) {
    if (!Array.isArray(value)) {
      throw option("parameters must be a list of (LMS, LM-OTS) type names, one per level");
    }

    const levels = value.map((level: unknown): lms.Level => {
      if (!Array.isArray(level) || level.length !== 2) {
        throw option("each level must be a pair of LMS and LM-OTS type names");
      }

      const tree = lms.LMS_BY_NAME.get(level[0]);

      const ots = lms.OTS_BY_NAME.get(level[1]);

      if (tree === undefined || ots === undefined) {
        throw option(`unknown LMS or LM-OTS type ${String(level[0])}, ${String(level[1])}`);
      }

      return [tree, ots];
    });

    if (levels.length < 1 || levels.length > 8) {
      throw option("HSS needs between 1 and 8 levels");
    }

    const families = new Set(levels.flatMap(([tree, ots]) => [`${tree.shake} ${tree.m}`, `${ots.shake} ${ots.n}`]));

    if (families.size !== 1) {
      throw option("every level must use the same hash function and output size");
    }

    if (levels.reduce((total, [tree]) => total + tree.h, 0) > 60) {
      throw option("the total tree height must not exceed 60");
    }

    return levels;
  },
  seedSize: (levels) => 16 + levels[0][0].m,
  capacity: (levels) => 1n << BigInt(levels.reduce((total, [tree]) => total + tree.h, 0)),
  encode(levels, seed, index) {
    const codes = levels.flatMap(([tree, ots]) => [uint32(tree.code), uint32(ots.code)]);

    return seal(concat(Uint8Array.of(VERSION, HSS_KIND, levels.length), ...codes, seed, uint64(index)));
  },
  decode(state) {
    const body = unseal(state, HSS_KIND);

    const count = body.length > 0 ? body[0] : 0;

    if (body.length < 1 + 8 * count) {
      throw mismatch("the stored key has invalid parameters");
    }

    let levels: readonly lms.Level[];

    try {
      const names: [string, string][] = [];

      for (let i = 0; i < count; i++) {
        const tree = lms.LMS_TYPES.get(readUint32(body, 1 + 8 * i));

        const ots = lms.OTS_TYPES.get(readUint32(body, 5 + 8 * i));

        if (tree === undefined || ots === undefined) {
          throw option("unknown type code");
        }

        names.push([tree.name, ots.name]);
      }

      levels = HSS_BACKEND.parameters(names);
    } catch {
      throw mismatch("the stored key has invalid parameters");
    }

    const rest = body.subarray(1 + 8 * count);

    const size = HSS_BACKEND.seedSize(levels);

    if (rest.length !== size + 8) {
      throw mismatch("the stored key has the wrong length");
    }

    return { parameters: levels, seed: rest.slice(0, size), index: readUint64(rest, size) };
  },
  signer: (levels, seed) => new lms.Hss(levels, seed.subarray(0, 16), seed.subarray(16)),
  checkPublicKey: (key) => lms.checkPublicKey(key),
  verify: (key, message, signature) => lms.hssVerify(key, message, signature),
};

function xmssBackend(multi: boolean): StatefulBackend<xmss.Parameters> {
  const kind = multi ? XMSS_MT_KIND : XMSS_KIND;

  const sets = multi ? xmss.XMSS_MT_SETS : xmss.XMSS_SETS;

  const oidOf = (key: Uint8Array) => (key.length >= 4 ? xmss.byOid(sets, readUint32(key, 0)) : null);

  return {
    kind,
    oid: objectIdentifier(`1.3.6.1.5.5.7.6.${multi ? 35 : 34}`),
    parameters(value) {
      const p = typeof value === "string" ? sets.get(value) : undefined;

      if (p === undefined) {
        throw option(`parameters must be one of ${[...sets.keys()].join(", ")}`);
      }

      return p;
    },
    seedSize: (p) => 3 * p.n,
    capacity: (p) => 1n << BigInt(p.h),
    encode: (p, seed, index) => seal(concat(Uint8Array.of(VERSION, kind), uint32(p.oid), uint64(index), seed)),
    decode(state) {
      const body = unseal(state, kind);

      const p = oidOf(body);

      if (p === null || body.length !== 12 + 3 * p.n) {
        throw mismatch("the stored key has invalid parameters");
      }

      return { parameters: p, seed: body.slice(12), index: readUint64(body, 4) };
    },
    signer(p, seed) {
      const n = p.n;

      return new xmss.Xmss(p, seed.subarray(0, n), seed.subarray(n, 2 * n), seed.subarray(2 * n));
    },
    checkPublicKey(key) {
      const p = oidOf(key);

      return p !== null && key.length === p.publicKeySize;
    },
    verify(key, message, signature) {
      const p = oidOf(key);

      return p !== null && xmss.verify(p, key, message, signature);
    },
  };
}

function checkStore(store: unknown): StateStore {
  if (store === undefined || store === null) {
    throw new CryptoPQError("INVALID_OPTION", "a stateStore is required");
  }

  const candidate = store as Partial<StateStore>;

  if (typeof candidate.read !== "function" || typeof candidate.update !== "function") {
    throw new TypeError("stateStore must have read and update methods");
  }

  return candidate as StateStore;
}

let backendOf: (algorithm: StatefulSignatureAlgorithm) => StatefulBackend<unknown>;

let createKey: (
  algorithm: StatefulSignatureAlgorithm,
  parameters: unknown,
  seed: Uint8Array,
  index: bigint,
  store: StateStore,
  reserve: bigint,
) => StatefulKeyPair;

export class StatefulPublicKey {
  readonly algorithm: StatefulSignatureAlgorithm;

  readonly #key: Uint8Array;

  constructor(algorithm: StatefulSignatureAlgorithm, key: Uint8Array) {
    this.algorithm = algorithm;

    this.#key = key;

    Object.freeze(this);
  }

  verify(signature: Uint8Array, message: Uint8Array): boolean {
    const data = bytes(signature, "signature");

    return backendOf(this.algorithm).verify(this.#key, bytes(message, "message"), data);
  }

  exportKey(format: "pem"): string;

  exportKey(format: "raw" | "der"): Uint8Array;

  exportKey(format: KeyFormat): Uint8Array | string;

  exportKey(format: KeyFormat): Uint8Array | string {
    return exportPublic(format, backendOf(this.algorithm).oid, this.#key);
  }

  equals(other: StatefulPublicKey): boolean {
    return (
      typeof other === "object" &&
      other !== null &&
      #key in other &&
      other.algorithm === this.algorithm &&
      equal(other.#key, this.#key)
    );
  }
}

export class StatefulPrivateKey {
  readonly algorithm: StatefulSignatureAlgorithm;

  readonly publicKey: StatefulPublicKey;

  readonly #parameters: unknown;

  readonly #seed: Uint8Array;

  readonly #signer: Signer;

  readonly #store: StateStore;

  readonly #capacity: bigint;

  readonly #reserve: bigint;

  // The blob in the store, whose next index is #reserved: the indices from #index up to it are
  // claimed and not used yet.
  #state: Uint8Array;

  #index: bigint;

  #reserved: bigint;

  #busy = false;

  constructor(
    algorithm: StatefulSignatureAlgorithm,
    parameters: unknown,
    seed: Uint8Array,
    signer: Signer,
    store: StateStore,
    state: Uint8Array,
    index: bigint,
    reserve: bigint,
  ) {
    this.algorithm = algorithm;

    this.publicKey = new StatefulPublicKey(algorithm, signer.publicKey);

    this.#parameters = parameters;

    this.#seed = seed;

    this.#signer = signer;

    this.#store = store;

    this.#capacity = backendOf(algorithm).capacity(parameters);

    this.#reserve = reserve;

    this.#state = state;

    this.#index = index;

    this.#reserved = index;

    Object.freeze(this);
  }

  remainingSignatures(): bigint {
    return this.#capacity - this.#index;
  }

  // A call made while this key is signing can only come from inside the store, and on one thread
  // waiting for the first call would never end, so it fails at once.
  sign(message: Uint8Array): Uint8Array {
    if (this.#busy) {
      throw new CryptoPQError("STATE_CONFLICT", "the key is signing in another call");
    }

    this.#busy = true;

    try {
      return this.#sign(bytes(message, "message"));
    } finally {
      this.#busy = false;
    }
  }

  // An index is in the store before its signature exists, so a crash or a failed write can waste
  // indices but never use one twice.
  #sign(message: Uint8Array): Uint8Array {
    const index = this.#index;

    if (index >= this.#capacity) {
      throw new CryptoPQError("KEY_EXHAUSTED", "every one-time key has been used");
    }

    if (index === this.#reserved) {
      const end = index + this.#reserve;

      this.#claim(end < this.#capacity ? end : this.#capacity);
    }

    this.#index = index + 1n;

    return this.#signer.sign(index, message);
  }

  // Stores reserved as the next index. Every blob holds the seed, so the key wipes the copy it hands
  // to update as previous, the blob it replaces, and the new blob if the store refuses it.
  #claim(reserved: bigint): void {
    const state = backendOf(this.algorithm).encode(this.#parameters, this.#seed, reserved);

    const previous = this.#state.slice();

    let updated: unknown;

    try {
      updated = this.#store.update(previous, state.slice());
    } catch (error) {
      wipe(state);

      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to save the key state", { cause: error });
    } finally {
      wipe(previous);
    }

    if (updated !== true) {
      wipe(state);

      synchronous(updated);

      throw new CryptoPQError("STATE_CONFLICT", "the stored key state changed; load the key again");
    }

    wipe(this.#state);

    this.#state = state;

    this.#reserved = reserved;
  }
}

export class StatefulSignatureAlgorithm {
  readonly name: string;

  readonly #backend: StatefulBackend<unknown>;

  constructor(name: string, backend: StatefulBackend<unknown>) {
    this.name = name;

    this.#backend = backend;

    Object.freeze(this);
  }

  generateKeyPair(options: StatefulKeyGenOptions): StatefulKeyPair {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("options must be an object");
    }

    const store = checkStore(options.stateStore);

    const parameters = this.#backend.parameters(options.parameters);

    const reserve = reserveOption(options);

    return this.#create(parameters, randomBytes(this.#backend.seedSize(parameters)), 0n, store, reserve);
  }

  // The key starts at the stored index, so indices that an earlier key claimed and never used are
  // skipped.
  loadPrivateKey(stateStore: StateStore, options?: StatefulLoadOptions): StatefulPrivateKey {
    const store = checkStore(stateStore);

    const reserve = reserveOption(options);

    let state: unknown;

    try {
      state = store.read();
    } catch (error) {
      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to read the key state", { cause: error });
    }

    synchronous(state);

    const { parameters, seed, index } = this.#backend.decode(state);

    if (index > this.#backend.capacity(parameters)) {
      wipe(seed);

      throw mismatch("the stored index is beyond the key's capacity");
    }

    const signer = this.#backend.signer(parameters, seed);

    const copy = (state as Uint8Array).slice();

    return new StatefulPrivateKey(this, parameters, seed, signer, store, copy, index, reserve);
  }

  importPublicKey(data: Uint8Array | string, format: KeyFormat): StatefulPublicKey {
    const key = importPublic(format, data, this.#backend.oid);

    if (!this.#backend.checkPublicKey(key)) {
      throw new CryptoPQError("INVALID_PUBLIC_KEY", "the public key is malformed");
    }

    return new StatefulPublicKey(this, key);
  }

  // The store gets the starting index; the first signature then claims the reserved indices.
  #create(parameters: unknown, seed: Uint8Array, index: bigint, store: StateStore, reserve: bigint): StatefulKeyPair {
    const backend = this.#backend;

    const signer = backend.signer(parameters, seed);

    const state = backend.encode(parameters, seed, index);

    let created: unknown;

    try {
      created = store.update(null, state.slice());
    } catch (error) {
      wipe(seed, state);

      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to save the new key", { cause: error });
    }

    if (created !== true) {
      wipe(seed, state);

      synchronous(created);

      throw new CryptoPQError("STATE_CONFLICT", "the state store already holds a key");
    }

    const privateKey = new StatefulPrivateKey(this, parameters, seed, signer, store, state, index, reserve);

    return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
  }

  static {
    backendOf = (algorithm) => algorithm.#backend;

    createKey = (algorithm, parameters, seed, index, store, reserve) =>
      algorithm.#create(parameters, seed, index, store, reserve);
  }
}

export interface HazmatStatefulOptions extends StatefulKeyGenOptions {
  index?: bigint;
}

// Stateful seeds are I || SEED of the top LMS tree, or SK_SEED || SK_PRF || PUB_SEED for XMSS.
export function keyPairFromSeed(
  algorithm: StatefulSignatureAlgorithm,
  seed: Uint8Array,
  options: HazmatStatefulOptions,
): StatefulKeyPair {
  const data = bytes(seed, "seed");

  if (typeof options !== "object" || options === null) {
    throw new TypeError("options must be an object");
  }

  const store = checkStore(options.stateStore);

  const backend = backendOf(algorithm);

  const parameters = backend.parameters(options.parameters);

  requireLength(data, backend.seedSize(parameters), "seed");

  const { index = 0n } = options;

  if (typeof index !== "bigint") {
    throw new TypeError("index must be a bigint");
  }

  if (index < 0n || index > backend.capacity(parameters)) {
    throw option("the index must lie between 0 and the key's capacity");
  }

  return createKey(algorithm, parameters, data.slice(), index, store, reserveOption(options));
}

export const HSS_LMS = new StatefulSignatureAlgorithm("HSS/LMS", HSS_BACKEND as StatefulBackend<unknown>);

export const XMSS = new StatefulSignatureAlgorithm("XMSS", xmssBackend(false) as StatefulBackend<unknown>);

export const XMSS_MT = new StatefulSignatureAlgorithm("XMSS^MT", xmssBackend(true) as StatefulBackend<unknown>);
