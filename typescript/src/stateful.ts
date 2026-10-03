import { bytes, concat, equal, readUint32, readUint64, uint32, uint64, wipe } from "./bytes.ts";
import { type KeyFormat, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import { exportPublic, importPublic, mismatch, requireLength } from "./keys.ts";
import * as lms from "./lms.ts";
import { sha256 } from "./primitives.ts";
import { randomBytes } from "./rng.ts";
import * as xmss from "./xmss.ts";

const VERSION = 1;

const HSS_KIND = 1;

const XMSS_KIND = 2;

const XMSS_MT_KIND = 3;

export interface StateStore {
  read(): Uint8Array | null | Promise<Uint8Array | null>;

  update(previous: Uint8Array | null, next: Uint8Array): boolean | Promise<boolean>;
}

export type StatefulParameters = string | readonly (readonly [string, string])[];

export interface StatefulKeyGenOptions {
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

// State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
// first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused.
function seal(body: Uint8Array): Uint8Array {
  return concat(body, sha256(body).subarray(0, 16));
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
) => Promise<StatefulKeyPair>;

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

  #state: Uint8Array;

  #index: bigint;

  #queue: Promise<unknown> = Promise.resolve();

  constructor(
    algorithm: StatefulSignatureAlgorithm,
    parameters: unknown,
    seed: Uint8Array,
    signer: Signer,
    store: StateStore,
    state: Uint8Array,
    index: bigint,
  ) {
    this.algorithm = algorithm;

    this.publicKey = new StatefulPublicKey(algorithm, signer.publicKey);

    this.#parameters = parameters;

    this.#seed = seed;

    this.#signer = signer;

    this.#store = store;

    this.#capacity = backendOf(algorithm).capacity(parameters);

    this.#state = state;

    this.#index = index;

    Object.freeze(this);
  }

  remainingSignatures(): bigint {
    return this.#capacity - this.#index;
  }

  // Calls on one key run one after another, so that two signatures never claim the same index.
  sign(message: Uint8Array): Promise<Uint8Array> {
    const data = message instanceof Uint8Array ? message.slice() : message;

    const result = this.#queue.then(() => this.#sign(data));

    this.#queue = result.catch(() => undefined);

    return result;
  }

  // The next index is written to the store before the signature exists, so a crash or a failed
  // write can waste an index but never use one twice.
  async #sign(message: unknown): Promise<Uint8Array> {
    const data = bytes(message, "message");

    const index = this.#index;

    if (index >= this.#capacity) {
      throw new CryptoPQError("KEY_EXHAUSTED", "every one-time key has been used");
    }

    const state = backendOf(this.algorithm).encode(this.#parameters, this.#seed, index + 1n);

    let updated: unknown;

    try {
      updated = await this.#store.update(this.#state.slice(), state.slice());
    } catch (error) {
      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to save the key state", { cause: error });
    }

    if (updated !== true) {
      throw new CryptoPQError("STATE_CONFLICT", "the stored key state changed; load the key again");
    }

    this.#state = state;

    this.#index = index + 1n;

    return this.#signer.sign(index, data);
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

  async generateKeyPair(options: StatefulKeyGenOptions): Promise<StatefulKeyPair> {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("options must be an object");
    }

    const store = checkStore(options.stateStore);

    const parameters = this.#backend.parameters(options.parameters);

    return this.#create(parameters, randomBytes(this.#backend.seedSize(parameters)), 0n, store);
  }

  async loadPrivateKey(stateStore: StateStore): Promise<StatefulPrivateKey> {
    const store = checkStore(stateStore);

    let state: unknown;

    try {
      state = await store.read();
    } catch (error) {
      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to read the key state", { cause: error });
    }

    const { parameters, seed, index } = this.#backend.decode(state);

    if (index > this.#backend.capacity(parameters)) {
      wipe(seed);

      throw mismatch("the stored index is beyond the key's capacity");
    }

    const signer = this.#backend.signer(parameters, seed);

    const copy = (state as Uint8Array).slice();

    return new StatefulPrivateKey(this, parameters, seed, signer, store, copy, index);
  }

  importPublicKey(data: Uint8Array | string, format: KeyFormat): StatefulPublicKey {
    const key = importPublic(format, data, this.#backend.oid);

    if (!this.#backend.checkPublicKey(key)) {
      throw new CryptoPQError("INVALID_PUBLIC_KEY", "the public key is malformed");
    }

    return new StatefulPublicKey(this, key);
  }

  async #create(parameters: unknown, seed: Uint8Array, index: bigint, store: StateStore): Promise<StatefulKeyPair> {
    const backend = this.#backend;

    const signer = backend.signer(parameters, seed);

    const state = backend.encode(parameters, seed, index);

    let created: unknown;

    try {
      created = await store.update(null, state.slice());
    } catch (error) {
      wipe(seed, state);

      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to save the new key", { cause: error });
    }

    if (created !== true) {
      wipe(seed, state);

      throw new CryptoPQError("STATE_CONFLICT", "the state store already holds a key");
    }

    const privateKey = new StatefulPrivateKey(this, parameters, seed, signer, store, state, index);

    return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
  }

  static {
    backendOf = (algorithm) => algorithm.#backend;

    createKey = (algorithm, parameters, seed, index, store) => algorithm.#create(parameters, seed, index, store);
  }
}

export interface HazmatStatefulOptions extends StatefulKeyGenOptions {
  index?: bigint;
}

// Stateful seeds are I || SEED of the top LMS tree, or SK_SEED || SK_PRF || PUB_SEED for XMSS.
export async function keyPairFromSeed(
  algorithm: StatefulSignatureAlgorithm,
  seed: Uint8Array,
  options: HazmatStatefulOptions,
): Promise<StatefulKeyPair> {
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

  return createKey(algorithm, parameters, data.slice(), index, store);
}

export const HSS_LMS = new StatefulSignatureAlgorithm("HSS/LMS", HSS_BACKEND as StatefulBackend<unknown>);

export const XMSS = new StatefulSignatureAlgorithm("XMSS", xmssBackend(false) as StatefulBackend<unknown>);

export const XMSS_MT = new StatefulSignatureAlgorithm("XMSS^MT", xmssBackend(true) as StatefulBackend<unknown>);
