import { bytes, concat, equal, readUint32, readUint64, uint32, uint64, wipe } from "./bytes.ts";
import { type KeyFormat, invalid, objectIdentifier } from "./encoding.ts";
import { CryptoPQError } from "./errors.ts";
import { STATEFUL_SIGNATURES } from "./families.ts";
import { exportPublic, importPublic, mismatch, readOptions, requireLength } from "./keys.ts";
import * as lms from "./lms.ts";
import { CACHED_HEIGHT, type CachedLevels, type CachedTree } from "./merkle.ts";
import { hmac, sha256 } from "./primitives.ts";
import { randomBytes } from "./rng.ts";
import { type Core, OK, PUBLIC, REJECTED, SECRET, check } from "./wasm.ts";
import * as xmss from "./xmss.ts";

const VERSION = 1;

const HSS_KIND = 1;

const XMSS_KIND = 2;

const XMSS_MT_KIND = 3;

const TREE_CACHE_VERSION = 1;

const TREE_CACHE_LABEL = Uint8Array.from("crypto-pq tree cache v1", (c) => c.charCodeAt(0));

const TAG_SIZE = 32;

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

  treeCache?: Uint8Array;
}

export interface StatefulKeyGenOptions {
  parameters: StatefulParameters;

  stateStore: StateStore;

  reserve?: number | bigint;
}

export interface StatefulKeyPair {
  readonly publicKey: StatefulPublicKey;

  readonly privateKey: StatefulPrivateKey;
}

// The trees of a key in TypeScript.
interface Trees {
  readonly publicKey: Uint8Array;

  sign(index: bigint, message: Uint8Array): Uint8Array;

  cached(): CachedTree[];
}

// A key's trees on the backend that made them. index is the key's next index, at which a signer
// whose WebAssembly instance a fault discarded builds its trees again; free releases the trees of
// a key that will never sign.
interface Signer {
  readonly publicKey: Uint8Array;

  sign(index: bigint, message: Uint8Array): Uint8Array;

  exportTreeCache(index: bigint): Uint8Array;

  free(): void;
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

  signer(parameters: P, seed: Uint8Array, cached?: ReadonlyMap<number, CachedLevels>): Trees;

  // The trees of a tree cache, top first, as [level, height, n].
  layout(parameters: P): readonly (readonly [number, number, number])[];

  // The number of the tree that index signs with on a level or layer.
  treeId(parameters: P, index: bigint, level: number): bigint;

  // The public key around the root, which only the top tree gives: the bytes before it, its size
  // and the bytes after it.
  publicParts(parameters: P, seed: Uint8Array): readonly [Uint8Array, number, Uint8Array];

  // The parameters as the state blob and the tree cache encode them.
  parameterSection(parameters: P): Uint8Array;

  checkPublicKey(key: Uint8Array): boolean;

  verify(key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

function option(message: string): CryptoPQError {
  return new CryptoPQError("INVALID_OPTION", message);
}

// How many indices one store update claims, so that the store is written once per that many
// signatures. Indices claimed but unused when the key is dropped are skipped, never reused.
function reserveOption(options: { reserve?: number | bigint } | undefined): bigint {
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

// A copy, so that the caller cannot change the cache between its checks and its use.
function treeCacheOption(options: StatefulLoadOptions | undefined): Uint8Array | null {
  const { treeCache } = readOptions(options);

  return treeCache === undefined ? null : bytes(treeCache, "treeCache").slice();
}

// The key of the tree cache tag: HKDF-Extract (RFC 5869) of the seed with the label as salt.
function treeCacheKey(seed: Uint8Array): Uint8Array {
  return hmac(32, TREE_CACHE_LABEL, seed);
}

// A tree cache holds public nodes only, but the signer trusts the root of a cached lower tree as the
// child key that its parent signs, and the public key covers only the top root and the top level's
// types, so the cache is authenticated with a key derived from the seed and names every level's
// parameters. The body is the version, the kind, the parameters as the state blob encodes them, the
// public key and every cached tree, top first: its level or layer, its number on that level, its
// lowest cached height, its height, n, its node count and its nodes, level by level from the
// lowest, left to right. The tag, HMAC-SHA-256 of the body, follows it.
function sealTreeCache(kind: number, section: Uint8Array, signer: Trees, seed: Uint8Array): Uint8Array {
  const publicKey = signer.publicKey;

  const trees = signer.cached();

  const parts = [Uint8Array.of(TREE_CACHE_VERSION, kind), section, uint32(publicKey.length), publicKey];

  parts.push(Uint8Array.of(trees.length));

  for (const { level, tree, merkle } of trees) {
    const nodes = merkle.nodes();

    parts.push(Uint8Array.of(level), uint64(tree), Uint8Array.of(merkle.low, merkle.height, merkle.n));

    parts.push(uint32(nodes.length / merkle.n), nodes);
  }

  const body = concat(...parts);

  const key = treeCacheKey(seed);

  try {
    return concat(body, hmac(32, key, body));
  } finally {
    wipe(key);
  }
}

interface ParsedTree {
  readonly level: number;

  readonly tree: bigint;

  readonly low: number;

  readonly height: number;

  readonly n: number;

  readonly count: number;

  readonly nodes: Uint8Array;
}

function parseTreeCache(data: Uint8Array) {
  let position = 0;

  const take = (size: number): Uint8Array => {
    if (size > data.length - position) {
      throw invalid("the tree cache is truncated");
    }

    position += size;

    return data.subarray(position - size, position);
  };

  const [version, kind] = take(2);

  // The parameters have the layout of the kind that the cache names: an HSS level count and a pair
  // of types per level, or an OID. A cache of no known kind cannot be read further.
  const start = position;

  if (kind === HSS_KIND) {
    take(8 * take(1)[0]);
  } else if (kind === XMSS_KIND || kind === XMSS_MT_KIND) {
    take(4);
  } else {
    throw invalid("the tree cache has an unknown kind");
  }

  const section = data.subarray(start, position);

  const publicKey = take(readUint32(take(4), 0));

  const trees: ParsedTree[] = [];

  for (let i = take(1)[0]; i > 0; i--) {
    const header = take(16);

    const n = header[11];

    const count = readUint32(header, 12);

    const nodes = take(count * n);

    trees.push({ level: header[0], tree: readUint64(header, 1), low: header[9], height: header[10], n, count, nodes });
  }

  const body = data.subarray(0, position);

  const tag = take(TAG_SIZE);

  if (position !== data.length) {
    throw invalid("the tree cache has trailing bytes");
  }

  return { version, kind, section, publicKey, trees, body, tag };
}

// The checks run in this order: the structure, then the version, the kind, the parameters and the
// parts of the public key that the state gives, then the tag in constant time, then each tree's
// level and shape.
// Every failure is INVALID_ENCODING except a cache of another algorithm, which is
// ALGORITHM_MISMATCH. A tree that the next index does not sign with is stale: it is skipped and
// built again when needed. The others are returned by level, for the signer to check against their
// own nodes; the caller then compares the signer's public key, and with it the top root, with the
// cache's.
function openTreeCache<P>(
  backend: StatefulBackend<P>,
  parameters: P,
  seed: Uint8Array,
  index: bigint,
  data: Uint8Array,
): [Uint8Array, Map<number, CachedLevels>] {
  const { version, kind, section, publicKey, trees, body, tag } = parseTreeCache(data);

  if (version !== TREE_CACHE_VERSION) {
    throw invalid("the tree cache has an unsupported version");
  }

  if (kind !== backend.kind) {
    throw new CryptoPQError("ALGORITHM_MISMATCH", "the tree cache belongs to another algorithm");
  }

  if (!equal(section, backend.parameterSection(parameters))) {
    throw invalid("the tree cache belongs to other parameters");
  }

  const [before, rootSize, after] = backend.publicParts(parameters, seed);

  const prefix = publicKey.subarray(0, before.length);

  const suffix = publicKey.subarray(before.length + rootSize);

  if (publicKey.length !== before.length + rootSize + after.length || !equal(prefix, before) || !equal(suffix, after)) {
    throw invalid("the tree cache belongs to another key");
  }

  const key = treeCacheKey(seed);

  const expected = hmac(32, key, body);

  const authentic = equal(expected, tag);

  wipe(key, expected);

  if (!authentic) {
    throw invalid("the tree cache is not authentic");
  }

  const layout = backend.layout(parameters);

  const cached = new Map<number, CachedLevels>();

  let previous = -1;

  for (const { level, tree, low, height, n, count, nodes } of trees) {
    const position = layout.findIndex(([entry]) => entry === level);

    if (position <= previous) {
      throw invalid("the tree cache lists an unknown level or its levels out of order");
    }

    previous = position;

    const [, expectedHeight, expectedN] = layout[position];

    const expectedLow = Math.max(0, expectedHeight - CACHED_HEIGHT);

    const shape = low === expectedLow && height === expectedHeight && n === expectedN;

    if (!shape || count !== 2 ** (expectedHeight - expectedLow + 1) - 1) {
      throw invalid("the tree cache does not match the key's parameters");
    }

    if (tree === backend.treeId(parameters, index, level)) {
      cached.set(level, [tree, splitLevels(nodes, low, height, n)]);
    }
  }

  return [publicKey, cached];
}

function splitLevels(nodes: Uint8Array, low: number, height: number, n: number): Uint8Array[] {
  const levels: Uint8Array[] = [];

  let offset = 0;

  for (let z = low; z <= height; z++) {
    const size = n * 2 ** (height - z);

    levels.push(nodes.subarray(offset, offset + size));

    offset += size;
  }

  return levels;
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
    return seal(concat(Uint8Array.of(VERSION, HSS_KIND), HSS_BACKEND.parameterSection(levels), seed, uint64(index)));
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
  signer: (levels, seed, cached) => new lms.Hss(levels, seed.subarray(0, 16), seed.subarray(16), cached),
  layout: (levels) => levels.map(([tree], level) => [level, tree.h, tree.m] as const),
  treeId(levels, index, level) {
    return level === 0 ? 0n : index >> BigInt(levels.slice(level).reduce((total, [tree]) => total + tree.h, 0));
  },
  publicParts(levels, seed) {
    const [tree, ots] = levels[0];

    const before = concat(uint32(levels.length), uint32(tree.code), uint32(ots.code), seed.subarray(0, 16));

    return [before, tree.m, new Uint8Array()];
  },
  parameterSection(levels) {
    const codes = levels.flatMap(([tree, ots]) => [uint32(tree.code), uint32(ots.code)]);

    return concat(Uint8Array.of(levels.length), ...codes);
  },
  checkPublicKey: (key) => lms.checkPublicKey(key),
  verify: (key, message, signature) => lms.hssVerify(key, message, signature),
};

function xmssBackend(multi: boolean): StatefulBackend<xmss.Parameters> {
  const kind = multi ? XMSS_MT_KIND : XMSS_KIND;

  const sets = multi ? xmss.XMSS_MT_SETS : xmss.XMSS_SETS;

  const oidOf = (key: Uint8Array) => (key.length >= 4 ? xmss.byOid(sets, readUint32(key, 0)) : null);

  const section = (p: xmss.Parameters) => uint32(p.oid);

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
    encode: (p, seed, index) => seal(concat(Uint8Array.of(VERSION, kind), section(p), uint64(index), seed)),
    parameterSection: section,
    decode(state) {
      const body = unseal(state, kind);

      const p = oidOf(body);

      if (p === null || body.length !== 12 + 3 * p.n) {
        throw mismatch("the stored key has invalid parameters");
      }

      return { parameters: p, seed: body.slice(12), index: readUint64(body, 4) };
    },
    signer(p, seed, cached) {
      const n = p.n;

      return new xmss.Xmss(p, seed.subarray(0, n), seed.subarray(n, 2 * n), seed.subarray(2 * n), cached);
    },
    layout: (p) => Array.from({ length: p.d }, (_, i) => [p.d - 1 - i, p.treeHeight, p.n] as const),
    treeId: (p, index, layer) => (layer === p.d - 1 ? 0n : index >> BigInt((layer + 1) * p.treeHeight)),
    publicParts: (p, seed) => [uint32(p.oid), p.n, seed.subarray(2 * p.n)],
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

function jsSigner<P>(backend: StatefulBackend<P>, parameters: P, seed: Uint8Array, trees: Trees): Signer {
  return {
    publicKey: trees.publicKey,
    sign: (index, message) => trees.sign(index, message),
    exportTreeCache: () => sealTreeCache(backend.kind, backend.parameterSection(parameters), trees, seed),
    free() {},
  };
}

const SIGNER_SLOT = 8;

const WITH_TREE_CACHE = 1;

const INVALID_PUBLIC_KEY = 4;

// The largest state blob and public key of any parameter set.
const STATE_LIMIT = 160;

const PUBLIC_LIMIT = 128;

const TREE_CACHE_ERRORS = {
  INVALID_ENCODING: "the tree cache is damaged or belongs to another key",
  ALGORITHM_MISMATCH: "the tree cache belongs to another algorithm",
};

// A signer's slot in WebAssembly memory: a block of its own, which holds the only pointer that the
// library keeps, to the trees it allocated.
interface Handle {
  readonly core: Core;

  readonly slot: number;

  readonly size: number;
}

// Frees a signer that no call is using: the key that held it is gone, or never left the call that
// made it. A refusal can then only be a fault, which discards the instance and zeroes its memory,
// so nothing remains to free and the caller's own error stands.
function release({ core, slot, size }: Handle): void {
  if (!core.live) {
    return;
  }

  try {
    core.run(SECRET, [], () => {
      if (core.x.cpq_slot_wipe(slot, size) !== OK) {
        throw new Error("the library refused to free a stateful signer");
      }

      core.free(slot, size);
    });
  } catch {}
}

let signers: FinalizationRegistry<Handle> | null | undefined;

function watch(signer: object, handle: Handle): void {
  if (signers === undefined) {
    signers = typeof FinalizationRegistry === "function" ? new FinalizationRegistry(release) : null;
  }

  signers?.register(signer, handle, signer);
}

// Builds the trees of the key from its seed at index, or, given the state that the key's own checks
// accepted, loads them with the tree cache if any: the handle, the public key and the signature size.
function open(
  kind: number,
  section: Uint8Array,
  seed: Uint8Array,
  index: bigint,
  state: Uint8Array | null,
  cache: Uint8Array | null,
): [Handle, Uint8Array, number] {
  const core = STATEFUL_SIGNATURES.core();

  const size = core.size(SIGNER_SLOT, kind);

  const slot = core.allocate(size);

  const lengths = [section.length, seed.length, STATE_LIMIT, state?.length ?? 0, cache?.length ?? 0, PUBLIC_LIMIT];

  try {
    return core.run(SECRET, lengths, ([parameters, s, created, stored, c, publicKey]) => {
      core.write(parameters, section);

      check(core.x.cpq_stateful_info(kind, parameters, section.length, core.scratch));

      const view = new DataView(core.bytes().buffer);

      const [stateSize, publicKeySize, signatureSize] = [1, 2, 3].map((i) =>
        Number(view.getBigUint64(core.scratch + 8 * i, true)),
      );

      if (stateSize > STATE_LIMIT || publicKeySize > PUBLIC_LIMIT) {
        throw new Error("the stateful parameters exceed the sizes this binding expects");
      }

      if (state === null) {
        core.write(s, seed);

        check(
          core.x.cpq_stateful_signer_create(
            kind,
            parameters,
            section.length,
            s,
            seed.length,
            index,
            created,
            stateSize,
            slot,
            size,
          ),
        );
      } else {
        core.write(stored, state);

        const flags = cache === null ? 0 : WITH_TREE_CACHE;

        if (cache !== null) {
          core.write(c, cache);
        }

        const status = core.x.cpq_stateful_signer_load(
          kind,
          stored,
          state.length,
          c,
          cache?.length ?? 0,
          flags,
          slot,
          size,
          core.scratch,
        );

        check(status, TREE_CACHE_ERRORS);
      }

      check(core.x.cpq_stateful_signer_public_key(slot, size, publicKey, publicKeySize));

      return [{ core, slot, size }, core.read(publicKey, publicKeySize), signatureSize];
    });
  } catch (error) {
    release({ core, slot, size });

    throw error;
  }
}

// A key's trees in WebAssembly memory, which the library keeps between calls. They are freed when
// the key is garbage collected, or at once for a key that will never sign.
class WasmSigner implements Signer {
  readonly publicKey: Uint8Array;

  readonly #kind: number;

  readonly #section: Uint8Array;

  readonly #seed: Uint8Array;

  readonly #signatureSize: number;

  #handle: Handle;

  constructor(
    kind: number,
    section: Uint8Array,
    seed: Uint8Array,
    index: bigint,
    state: Uint8Array | null,
    cache: Uint8Array | null,
  ) {
    const [handle, publicKey, signatureSize] = open(kind, section, seed, index, state, cache);

    this.publicKey = publicKey;

    this.#kind = kind;

    this.#section = section;

    this.#seed = seed;

    this.#signatureSize = signatureSize;

    this.#handle = handle;

    watch(this, handle);
  }

  sign(index: bigint, message: Uint8Array): Uint8Array {
    const { core, slot, size } = this.#live(index);

    const length = this.#signatureSize;

    return core.run(SECRET, [message.length, length], ([m, signature]) => {
      core.write(m, message);

      check(core.x.cpq_stateful_signer_sign(slot, size, index, m, message.length, signature, length));

      return core.read(signature, length);
    });
  }

  // The size of the cache changes when a signature starts a new lower tree, so it is read right
  // before the export.
  exportTreeCache(index: bigint): Uint8Array {
    const { core, slot, size } = this.#live(index);

    const length = core.run(PUBLIC, [], () => {
      check(core.x.cpq_stateful_signer_tree_cache_size(slot, size, core.scratch));

      return Number(new DataView(core.bytes().buffer).getBigUint64(core.scratch, true));
    });

    return core.run(SECRET, [length], ([out]) => {
      check(core.x.cpq_stateful_signer_export_tree_cache(slot, size, out, length));

      return core.read(out, length);
    });
  }

  free(): void {
    signers?.unregister(this);

    release(this.#handle);
  }

  #live(index: bigint): Handle {
    if (!this.#handle.core.live) {
      const [handle] = open(this.#kind, this.#section, this.#seed, index, null, null);

      signers?.unregister(this);

      this.#handle = handle;

      watch(this, handle);
    }

    return this.#handle;
  }
}

function wasmVerify(core: Core, kind: number, key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return core.run(PUBLIC, [key.length, message.length, signature.length], ([k, m, s]) => {
    core.write(k, key);

    core.write(m, message);

    core.write(s, signature);

    const status = core.x.cpq_stateful_verify(kind, k, key.length, m, message.length, s, signature.length);

    if (status !== REJECTED) {
      check(status);
    }

    return status === OK;
  });
}

function wasmCheck(core: Core, kind: number, key: Uint8Array): boolean {
  return core.run(PUBLIC, [key.length], ([k]) => {
    core.write(k, key);

    const status = core.x.cpq_stateful_check_public_key(kind, k, key.length);

    if (status !== INVALID_PUBLIC_KEY) {
      check(status);
    }

    return status === OK;
  });
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

    const text = bytes(message, "message");

    const backend = backendOf(this.algorithm);

    const core = STATEFUL_SIGNATURES.select();

    return core === null
      ? backend.verify(this.#key, text, data)
      : wasmVerify(core, backend.kind, this.#key, text, data);
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

  // The trees that the key holds, for loadPrivateKey's treeCache to skip their build. A call from
  // inside the store during a sign fails, as the trees are about to change.
  exportTreeCache(): Uint8Array {
    if (this.#busy) {
      throw new CryptoPQError("STATE_CONFLICT", "the key is signing in another call");
    }

    return this.#signer.exportTreeCache(this.#index);
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

  // Where new keys of this algorithm run, deciding it on first use.
  get backend(): "wasm" | "js" {
    return STATEFUL_SIGNATURES.select() === null ? "js" : "wasm";
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
  // skipped. A tree cache from exportTreeCache replaces the build of the trees it holds; the state is
  // checked first, and the key loads only if the cache passes.
  loadPrivateKey(stateStore: StateStore, options?: StatefulLoadOptions): StatefulPrivateKey {
    const store = checkStore(stateStore);

    const reserve = reserveOption(options);

    const cache = treeCacheOption(options);

    let state: unknown;

    try {
      state = store.read();
    } catch (error) {
      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to read the key state", { cause: error });
    }

    synchronous(state);

    const backend = this.#backend;

    const { parameters, seed, index } = backend.decode(state);

    if (index > backend.capacity(parameters)) {
      wipe(seed);

      throw mismatch("the stored index is beyond the key's capacity");
    }

    let signer: Signer;

    try {
      signer = this.#signer(parameters, seed, index, state as Uint8Array, cache);
    } catch (error) {
      wipe(seed);

      throw error;
    }

    const copy = (state as Uint8Array).slice();

    return new StatefulPrivateKey(this, parameters, seed, signer, store, copy, index, reserve);
  }

  importPublicKey(data: Uint8Array | string, format: KeyFormat): StatefulPublicKey {
    const backend = this.#backend;

    const key = importPublic(format, data, backend.oid);

    const core = STATEFUL_SIGNATURES.select();

    if (core === null ? !backend.checkPublicKey(key) : !wasmCheck(core, backend.kind, key)) {
      throw new CryptoPQError("INVALID_PUBLIC_KEY", "the public key is malformed");
    }

    return new StatefulPublicKey(this, key);
  }

  // The store gets the starting index; the first signature then claims the reserved indices.
  #create(parameters: unknown, seed: Uint8Array, index: bigint, store: StateStore, reserve: bigint): StatefulKeyPair {
    const backend = this.#backend;

    const signer = this.#signer(parameters, seed, index, null, null);

    const state = backend.encode(parameters, seed, index);

    let created: unknown;

    try {
      created = store.update(null, state.slice());
    } catch (error) {
      signer.free();

      wipe(seed, state);

      throw new CryptoPQError("STATE_PERSIST_FAILED", "the state store failed to save the new key", { cause: error });
    }

    if (created !== true) {
      signer.free();

      wipe(seed, state);

      synchronous(created);

      throw new CryptoPQError("STATE_CONFLICT", "the state store already holds a key");
    }

    const privateKey = new StatefulPrivateKey(this, parameters, seed, signer, store, state, index, reserve);

    return Object.freeze({ publicKey: privateKey.publicKey, privateKey });
  }

  // The trees of a key: built from the seed at index for a new key, or for a stored one from the
  // state that its checks accepted, with the tree cache if any, which WebAssembly checks with the
  // codes of openTreeCache. Under "auto", a key that the instance has no memory for runs in
  // TypeScript.
  #signer(
    parameters: unknown,
    seed: Uint8Array,
    index: bigint,
    state: Uint8Array | null,
    cache: Uint8Array | null,
  ): Signer {
    const backend = this.#backend;

    if (STATEFUL_SIGNATURES.select() !== null) {
      try {
        return new WasmSigner(backend.kind, backend.parameterSection(parameters), seed, index, state, cache);
      } catch (error) {
        if (!STATEFUL_SIGNATURES.fallsBack(error)) {
          throw error;
        }
      }
    }

    if (cache === null) {
      return jsSigner(backend, parameters, seed, backend.signer(parameters, seed));
    }

    const [publicKey, cached] = openTreeCache(backend, parameters, seed, index, cache);

    const trees = backend.signer(parameters, seed, cached);

    if (!equal(trees.publicKey, publicKey)) {
      throw invalid("the tree cache belongs to another key");
    }

    return jsSigner(backend, parameters, seed, trees);
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

export const HSS_LMS = /* @__PURE__ */ new StatefulSignatureAlgorithm(
  "HSS/LMS",
  HSS_BACKEND as StatefulBackend<unknown>,
);

export const XMSS = /* @__PURE__ */ new StatefulSignatureAlgorithm(
  "XMSS",
  /* @__PURE__ */ xmssBackend(false) as StatefulBackend<unknown>,
);

export const XMSS_MT = /* @__PURE__ */ new StatefulSignatureAlgorithm(
  "XMSS^MT",
  /* @__PURE__ */ xmssBackend(true) as StatefulBackend<unknown>,
);
