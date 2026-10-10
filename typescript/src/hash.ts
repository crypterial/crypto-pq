import {
  AsconHash,
  AsconSponge,
  HASH_INITIAL,
  MAX_CUSTOMIZATION,
  XOF_INITIAL,
  asconDigest,
  customize,
} from "./ascon.ts";
import {
  BLAKE2B,
  BLAKE2S,
  type Blake2,
  Blake2Engine,
  digest as blake2Digest,
  initial as blake2Initial,
} from "./blake2.ts";
import { bytes, equal } from "./bytes.ts";
import { CryptoPQError } from "./errors.ts";
import { X_WING_HASH } from "./families.ts";
import { Keccak, keccakDigest } from "./keccak.ts";
import { PRE_HASHES, REFUSED_PRE_HASHES } from "./prehash.ts";
import {
  IV_224,
  IV_256,
  IV_384,
  IV_512,
  IV_512_224,
  IV_512_256,
  Sha256,
  Sha512,
  digest256,
  digest512,
} from "./sha2.ts";
import { Kmac, cshake, cshakeDigest, cshakePrefix, kmacDigest, kmacPrefix } from "./sp800185.ts";
import { type Core, HASHING, OK, REJECTED, check } from "./wasm.ts";

// The slot types of the C ABI: the states of hashes, XOFs and MACs, and configured algorithms.
const HASHER_SLOT = 5;

const XOF_SLOT = 6;

const MAC_SLOT = 7;

const CONFIGURED_HASH = 9;

const CONFIGURED_XOF = 10;

const CONFIGURED_MAC = 11;

// On WebAssembly, longer inputs and outputs cross the I/O block in pieces of this size, and
// incremental updates gather in JS up to the second size.
const PIECE = 32768;

const GATHER = 4096;

export interface Engine {
  update(data: Uint8Array): void;

  digest(): Uint8Array;

  copy(): Engine;
}

// id is the hash's id in the C ABI, which is also the HMAC's for SHA-224 to SHA-512; preHash, for
// a hash that signatures accept, the last arc of its OID and its collision strength in bits. The
// pre-hash ids of the C ABI are the hash ids plus one, then the XOF ids plus 11. variant is the
// BLAKE2 that configure gives a salt and a personalization.
export interface Spec {
  readonly id: number;

  readonly digestSize: number;

  readonly blockSize: number;

  readonly preHash: readonly [number, number] | null;

  readonly variant?: Blake2;

  create(): Engine;

  digest(data: Uint8Array): Uint8Array;
}

// An XOF in TypeScript; preHash as for Spec, with the output size of a pre-hash; rate, cSHAKE's,
// for configure.
interface XofSpec {
  readonly id: number;

  readonly kind: "shake" | "cshake" | "ascon" | "cxof";

  readonly rate: number;

  readonly preHash: readonly [number, number, number] | null;

  create(): XofState;

  digest(data: Uint8Array, length: number): Uint8Array;
}

// A MAC in TypeScript. keyLimit is the longest key of a BLAKE2 MAC, whose keys have at least one
// byte, and 0 for the MACs that take any key.
interface MacSpec {
  readonly id: number;

  readonly kind: "hmac" | "kmac" | "blake2";

  readonly digestSize: number;

  readonly keyLimit: number;

  create(key: Uint8Array): MacState;

  digest(key: Uint8Array, data: Uint8Array): Uint8Array;
}

function takes(spec: MacSpec, key: Uint8Array): boolean {
  return spec.keyLimit === 0 || (key.length >= 1 && key.length <= spec.keyLimit);
}

export interface HashOptions {
  salt?: Uint8Array;

  personalization?: Uint8Array;
}

export interface XofOptions {
  customization?: Uint8Array;
}

// length: the tag size in bytes, by default 32 (KMAC128), 64 (KMAC256, BLAKE2b-MAC) or 32
// (BLAKE2s-MAC). KMAC takes a customization and xof (KMACXOF); BLAKE2 a salt and personalization.
export interface MacOptions {
  length?: number;

  customization?: Uint8Array;

  xof?: boolean;

  salt?: Uint8Array;

  personalization?: Uint8Array;
}

// The states of incremental hashing on the backend that made them.
interface HashState {
  update(data: Uint8Array): void;

  digest(): Uint8Array;
}

interface XofState {
  update(data: Uint8Array): void;

  read(length: number): Uint8Array;
}

interface MacState extends HashState {
  verify(tag: Uint8Array): boolean;
}

class Sha3 implements Engine {
  readonly #sponge: Keccak;

  readonly #size: number;

  constructor(sponge: Keccak, size: number) {
    this.#sponge = sponge;

    this.#size = size;
  }

  update(data: Uint8Array): void {
    this.#sponge.update(data);
  }

  digest(): Uint8Array {
    return this.#sponge.copy().read(this.#size);
  }

  copy(): Engine {
    return new Sha3(this.#sponge.copy(), this.#size);
  }
}

// A MAC state from an engine whose digest is the tag.
function macState(engine: HashState): MacState {
  return {
    update: (data) => engine.update(data),
    digest: () => engine.digest(),
    verify: (tag) => equal(engine.digest(), tag),
  };
}

function jsHmac(inner: Engine, outer: Engine): MacState {
  const digest = () => {
    const copy = outer.copy();

    copy.update(inner.digest());

    return copy.digest();
  };

  return { update: (data) => inner.update(data), digest, verify: (tag) => equal(digest(), tag) };
}

function requireReadLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new CryptoPQError("INVALID_LENGTH", "length must be a non-negative integer");
  }
}

const EMPTY = new Uint8Array(0);

// The fields of an options argument, which may be absent; a byte string field, empty when absent.
function optionsOf<T extends object>(value: T | undefined): Partial<T> {
  if (value === undefined || value === null) {
    return {};
  }

  if (typeof value !== "object") {
    throw new TypeError("options must be an object");
  }

  return value;
}

// A view of exactly the length that the value reports, which configure copies.
function optionBytes(value: unknown, name: string): Uint8Array {
  if (value === undefined) {
    return EMPTY;
  }

  const data = bytes(value, name);

  return data.subarray(0, data.length);
}

function invalidOption(message: string): CryptoPQError {
  return new CryptoPQError("INVALID_OPTION", message);
}

// Writes data into the region at input one piece at a time and hands each piece's length to use.
function pieces(core: Core, input: number, data: Uint8Array, use: (length: number) => void): void {
  for (let offset = 0; offset < data.length; offset += PIECE) {
    const piece = data.subarray(offset, Math.min(offset + PIECE, data.length));

    core.write(input, piece);

    use(piece.length);
  }
}

// The initial state of each hash and XOF, made once: a new state is a copy of it, whatever the
// instance, as a state holds no address.
const INITIAL = new Map<number, Uint8Array>();

// A state on WebAssembly, in a JS array between calls: each call places it in the I/O block and
// copies it back. Short updates gather in a JS buffer, which the state absorbs, through the export
// named absorb, when it fills or before a result, so that they do not each pay for a call. init
// makes the state in the slot, with the regions of the given lengths next to it.
class WasmState {
  readonly #slot: Uint8Array;

  readonly #absorb: string;

  #gathered: Uint8Array | null = null;

  #length = 0;

  // A fault of the instance in the middle of a call loses what the state had absorbed: every later
  // use then fails rather than give a wrong result.
  #lost = false;

  constructor(slot: Uint8Array, absorb: string) {
    this.#slot = slot;

    this.#absorb = absorb;
  }

  update(data: Uint8Array): void {
    if (this.#lost) {
      throw new Error("this state was lost to a fault of crypto-pq's WebAssembly core");
    }

    if (this.#length + data.length <= GATHER) {
      this.#gathered ??= new Uint8Array(GATHER);

      this.#gathered.set(data.subarray(0, data.length), this.#length);

      this.#length += data.length;
    } else {
      this.run(data, [], () => undefined);
    }
  }

  // Runs body on the state once it has absorbed the gathered bytes, then data.
  run<T>(
    data: Uint8Array,
    lengths: readonly number[],
    body: (core: Core, slot: number, size: number, at: number[]) => T,
  ): T {
    const core = X_WING_HASH.core();

    const state = this.#slot;

    const gathered = this.#gathered === null ? EMPTY : this.#gathered.subarray(0, this.#length);

    const input = Math.min(Math.max(gathered.length, data.length), PIECE);

    if (this.#lost) {
      throw new Error("this state was lost to a fault of crypto-pq's WebAssembly core");
    }

    try {
      return core.run(HASHING, [state.length, input, ...lengths], ([slot, at, ...rest]) => {
        core.write(slot, state);

        for (const part of [gathered, data]) {
          pieces(core, at, part, (length) => check(core.x[this.#absorb](slot, state.length, at, length)));
        }

        const result = body(core, slot, state.length, rest);

        state.set(core.bytes().subarray(slot, slot + state.length));

        return result;
      });
    } catch (error) {
      this.#lost ||= !(error instanceof CryptoPQError);

      throw error;
    } finally {
      gathered.fill(0);

      this.#length = 0;
    }
  }
}

// A new state made in a slot of the type, with regions of the given lengths next to it.
function created(
  type: number,
  id: number,
  lengths: readonly number[],
  init: (core: Core, slot: number, size: number, at: number[]) => number,
): Uint8Array {
  const core = X_WING_HASH.core();

  const size = core.size(type, id);

  return core.run(HASHING, [size, ...lengths], ([slot, ...at]) => {
    check(init(core, slot, size, at));

    return core.read(slot, size);
  });
}

function initial(type: number, id: number, init: string): Uint8Array {
  const key = (type << 8) | id;

  let state = INITIAL.get(key);

  if (state === undefined) {
    state = created(type, id, [], (core, slot, size) => core.x[init](id, slot, size));

    INITIAL.set(key, state);
  }

  return state.slice();
}

// What a configured algorithm needs on WebAssembly: the slot of its configuration (types 9 to 11),
// which the export call makes from copies of the options that configure kept, and for a hash or an
// XOF the initial state made from it. Both are made on first use and kept, as neither holds an
// address or a secret.
class Configuration {
  readonly #type: number;

  readonly #id: number;

  readonly #inputs: readonly Uint8Array[];

  readonly #call: (x: Core["x"], slot: number, size: number, at: number[]) => number;

  #slot: Uint8Array | null = null;

  #initial: Uint8Array | null = null;

  constructor(
    type: number,
    id: number,
    inputs: readonly Uint8Array[],
    call: (x: Core["x"], slot: number, size: number, at: number[]) => number,
  ) {
    this.#type = type;

    this.#id = id;

    this.#inputs = inputs.map((input) => input.slice());

    this.#call = call;
  }

  get slot(): Uint8Array {
    if (this.#slot === null) {
      const inputs = this.#inputs;

      this.#slot = created(this.#type, this.#id, inputs.map((input) => input.length), (core, slot, size, at) => {
        inputs.forEach((input, i) => core.write(at[i], input));

        return this.#call(core.x, slot, size, at);
      });
    }

    return this.#slot;
  }

  // A new state of the configured hash or XOF, made by the export named init from the slot.
  state(type: number, init: string): Uint8Array {
    if (this.#initial === null) {
      const spec = this.slot;

      this.#initial = created(type, this.#id, [spec.length], (core, slot, size, [at]) => {
        core.write(at, spec);

        return core.x[init](at, spec.length, slot, size);
      });
    }

    return this.#initial.slice();
  }
}

function wasmHash(state: Uint8Array, size: number): HashState {
  const wasm = new WasmState(state, "cpq_hash_update");

  return {
    update: (data) => wasm.update(data),
    digest: () =>
      wasm.run(EMPTY, [size], (core, slot, length, [out]) => {
        check(core.x.cpq_hash_final(slot, length, out, size));

        return core.read(out, size);
      }),
  };
}

// Reading starts the output, after which the state takes no more input, as in TypeScript; a read
// of nothing does not.
function wasmXof(state: Uint8Array): XofState {
  const wasm = new WasmState(state, "cpq_xof_update");

  let reading = false;

  return {
    update(data) {
      if (reading) {
        throw new CryptoPQError("UNSUPPORTED", "cannot update after read");
      }

      wasm.update(data);
    },
    read(length) {
      reading ||= length > 0;

      return wasm.run(EMPTY, [Math.min(length, PIECE)], (core, slot, size, [piece]) => {
        const out = new Uint8Array(length);

        for (let offset = 0; offset < length; offset += PIECE) {
          const count = Math.min(PIECE, length - offset);

          check(core.x.cpq_xof_read(slot, size, piece, count));

          out.set(core.bytes().subarray(piece, piece + count), offset);
        }

        return out;
      });
    },
  };
}

// A MAC state, which holds what the key gave it, and whose tag has size bytes.
function wasmMac(state: Uint8Array, size: number): MacState {
  const wasm = new WasmState(state, "cpq_mac_update");

  return {
    update: (data) => wasm.update(data),
    digest: () =>
      wasm.run(EMPTY, [size], (core, slot, length, [out]) => {
        check(core.x.cpq_mac_final(slot, length, out, size));

        return core.read(out, size);
      }),
    verify: (tag) =>
      wasm.run(EMPTY, [tag.length], (core, slot, length, [input]) => {
        core.write(input, tag);

        return verified(core.x.cpq_mac_final_verify(slot, length, input, tag.length));
      }),
  };
}

function verified(status: number): boolean {
  if (status !== REJECTED) {
    check(status);
  }

  return status === OK;
}

export class Hasher {
  readonly #state: HashState;

  constructor(state: HashState) {
    this.#state = state;
  }

  update(data: Uint8Array): this {
    this.#state.update(bytes(data, "data"));

    return this;
  }

  digest(): Uint8Array {
    return this.#state.digest();
  }
}

export class HashAlgorithm {
  readonly name: string;

  readonly digestSize: number;

  readonly #spec: Spec;

  // The algorithm that a configured one was made from, and its configuration on WebAssembly.
  readonly #base: HashAlgorithm | null;

  readonly #configuration: Configuration | null;

  constructor(name: string, spec: Spec, base: HashAlgorithm | null = null, configuration: Configuration | null = null) {
    this.name = name;

    this.digestSize = spec.digestSize;

    this.#spec = spec;

    this.#base = base;

    this.#configuration = configuration;

    if (spec.preHash !== null) {
      const [arc, strength] = spec.preHash;

      PRE_HASHES.set(this, { id: spec.id + 1, arc, strength, digest: (message) => this.digest(message) });
    } else {
      REFUSED_PRE_HASHES.add(this);
    }

    Object.freeze(this);
  }

  // Where this algorithm runs, deciding it on first use.
  get backend(): "wasm" | "js" {
    return X_WING_HASH.select() === null ? "js" : "wasm";
  }

  digest(data: Uint8Array): Uint8Array {
    const core = X_WING_HASH.select();

    const input = bytes(data, "data");

    return core === null ? this.#spec.digest(input) : this.#wasmDigest(core, input);
  }

  create(): Hasher {
    return new Hasher(X_WING_HASH.select() === null ? this.#spec.create() : this.#wasmState());
  }


  // The algorithm with these options and the defaults for the rest: a BLAKE2 hash takes a salt and
  // a personalization of at most 16 bytes (BLAKE2b) or 8 (BLAKE2s) each, zero-padded; the others
  // take none. Without options, or with the defaults, it is the algorithm configure started from.
  configure(options?: HashOptions): HashAlgorithm {
    const { salt, personalization } = optionsOf(options);

    const s = optionBytes(salt, "salt");

    const p = optionBytes(personalization, "personalization");

    const base = this.#base ?? this;

    const variant = base.#spec.variant;

    if (variant === undefined) {
      if (s.length > 0 || p.length > 0) {
        throw invalidOption(`${base.name} takes no salt or personalization`);
      }

      return base;
    }

    if (s.length > variant.field || p.length > variant.field) {
      throw invalidOption(`a ${base.name} salt or personalization has at most ${variant.field} bytes`);
    }

    if (s.length === 0 && p.length === 0) {
      return base;
    }

    const { id, digestSize } = base.#spec;

    const configuration = new Configuration(CONFIGURED_HASH, id, [s, p], (x, slot, size, at) =>
      x.cpq_hash_configure(id, at[0], s.length, at[1], p.length, slot, size),
    );

    return new HashAlgorithm(base.name, blake2Spec(variant, id, digestSize, s, p), base, configuration);
  }

  // The digest on WebAssembly, the code apart so that the TypeScript path stays small.
  #wasmDigest(core: Core, input: Uint8Array): Uint8Array {
    if (input.length > PIECE) {
      return new Hasher(this.#wasmState()).update(input).digest();
    }

    const { id, digestSize } = this.#spec;

    const configuration = this.#configuration;

    if (configuration !== null) {
      const spec = configuration.slot;

      return core.run(HASHING, [spec.length, input.length, digestSize], ([at, data, out]) => {
        core.write(at, spec);

        core.write(data, input);

        check(core.x.cpq_hash_with(at, spec.length, data, input.length, out, digestSize));

        return core.read(out, digestSize);
      });
    }

    return core.run(HASHING, [input.length, digestSize], ([at, out]) => {
      core.write(at, input);

      check(core.x.cpq_hash(id, at, input.length, out, digestSize));

      return core.read(out, digestSize);
    });
  }

  #wasmState(): HashState {
    const { id, digestSize } = this.#spec;

    const configuration = this.#configuration;

    const state =
      configuration === null
        ? initial(HASHER_SLOT, id, "cpq_hash_init")
        : configuration.state(HASHER_SLOT, "cpq_hash_init_with");

    return wasmHash(state, digestSize);
  }
}

export class Xof {
  readonly #state: XofState;

  constructor(state: XofState) {
    this.#state = state;
  }

  update(data: Uint8Array): this {
    this.#state.update(bytes(data, "data"));

    return this;
  }

  read(length: number): Uint8Array {
    requireReadLength(length);

    return this.#state.read(length);
  }
}

// Set by XofAlgorithm, which alone sees its fields; hazmat exposes it with the function name.
export let configureCshake: (
  algorithm: XofAlgorithm,
  functionName: Uint8Array,
  customization: Uint8Array,
) => XofAlgorithm;

export class XofAlgorithm {
  readonly name: string;

  readonly #spec: XofSpec;

  readonly #base: XofAlgorithm | null;

  readonly #configuration: Configuration | null;

  constructor(
    name: string,
    spec: XofSpec,
    base: XofAlgorithm | null = null,
    configuration: Configuration | null = null,
  ) {
    this.name = name;

    this.#spec = spec;

    this.#base = base;

    this.#configuration = configuration;

    if (spec.preHash !== null) {
      const [arc, strength, size] = spec.preHash;

      PRE_HASHES.set(this, { id: 11 + spec.id, arc, strength, digest: (message) => this.digest(message, size) });
    } else {
      REFUSED_PRE_HASHES.add(this);
    }

    Object.freeze(this);
  }

  // Where this algorithm runs, deciding it on first use.
  get backend(): "wasm" | "js" {
    return X_WING_HASH.select() === null ? "js" : "wasm";
  }

  digest(data: Uint8Array, length: number): Uint8Array {
    const core = X_WING_HASH.select();

    const input = bytes(data, "data");

    requireReadLength(length);

    return core === null ? this.#spec.digest(input, length) : this.#wasmDigest(core, input, length);
  }

  create(): Xof {
    return new Xof(X_WING_HASH.select() === null ? this.#spec.create() : this.#wasmState());
  }

  // The algorithm with this customization string: any length for cSHAKE, whose function name stays
  // empty (hazmat sets one), at most 256 bytes for Ascon-CXOF128, none for the others. Without
  // options, or with the defaults, it is the algorithm configure started from.
  configure(options?: XofOptions): XofAlgorithm {
    const { customization } = optionsOf(options);

    const base = this.#base ?? this;

    const s = optionBytes(customization, "customization");

    if (base.#spec.kind === "cshake") {
      return configureCshake(base, EMPTY, s);
    }

    if (base.#spec.kind !== "cxof") {
      if (s.length > 0) {
        throw invalidOption(`${base.name} takes no customization`);
      }

      return base;
    }

    if (s.length > MAX_CUSTOMIZATION) {
      throw invalidOption(`an Ascon-CXOF128 customization has at most ${MAX_CUSTOMIZATION} bytes`);
    }

    if (s.length === 0) {
      return base;
    }

    const id = base.#spec.id;

    const configuration = new Configuration(CONFIGURED_XOF, id, [s], (x, slot, size, at) =>
      x.cpq_xof_configure(id, 0, 0, at[0], s.length, slot, size),
    );

    return new XofAlgorithm(base.name, asconXofSpec(id, "cxof", customize(s)), base, configuration);
  }

  #wasmDigest(core: Core, input: Uint8Array, length: number): Uint8Array {
    if (input.length > PIECE || length > PIECE) {
      return new Xof(this.#wasmState()).update(input).read(length);
    }

    const configuration = this.#configuration;

    if (configuration !== null) {
      const spec = configuration.slot;

      return core.run(HASHING, [spec.length, input.length, length], ([at, data, out]) => {
        core.write(at, spec);

        core.write(data, input);

        check(core.x.cpq_xof_with(at, spec.length, data, input.length, out, length));

        return core.read(out, length);
      });
    }

    const id = this.#spec.id;

    return core.run(HASHING, [input.length, length], ([at, out]) => {
      core.write(at, input);

      check(core.x.cpq_xof(id, at, input.length, out, length));

      return core.read(out, length);
    });
  }

  #wasmState(): XofState {
    const configuration = this.#configuration;

    const state =
      configuration === null
        ? initial(XOF_SLOT, this.#spec.id, "cpq_xof_init")
        : configuration.state(XOF_SLOT, "cpq_xof_init_with");

    return wasmXof(state);
  }

  // cSHAKE with a function name and a customization (SP 800-185, 3.3), both empty giving the
  // algorithm itself, which equals SHAKE.
  static {
    configureCshake = (algorithm, functionName, customization) => {
      const base = algorithm.#base ?? algorithm;

      const { id, kind, rate } = base.#spec;

      if (kind !== "cshake") {
        throw invalidOption(`${base.name} is not cSHAKE`);
      }

      if (functionName.length === 0 && customization.length === 0) {
        return base;
      }

      const configuration = new Configuration(CONFIGURED_XOF, id, [functionName, customization], (x, slot, size, at) =>
        x.cpq_xof_configure(id, at[0], functionName.length, at[1], customization.length, slot, size),
      );

      const spec = cshakeSpec(id, rate, cshakePrefix(rate, functionName, customization));

      return new XofAlgorithm(base.name, spec, base, configuration);
    };
  }
}

export class Mac {
  readonly #state: MacState;

  constructor(state: MacState) {
    this.#state = state;
  }

  update(data: Uint8Array): this {
    this.#state.update(bytes(data, "data"));

    return this;
  }

  digest(): Uint8Array {
    return this.#state.digest();
  }

  verify(tag: Uint8Array): boolean {
    return this.#state.verify(bytes(tag, "tag"));
  }
}

// One MAC type for HMAC, KMAC and the BLAKE2 MACs. Every key is secret: in TypeScript the padded
// keys and keyed states are zeroed where the code holds them, though JavaScript cannot promise that
// no other copy remains.
export class MacAlgorithm {
  readonly name: string;

  readonly digestSize: number;

  readonly #spec: MacSpec;

  readonly #base: MacAlgorithm | null;

  readonly #configuration: Configuration | null;

  constructor(
    name: string,
    spec: MacSpec,
    base: MacAlgorithm | null = null,
    configuration: Configuration | null = null,
  ) {
    this.name = name;

    this.digestSize = spec.digestSize;

    this.#spec = spec;

    this.#base = base;

    this.#configuration = configuration;

    Object.freeze(this);
  }

  // Where this algorithm runs, deciding it on first use.
  get backend(): "wasm" | "js" {
    return X_WING_HASH.select() === null ? "js" : "wasm";
  }

  digest(key: Uint8Array, data: Uint8Array): Uint8Array {
    const core = X_WING_HASH.select();

    const [secret, input] = [this.#key(key), bytes(data, "data")];

    return core === null ? this.#spec.digest(secret, input) : this.#wasmDigest(core, secret, input);
  }

  #wasmDigest(core: Core, secret: Uint8Array, input: Uint8Array): Uint8Array {
    if (secret.length > PIECE || input.length > PIECE) {
      return this.create(secret).update(input).digest();
    }

    const { id, digestSize } = this.#spec;

    const configuration = this.#configuration;

    if (configuration !== null) {
      const spec = configuration.slot;

      const lengths = [spec.length, secret.length, input.length, digestSize];

      return core.run(HASHING, lengths, ([at, k, data, out]) => {
        core.write(at, spec);

        core.write(k, secret);

        core.write(data, input);

        check(core.x.cpq_mac_with(at, spec.length, k, secret.length, data, input.length, out, digestSize));

        return core.read(out, digestSize);
      });
    }

    return core.run(HASHING, [secret.length, input.length, digestSize], ([k, at, out]) => {
      core.write(k, secret);

      core.write(at, input);

      check(core.x.cpq_mac(id, k, secret.length, at, input.length, out, digestSize));

      return core.read(out, digestSize);
    });
  }

  create(key: Uint8Array): Mac {
    const secret = this.#key(key);

    if (X_WING_HASH.select() === null) {
      return new Mac(this.#spec.create(secret));
    }

    const id = this.#spec.id;

    const configuration = this.#configuration;

    if (configuration === null) {
      const state = created(MAC_SLOT, id, [secret.length], (core, slot, size, [k]) => {
        core.write(k, secret);

        return core.x.cpq_mac_init(id, k, secret.length, slot, size);
      });

      return new Mac(wasmMac(state, this.digestSize));
    }

    const spec = configuration.slot;

    const state = created(MAC_SLOT, id, [spec.length, secret.length], (core, slot, size, [at, k]) => {
      core.write(at, spec);

      core.write(k, secret);

      return core.x.cpq_mac_init_with(at, spec.length, k, secret.length, slot, size);
    });

    return new Mac(wasmMac(state, this.digestSize));
  }

  // Constant time in the tag's contents; a tag of another length, or a key that the MAC does not
  // take, is not valid.
  verify(key: Uint8Array, data: Uint8Array, tag: Uint8Array): boolean {
    const core = X_WING_HASH.select();

    const [secret, input, expected] = [bytes(key, "key"), bytes(data, "data"), bytes(tag, "tag")];

    if (!takes(this.#spec, secret) || expected.length !== this.digestSize) {
      return false;
    }

    if (core === null) {
      return equal(this.#spec.digest(secret, input), expected);
    }

    return this.#wasmVerify(core, secret, input, expected);
  }

  #wasmVerify(core: Core, secret: Uint8Array, input: Uint8Array, expected: Uint8Array): boolean {
    if (secret.length > PIECE || input.length > PIECE) {
      return this.create(secret).update(input).verify(expected);
    }

    const configuration = this.#configuration;

    if (configuration !== null) {
      const spec = configuration.slot;

      const lengths = [spec.length, secret.length, input.length, expected.length];

      return core.run(HASHING, lengths, ([at, k, data, t]) => {
        core.write(at, spec);

        core.write(k, secret);

        core.write(data, input);

        core.write(t, expected);

        const size = secret.length;

        return verified(core.x.cpq_mac_verify_with(at, spec.length, k, size, data, input.length, t, expected.length));
      });
    }

    const id = this.#spec.id;

    return core.run(HASHING, [secret.length, input.length, expected.length], ([k, at, t]) => {
      core.write(k, secret);

      core.write(at, input);

      core.write(t, expected);

      return verified(core.x.cpq_mac_verify(id, k, secret.length, at, input.length, t, expected.length));
    });
  }

  // The algorithm with these options and the defaults for the rest: KMAC takes a length (at least 4
  // bytes, SP 800-185, 8.4.2), a customization and xof; BLAKE2 a length (1 to 64 or 32 bytes), a salt
  // and a personalization; HMAC none. Without options, or with the defaults, it is the algorithm
  // configure started from.
  configure(options?: MacOptions): MacAlgorithm {
    const { length, customization, xof, salt, personalization } = optionsOf(options);

    const c = optionBytes(customization, "customization");

    const extendable = xof === undefined ? false : requireBool(xof, "xof");

    const s = optionBytes(salt, "salt");

    const p = optionBytes(personalization, "personalization");

    const base = this.#base ?? this;

    const { id, kind, digestSize } = base.#spec;

    if (kind === "hmac") {
      if (length !== undefined || c.length > 0 || extendable || s.length > 0 || p.length > 0) {
        throw invalidOption(`${base.name} takes no options`);
      }

      return base;
    }

    const size = length === undefined ? digestSize : requireMacLength(length, kind === "kmac" ? 4 : 1);

    if (kind === "kmac") {
      if (s.length > 0 || p.length > 0) {
        throw invalidOption(`${base.name} takes no salt or personalization`);
      }

      if (size === digestSize && c.length === 0 && !extendable) {
        return base;
      }

      const configuration = new Configuration(CONFIGURED_MAC, id, [c], (x, slot, length, at) =>
        x.cpq_mac_configure(id, size, (extendable ? 1 : 0) | 2, at[0], c.length, 0, 0, slot, length),
      );

      const rate = id === 4 ? 168 : 136;

      return new MacAlgorithm(base.name, kmacSpec(id, rate, size, c, extendable), base, configuration);
    }

    const variant = id === 6 ? BLAKE2B : BLAKE2S;

    if (c.length > 0 || extendable) {
      throw invalidOption(`${base.name} takes no customization or xof`);
    }

    if (size > variant.maxSize) {
      throw invalidOption(`a ${base.name} tag has at most ${variant.maxSize} bytes`);
    }

    if (s.length > variant.field || p.length > variant.field) {
      throw invalidOption(`a ${base.name} salt or personalization has at most ${variant.field} bytes`);
    }

    if (size === digestSize && s.length === 0 && p.length === 0) {
      return base;
    }

    const configuration = new Configuration(CONFIGURED_MAC, id, [s, p], (x, slot, length, at) =>
      x.cpq_mac_configure(id, size, 2, at[0], s.length, at[1], p.length, slot, length),
    );

    return new MacAlgorithm(base.name, blake2MacSpec(id, variant, size, s, p), base, configuration);
  }

  // A key that a computation can take: BLAKE2 keys have 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes.
  #key(key: unknown): Uint8Array {
    const secret = bytes(key, "key");

    if (!takes(this.#spec, secret)) {
      throw new CryptoPQError("INVALID_LENGTH", `a ${this.name} key has 1 to ${this.#spec.keyLimit} bytes`);
    }

    return secret;
  }
}

function requireBool(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    throw invalidOption(`${name} must be a boolean`);
  }

  return value;
}

// A tag length from minimum on; on WebAssembly, lengths are 32-bit.
function requireMacLength(length: unknown, minimum: number): number {
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < minimum || length > 0xffffffff) {
    throw invalidOption(`length must be an integer of at least ${minimum}`);
  }

  return length;
}

function sha256(id: number, iv: Int32Array, digestSize: number, preHash: Spec["preHash"]): Spec {
  return {
    id,
    digestSize,
    blockSize: 64,
    preHash,
    create: () => new Sha256(iv, digestSize),
    digest: (data) => digest256(iv, digestSize, data),
  };
}

function sha512(id: number, iv: Int32Array, digestSize: number, preHash: Spec["preHash"]): Spec {
  return {
    id,
    digestSize,
    blockSize: 128,
    preHash,
    create: () => new Sha512(iv, digestSize),
    digest: (data) => digest512(iv, digestSize, data),
  };
}

function sha3(id: number, digestSize: number, preHash: Spec["preHash"]): Spec {
  const rate = 200 - 2 * digestSize;

  return {
    id,
    digestSize,
    blockSize: rate,
    preHash,
    create: () => new Sha3(new Keccak(rate, 0x06), digestSize),
    digest: (data) => keccakDigest(rate, 0x06, data, digestSize),
  };
}

function blake2Spec(
  variant: Blake2,
  id: number,
  digestSize: number,
  salt: Uint8Array,
  personalization: Uint8Array,
): Spec {
  const h0 = blake2Initial(variant, digestSize, salt, personalization);

  return {
    id,
    digestSize,
    blockSize: variant.block,
    preHash: null,
    variant,
    create: () => new Blake2Engine(variant, h0, EMPTY, digestSize),
    digest: (data) => blake2Digest(variant, h0, EMPTY, data, digestSize),
  };
}

const ASCON_HASH256_SPEC: Spec = {
  id: 18,
  digestSize: 32,
  blockSize: 8,
  preHash: null,
  create: () => new AsconHash(),
  digest(data) {
    const out = new Uint8Array(32);

    asconDigest(HASH_INITIAL, data, out);

    return out;
  },
};

function shakeSpec(id: number, rate: number, preHash: XofSpec["preHash"]): XofSpec {
  return {
    id,
    kind: "shake",
    rate,
    preHash,
    create: () => new Keccak(rate, 0x1f),
    digest: (data, length) => keccakDigest(rate, 0x1f, data, length),
  };
}

// cSHAKE from its prefix state; without a prefix, SHAKE.
function cshakeSpec(id: number, rate: number, prefix: Uint32Array | null): XofSpec {
  if (prefix === null) {
    return { ...shakeSpec(id, rate, null), kind: "cshake" };
  }

  return {
    id,
    kind: "cshake",
    rate,
    preHash: null,
    create: () => cshake(rate, prefix),
    digest: (data, length) => cshakeDigest(rate, prefix, data, length),
  };
}

function asconXofSpec(id: number, kind: "ascon" | "cxof", initial: Uint32Array): XofSpec {
  return {
    id,
    kind,
    rate: 8,
    preHash: null,
    create: () => new AsconSponge(initial),
    digest(data, length) {
      const out = new Uint8Array(length);

      asconDigest(initial, data, out);

      return out;
    },
  };
}

function hmacSpec(hash: Spec): MacSpec {
  return {
    id: hash.id,
    kind: "hmac",
    digestSize: hash.digestSize,
    keyLimit: 0,
    digest(key, data) {
      const state = this.create(key);

      state.update(data);

      return state.digest();
    },
    // The padded key is zeroed before returning; JavaScript cannot promise that no other copy remains.
    create(key) {
      const pad = new Uint8Array(hash.blockSize);

      if (key.length > hash.blockSize) {
        const digest = hash.digest(key);

        pad.set(digest);

        digest.fill(0);
      } else {
        pad.set(key);
      }

      for (let i = 0; i < pad.length; i++) {
        pad[i] ^= 0x36;
      }

      const inner = hash.create();

      inner.update(pad);

      for (let i = 0; i < pad.length; i++) {
        pad[i] ^= 0x36 ^ 0x5c;
      }

      const outer = hash.create();

      outer.update(pad);

      pad.fill(0);

      return jsHmac(inner, outer);
    },
  };
}

function kmacSpec(id: number, rate: number, digestSize: number, customization: Uint8Array, xof: boolean): MacSpec {
  const prefix = kmacPrefix(rate, customization);

  return {
    id,
    kind: "kmac",
    digestSize,
    keyLimit: 0,
    create: (key) => macState(new Kmac(rate, prefix, xof, key, digestSize)),
    digest: (key, data) => kmacDigest(rate, prefix, xof, key, data, digestSize),
  };
}

function blake2MacSpec(
  id: number,
  variant: Blake2,
  digestSize: number,
  salt: Uint8Array,
  personalization: Uint8Array,
): MacSpec {
  const h0 = blake2Initial(variant, digestSize, salt, personalization);

  return {
    id,
    kind: "blake2",
    digestSize,
    keyLimit: variant.maxSize,
    create: (key) => macState(new Blake2Engine(variant, h0, key, digestSize)),
    digest: (key, data) => blake2Digest(variant, h0, key, data, digestSize),
  };
}

const SHA_224_SPEC = /* @__PURE__ */ sha256(0, IV_224, 28, [4, 112]);

const SHA_256_SPEC = /* @__PURE__ */ sha256(1, IV_256, 32, [1, 128]);

const SHA_384_SPEC = /* @__PURE__ */ sha512(2, IV_384, 48, [2, 192]);

const SHA_512_SPEC = /* @__PURE__ */ sha512(3, IV_512, 64, [3, 256]);

export const SHA_224 = /* @__PURE__ */ new HashAlgorithm("SHA-224", SHA_224_SPEC);

export const SHA_256 = /* @__PURE__ */ new HashAlgorithm("SHA-256", SHA_256_SPEC);

export const SHA_384 = /* @__PURE__ */ new HashAlgorithm("SHA-384", SHA_384_SPEC);

export const SHA_512 = /* @__PURE__ */ new HashAlgorithm("SHA-512", SHA_512_SPEC);

export const SHA_512_224 = /* @__PURE__ */ new HashAlgorithm(
  "SHA-512/224",
  /* @__PURE__ */ sha512(4, IV_512_224, 28, [5, 112]),
);

export const SHA_512_256 = /* @__PURE__ */ new HashAlgorithm(
  "SHA-512/256",
  /* @__PURE__ */ sha512(5, IV_512_256, 32, [6, 128]),
);

export const SHA3_224 = /* @__PURE__ */ new HashAlgorithm("SHA3-224", /* @__PURE__ */ sha3(6, 28, [7, 112]));

export const SHA3_256 = /* @__PURE__ */ new HashAlgorithm("SHA3-256", /* @__PURE__ */ sha3(7, 32, [8, 128]));

export const SHA3_384 = /* @__PURE__ */ new HashAlgorithm("SHA3-384", /* @__PURE__ */ sha3(8, 48, [9, 192]));

export const SHA3_512 = /* @__PURE__ */ new HashAlgorithm("SHA3-512", /* @__PURE__ */ sha3(9, 64, [10, 256]));

export const BLAKE2B_160 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2b-160",
  /* @__PURE__ */ blake2Spec(BLAKE2B, 10, 20, EMPTY, EMPTY),
);

export const BLAKE2B_256 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2b-256",
  /* @__PURE__ */ blake2Spec(BLAKE2B, 11, 32, EMPTY, EMPTY),
);

export const BLAKE2B_384 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2b-384",
  /* @__PURE__ */ blake2Spec(BLAKE2B, 12, 48, EMPTY, EMPTY),
);

export const BLAKE2B_512 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2b-512",
  /* @__PURE__ */ blake2Spec(BLAKE2B, 13, 64, EMPTY, EMPTY),
);

export const BLAKE2S_128 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2s-128",
  /* @__PURE__ */ blake2Spec(BLAKE2S, 14, 16, EMPTY, EMPTY),
);

export const BLAKE2S_160 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2s-160",
  /* @__PURE__ */ blake2Spec(BLAKE2S, 15, 20, EMPTY, EMPTY),
);

export const BLAKE2S_224 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2s-224",
  /* @__PURE__ */ blake2Spec(BLAKE2S, 16, 28, EMPTY, EMPTY),
);

export const BLAKE2S_256 = /* @__PURE__ */ new HashAlgorithm(
  "BLAKE2s-256",
  /* @__PURE__ */ blake2Spec(BLAKE2S, 17, 32, EMPTY, EMPTY),
);

export const ASCON_HASH256 = /* @__PURE__ */ new HashAlgorithm("Ascon-Hash256", ASCON_HASH256_SPEC);

export const SHAKE128 = /* @__PURE__ */ new XofAlgorithm("SHAKE128", /* @__PURE__ */ shakeSpec(0, 168, [11, 128, 32]));

export const SHAKE256 = /* @__PURE__ */ new XofAlgorithm("SHAKE256", /* @__PURE__ */ shakeSpec(1, 136, [12, 256, 64]));

export const CSHAKE128 = /* @__PURE__ */ new XofAlgorithm("cSHAKE128", /* @__PURE__ */ cshakeSpec(2, 168, null));

export const CSHAKE256 = /* @__PURE__ */ new XofAlgorithm("cSHAKE256", /* @__PURE__ */ cshakeSpec(3, 136, null));

export const ASCON_XOF128 = /* @__PURE__ */ new XofAlgorithm(
  "Ascon-XOF128",
  /* @__PURE__ */ asconXofSpec(4, "ascon", XOF_INITIAL),
);

export const ASCON_CXOF128 = /* @__PURE__ */ new XofAlgorithm(
  "Ascon-CXOF128",
  /* @__PURE__ */ asconXofSpec(5, "cxof", /* @__PURE__ */ customize(EMPTY)),
);

export const HMAC_SHA_224 = /* @__PURE__ */ new MacAlgorithm("HMAC-SHA-224", /* @__PURE__ */ hmacSpec(SHA_224_SPEC));

export const HMAC_SHA_256 = /* @__PURE__ */ new MacAlgorithm("HMAC-SHA-256", /* @__PURE__ */ hmacSpec(SHA_256_SPEC));

export const HMAC_SHA_384 = /* @__PURE__ */ new MacAlgorithm("HMAC-SHA-384", /* @__PURE__ */ hmacSpec(SHA_384_SPEC));

export const HMAC_SHA_512 = /* @__PURE__ */ new MacAlgorithm("HMAC-SHA-512", /* @__PURE__ */ hmacSpec(SHA_512_SPEC));

export const KMAC128 = /* @__PURE__ */ new MacAlgorithm("KMAC128", /* @__PURE__ */ kmacSpec(4, 168, 32, EMPTY, false));

export const KMAC256 = /* @__PURE__ */ new MacAlgorithm("KMAC256", /* @__PURE__ */ kmacSpec(5, 136, 64, EMPTY, false));

export const BLAKE2B_MAC = /* @__PURE__ */ new MacAlgorithm(
  "BLAKE2b-MAC",
  /* @__PURE__ */ blake2MacSpec(6, BLAKE2B, 64, EMPTY, EMPTY),
);

export const BLAKE2S_MAC = /* @__PURE__ */ new MacAlgorithm(
  "BLAKE2s-MAC",
  /* @__PURE__ */ blake2MacSpec(7, BLAKE2S, 32, EMPTY, EMPTY),
);
