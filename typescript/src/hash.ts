import { bytes, equal } from "./bytes.ts";
import { CryptoPQError } from "./errors.ts";
import { X_WING_HASH } from "./families.ts";
import { Keccak, keccakDigest } from "./keccak.ts";
import { PRE_HASHES } from "./prehash.ts";
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
import { type Core, HASHING, OK, REJECTED, check } from "./wasm.ts";

const HASHER_SLOT = 5;

const XOF_SLOT = 6;

const HMAC_SLOT = 7;

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
// pre-hash ids of the C ABI are the hash ids plus one, then the XOF ids plus 11.
export interface Spec {
  readonly id: number;

  readonly digestSize: number;

  readonly blockSize: number;

  readonly preHash: readonly [number, number] | null;

  create(): Engine;

  digest(data: Uint8Array): Uint8Array;
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

interface HmacState extends HashState {
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

function jsHmac(inner: Engine, outer: Engine): HmacState {
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

// Writes data into the region at input one piece at a time and hands each piece's length to use.
function pieces(core: Core, input: number, data: Uint8Array, use: (length: number) => void): void {
  for (let offset = 0; offset < data.length; offset += PIECE) {
    const piece = data.subarray(offset, Math.min(offset + PIECE, data.length));

    core.write(input, piece);

    use(piece.length);
  }
}

const EMPTY = new Uint8Array(0);

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

function wasmHash(id: number, size: number): HashState {
  const state = new WasmState(initial(HASHER_SLOT, id, "cpq_hash_init"), "cpq_hash_update");

  return {
    update: (data) => state.update(data),
    digest: () =>
      state.run(EMPTY, [size], (core, slot, length, [out]) => {
        check(core.x.cpq_hash_final(slot, length, out, size));

        return core.read(out, size);
      }),
  };
}

// Reading starts the output, after which the state takes no more input, as in TypeScript; a read
// of nothing does not.
function wasmXof(id: number): XofState {
  const state = new WasmState(initial(XOF_SLOT, id, "cpq_xof_init"), "cpq_xof_update");

  let reading = false;

  return {
    update(data) {
      if (reading) {
        throw new CryptoPQError("UNSUPPORTED", "cannot update after read");
      }

      state.update(data);
    },
    read(length) {
      reading ||= length > 0;

      return state.run(EMPTY, [Math.min(length, PIECE)], (core, slot, size, [piece]) => {
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

function wasmHmac(id: number, size: number, key: Uint8Array): HmacState {
  const slot = created(HMAC_SLOT, id, [key.length], (core, at, length, [input]) => {
    core.write(input, key);

    return core.x.cpq_hmac_init(id, input, key.length, at, length);
  });

  const state = new WasmState(slot, "cpq_hmac_update");

  return {
    update: (data) => state.update(data),
    digest: () =>
      state.run(EMPTY, [size], (core, slot, length, [out]) => {
        check(core.x.cpq_hmac_final(slot, length, out, size));

        return core.read(out, size);
      }),
    verify: (tag) =>
      state.run(EMPTY, [tag.length], (core, slot, length, [input]) => {
        core.write(input, tag);

        const status = core.x.cpq_hmac_final_verify(slot, length, input, tag.length);

        if (status !== REJECTED) {
          check(status);
        }

        return status === OK;
      }),
  };
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

  constructor(name: string, spec: Spec) {
    this.name = name;

    this.digestSize = spec.digestSize;

    this.#spec = spec;

    if (spec.preHash !== null) {
      const [arc, strength] = spec.preHash;

      PRE_HASHES.set(this, { id: spec.id + 1, arc, strength, digest: (message) => this.digest(message) });
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

    if (core === null) {
      return this.#spec.digest(input);
    }

    const { id, digestSize } = this.#spec;

    if (input.length > PIECE) {
      return new Hasher(wasmHash(id, digestSize)).update(input).digest();
    }

    return core.run(HASHING, [input.length, digestSize], ([at, out]) => {
      core.write(at, input);

      check(core.x.cpq_hash(id, at, input.length, out, digestSize));

      return core.read(out, digestSize);
    });
  }

  create(): Hasher {
    const spec = this.#spec;

    return new Hasher(X_WING_HASH.select() === null ? spec.create() : wasmHash(spec.id, spec.digestSize));
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

export class XofAlgorithm {
  readonly name: string;

  readonly #rate: number;

  readonly #id: number;

  // As a pre-hash, SHAKE128 gives 256 bits and SHAKE256 512.
  constructor(name: string, rate: number, id: number, preHash: readonly [number, number, number]) {
    this.name = name;

    this.#rate = rate;

    this.#id = id;

    const [arc, strength, size] = preHash;

    PRE_HASHES.set(this, { id: 11 + id, arc, strength, digest: (message) => this.digest(message, size) });

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

    if (core === null) {
      return keccakDigest(this.#rate, 0x1f, input, length);
    }

    const id = this.#id;

    if (input.length > PIECE || length > PIECE) {
      return new Xof(wasmXof(id)).update(input).read(length);
    }

    return core.run(HASHING, [input.length, length], ([at, out]) => {
      core.write(at, input);

      check(core.x.cpq_xof(id, at, input.length, out, length));

      return core.read(out, length);
    });
  }

  create(): Xof {
    return new Xof(X_WING_HASH.select() === null ? new Keccak(this.#rate, 0x1f) : wasmXof(this.#id));
  }
}

export class Hmac {
  readonly #state: HmacState;

  constructor(state: HmacState) {
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

export class HmacAlgorithm {
  readonly name: string;

  readonly digestSize: number;

  readonly #spec: Spec;

  constructor(name: string, spec: Spec) {
    this.name = name;

    this.digestSize = spec.digestSize;

    this.#spec = spec;

    Object.freeze(this);
  }

  // Where this algorithm runs, deciding it on first use.
  get backend(): "wasm" | "js" {
    return X_WING_HASH.select() === null ? "js" : "wasm";
  }

  digest(key: Uint8Array, data: Uint8Array): Uint8Array {
    const core = X_WING_HASH.select();

    const [secret, input] = [bytes(key, "key"), bytes(data, "data")];

    if (core === null || secret.length > PIECE || input.length > PIECE) {
      return this.create(secret).update(input).digest();
    }

    const { id, digestSize } = this.#spec;

    return core.run(HASHING, [secret.length, input.length, digestSize], ([k, at, out]) => {
      core.write(k, secret);

      core.write(at, input);

      check(core.x.cpq_hmac(id, k, secret.length, at, input.length, out, digestSize));

      return core.read(out, digestSize);
    });
  }

  // The padded key is zeroed before returning; JavaScript cannot promise that no other copy remains.
  create(key: Uint8Array): Hmac {
    const spec = this.#spec;

    const secret = bytes(key, "key");

    if (X_WING_HASH.select() !== null) {
      return new Hmac(wasmHmac(spec.id, spec.digestSize, secret));
    }

    const pad = new Uint8Array(spec.blockSize);

    if (secret.length > spec.blockSize) {
      const hash = spec.create();

      hash.update(secret);

      const digest = hash.digest();

      pad.set(digest);

      digest.fill(0);
    } else {
      pad.set(secret);
    }

    for (let i = 0; i < pad.length; i++) {
      pad[i] ^= 0x36;
    }

    const inner = spec.create();

    inner.update(pad);

    for (let i = 0; i < pad.length; i++) {
      pad[i] ^= 0x36 ^ 0x5c;
    }

    const outer = spec.create();

    outer.update(pad);

    pad.fill(0);

    return new Hmac(jsHmac(inner, outer));
  }

  verify(key: Uint8Array, data: Uint8Array, tag: Uint8Array): boolean {
    const core = X_WING_HASH.select();

    const [secret, input, expected] = [bytes(key, "key"), bytes(data, "data"), bytes(tag, "tag")];

    if (core === null || secret.length > PIECE || input.length > PIECE || expected.length > PIECE) {
      return this.create(secret).update(input).verify(expected);
    }

    const id = this.#spec.id;

    return core.run(HASHING, [secret.length, input.length, expected.length], ([k, at, t]) => {
      core.write(k, secret);

      core.write(at, input);

      core.write(t, expected);

      const status = core.x.cpq_hmac_verify(id, k, secret.length, at, input.length, t, expected.length);

      if (status !== REJECTED) {
        check(status);
      }

      return status === OK;
    });
  }
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

export const SHAKE128 = /* @__PURE__ */ new XofAlgorithm("SHAKE128", 168, 0, [11, 128, 32]);

export const SHAKE256 = /* @__PURE__ */ new XofAlgorithm("SHAKE256", 136, 1, [12, 256, 64]);

export const HMAC_SHA_224 = /* @__PURE__ */ new HmacAlgorithm("HMAC-SHA-224", SHA_224_SPEC);

export const HMAC_SHA_256 = /* @__PURE__ */ new HmacAlgorithm("HMAC-SHA-256", SHA_256_SPEC);

export const HMAC_SHA_384 = /* @__PURE__ */ new HmacAlgorithm("HMAC-SHA-384", SHA_384_SPEC);

export const HMAC_SHA_512 = /* @__PURE__ */ new HmacAlgorithm("HMAC-SHA-512", SHA_512_SPEC);
