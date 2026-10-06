import { CryptoPQError, type ErrorCode } from "./errors.ts";
import { randomInto } from "./rng.ts";

export type Backend = "auto" | "wasm" | "js";

// The parts of the engine's WebAssembly API used here; the standard library declares them only
// with the DOM.
interface Api {
  validate(bytes: Uint8Array): boolean;

  readonly Module: new (bytes: Uint8Array) => object;

  readonly Instance: new (module: object, imports: object) => { readonly exports: Record<string, unknown> };
}

type Call = (...args: (number | bigint)[]) => number;

interface Memory {
  readonly buffer: ArrayBuffer;
}

export const OK = 0;

export const REJECTED = 100;

const OUT_OF_MEMORY = 103;

// How far below its top an operation may leave secrets on the stack, which is zeroed that far when
// the operation returns: nothing for a public operation, the whole stack for the others, and 4 KiB
// for hashing, which uses at most 2.6 KB of it (test/wasm.test.ts measures every export).
export const PUBLIC = 0;

export const SECRET = Infinity;

export const HASHING = 4096;

// Status codes 1 to 13, in the order of the C ABI.
const CODES: readonly ErrorCode[] = [
  "INVALID_LENGTH",
  "INVALID_ENCODING",
  "ALGORITHM_MISMATCH",
  "INVALID_PUBLIC_KEY",
  "INVALID_PRIVATE_KEY",
  "INVALID_CONTEXT",
  "INVALID_OPTION",
  "RNG_FAILURE",
  "SELF_TEST_FAILED",
  "KEY_EXHAUSTED",
  "STATE_PERSIST_FAILED",
  "STATE_CONFLICT",
  "UNSUPPORTED",
];

const MESSAGES: Partial<Record<ErrorCode, string>> = {
  INVALID_LENGTH: "an input has the wrong length",
  INVALID_ENCODING: "an input is not validly encoded",
  ALGORITHM_MISMATCH: "the input belongs to another algorithm",
  INVALID_PUBLIC_KEY: "the public key is invalid",
  INVALID_PRIVATE_KEY: "the private key is invalid",
  INVALID_CONTEXT: "the context must be at most 255 bytes",
  INVALID_OPTION: "an option is invalid",
  SELF_TEST_FAILED: "the new key pair failed its consistency test",
  KEY_EXHAUSTED: "every one-time key has been used",
  STATE_CONFLICT: "the key is signing in another call",
  UNSUPPORTED: "the operation is not supported",
};

const COMMON = [
  "cpq_abi_version",
  "cpq_slot_size",
  "cpq_slot_info",
  "cpq_slot_wipe",
  "cpq_alloc",
  "cpq_free",
  "cpq_stack_low",
  "cpq_stack_high",
  "cpq_wasm_tune",
];

// The smallest module with a SIMD128 instruction: i8x16.popcnt of a splat.
const SIMD_PROBE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11,
]);

const PAGE = 65536;

// The allocator gives large blocks a power of two of 64 KiB pages, which hold a block of this many
// bytes less with its headers.
const HEADERS = 32;

// The I/O block grows to at most this size; a call that needs more takes a block of its own.
const IO_LIMIT = 16 * PAGE - HEADERS;

// An instance that holds nothing between calls is replaced once its memory exceeds this size, so
// that one large message does not keep its memory for the life of the process.
const MEMORY_LIMIT = 512 * PAGE;

let chosen: Backend = "auto";

export function setBackend(backend: Backend): void {
  if (backend !== "auto" && backend !== "wasm" && backend !== "js") {
    throw new CryptoPQError("INVALID_OPTION", 'backend must be "auto", "wasm" or "js"');
  }

  chosen = backend;
}

// What the core is told of the engine (cpq_wasm_tune), which picks between code shapes of equal
// results: bit 0 for V8 before version 15, which compiles a rotation of 64-bit vector lanes faster
// as two added shifts, bit 1 for any V8, which runs a single Keccak state faster with two rounds
// per iteration, and bit 2 for V8 from version 15 and for Bun's JavaScriptCore, which run two
// Keccak states faster in the lanes of vectors. Bun reports a V8 version for compatibility; engines
// that report none get the shapes that the engines measured run best on average.
export function engineFlags(): number {
  const g = globalThis as {
    process?: { versions?: { v8?: unknown; bun?: unknown } };
    Deno?: { version?: { v8?: unknown } };
  };

  const versions = g.process?.versions;

  if (versions?.bun !== undefined) {
    return 4;
  }

  const v8 = g.Deno?.version?.v8 ?? versions?.v8;

  if (typeof v8 !== "string") {
    return 0;
  }

  return (Number.parseInt(v8, 10) < 15 ? 1 : 4) | 2;
}

function api(): Api {
  const found = (globalThis as { WebAssembly?: Api }).WebAssembly;

  if (typeof found !== "object" || found === null) {
    throw new Error("this platform has no WebAssembly");
  }

  return found;
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// The embedded modules are padded base64 without whitespace.
export function decodeBase64(text: string): Uint8Array {
  const native = (Uint8Array as { fromBase64?: (text: string) => Uint8Array }).fromBase64;

  if (typeof native === "function") {
    return native.call(Uint8Array, text);
  }

  const atob = (globalThis as { atob?: (text: string) => string }).atob;

  if (typeof atob === "function") {
    const binary = atob(text);

    const out = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }

    return out;
  }

  const values = new Uint8Array(128).fill(255);

  for (let i = 0; i < 64; i++) {
    values[ALPHABET.charCodeAt(i)] = i;
  }

  const end = text.length - (text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0);

  const out = new Uint8Array((end * 3) >>> 2);

  let bits = 0;

  let count = 0;

  let at = 0;

  for (let i = 0; i < end; i++) {
    const char = text.charCodeAt(i);

    const value = char < 128 ? values[char] : 255;

    if (value === 255) {
      throw new Error("the embedded module is not valid base64");
    }

    bits = (bits << 6) | value;

    count += 6;

    if (count >= 8) {
      count -= 8;

      out[at++] = bits >>> count;
    }
  }

  return out;
}

// Linear memory cannot grow, or the library has no room for another stateful signer: the call
// failed, and the instance is as it was.
class Exhausted extends RangeError {}

// The error of a failed call: crypto-pq's own for codes 1 to 13, with the message that the
// TypeScript backend gives where the caller names one, and an internal error for the other codes
// of the C ABI, which only a mistake of this binding can produce.
export function failure(status: number, messages?: Partial<Record<ErrorCode, string>>): Error {
  const code = CODES[status - 1];

  if (status === OUT_OF_MEMORY) {
    return new Exhausted("crypto-pq's WebAssembly core is out of memory");
  }

  if (code === undefined) {
    return new Error(`crypto-pq's WebAssembly core refused a call with status ${status}`);
  }

  return new CryptoPQError(code, messages?.[code] ?? MESSAGES[code] ?? code);
}

export function check(status: number, messages?: Partial<Record<ErrorCode, string>>): void {
  if (status !== OK) {
    throw failure(status, messages);
  }
}

// A key slot that lives in a JS array between calls and is copied into the I/O block for each one,
// always at the start of the call's regions, so at one address while the block stays. The library
// ties a cache to the address where it was filled: after a call that fills one, or fills it again
// at a new address, the copy is updated, and until then calls at that address use it.
export class Slot {
  readonly bytes: Uint8Array;

  readonly #caches: number;

  #filled: number;

  #home: number;

  constructor(core: Core, at: number, length: number, caches: number) {
    this.bytes = core.read(at, length);

    this.#caches = caches;

    this.#filled = caches === 0 ? 0 : core.flags(at, length) & caches;

    this.#home = at;
  }

  load(core: Core, at: number): void {
    core.write(at, this.bytes);
  }

  update(core: Core, at: number): void {
    if (this.#caches === 0 || (at === this.#home && this.#filled === this.#caches)) {
      return;
    }

    const filled = core.flags(at, this.bytes.length) & this.#caches;

    if (filled !== 0 && (filled !== this.#filled || at !== this.#home)) {
      this.bytes.set(core.bytes().subarray(at, at + this.bytes.length));

      this.#filled = filled;

      this.#home = at;
    }
  }
}

// One family's WebAssembly module, compiled the first time the family is used. Whether the family
// runs on it is decided once: without WebAssembly or SIMD, when the engine refuses to compile or
// instantiate it, or when its known-answer test fails, the family runs in TypeScript.
export class Family {
  readonly name: string;

  readonly #base64: string;

  readonly #exports: readonly string[];

  readonly #test: (core: Core) => boolean;

  #module: object | null = null;

  #failure: Error | null = null;

  #core: Core | null = null;

  // The lists name the exports that the family needs; they are separate arguments, as a spread at
  // the call would keep bundlers from dropping an unused family.
  constructor(name: string, base64: string, test: (core: Core) => boolean, ...exports: (readonly string[])[]) {
    this.name = name;

    this.#base64 = base64;

    this.#exports = exports.flat();

    this.#test = test;
  }

  // The instance that a new key, or an operation without a key, runs on; null when the family runs
  // in TypeScript.
  select(): Core | null {
    if (chosen === "js") {
      return null;
    }

    if (this.#module === null && this.#failure === null) {
      this.#load();
    }

    if (this.#module === null) {
      if (chosen === "wasm") {
        throw new CryptoPQError("UNSUPPORTED", `${this.name} cannot run on WebAssembly here`, { cause: this.#failure });
      }

      return null;
    }

    return this.core();
  }

  // Whether, after this error of its instance, a new key goes to TypeScript instead: under "auto",
  // when the instance had no memory left for it.
  fallsBack(error: unknown): boolean {
    return chosen === "auto" && error instanceof Exhausted;
  }

  // The instance that keys made on WebAssembly run on, created again once the last one was
  // discarded.
  core(): Core {
    if (this.#core === null || !this.#core.live) {
      this.#core = this.#instantiate(this.#module!);
    }

    return this.#core;
  }

  #load(): void {
    try {
      const engine = api();

      if (!engine.validate(SIMD_PROBE)) {
        throw new Error("this platform's WebAssembly has no SIMD");
      }

      const module = new engine.Module(decodeBase64(this.#base64));

      const core = this.#instantiate(module);

      if (!this.#test(core)) {
        throw new Error(`the known-answer test of ${this.name} failed`);
      }

      this.#module = module;

      this.#core = core;
    } catch (error) {
      this.#failure = error instanceof Error ? error : new Error(String(error));
    }
  }

  #instantiate(module: object): Core {
    const instance = new (api().Instance)(module, {});

    return new Core(instance.exports, this.#exports);
  }
}

// One instance of a family's module. Each call places its inputs in the I/O block, which holds
// nothing between calls: every byte that a call used is zeroed when it returns, with the stack
// after an operation on secrets. Any failure other than crypto-pq's own error or a lack of memory
// discards the instance and zeroes its memory, and the family creates a new one on next use.
export class Core {
  readonly x: Readonly<Record<string, Call>>;

  readonly #memory: Memory;

  readonly #stackLow: number;

  readonly #stackHigh: number;

  readonly #sizes = new Map<number, number>();

  readonly #scratch: number;

  #view: Uint8Array;

  #io = 0;

  #capacity = 0;

  #depth = 0;

  #residents = 0;

  #live = true;

  constructor(exports: Record<string, unknown>, names: readonly string[]) {
    for (const name of [...COMMON, ...names]) {
      if (typeof exports[name] !== "function") {
        throw new Error(`the WebAssembly module lacks ${name}`);
      }
    }

    const memory = exports.memory as Memory | undefined;

    if (!(memory?.buffer instanceof ArrayBuffer)) {
      throw new Error("the WebAssembly module exports no memory");
    }

    this.x = exports as Record<string, Call>;

    this.#memory = memory;

    this.#view = new Uint8Array(memory.buffer);

    if (this.x.cpq_abi_version() !== 1) {
      throw new Error("the WebAssembly module has another ABI version");
    }

    this.x.cpq_wasm_tune(engineFlags());

    this.#stackLow = this.x.cpq_stack_low() >>> 0;

    this.#stackHigh = this.x.cpq_stack_high() >>> 0;

    this.#scratch = this.#allocate(64);
  }

  get live(): boolean {
    return this.#live;
  }

  // The current view of linear memory, which a call that grows the memory replaces.
  bytes(): Uint8Array {
    const buffer = this.#memory.buffer;

    if (this.#view.buffer !== buffer) {
      this.#view = new Uint8Array(buffer);
    }

    return this.#view;
  }

  // Regions are sized by the length that data reports, which its owner can change; the copy stays
  // within that length whatever the array really holds.
  write(at: number, data: Uint8Array): void {
    this.bytes().set(data.subarray(0, data.length), at);
  }

  read(at: number, length: number): Uint8Array {
    return this.bytes().slice(at, at + length);
  }

  // Writes fresh random bytes straight into linear memory. A random source that itself calls into
  // this instance can grow its memory, which detaches the view before the bytes arrive: the bytes
  // are then drawn again into a new view.
  random(at: number, length: number): void {
    for (let attempt = 0; attempt < 4; attempt++) {
      const view = this.bytes().subarray(at, at + length);

      randomInto(view);

      if (!this.#live) {
        throw new Error("the WebAssembly instance was discarded while the platform made random bytes");
      }

      if (view.length === length) {
        return;
      }
    }

    throw new CryptoPQError("RNG_FAILURE", "the random bytes did not reach WebAssembly memory");
  }

  // A 64-byte block for the small public outputs of a call, such as sizes and slot flags; read
  // it at once.
  get scratch(): number {
    return this.#scratch;
  }

  size(type: number, algorithm: number): number {
    const key = (type << 8) | algorithm;

    let size = this.#sizes.get(key);

    if (size === undefined) {
      size = this.x.cpq_slot_size(type, algorithm) >>> 0;

      this.#sizes.set(key, size);
    }

    return size;
  }

  // The flags of the slot at the address: bit 0 the key kept its seed, bit 8 the public cache is
  // filled, bit 9 the secret cache.
  flags(at: number, length: number): number {
    check(this.x.cpq_slot_info(at, length, this.#scratch));

    return new DataView(this.#memory.buffer).getUint32(this.#scratch + 8, true);
  }

  // Runs one operation on regions of the given lengths, each aligned to 16 bytes, and zeroes them
  // afterwards, with the given depth of the stack. A call made while another runs, which only the
  // platform's random source can start, gets a block of its own.
  run<T>(stack: number, lengths: readonly number[], body: (at: number[]) => T): T {
    const offsets: number[] = [];

    let total = 0;

    for (const length of lengths) {
      offsets.push(total);

      total += (length + 15) & ~15;
    }

    const own = this.#depth > 0 || total > IO_LIMIT;

    let base = 0;

    this.#depth++;

    try {
      base = own ? this.#allocate(total) : this.#reserve(total);

      return body(offsets.map((offset) => base + offset));
    } catch (error) {
      if (error instanceof CryptoPQError || error instanceof Exhausted) {
        throw error;
      }

      this.#discard();

      throw new Error("crypto-pq's WebAssembly core failed; its instance was discarded", { cause: error });
    } finally {
      this.#depth--;

      if (this.#live) {
        this.#wipe(stack, base, total, own);
      }
    }
  }

  // A block that outlives the call, a stateful signer's slot; while one is held the instance is not
  // replaced to give its memory back.
  allocate(size: number): number {
    this.#residents++;

    try {
      return this.run(PUBLIC, [], () => this.#allocate(size));
    } catch (error) {
      this.#residents--;

      throw error;
    }
  }

  // Called within a run, whose wipe covers what the allocator leaves on the stack. The library
  // refuses only a block that this binding never allocated or already freed: a fault.
  free(at: number, size: number): void {
    this.#residents--;

    if (this.x.cpq_free(at, size) !== OK) {
      throw new Error("the library refused to free a block");
    }
  }

  #wipe(stack: number, base: number, total: number, own: boolean): void {
    const view = this.bytes();

    if (base !== 0) {
      view.fill(0, base, base + total);

      if (own && this.x.cpq_free(base, total) !== OK) {
        this.#discard();

        return;
      }
    }

    if (stack > 0) {
      view.fill(0, Math.max(this.#stackLow, this.#stackHigh - stack), this.#stackHigh);
    }

    if (this.#depth === 0 && this.#residents === 0 && this.#memory.buffer.byteLength > MEMORY_LIMIT) {
      this.#live = false;
    }
  }

  #reserve(total: number): number {
    if (total > this.#capacity) {
      let size = PAGE - HEADERS;

      while (size < total) {
        size = 2 * size + HEADERS;
      }

      if (this.#io !== 0) {
        const freed = this.x.cpq_free(this.#io, this.#capacity);

        this.#io = 0;

        this.#capacity = 0;

        if (freed !== OK) {
          throw new Error("the library refused to free the I/O block");
        }
      }

      this.#io = this.#allocate(size);

      this.#capacity = size;
    }

    return this.#io;
  }

  #allocate(size: number): number {
    const at = this.x.cpq_alloc(size) >>> 0;

    if (at === 0) {
      throw new Exhausted("the WebAssembly memory cannot grow");
    }

    return at;
  }

  #discard(): void {
    if (this.#live) {
      this.#live = false;

      new Uint8Array(this.#memory.buffer).fill(0);
    }
  }
}
