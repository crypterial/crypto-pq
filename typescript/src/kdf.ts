import { bytes, checkBytes, writeUint32 } from "./bytes.ts";
import { CryptoPQError } from "./errors.ts";
import { X_WING_HASH } from "./families.ts";
import { IV_256, IV_384, IV_512, compress256, compress512, digest256, digest512, wipeSha2 } from "./sha2.ts";
import { HASHING, check } from "./wasm.ts";

// HKDF (RFC 5869) over HMAC with SHA-256, SHA-384 or SHA-512. The key's pad blocks are compressed
// once per key, so each block of output costs the two compressions of its own message.

interface Sha2 {
  readonly iv: Int32Array;

  readonly block: number;

  readonly size: number;

  compress(state: Int32Array, data: Uint8Array, offset: number): void;

  hash(data: Uint8Array): Uint8Array;
}

const SHA_256: Sha2 = {
  iv: IV_256,
  block: 64,
  size: 32,
  compress: compress256,
  hash: (data) => digest256(IV_256, 32, data),
};

const SHA_384: Sha2 = {
  iv: IV_384,
  block: 128,
  size: 48,
  compress: compress512,
  hash: (data) => digest512(IV_384, 48, data),
};

const SHA_512: Sha2 = {
  iv: IV_512,
  block: 128,
  size: 64,
  compress: compress512,
  hash: (data) => digest512(IV_512, 64, data),
};

// The scratch of a derivation, cleared at its end: the chaining values after the inner and outer
// pad blocks, the state of a hash, its block, the inner hash of an HMAC, the counter byte and the
// pseudorandom key.
const INNER = new Int32Array(16);

const OUTER = new Int32Array(16);

const STATE = new Int32Array(16);

const BLOCK = new Uint8Array(128);

const TAG = new Uint8Array(64);

const COUNTER = new Uint8Array(1);

const PRK = new Uint8Array(64);

function clear(hash: Sha2): void {
  INNER.fill(0);

  OUTER.fill(0);

  STATE.fill(0);

  BLOCK.fill(0);

  TAG.fill(0);

  PRK.fill(0);

  wipeSha2(hash.block === 128);
}

// RFC 2104: the first length bytes of the key, hashed first when they are longer than a block,
// zero-padded and XORed with ipad and opad, each block compressed once into INNER and OUTER.
function keyPads(hash: Sha2, key: Uint8Array, length: number): void {
  const pad = BLOCK;

  pad.fill(0);

  if (length > hash.block) {
    const hashed = hash.hash(key.subarray(0, length));

    pad.set(hashed);

    hashed.fill(0);
  } else {
    for (let i = 0; i < length; i++) {
      pad[i] = key[i];
    }
  }

  for (let i = 0; i < hash.block; i++) {
    pad[i] ^= 0x36;
  }

  INNER.set(hash.iv);

  hash.compress(INNER, pad, 0);

  for (let i = 0; i < hash.block; i++) {
    pad[i] ^= 0x36 ^ 0x5c;
  }

  OUTER.set(hash.iv);

  hash.compress(OUTER, pad, 0);

  pad.fill(0);
}

// Absorbs data[from .. from + length) into STATE after the used bytes of a block that BLOCK holds:
// whole blocks are compressed where they are. Returns how many bytes BLOCK holds after it.
function absorb(hash: Sha2, data: Uint8Array, from: number, length: number, used: number): number {
  const { block: size, compress } = hash;

  const block = BLOCK;

  const end = from + length;

  let at = from;

  if (used === 0) {
    for (; end - at >= size; at += size) {
      compress(STATE, data, at);
    }
  }

  while (at < end) {
    const take = Math.min(size - used, end - at);

    for (let i = 0; i < take; i++) {
      block[used + i] = data[at + i];
    }

    used += take;

    at += take;

    if (used === size) {
      compress(STATE, block, 0);

      used = 0;

      for (; end - at >= size; at += size) {
        compress(STATE, data, at);
      }
    }
  }

  return used;
}

// The padding of a message of total bytes, the pad block included, after the used bytes in BLOCK;
// then count bytes of the hash into out at offset.
function finish(hash: Sha2, used: number, total: number, out: Uint8Array, offset: number, count: number): void {
  const { block: size, compress } = hash;

  const block = BLOCK;

  block[used++] = 0x80;

  if (used > size - size / 8) {
    block.fill(0, used, size);

    compress(STATE, block, 0);

    used = 0;
  }

  block.fill(0, used, size - 8);

  writeUint32(block, size - 8, Math.floor(total / 0x20000000));

  writeUint32(block, size - 4, (total % 0x20000000) * 8);

  compress(STATE, block, 0);

  for (let i = 0; i < count; i++) {
    out[offset + i] = STATE[i >>> 2] >>> (24 - 8 * (i & 3));
  }
}

// Ends the inner hash of an HMAC, whose message has the used bytes in BLOCK and total bytes in all,
// in TAG, then hashes it from OUTER: count bytes of the tag into out at offset.
function outer(hash: Sha2, used: number, total: number, out: Uint8Array, offset: number, count: number): void {
  finish(hash, used, total, TAG, 0, hash.size);

  STATE.set(OUTER);

  finish(hash, absorb(hash, TAG, 0, hash.size, 0), hash.block + hash.size, out, offset, count);
}

// HMAC of data with the key of keyPads: count bytes of the tag into out at offset.
function hmac(hash: Sha2, data: Uint8Array, out: Uint8Array, offset: number, count: number): void {
  STATE.set(INNER);

  outer(hash, absorb(hash, data, 0, data.length, 0), hash.block + data.length, out, offset, count);
}

// RFC 5869, 2.3: T(i) = HMAC(PRK, T(i - 1) || info || i), T(0) empty, with the PRK's pads set; T(i - 1)
// is read where it was written.
function expandInto(hash: Sha2, info: Uint8Array, out: Uint8Array): void {
  const size = hash.size;

  for (let i = 1, offset = 0; offset < out.length; i++, offset += size) {
    COUNTER[0] = i;

    STATE.set(INNER);

    const previous = i === 1 ? 0 : size;

    let used = absorb(hash, out, offset - previous, previous, 0);

    used = absorb(hash, info, 0, info.length, used);

    used = absorb(hash, COUNTER, 0, 1, used);

    outer(hash, used, hash.block + previous + info.length + 1, out, offset, Math.min(size, out.length - offset));
  }
}

function hkdfExtract(hash: Sha2, salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  const prk = new Uint8Array(hash.size);

  try {
    keyPads(hash, salt, salt.length);

    hmac(hash, ikm, prk, 0, hash.size);
  } finally {
    clear(hash);
  }

  return prk;
}

function hkdfExpand(hash: Sha2, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const okm = new Uint8Array(length);

  try {
    keyPads(hash, prk, prk.length);

    expandInto(hash, info, okm);
  } finally {
    clear(hash);
  }

  return okm;
}

// Extract then Expand, the PRK in the scratch.
function hkdf(hash: Sha2, ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const okm = new Uint8Array(length);

  try {
    keyPads(hash, salt, salt.length);

    hmac(hash, ikm, PRK, 0, hash.size);

    keyPads(hash, PRK, hash.size);

    expandInto(hash, info, okm);
  } finally {
    clear(hash);
  }

  return okm;
}

export interface KdfOptions {
  salt?: Uint8Array;

  info?: Uint8Array;
}

const EMPTY = new Uint8Array(0);

// Absent options read as one shared empty object, so that reading them allocates nothing. A call
// checks its arguments' types, then reads the options, whose getters are caller code that may change
// an input, and reads the inputs with bytes() only then.
const NO_OPTIONS: KdfOptions = Object.freeze({});

function optionsOf(options: KdfOptions | undefined): KdfOptions {
  if (options === undefined || options === null) {
    return NO_OPTIONS;
  }

  if (typeof options !== "object") {
    throw new TypeError("options must be an object");
  }

  return options;
}

export class KdfAlgorithm {
  readonly name: string;

  // The length of a pseudorandom key: the hash length.
  readonly prkSize: number;

  readonly #id: number;

  readonly #hash: Sha2;

  constructor(name: string, id: number, hash: Sha2) {
    this.name = name;

    this.prkSize = hash.size;

    this.#id = id;

    this.#hash = hash;

    Object.freeze(this);
  }

  // Where this algorithm runs, deciding it on first use.
  get backend(): "wasm" | "js" {
    return X_WING_HASH.select() === null ? "js" : "wasm";
  }

  // RFC 5869, 2.3: L is 1 to 255 hash lengths.
  #checkLength(length: number): void {
    if (!Number.isSafeInteger(length) || length < 1 || length > 255 * this.prkSize) {
      throw new CryptoPQError("INVALID_LENGTH", `the output of ${this.name} is 1 to ${255 * this.prkSize} bytes`);
    }
  }

  // Expand(Extract(salt, ikm), info) of length bytes; an empty salt is HashLen zero bytes.
  derive(ikm: Uint8Array, length: number, options?: KdfOptions): Uint8Array {
    checkBytes(ikm, "ikm");

    const { salt: givenSalt = EMPTY, info: givenInfo = EMPTY } = optionsOf(options);

    const secret = bytes(ikm, "ikm");

    const salt = bytes(givenSalt, "salt");

    const info = bytes(givenInfo, "info");

    this.#checkLength(length);

    const core = X_WING_HASH.select();

    if (core === null) {
      return hkdf(this.#hash, secret, salt, info, length);
    }

    const lengths = [secret.length, salt.length, info.length, length];

    return core.run(HASHING, lengths, (k, s, i, out) => {
      core.write(k, secret);

      core.write(s, salt);

      core.write(i, info);

      check(core.x.cpq_kdf_derive(this.#id, k, secret.length, s, salt.length, i, info.length, out, length));

      return core.read(out, length);
    });
  }

  // The pseudorandom key, prkSize bytes. Extract takes no info.
  extract(ikm: Uint8Array, options?: KdfOptions): Uint8Array {
    checkBytes(ikm, "ikm");

    const { salt: givenSalt = EMPTY, info: givenInfo = EMPTY } = optionsOf(options);

    const secret = bytes(ikm, "ikm");

    const salt = bytes(givenSalt, "salt");

    const info = bytes(givenInfo, "info");

    if (info.length > 0) {
      throw new CryptoPQError("INVALID_OPTION", "HKDF-Extract takes no info");
    }

    const core = X_WING_HASH.select();

    if (core === null) {
      return hkdfExtract(this.#hash, salt, secret);
    }

    const size = this.prkSize;

    return core.run(HASHING, [secret.length, salt.length, size], (k, s, out) => {
      core.write(k, secret);

      core.write(s, salt);

      check(core.x.cpq_kdf_extract(this.#id, k, secret.length, s, salt.length, out, size));

      return core.read(out, size);
    });
  }

  // length bytes from a pseudorandom key of at least prkSize bytes. Expand takes no salt.
  expand(prk: Uint8Array, length: number, options?: KdfOptions): Uint8Array {
    checkBytes(prk, "prk");

    const { salt: givenSalt = EMPTY, info: givenInfo = EMPTY } = optionsOf(options);

    const key = bytes(prk, "prk");

    const salt = bytes(givenSalt, "salt");

    const info = bytes(givenInfo, "info");

    this.#checkLength(length);

    if (salt.length > 0) {
      throw new CryptoPQError("INVALID_OPTION", "HKDF-Expand takes no salt");
    }

    if (key.length < this.prkSize) {
      throw new CryptoPQError("INVALID_LENGTH", `a pseudorandom key of ${this.name} has ${this.prkSize} bytes or more`);
    }

    const core = X_WING_HASH.select();

    if (core === null) {
      return hkdfExpand(this.#hash, key, info, length);
    }

    return core.run(HASHING, [key.length, info.length, length], (k, i, out) => {
      core.write(k, key);

      core.write(i, info);

      check(core.x.cpq_kdf_expand(this.#id, k, key.length, i, info.length, out, length));

      return core.read(out, length);
    });
  }
}

export const HKDF_SHA_256 = /* @__PURE__ */ new KdfAlgorithm("HKDF-SHA-256", 0, SHA_256);

export const HKDF_SHA_384 = /* @__PURE__ */ new KdfAlgorithm("HKDF-SHA-384", 1, SHA_384);

export const HKDF_SHA_512 = /* @__PURE__ */ new KdfAlgorithm("HKDF-SHA-512", 2, SHA_512);
