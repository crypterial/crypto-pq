import { bytes, writeUint32 } from "./bytes.ts";
import { CryptoPQError } from "./errors.ts";
import { X_WING_HASH } from "./families.ts";
import { IV_256, IV_384, IV_512, compress256, compress512, digest256, digest512 } from "./sha2.ts";
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
// pad blocks, the state of a hash, its block, the last T(i) and the counter byte.
const INNER = new Int32Array(16);

const OUTER = new Int32Array(16);

const STATE = new Int32Array(16);

const BLOCK = new Uint8Array(128);

const TAG = new Uint8Array(64);

const COUNTER = new Uint8Array(1);

function clear(): void {
  INNER.fill(0);

  OUTER.fill(0);

  STATE.fill(0);

  BLOCK.fill(0);

  TAG.fill(0);
}

// RFC 2104: the key, hashed first when it is longer than a block, zero-padded and XORed with ipad
// and opad, each block compressed once into INNER and OUTER.
function keyPads(hash: Sha2, key: Uint8Array): void {
  const pad = BLOCK;

  pad.fill(0);

  if (key.length > hash.block) {
    const hashed = hash.hash(key);

    pad.set(hashed);

    hashed.fill(0);
  } else {
    pad.set(key.subarray(0, key.length));
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

// The hash of a pad block, already compressed into STATE, then the parts: count bytes of it into out
// at offset. Whole blocks of a part are compressed where they are.
function finish(hash: Sha2, parts: readonly Uint8Array[], out: Uint8Array, offset: number, count: number): void {
  const { block: size, compress } = hash;

  const block = BLOCK;

  let used = 0;

  let total = size;

  for (const part of parts) {
    let at = 0;

    if (used === 0) {
      for (; part.length - at >= size; at += size) {
        compress(STATE, part, at);
      }
    }

    while (at < part.length) {
      const take = Math.min(size - used, part.length - at);

      for (let i = 0; i < take; i++) {
        block[used + i] = part[at + i];
      }

      used += take;

      at += take;

      if (used === size) {
        compress(STATE, block, 0);

        used = 0;

        for (; part.length - at >= size; at += size) {
          compress(STATE, part, at);
        }
      }
    }

    total += part.length;
  }

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

// HMAC of the parts with the key of keyPads: count bytes of the tag into out at offset.
function hmac(hash: Sha2, parts: readonly Uint8Array[], out: Uint8Array, offset: number, count: number): void {
  STATE.set(INNER);

  finish(hash, parts, TAG, 0, hash.size);

  STATE.set(OUTER);

  finish(hash, [TAG.subarray(0, hash.size)], out, offset, count);
}

// RFC 5869, 2.3: T(i) = HMAC(PRK, T(i - 1) || info || i), T(0) empty, with the PRK's pads set.
function expandInto(hash: Sha2, info: Uint8Array, out: Uint8Array): void {
  const size = hash.size;

  for (let i = 1, offset = 0; offset < out.length; i++, offset += size) {
    COUNTER[0] = i;

    const count = Math.min(size, out.length - offset);

    const parts = i === 1 ? [info, COUNTER] : [out.subarray(offset - size, offset), info, COUNTER];

    hmac(hash, parts, out, offset, count);
  }
}

function hkdfExtract(hash: Sha2, salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  const prk = new Uint8Array(hash.size);

  try {
    keyPads(hash, salt);

    hmac(hash, [ikm], prk, 0, hash.size);
  } finally {
    clear();
  }

  return prk;
}

function hkdfExpand(hash: Sha2, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const okm = new Uint8Array(length);

  try {
    keyPads(hash, prk);

    expandInto(hash, info, okm);
  } finally {
    clear();
  }

  return okm;
}

// Extract then Expand; the PRK is cleared once its pads are made.
function hkdf(hash: Sha2, ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const okm = new Uint8Array(length);

  const prk = new Uint8Array(hash.size);

  try {
    keyPads(hash, salt);

    hmac(hash, [ikm], prk, 0, hash.size);

    keyPads(hash, prk);

    prk.fill(0);

    expandInto(hash, info, okm);
  } finally {
    prk.fill(0);

    clear();
  }

  return okm;
}

export interface KdfOptions {
  salt?: Uint8Array;

  info?: Uint8Array;
}

const EMPTY = new Uint8Array(0);

function inputs(options: KdfOptions | undefined): [Uint8Array, Uint8Array] {
  if (options === undefined || options === null) {
    return [EMPTY, EMPTY];
  }

  if (typeof options !== "object") {
    throw new TypeError("options must be an object");
  }

  const { salt, info } = options;

  return [salt === undefined ? EMPTY : bytes(salt, "salt"), info === undefined ? EMPTY : bytes(info, "info")];
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
    const secret = bytes(ikm, "ikm");

    const [salt, info] = inputs(options);

    this.#checkLength(length);

    const core = X_WING_HASH.select();

    if (core === null) {
      return hkdf(this.#hash, secret, salt, info, length);
    }

    const lengths = [secret.length, salt.length, info.length, length];

    return core.run(HASHING, lengths, ([k, s, i, out]) => {
      core.write(k, secret);

      core.write(s, salt);

      core.write(i, info);

      check(core.x.cpq_kdf_derive(this.#id, k, secret.length, s, salt.length, i, info.length, out, length));

      return core.read(out, length);
    });
  }

  // The pseudorandom key, prkSize bytes. Extract takes no info.
  extract(ikm: Uint8Array, options?: KdfOptions): Uint8Array {
    const secret = bytes(ikm, "ikm");

    const [salt, info] = inputs(options);

    if (info.length > 0) {
      throw new CryptoPQError("INVALID_OPTION", "HKDF-Extract takes no info");
    }

    const core = X_WING_HASH.select();

    if (core === null) {
      return hkdfExtract(this.#hash, salt, secret);
    }

    const size = this.prkSize;

    return core.run(HASHING, [secret.length, salt.length, size], ([k, s, out]) => {
      core.write(k, secret);

      core.write(s, salt);

      check(core.x.cpq_kdf_extract(this.#id, k, secret.length, s, salt.length, out, size));

      return core.read(out, size);
    });
  }

  // length bytes from a pseudorandom key of at least prkSize bytes. Expand takes no salt.
  expand(prk: Uint8Array, length: number, options?: KdfOptions): Uint8Array {
    const key = bytes(prk, "prk");

    const [salt, info] = inputs(options);

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

    return core.run(HASHING, [key.length, info.length, length], ([k, i, out]) => {
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
