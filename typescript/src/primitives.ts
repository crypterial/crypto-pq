import { readUint32, wipe, writeUint32 } from "./bytes.ts";
import { Keccak, absorbBytes, squeezeBytes } from "./keccak.ts";
import { IV_256, IV_512, Sha256, Sha512, compress256 } from "./sha2.ts";

const SHAKE256_RATE = 136;

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const engine = new Sha256(IV_256, 32);

  for (const part of parts) {
    engine.update(part);
  }

  return engine.digest();
}

export function sha512(...parts: Uint8Array[]): Uint8Array {
  const engine = new Sha512(IV_512, 64);

  for (const part of parts) {
    engine.update(part);
  }

  return engine.digest();
}

// SHA3-256 or SHA3-512, chosen by the digest size in bytes.
export function sha3(size: 32 | 64, ...parts: Uint8Array[]): Uint8Array {
  const sponge = new Keccak(200 - 2 * size, 0x06);

  for (const part of parts) {
    sponge.update(part);
  }

  return sponge.read(size);
}

export function shake128(...parts: Uint8Array[]): Keccak {
  const sponge = new Keccak(168, 0x1f);

  for (const part of parts) {
    sponge.update(part);
  }

  return sponge;
}

export function shake256Stream(...parts: Uint8Array[]): Keccak {
  const sponge = new Keccak(SHAKE256_RATE, 0x1f);

  for (const part of parts) {
    sponge.update(part);
  }

  return sponge;
}

export function shake256(length: number, ...parts: Uint8Array[]): Uint8Array {
  return shake256Stream(...parts).read(length);
}

// HMAC (RFC 2104) with SHA-256 or SHA-512, chosen by the digest size in bytes, of the concatenated
// parts; the padded key is zeroed afterwards.
export function hmac(size: 32 | 64, key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const hash = size === 32 ? sha256 : sha512;

  const pad = new Uint8Array(2 * size);

  if (key.length > pad.length) {
    const digest = hash(key);

    pad.set(digest);

    digest.fill(0);
  } else {
    pad.set(key);
  }

  for (let i = 0; i < pad.length; i++) {
    pad[i] ^= 0x36;
  }

  const inner = hash(pad, ...parts);

  for (let i = 0; i < pad.length; i++) {
    pad[i] ^= 0x36 ^ 0x5c;
  }

  const tag = hash(pad, inner);

  wipe(pad, inner);

  return tag;
}

export interface PrefixedHash {
  digest(length: number, ...parts: Uint8Array[]): Uint8Array;
}

// Hashes many short messages that share a prefix: the prefix blocks are compressed once, and each
// digest reuses one block buffer instead of allocating an engine.
class PrefixedSha2 implements PrefixedHash {
  readonly #initial: Int32Array;

  readonly #tail: Uint8Array;

  readonly #prefixLength: number;

  readonly #state: Int32Array;

  readonly #block: Uint8Array;

  readonly #compress: (state: Int32Array, data: Uint8Array, offset: number) => void;

  constructor(
    iv: Int32Array,
    blockSize: number,
    compress: (state: Int32Array, data: Uint8Array, offset: number) => void,
    prefix: Uint8Array,
  ) {
    const full = prefix.length - (prefix.length % blockSize);

    this.#initial = iv.slice();

    for (let offset = 0; offset < full; offset += blockSize) {
      compress(this.#initial, prefix, offset);
    }

    this.#tail = prefix.slice(full);

    this.#prefixLength = prefix.length;

    this.#state = new Int32Array(iv.length);

    this.#block = new Uint8Array(blockSize);

    this.#compress = compress;
  }

  digest(length: number, ...parts: Uint8Array[]): Uint8Array {
    const state = this.#state;

    const block = this.#block;

    const size = block.length;

    const compress = this.#compress;

    let used = this.#tail.length;

    let total = this.#prefixLength;

    state.set(this.#initial);

    block.set(this.#tail);

    for (const part of parts) {
      for (let offset = 0; offset < part.length; ) {
        const take = Math.min(size - used, part.length - offset);

        for (let i = 0; i < take; i++) {
          block[used + i] = part[offset + i];
        }

        used += take;

        offset += take;

        if (used === size) {
          compress(state, block, 0);

          used = 0;
        }
      }

      total += part.length;
    }

    block[used++] = 0x80;

    if (used > size - size / 8) {
      block.fill(0, used);

      compress(state, block, 0);

      used = 0;
    }

    block.fill(0, used, size - 8);

    writeUint32(block, size - 8, Math.floor(total / 0x20000000));

    writeUint32(block, size - 4, (total % 0x20000000) * 8);

    compress(state, block, 0);

    const out = new Uint8Array(length);

    for (let i = 0; i < length; i++) {
      out[i] = state[i >>> 2] >>> (24 - 8 * (i & 3));
    }

    return out;
  }
}

export function prefixedSha256(prefix: Uint8Array): PrefixedHash {
  return new PrefixedSha2(IV_256, 64, compress256, prefix);
}

class PrefixedShake256 implements PrefixedHash {
  readonly #initial = new Uint32Array(50);

  readonly #position: number;

  readonly #state = new Uint32Array(50);

  constructor(prefix: Uint8Array) {
    this.#position = absorbBytes(this.#initial, SHAKE256_RATE, 0, prefix, 0, prefix.length);
  }

  digest(length: number, ...parts: Uint8Array[]): Uint8Array {
    const state = this.#state;

    let position = this.#position;

    state.set(this.#initial);

    for (const part of parts) {
      position = absorbBytes(state, SHAKE256_RATE, position, part, 0, part.length);
    }

    const out = new Uint8Array(length);

    squeezeBytes(state, SHAKE256_RATE, position, 0x1f, out);

    return out;
  }
}

export function prefixedShake256(prefix: Uint8Array): PrefixedHash {
  return new PrefixedShake256(prefix);
}

// A message of fixed length rewritten in place between digests, for the inner loops of the
// hash-based signatures. Its first prefix.length bytes never change, so the blocks they fill are
// processed once. A digest may write its output over the message itself.
export interface FixedHash {
  readonly message: Uint8Array;

  digest(out: Uint8Array): void;
}

class FixedShake256 implements FixedHash {
  readonly message: Uint8Array;

  readonly #initial = new Uint32Array(50);

  readonly #state = new Uint32Array(50);

  readonly #prefixLength: number;

  readonly #position: number;

  constructor(length: number, prefix: Uint8Array) {
    this.message = new Uint8Array(length);

    this.message.set(prefix);

    this.#prefixLength = prefix.length;

    this.#position = absorbBytes(this.#initial, SHAKE256_RATE, 0, prefix, 0, prefix.length);
  }

  digest(out: Uint8Array): void {
    const state = this.#state;

    const message = this.message;

    state.set(this.#initial);

    const position = absorbBytes(state, SHAKE256_RATE, this.#position, message, this.#prefixLength, message.length);

    squeezeBytes(state, SHAKE256_RATE, position, 0x1f, out);
  }
}

export function fixedShake256(length: number, prefix: Uint8Array): FixedHash {
  return new FixedShake256(length, prefix);
}

// SHA-2 messages of the hash-based signatures as big-endian words. Both SLH-DSA (ADRSc) and LMS
// (I || u32(q) || u16(D)) start a block with a 22-byte header: words 0 to 4 and the high half of
// word 5, so every value after the header is shifted by two bytes against the word boundaries.

// Words 5 onward: the end of the header in the high half of high, then count words of m from offset
// on, then the 0x80 padding byte.
export function messageWords(w: Int32Array, high: number, m: Int32Array, offset: number, count: number): void {
  w[5] = high | (m[offset] >>> 16);

  for (let k = 1; k < count; k++) {
    w[5 + k] = (m[offset + k - 1] << 16) | (m[offset + k] >>> 16);
  }

  w[5 + count] = (m[offset + count - 1] << 16) | 0x8000;
}

// The same for a message of length bytes at data[offset].
export function messageBytes(w: Int32Array, high: number, data: Uint8Array, offset: number, length: number): void {
  w[5] = high | (data[offset] << 8) | data[offset + 1];

  for (let k = 1; k < length >>> 2; k++) {
    w[5 + k] = readUint32(data, offset + 4 * k - 2);
  }

  w[5 + (length >>> 2)] = (data[offset + length - 2] << 24) | (data[offset + length - 1] << 16) | 0x8000;
}

// The blocks for the header and length more bytes, after prefix bytes compressed beforehand, with
// the message length in place; wide blocks are SHA-512's.
export function blocks(wide: boolean, prefix: number, length: number): Int32Array {
  const size = wide ? 128 : 64;

  const w = new Int32Array((size / 4) * Math.ceil((22 + length + 1 + size / 8) / size));

  w[w.length - 1] = 8 * (prefix + 22 + length);

  return w;
}

export function storeWords(state: Int32Array, count: number, out: Uint8Array, offset: number): void {
  for (let k = 0; k < count; k++) {
    writeUint32(out, offset + 4 * k, state[k]);
  }
}

export function loadWords(data: Uint8Array, offset: number, count: number, out: Int32Array): void {
  for (let k = 0; k < count; k++) {
    out[k] = readUint32(data, offset + 4 * k);
  }
}
