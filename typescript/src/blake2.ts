import { blake2bCompress, blake2sCompress } from "./blake2-rounds.ts";
import { IV_256, IV_512 } from "./sha2.ts";

// BLAKE2b and BLAKE2s (RFC 7693) in sequential mode, keyed or not, with a salt and a
// personalization. A chaining value is little-endian 32-bit words, BLAKE2b's 64-bit words as
// (low, high) pairs, which is also the byte order of the digest.
export interface Blake2 {
  readonly block: number;

  // The longest digest and key, and the size of the salt and personalization fields.
  readonly maxSize: number;

  readonly field: number;

  readonly iv: Int32Array;

  compress(h: Int32Array, data: Uint8Array, offset: number, counter: number, last: number): void;
}

export const BLAKE2B: Blake2 = {
  block: 128,
  maxSize: 64,
  field: 16,
  iv: /* @__PURE__ */ Int32Array.from({ length: 16 }, (_, i) => IV_512[i ^ 1]),
  compress: blake2bCompress,
};

export const BLAKE2S: Blake2 = { block: 64, maxSize: 32, field: 8, iv: IV_256, compress: blake2sCompress };

// The chaining value of the parameter block (RFC 7693, 2.5, and the BLAKE2 specification, 2.8) for
// sequential hashing to size bytes: fanout and depth 1, the salt and personalization zero-padded.
// The key length field stays zero; keying adds it.
export function initial(variant: Blake2, size: number, salt: Uint8Array, personalization: Uint8Array): Int32Array {
  const block = new Uint8Array(4 * variant.iv.length);

  block[0] = size;

  block[2] = 1;

  block[3] = 1;

  block.set(salt, 2 * variant.field);

  block.set(personalization, 3 * variant.field);

  const h = variant.iv.slice();

  for (let i = 0; i < h.length; i++) {
    h[i] ^= block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
  }

  return h;
}

export function store(h: Int32Array, out: Uint8Array): void {
  for (let i = 0; i < out.length; i++) {
    out[i] = h[i >>> 2] >>> (8 * (i & 3));
  }
}

// The scratch of one-shot digests, cleared after each: a digest runs to its end without calling out,
// so one serves every call.
const STATE = new Int32Array(16);

const LAST = new Uint8Array(128);

// The digest of a whole message, its whole blocks compressed where they are: the key block (RFC 7693,
// 3.3) first when there is a key, and the last block always with the final flag, padded with zeros.
export function digest(variant: Blake2, h0: Int32Array, key: Uint8Array, data: Uint8Array, size: number): Uint8Array {
  const { block, compress } = variant;

  const h = STATE;

  const length = data.length;

  h.set(h0);

  h[0] ^= key.length << 8;

  let counter = 0;

  if (key.length > 0) {
    LAST.set(key.subarray(0, key.length));

    counter = block;

    compress(h, LAST, 0, counter, length === 0 ? -1 : 0);

    LAST.fill(0, 0, key.length);
  }

  if (length > 0 || key.length === 0) {
    const rest = length === 0 ? 0 : length - block * Math.floor((length - 1) / block);

    const whole = length - rest;

    for (let offset = 0; offset < whole; offset += block) {
      counter += block;

      compress(h, data, offset, counter, 0);
    }

    counter += rest;

    if (rest === block) {
      compress(h, data, whole, counter, -1);
    } else {
      for (let i = 0; i < rest; i++) {
        LAST[i] = data[whole + i];
      }

      compress(h, LAST, 0, counter, -1);

      LAST.fill(0, 0, rest);
    }
  }

  const out = new Uint8Array(size);

  store(h, out);

  h.fill(0);

  return out;
}

// A BLAKE2 hash over updates. The last block is compressed only once the next update shows that it is
// not the last, or by digest, which works on copies and so can be called again.
export class Blake2Engine {
  readonly #variant: Blake2;

  readonly #h: Int32Array;

  readonly #buffer: Uint8Array;

  readonly #size: number;

  #buffered = 0;

  #counter = 0;

  // A key is the first block; a key of length 0 means none.
  constructor(variant: Blake2, h0: Int32Array, key: Uint8Array, size: number) {
    this.#variant = variant;

    this.#h = h0.slice();

    this.#h[0] ^= key.length << 8;

    this.#buffer = new Uint8Array(variant.block);

    this.#size = size;

    if (key.length > 0) {
      this.#buffer.set(key.subarray(0, key.length));

      this.#buffered = variant.block;
    }
  }

  update(data: Uint8Array): void {
    const { block, compress } = this.#variant;

    const buffer = this.#buffer;

    const length = data.length;

    let offset = 0;

    while (offset < length) {
      if (this.#buffered === block) {
        this.#counter += block;

        compress(this.#h, buffer, 0, this.#counter, 0);

        this.#buffered = 0;
      }

      if (this.#buffered === 0) {
        for (; length - offset > block; offset += block) {
          this.#counter += block;

          compress(this.#h, data, offset, this.#counter, 0);
        }
      }

      const take = Math.min(block - this.#buffered, length - offset);

      for (let i = 0; i < take; i++) {
        buffer[this.#buffered + i] = data[offset + i];
      }

      this.#buffered += take;

      offset += take;
    }
  }

  digest(): Uint8Array {
    const h = this.#h.slice();

    const last = this.#buffer.slice();

    last.fill(0, this.#buffered);

    this.#variant.compress(h, last, 0, this.#counter + this.#buffered, -1);

    const out = new Uint8Array(this.#size);

    store(h, out);

    h.fill(0);

    last.fill(0);

    return out;
  }

  copy(): Blake2Engine {
    const other = new Blake2Engine(this.#variant, this.#h, new Uint8Array(0), this.#size);

    other.#buffer.set(this.#buffer);

    other.#buffered = this.#buffered;

    other.#counter = this.#counter;

    return other;
  }
}
