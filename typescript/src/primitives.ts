import { writeUint32 } from "./bytes.ts";
import { Keccak, permute } from "./keccak.ts";
import { IV_256, IV_512, Sha256, Sha512, compress256, compress512 } from "./sha2.ts";

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

export interface PrefixedHash {
  digest(length: number, ...parts: Uint8Array[]): Uint8Array;
}

// Hashes many short messages that share a prefix: the prefix blocks are compressed once, and each
// digest reuses one block buffer instead of allocating an engine.
class PrefixedSha2 implements PrefixedHash {
  readonly #initial: Uint32Array;

  readonly #tail: Uint8Array;

  readonly #prefixLength: number;

  readonly #state: Uint32Array;

  readonly #block: Uint8Array;

  readonly #compress: (state: Uint32Array, data: Uint8Array, offset: number) => void;

  constructor(
    iv: readonly number[],
    blockSize: number,
    compress: (state: Uint32Array, data: Uint8Array, offset: number) => void,
    prefix: Uint8Array,
  ) {
    const full = prefix.length - (prefix.length % blockSize);

    this.#initial = Uint32Array.from(iv);

    for (let offset = 0; offset < full; offset += blockSize) {
      compress(this.#initial, prefix, offset);
    }

    this.#tail = prefix.slice(full);

    this.#prefixLength = prefix.length;

    this.#state = new Uint32Array(iv.length);

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

export function prefixedSha512(prefix: Uint8Array): PrefixedHash {
  return new PrefixedSha2(IV_512, 128, compress512, prefix);
}

class PrefixedShake256 implements PrefixedHash {
  readonly #initial = new Uint32Array(50);

  readonly #position: number;

  readonly #state = new Uint32Array(50);

  constructor(prefix: Uint8Array) {
    this.#position = absorb(this.#initial, 0, prefix, 0, prefix.length);
  }

  digest(length: number, ...parts: Uint8Array[]): Uint8Array {
    const state = this.#state;

    let position = this.#position;

    state.set(this.#initial);

    for (const part of parts) {
      position = absorb(state, position, part, 0, part.length);
    }

    const out = new Uint8Array(length);

    finish(state, position, out);

    return out;
  }
}

// XORs data[from:to] into the sponge at position, whole words at a time where aligned, and returns
// the new position.
function absorb(state: Uint32Array, position: number, data: Uint8Array, from: number, to: number): number {
  for (let i = from; i < to; ) {
    if ((position & 3) === 0 && to - i >= 4) {
      state[position >>> 2] ^= data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);

      position += 4;

      i += 4;
    } else {
      state[position >>> 2] ^= data[i] << ((position & 3) << 3);

      position++;

      i++;
    }

    if (position === SHAKE256_RATE) {
      permute(state);

      position = 0;
    }
  }

  return position;
}

// Pads the absorbed input and squeezes out.length bytes.
function finish(state: Uint32Array, position: number, out: Uint8Array): void {
  state[position >>> 2] ^= 0x1f << ((position & 3) << 3);

  state[(SHAKE256_RATE - 1) >>> 2] ^= 0x80 << (((SHAKE256_RATE - 1) & 3) << 3);

  permute(state);

  for (let i = 0, offset = 0; i < out.length; i++, offset++) {
    if (offset === SHAKE256_RATE) {
      permute(state);

      offset = 0;
    }

    out[i] = state[offset >>> 2] >>> ((offset & 3) << 3);
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

class FixedSha256 implements FixedHash {
  readonly message: Uint8Array;

  readonly #blocks: Uint8Array;

  readonly #initial = Uint32Array.from(IV_256);

  readonly #state = new Uint32Array(8);

  readonly #start: number;

  constructor(length: number, prefix: Uint8Array) {
    const size = 64 * Math.ceil((length + 9) / 64);

    this.#blocks = new Uint8Array(size);

    this.message = this.#blocks.subarray(0, length);

    this.message.set(prefix);

    this.#blocks[length] = 0x80;

    writeUint32(this.#blocks, size - 8, Math.floor(length / 0x20000000));

    writeUint32(this.#blocks, size - 4, (length % 0x20000000) * 8);

    this.#start = prefix.length - (prefix.length % 64);

    for (let offset = 0; offset < this.#start; offset += 64) {
      compress256(this.#initial, this.#blocks, offset);
    }
  }

  digest(out: Uint8Array): void {
    const state = this.#state;

    state.set(this.#initial);

    for (let offset = this.#start; offset < this.#blocks.length; offset += 64) {
      compress256(state, this.#blocks, offset);
    }

    for (let i = 0; i < out.length; i++) {
      out[i] = state[i >>> 2] >>> (24 - 8 * (i & 3));
    }
  }
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

    this.#position = absorb(this.#initial, 0, prefix, 0, prefix.length);
  }

  digest(out: Uint8Array): void {
    const state = this.#state;

    state.set(this.#initial);

    finish(state, absorb(state, this.#position, this.message, this.#prefixLength, this.message.length), out);
  }
}

export function fixedSha256(length: number, prefix: Uint8Array): FixedHash {
  return new FixedSha256(length, prefix);
}

export function fixedShake256(length: number, prefix: Uint8Array): FixedHash {
  return new FixedShake256(length, prefix);
}
