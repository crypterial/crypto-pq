import { Blocks } from "./blocks.ts";
import { CryptoPQError } from "./errors.ts";
import { permute } from "./keccak-permute.ts";

// The state is bit-interleaved, as permute expects: lane i is s[2i], holding its even-numbered bits,
// and s[2i + 1], holding its odd-numbered bits. Input and output pass through unzip and zip.

// Gathers the even-numbered bits of x in its low half and the odd-numbered bits in its high half.
function unzip(x: number): number {
  let t = (x ^ (x >>> 1)) & 0x22222222;

  x ^= t ^ (t << 1);

  t = (x ^ (x >>> 2)) & 0x0c0c0c0c;

  x ^= t ^ (t << 2);

  t = (x ^ (x >>> 4)) & 0x00f000f0;

  x ^= t ^ (t << 4);

  t = (x ^ (x >>> 8)) & 0x0000ff00;

  return x ^ t ^ (t << 8);
}

function zip(x: number): number {
  let t = (x ^ (x >>> 8)) & 0x0000ff00;

  x ^= t ^ (t << 8);

  t = (x ^ (x >>> 4)) & 0x00f000f0;

  x ^= t ^ (t << 4);

  t = (x ^ (x >>> 2)) & 0x0c0c0c0c;

  x ^= t ^ (t << 2);

  t = (x ^ (x >>> 1)) & 0x22222222;

  return x ^ t ^ (t << 1);
}

// XORs the 64-bit lane lo + 2^32 hi into lane i of the state.
export function xorLane(s: Uint32Array, i: number, lo: number, hi: number): void {
  const low = unzip(lo);

  const high = unzip(hi);

  s[2 * i] ^= (low & 0xffff) | (high << 16);

  s[2 * i + 1] ^= (low >>> 16) | (high & 0xffff0000);
}

// Writes lane i of the state as eight little-endian bytes at out[offset].
export function storeLane(s: Uint32Array, i: number, out: Uint8Array, offset: number): void {
  const even = s[2 * i];

  const odd = s[2 * i + 1];

  const low = zip((even & 0xffff) | (odd << 16));

  const high = zip((even >>> 16) | (odd & 0xffff0000));

  out[offset] = low;

  out[offset + 1] = low >>> 8;

  out[offset + 2] = low >>> 16;

  out[offset + 3] = low >>> 24;

  out[offset + 4] = high;

  out[offset + 5] = high >>> 8;

  out[offset + 6] = high >>> 16;

  out[offset + 7] = high >>> 24;
}

const LANE = new Uint8Array(8);

function readLittleEndian(data: Uint8Array, offset: number): number {
  return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
}

// XORs the length bytes at data[offset], whole lanes, into the state from its first lane on.
function absorb(s: Uint32Array, data: Uint8Array, offset: number, length: number): void {
  for (let i = 0; i < length >>> 3; i++, offset += 8) {
    xorLane(s, i, readLittleEndian(data, offset), readLittleEndian(data, offset + 4));
  }
}

// XORs data[from .. to) into the state from byte position of the current block on, permuting each
// time a block of rate bytes fills, and returns the new position.
export function absorbBytes(
  s: Uint32Array,
  rate: number,
  position: number,
  data: Uint8Array,
  from: number,
  to: number,
): number {
  while (from < to) {
    const shift = position & 7;

    const take = Math.min(8 - shift, to - from);

    if (take === 8) {
      xorLane(s, position >>> 3, readLittleEndian(data, from), readLittleEndian(data, from + 4));
    } else {
      let lo = 0;

      let hi = 0;

      for (let k = 0; k < take; k++) {
        const at = 8 * (shift + k);

        if (at < 32) {
          lo |= data[from + k] << at;
        } else {
          hi |= data[from + k] << (at - 32);
        }
      }

      xorLane(s, position >>> 3, lo, hi);
    }

    position += take;

    from += take;

    if (position === rate) {
      permute(s);

      position = 0;
    }
  }

  return position;
}

// Pads a message that ends at byte position of the current block with the domain suffix, then
// squeezes out.length bytes.
export function squeezeBytes(s: Uint32Array, rate: number, position: number, suffix: number, out: Uint8Array): void {
  const at = 8 * (position & 7);

  xorLane(s, position >>> 3, at < 32 ? suffix << at : 0, at < 32 ? 0 : suffix << (at - 32));

  xorLane(s, (rate >>> 3) - 1, 0, 0x80000000);

  permute(s);

  for (let offset = 0, i = 0; offset < out.length; offset += 8, i++) {
    if (8 * i === rate) {
      permute(s);

      i = 0;
    }

    if (out.length - offset >= 8) {
      storeLane(s, i, out, offset);
    } else {
      storeLane(s, i, LANE, 0);

      out.set(LANE.subarray(0, out.length - offset), offset);

      LANE.fill(0);
    }
  }
}

// A Keccak sponge over bytes. The buffer collects the input of a partial block while absorbing and
// holds the current block of output while squeezing.
export class Keccak extends Blocks {
  readonly #state = new Uint32Array(50);

  readonly #suffix: number;

  // The unread bytes of the output block in the buffer, or -1 while absorbing.
  #available = -1;

  constructor(rate: number, suffix: number) {
    super(rate);

    this.#suffix = suffix;
  }

  override update(data: Uint8Array): void {
    if (this.#available >= 0) {
      throw new CryptoPQError("UNSUPPORTED", "cannot update after read");
    }

    super.update(data);
  }

  read(length: number): Uint8Array {
    const out = new Uint8Array(length);

    this.readInto(out);

    return out;
  }

  readInto(out: Uint8Array): void {
    const buffer = this.buffer;

    for (let offset = 0; offset < out.length; ) {
      if (this.#available <= 0) {
        this.#squeeze();
      }

      const start = buffer.length - this.#available;

      const take = Math.min(this.#available, out.length - offset);

      if (take > 16) {
        out.set(buffer.subarray(start, start + take), offset);
      } else {
        for (let i = 0; i < take; i++) {
          out[offset + i] = buffer[start + i];
        }
      }

      offset += take;

      this.#available -= take;
    }
  }

  // The next block of output, in a buffer that the following call overwrites; only for a stream read
  // in whole blocks.
  readBlock(): Uint8Array {
    this.#squeeze();

    this.#available = 0;

    return this.buffer;
  }

  // Starts a new message, clearing everything the previous one left in the sponge.
  reset(): void {
    this.#state.fill(0);

    this.buffer.fill(0);

    this.buffered = 0;

    this.#available = -1;
  }

  copy(): Keccak {
    const other = new Keccak(this.buffer.length, this.#suffix);

    other.#state.set(this.#state);

    other.buffer.set(this.buffer);

    other.buffered = this.buffered;

    other.#available = this.#available;

    return other;
  }

  protected override process(data: Uint8Array, offset: number): void {
    absorb(this.#state, data, offset, this.buffer.length);

    permute(this.#state);
  }

  // Pads the input on the first call, then permutes and unpacks the next block of output. The padding
  // absorbs only the lanes that hold input or the domain suffix; the final bit goes straight into the
  // last lane of the block.
  #squeeze(): void {
    const state = this.#state;

    const buffer = this.buffer;

    if (this.#available < 0) {
      const end = (this.buffered + 8) & ~7;

      buffer.fill(0, this.buffered, end);

      buffer[this.buffered] = this.#suffix;

      absorb(state, buffer, 0, end);

      xorLane(state, (buffer.length >>> 3) - 1, 0, 0x80000000);
    }

    permute(state);

    for (let i = 0; i < buffer.length >>> 3; i++) {
      storeLane(state, i, buffer, 8 * i);
    }

    this.#available = buffer.length;
  }
}
