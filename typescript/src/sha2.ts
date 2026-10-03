import { Blocks } from "./blocks.ts";
import { readUint32, writeUint32 } from "./bytes.ts";
import { block256, block512 } from "./sha2-rounds.ts";

export const IV_224 = Int32Array.of(
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
);

export const IV_256 = Int32Array.of(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
);

export const IV_384 = Int32Array.of(
  0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
  0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
);

export const IV_512 = Int32Array.of(
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
);

export const IV_512_224 = Int32Array.of(
  0x8c3d37c8, 0x19544da2, 0x73e19966, 0x89dcd4d6, 0x1dfab7ae, 0x32ff9c82, 0x679dd514, 0x582f9fcf,
  0x0f6d2b69, 0x7bd44da8, 0x77e36f73, 0x04c48942, 0x3f9d85a8, 0x6a1d36c8, 0x1112e6ad, 0x91d692a1,
);

export const IV_512_256 = Int32Array.of(
  0x22312194, 0xfc2bf72c, 0x9f555fa3, 0xc84c64c2, 0x2393b86b, 0x6f53b151, 0x96387719, 0x5940eabd,
  0x96283ee2, 0xa88effe3, 0xbe5e1e25, 0x53863992, 0x2b0199fc, 0x2c85b8aa, 0x0eb72ddc, 0x81c52ca2,
);

// The last one or two blocks of a digest: the end of the message, its padding and its length.
const TAIL = new Uint8Array(256);

const WORDS = new Int32Array(32);

export function compress256(state: Int32Array, data: Uint8Array, offset: number): void {
  for (let t = 0; t < 16; t++) {
    WORDS[t] = readUint32(data, offset + 4 * t);
  }

  block256(state, WORDS, 0, state);
}

export function compress512(state: Int32Array, data: Uint8Array, offset: number): void {
  for (let t = 0; t < 32; t++) {
    WORDS[t] = readUint32(data, offset + 4 * t);
  }

  block512(state, WORDS, 0, state);
}

abstract class Sha2 extends Blocks {
  protected readonly state: Int32Array;

  protected readonly size: number;

  protected length = 0;

  constructor(blockSize: number, iv: Int32Array, size: number) {
    super(blockSize);

    this.state = iv.slice();

    this.size = size;
  }

  override update(data: Uint8Array): void {
    this.length += data.length;

    super.update(data);
  }

  protected override process(data: Uint8Array, offset: number): void {
    this.compress(this.state, data, offset);
  }

  // FIPS 180-4, 5.1: the 0x80 marker, zeros, then the message length in bits, big-endian. The tail is
  // shared scratch, cleared after use since it holds the end of the message.
  digest(): Uint8Array {
    const block = this.buffer.length;

    const buffered = this.buffered;

    const state = this.state.slice();

    const tail = TAIL;

    for (let i = 0; i < buffered; i++) {
      tail[i] = this.buffer[i];
    }

    tail[buffered] = 0x80;

    const end = buffered + 1 + block / 8 > block ? 2 * block : block;

    tail.fill(0, buffered + 1, end - 8);

    writeUint32(tail, end - 8, Math.floor(this.length / 0x20000000));

    writeUint32(tail, end - 4, (this.length % 0x20000000) * 8);

    for (let offset = 0; offset < end; offset += block) {
      this.compress(state, tail, offset);
    }

    tail.fill(0, 0, end);

    const out = new Uint8Array(this.size);

    for (let i = 0; i < this.size; i++) {
      out[i] = state[i >>> 2] >>> (24 - 8 * (i & 3));
    }

    return out;
  }

  copy(): Sha2 {
    const other = this.clone();

    other.buffer.set(this.buffer);

    other.buffered = this.buffered;

    other.length = this.length;

    return other;
  }

  protected abstract compress(state: Int32Array, data: Uint8Array, offset: number): void;

  protected abstract clone(): Sha2;
}

export class Sha256 extends Sha2 {
  constructor(iv: Int32Array, size: number) {
    super(64, iv, size);
  }

  protected override compress(state: Int32Array, data: Uint8Array, offset: number): void {
    compress256(state, data, offset);
  }

  protected override clone(): Sha2 {
    return new Sha256(this.state, this.size);
  }
}

export class Sha512 extends Sha2 {
  constructor(iv: Int32Array, size: number) {
    super(128, iv, size);
  }

  protected override compress(state: Int32Array, data: Uint8Array, offset: number): void {
    compress512(state, data, offset);
  }

  protected override clone(): Sha2 {
    return new Sha512(this.state, this.size);
  }
}
