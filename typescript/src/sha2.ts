import { Blocks } from "./blocks.ts";
import { readUint32, writeUint32 } from "./bytes.ts";

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// SHA-512 words are stored as (high, low) 32-bit pairs.
const K512 = new Uint32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]);

export const IV_224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];

export const IV_256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

export const IV_384 = [
  0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
  0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
];

export const IV_512 = [
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
];

export const IV_512_224 = [
  0x8c3d37c8, 0x19544da2, 0x73e19966, 0x89dcd4d6, 0x1dfab7ae, 0x32ff9c82, 0x679dd514, 0x582f9fcf,
  0x0f6d2b69, 0x7bd44da8, 0x77e36f73, 0x04c48942, 0x3f9d85a8, 0x6a1d36c8, 0x1112e6ad, 0x91d692a1,
];

export const IV_512_256 = [
  0x22312194, 0xfc2bf72c, 0x9f555fa3, 0xc84c64c2, 0x2393b86b, 0x6f53b151, 0x96387719, 0x5940eabd,
  0x96283ee2, 0xa88effe3, 0xbe5e1e25, 0x53863992, 0x2b0199fc, 0x2c85b8aa, 0x0eb72ddc, 0x81c52ca2,
];

const TWO_32 = 0x100000000;

const W = new Uint32Array(64);

const WH = new Uint32Array(80);

const WL = new Uint32Array(80);

function compress256(state: Uint32Array, data: Uint8Array, offset: number): void {
  for (let t = 0; t < 16; t++) {
    W[t] = readUint32(data, offset + 4 * t);
  }

  for (let t = 16; t < 64; t++) {
    const x = W[t - 15];

    const y = W[t - 2];

    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);

    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);

    W[t] = W[t - 16] + s0 + W[t - 7] + s1;
  }

  let a = state[0];

  let b = state[1];

  let c = state[2];

  let d = state[3];

  let e = state[4];

  let f = state[5];

  let g = state[6];

  let h = state[7];

  for (let t = 0; t < 64; t++) {
    const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));

    const t1 = (h + s1 + ((e & f) ^ (~e & g)) + K256[t] + W[t]) | 0;

    const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));

    const t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;

    h = g;

    g = f;

    f = e;

    e = (d + t1) | 0;

    d = c;

    c = b;

    b = a;

    a = (t1 + t2) | 0;
  }

  state[0] += a;

  state[1] += b;

  state[2] += c;

  state[3] += d;

  state[4] += e;

  state[5] += f;

  state[6] += g;

  state[7] += h;
}

function add64(state: Uint32Array, index: number, high: number, low: number): void {
  const sum = state[index + 1] + (low >>> 0);

  state[index + 1] = sum;

  state[index] += high + ((sum / TWO_32) | 0);
}

// Low halves are kept unsigned so that a sum divided by 2^32 gives its carry.
function compress512(state: Uint32Array, data: Uint8Array, offset: number): void {
  for (let t = 0; t < 16; t++) {
    WH[t] = readUint32(data, offset + 8 * t);

    WL[t] = readUint32(data, offset + 8 * t + 4);
  }

  for (let t = 16; t < 80; t++) {
    const xh = WH[t - 15];

    const xl = WL[t - 15];

    const yh = WH[t - 2];

    const yl = WL[t - 2];

    const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);

    const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));

    const s1h = ((yh >>> 19) | (yl << 13)) ^ ((yl >>> 29) | (yh << 3)) ^ (yh >>> 6);

    const s1l = ((yl >>> 19) | (yh << 13)) ^ ((yh >>> 29) | (yl << 3)) ^ ((yl >>> 6) | (yh << 26));

    const low = (s0l >>> 0) + (s1l >>> 0) + WL[t - 7] + WL[t - 16];

    WL[t] = low;

    WH[t] = s0h + s1h + WH[t - 7] + WH[t - 16] + ((low / TWO_32) | 0);
  }

  let ah = state[0];

  let al = state[1];

  let bh = state[2];

  let bl = state[3];

  let ch = state[4];

  let cl = state[5];

  let dh = state[6];

  let dl = state[7];

  let eh = state[8];

  let el = state[9];

  let fh = state[10];

  let fl = state[11];

  let gh = state[12];

  let gl = state[13];

  let hh = state[14];

  let hl = state[15];

  for (let t = 0; t < 80; t++) {
    const s1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));

    const s1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));

    const chooseHigh = (eh & fh) ^ (~eh & gh);

    const chooseLow = (el & fl) ^ (~el & gl);

    const t1Sum = hl + (s1l >>> 0) + (chooseLow >>> 0) + K512[2 * t + 1] + WL[t];

    const t1h = (hh + s1h + chooseHigh + K512[2 * t] + WH[t] + ((t1Sum / TWO_32) | 0)) | 0;

    const t1l = t1Sum >>> 0;

    const s0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));

    const s0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));

    const majorityHigh = (ah & bh) ^ (ah & ch) ^ (bh & ch);

    const majorityLow = (al & bl) ^ (al & cl) ^ (bl & cl);

    const t2Sum = (s0l >>> 0) + (majorityLow >>> 0);

    const t2h = (s0h + majorityHigh + ((t2Sum / TWO_32) | 0)) | 0;

    const t2l = t2Sum >>> 0;

    hh = gh;

    hl = gl;

    gh = fh;

    gl = fl;

    fh = eh;

    fl = el;

    const eSum = dl + t1l;

    eh = (dh + t1h + ((eSum / TWO_32) | 0)) | 0;

    el = eSum >>> 0;

    dh = ch;

    dl = cl;

    ch = bh;

    cl = bl;

    bh = ah;

    bl = al;

    const aSum = t1l + t2l;

    ah = (t1h + t2h + ((aSum / TWO_32) | 0)) | 0;

    al = aSum >>> 0;
  }

  add64(state, 0, ah, al);

  add64(state, 2, bh, bl);

  add64(state, 4, ch, cl);

  add64(state, 6, dh, dl);

  add64(state, 8, eh, el);

  add64(state, 10, fh, fl);

  add64(state, 12, gh, gl);

  add64(state, 14, hh, hl);
}

abstract class Sha2 extends Blocks {
  protected readonly state: Uint32Array;

  protected readonly size: number;

  protected length = 0;

  constructor(blockSize: number, iv: ArrayLike<number>, size: number) {
    super(blockSize);

    this.state = Uint32Array.from(iv);

    this.size = size;
  }

  override update(data: Uint8Array): void {
    this.length += data.length;

    super.update(data);
  }

  protected override process(data: Uint8Array, offset: number): void {
    this.compress(this.state, data, offset);
  }

  // FIPS 180-4, 5.1: the 0x80 marker, zeros, then the message length in bits, big-endian.
  digest(): Uint8Array {
    const block = this.buffer.length;

    const state = this.state.slice();

    const tail = new Uint8Array(2 * block);

    tail.set(this.buffer.subarray(0, this.buffered));

    tail[this.buffered] = 0x80;

    const end = this.buffered + 1 + block / 8 > block ? 2 * block : block;

    writeUint32(tail, end - 8, Math.floor(this.length / 0x20000000));

    writeUint32(tail, end - 4, (this.length % 0x20000000) * 8);

    for (let offset = 0; offset < end; offset += block) {
      this.compress(state, tail, offset);
    }

    const out = new Uint8Array(4 * state.length);

    for (let i = 0; i < state.length; i++) {
      writeUint32(out, 4 * i, state[i]);
    }

    return out.slice(0, this.size);
  }

  copy(): Sha2 {
    const other = this.clone();

    other.buffer.set(this.buffer);

    other.buffered = this.buffered;

    other.length = this.length;

    return other;
  }

  protected abstract compress(state: Uint32Array, data: Uint8Array, offset: number): void;

  protected abstract clone(): Sha2;
}

export class Sha256 extends Sha2 {
  constructor(iv: ArrayLike<number>, size: number) {
    super(64, iv, size);
  }

  protected override compress(state: Uint32Array, data: Uint8Array, offset: number): void {
    compress256(state, data, offset);
  }

  protected override clone(): Sha2 {
    return new Sha256(this.state, this.size);
  }
}

export class Sha512 extends Sha2 {
  constructor(iv: ArrayLike<number>, size: number) {
    super(128, iv, size);
  }

  protected override compress(state: Uint32Array, data: Uint8Array, offset: number): void {
    compress512(state, data, offset);
  }

  protected override clone(): Sha2 {
    return new Sha512(this.state, this.size);
  }
}
