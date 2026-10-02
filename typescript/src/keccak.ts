import { CryptoPQError } from "./errors.ts";

// Each 64-bit lane is a (low, high) pair, so the state reads as little-endian 32-bit words.
const ROUND_CONSTANTS = new Int32Array([
  0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000, 0x80008000, 0x80000000,
  0x0000808b, 0x00000000, 0x80000001, 0x00000000, 0x80008081, 0x80000000, 0x00008009, 0x80000000,
  0x0000008a, 0x00000000, 0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
  0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000, 0x00008003, 0x80000000,
  0x00008002, 0x80000000, 0x00000080, 0x80000000, 0x0000800a, 0x00000000, 0x8000000a, 0x80000000,
  0x80008081, 0x80000000, 0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
]);

// Keccak-f[1600], unrolled. Lane x + 5y is a{x + 5y} as (low, high) halves; rho and pi move it to
// b{y + 5((2x + 3y) mod 5)}.
export function permute(s: Uint32Array): void {
  let a0l = s[0] | 0;

  let a0h = s[1] | 0;

  let a1l = s[2] | 0;

  let a1h = s[3] | 0;

  let a2l = s[4] | 0;

  let a2h = s[5] | 0;

  let a3l = s[6] | 0;

  let a3h = s[7] | 0;

  let a4l = s[8] | 0;

  let a4h = s[9] | 0;

  let a5l = s[10] | 0;

  let a5h = s[11] | 0;

  let a6l = s[12] | 0;

  let a6h = s[13] | 0;

  let a7l = s[14] | 0;

  let a7h = s[15] | 0;

  let a8l = s[16] | 0;

  let a8h = s[17] | 0;

  let a9l = s[18] | 0;

  let a9h = s[19] | 0;

  let a10l = s[20] | 0;

  let a10h = s[21] | 0;

  let a11l = s[22] | 0;

  let a11h = s[23] | 0;

  let a12l = s[24] | 0;

  let a12h = s[25] | 0;

  let a13l = s[26] | 0;

  let a13h = s[27] | 0;

  let a14l = s[28] | 0;

  let a14h = s[29] | 0;

  let a15l = s[30] | 0;

  let a15h = s[31] | 0;

  let a16l = s[32] | 0;

  let a16h = s[33] | 0;

  let a17l = s[34] | 0;

  let a17h = s[35] | 0;

  let a18l = s[36] | 0;

  let a18h = s[37] | 0;

  let a19l = s[38] | 0;

  let a19h = s[39] | 0;

  let a20l = s[40] | 0;

  let a20h = s[41] | 0;

  let a21l = s[42] | 0;

  let a21h = s[43] | 0;

  let a22l = s[44] | 0;

  let a22h = s[45] | 0;

  let a23l = s[46] | 0;

  let a23h = s[47] | 0;

  let a24l = s[48] | 0;

  let a24h = s[49] | 0;

  for (let round = 0; round < 48; round += 2) {
    const c0l = a0l ^ a5l ^ a10l ^ a15l ^ a20l;

    const c0h = a0h ^ a5h ^ a10h ^ a15h ^ a20h;

    const c1l = a1l ^ a6l ^ a11l ^ a16l ^ a21l;

    const c1h = a1h ^ a6h ^ a11h ^ a16h ^ a21h;

    const c2l = a2l ^ a7l ^ a12l ^ a17l ^ a22l;

    const c2h = a2h ^ a7h ^ a12h ^ a17h ^ a22h;

    const c3l = a3l ^ a8l ^ a13l ^ a18l ^ a23l;

    const c3h = a3h ^ a8h ^ a13h ^ a18h ^ a23h;

    const c4l = a4l ^ a9l ^ a14l ^ a19l ^ a24l;

    const c4h = a4h ^ a9h ^ a14h ^ a19h ^ a24h;

    const d0l = c4l ^ ((c1l << 1) | (c1h >>> 31));

    const d0h = c4h ^ ((c1h << 1) | (c1l >>> 31));

    const d1l = c0l ^ ((c2l << 1) | (c2h >>> 31));

    const d1h = c0h ^ ((c2h << 1) | (c2l >>> 31));

    const d2l = c1l ^ ((c3l << 1) | (c3h >>> 31));

    const d2h = c1h ^ ((c3h << 1) | (c3l >>> 31));

    const d3l = c2l ^ ((c4l << 1) | (c4h >>> 31));

    const d3h = c2h ^ ((c4h << 1) | (c4l >>> 31));

    const d4l = c3l ^ ((c0l << 1) | (c0h >>> 31));

    const d4h = c3h ^ ((c0h << 1) | (c0l >>> 31));

    a0l ^= d0l;

    a0h ^= d0h;

    a1l ^= d1l;

    a1h ^= d1h;

    a2l ^= d2l;

    a2h ^= d2h;

    a3l ^= d3l;

    a3h ^= d3h;

    a4l ^= d4l;

    a4h ^= d4h;

    a5l ^= d0l;

    a5h ^= d0h;

    a6l ^= d1l;

    a6h ^= d1h;

    a7l ^= d2l;

    a7h ^= d2h;

    a8l ^= d3l;

    a8h ^= d3h;

    a9l ^= d4l;

    a9h ^= d4h;

    a10l ^= d0l;

    a10h ^= d0h;

    a11l ^= d1l;

    a11h ^= d1h;

    a12l ^= d2l;

    a12h ^= d2h;

    a13l ^= d3l;

    a13h ^= d3h;

    a14l ^= d4l;

    a14h ^= d4h;

    a15l ^= d0l;

    a15h ^= d0h;

    a16l ^= d1l;

    a16h ^= d1h;

    a17l ^= d2l;

    a17h ^= d2h;

    a18l ^= d3l;

    a18h ^= d3h;

    a19l ^= d4l;

    a19h ^= d4h;

    a20l ^= d0l;

    a20h ^= d0h;

    a21l ^= d1l;

    a21h ^= d1h;

    a22l ^= d2l;

    a22h ^= d2h;

    a23l ^= d3l;

    a23h ^= d3h;

    a24l ^= d4l;

    a24h ^= d4h;

    const b0l = a0l;

    const b0h = a0h;

    const b1l = (a6h << 12) | (a6l >>> 20);

    const b1h = (a6l << 12) | (a6h >>> 20);

    const b2l = (a12h << 11) | (a12l >>> 21);

    const b2h = (a12l << 11) | (a12h >>> 21);

    const b3l = (a18l << 21) | (a18h >>> 11);

    const b3h = (a18h << 21) | (a18l >>> 11);

    const b4l = (a24l << 14) | (a24h >>> 18);

    const b4h = (a24h << 14) | (a24l >>> 18);

    const b5l = (a3l << 28) | (a3h >>> 4);

    const b5h = (a3h << 28) | (a3l >>> 4);

    const b6l = (a9l << 20) | (a9h >>> 12);

    const b6h = (a9h << 20) | (a9l >>> 12);

    const b7l = (a10l << 3) | (a10h >>> 29);

    const b7h = (a10h << 3) | (a10l >>> 29);

    const b8l = (a16h << 13) | (a16l >>> 19);

    const b8h = (a16l << 13) | (a16h >>> 19);

    const b9l = (a22h << 29) | (a22l >>> 3);

    const b9h = (a22l << 29) | (a22h >>> 3);

    const b10l = (a1l << 1) | (a1h >>> 31);

    const b10h = (a1h << 1) | (a1l >>> 31);

    const b11l = (a7l << 6) | (a7h >>> 26);

    const b11h = (a7h << 6) | (a7l >>> 26);

    const b12l = (a13l << 25) | (a13h >>> 7);

    const b12h = (a13h << 25) | (a13l >>> 7);

    const b13l = (a19l << 8) | (a19h >>> 24);

    const b13h = (a19h << 8) | (a19l >>> 24);

    const b14l = (a20l << 18) | (a20h >>> 14);

    const b14h = (a20h << 18) | (a20l >>> 14);

    const b15l = (a4l << 27) | (a4h >>> 5);

    const b15h = (a4h << 27) | (a4l >>> 5);

    const b16l = (a5h << 4) | (a5l >>> 28);

    const b16h = (a5l << 4) | (a5h >>> 28);

    const b17l = (a11l << 10) | (a11h >>> 22);

    const b17h = (a11h << 10) | (a11l >>> 22);

    const b18l = (a17l << 15) | (a17h >>> 17);

    const b18h = (a17h << 15) | (a17l >>> 17);

    const b19l = (a23h << 24) | (a23l >>> 8);

    const b19h = (a23l << 24) | (a23h >>> 8);

    const b20l = (a2h << 30) | (a2l >>> 2);

    const b20h = (a2l << 30) | (a2h >>> 2);

    const b21l = (a8h << 23) | (a8l >>> 9);

    const b21h = (a8l << 23) | (a8h >>> 9);

    const b22l = (a14h << 7) | (a14l >>> 25);

    const b22h = (a14l << 7) | (a14h >>> 25);

    const b23l = (a15h << 9) | (a15l >>> 23);

    const b23h = (a15l << 9) | (a15h >>> 23);

    const b24l = (a21l << 2) | (a21h >>> 30);

    const b24h = (a21h << 2) | (a21l >>> 30);

    a0l = b0l ^ (~b1l & b2l) ^ ROUND_CONSTANTS[round];

    a0h = b0h ^ (~b1h & b2h) ^ ROUND_CONSTANTS[round + 1];

    a1l = b1l ^ (~b2l & b3l);

    a1h = b1h ^ (~b2h & b3h);

    a2l = b2l ^ (~b3l & b4l);

    a2h = b2h ^ (~b3h & b4h);

    a3l = b3l ^ (~b4l & b0l);

    a3h = b3h ^ (~b4h & b0h);

    a4l = b4l ^ (~b0l & b1l);

    a4h = b4h ^ (~b0h & b1h);

    a5l = b5l ^ (~b6l & b7l);

    a5h = b5h ^ (~b6h & b7h);

    a6l = b6l ^ (~b7l & b8l);

    a6h = b6h ^ (~b7h & b8h);

    a7l = b7l ^ (~b8l & b9l);

    a7h = b7h ^ (~b8h & b9h);

    a8l = b8l ^ (~b9l & b5l);

    a8h = b8h ^ (~b9h & b5h);

    a9l = b9l ^ (~b5l & b6l);

    a9h = b9h ^ (~b5h & b6h);

    a10l = b10l ^ (~b11l & b12l);

    a10h = b10h ^ (~b11h & b12h);

    a11l = b11l ^ (~b12l & b13l);

    a11h = b11h ^ (~b12h & b13h);

    a12l = b12l ^ (~b13l & b14l);

    a12h = b12h ^ (~b13h & b14h);

    a13l = b13l ^ (~b14l & b10l);

    a13h = b13h ^ (~b14h & b10h);

    a14l = b14l ^ (~b10l & b11l);

    a14h = b14h ^ (~b10h & b11h);

    a15l = b15l ^ (~b16l & b17l);

    a15h = b15h ^ (~b16h & b17h);

    a16l = b16l ^ (~b17l & b18l);

    a16h = b16h ^ (~b17h & b18h);

    a17l = b17l ^ (~b18l & b19l);

    a17h = b17h ^ (~b18h & b19h);

    a18l = b18l ^ (~b19l & b15l);

    a18h = b18h ^ (~b19h & b15h);

    a19l = b19l ^ (~b15l & b16l);

    a19h = b19h ^ (~b15h & b16h);

    a20l = b20l ^ (~b21l & b22l);

    a20h = b20h ^ (~b21h & b22h);

    a21l = b21l ^ (~b22l & b23l);

    a21h = b21h ^ (~b22h & b23h);

    a22l = b22l ^ (~b23l & b24l);

    a22h = b22h ^ (~b23h & b24h);

    a23l = b23l ^ (~b24l & b20l);

    a23h = b23h ^ (~b24h & b20h);

    a24l = b24l ^ (~b20l & b21l);

    a24h = b24h ^ (~b20h & b21h);
  }

  s[0] = a0l;

  s[1] = a0h;

  s[2] = a1l;

  s[3] = a1h;

  s[4] = a2l;

  s[5] = a2h;

  s[6] = a3l;

  s[7] = a3h;

  s[8] = a4l;

  s[9] = a4h;

  s[10] = a5l;

  s[11] = a5h;

  s[12] = a6l;

  s[13] = a6h;

  s[14] = a7l;

  s[15] = a7h;

  s[16] = a8l;

  s[17] = a8h;

  s[18] = a9l;

  s[19] = a9h;

  s[20] = a10l;

  s[21] = a10h;

  s[22] = a11l;

  s[23] = a11h;

  s[24] = a12l;

  s[25] = a12h;

  s[26] = a13l;

  s[27] = a13h;

  s[28] = a14l;

  s[29] = a14h;

  s[30] = a15l;

  s[31] = a15h;

  s[32] = a16l;

  s[33] = a16h;

  s[34] = a17l;

  s[35] = a17h;

  s[36] = a18l;

  s[37] = a18h;

  s[38] = a19l;

  s[39] = a19h;

  s[40] = a20l;

  s[41] = a20h;

  s[42] = a21l;

  s[43] = a21h;

  s[44] = a22l;

  s[45] = a22h;

  s[46] = a23l;

  s[47] = a23h;

  s[48] = a24l;

  s[49] = a24h;
}

export class Keccak {
  readonly #state = new Uint32Array(50);

  readonly #rate: number;

  readonly #suffix: number;

  #position = 0;

  #squeezing = false;

  constructor(rate: number, suffix: number) {
    this.#rate = rate;

    this.#suffix = suffix;
  }

  update(data: Uint8Array): void {
    if (this.#squeezing) {
      throw new CryptoPQError("UNSUPPORTED", "cannot update after read");
    }

    const state = this.#state;

    const rate = this.#rate;

    let offset = 0;

    while (offset < data.length) {
      if (this.#position === 0 && data.length - offset >= rate) {
        for (let word = 0; word < rate / 4; word++, offset += 4) {
          state[word] ^= data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
        }

        permute(state);

        continue;
      }

      const end = Math.min(offset + rate - this.#position, data.length);

      for (; offset < end; offset++, this.#position++) {
        state[this.#position >>> 2] ^= data[offset] << ((this.#position & 3) << 3);
      }

      if (this.#position === rate) {
        permute(state);

        this.#position = 0;
      }
    }
  }

  read(length: number): Uint8Array {
    const state = this.#state;

    const rate = this.#rate;

    if (!this.#squeezing) {
      state[this.#position >>> 2] ^= this.#suffix << ((this.#position & 3) << 3);

      state[(rate - 1) >>> 2] ^= 0x80 << (((rate - 1) & 3) << 3);

      permute(state);

      this.#position = 0;

      this.#squeezing = true;
    }

    const out = new Uint8Array(length);

    for (let i = 0; i < length; i++, this.#position++) {
      if (this.#position === rate) {
        permute(state);

        this.#position = 0;
      }

      out[i] = state[this.#position >>> 2] >>> ((this.#position & 3) << 3);
    }

    return out;
  }

  copy(): Keccak {
    const other = new Keccak(this.#rate, this.#suffix);

    other.#state.set(this.#state);

    other.#position = this.#position;

    other.#squeezing = this.#squeezing;

    return other;
  }
}
