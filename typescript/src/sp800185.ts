import { permute } from "./keccak-permute.ts";
import { Keccak, absorbBytes, squeezeBytes } from "./keccak.ts";

// cSHAKE and KMAC (NIST SP 800-185) over the Keccak sponge of src/keccak.ts. cSHAKE pads with the
// bits 00 before pad10*1, the byte 0x04 (3.3).
export const CSHAKE_SUFFIX = 0x04;

const KMAC = /* @__PURE__ */ Uint8Array.of(0x4b, 0x4d, 0x41, 0x43);

// left_encode(value) (2.3.1) at out[offset], returning the offset after it: the byte count, then
// the bytes big-endian, at least one.
function leftEncodeInto(value: number, out: Uint8Array, offset: number): number {
  let count = 1;

  while (count < 8 && value >= 2 ** (8 * count)) {
    count++;
  }

  out[offset] = count;

  for (let i = count; i > 0; i--) {
    out[offset + i] = value % 256;

    value = Math.floor(value / 256);
  }

  return offset + count + 1;
}

// right_encode(value) (2.3.1): the bytes big-endian, at least one, then their count.
export function rightEncode(value: number): Uint8Array {
  const scratch = new Uint8Array(9);

  const end = leftEncodeInto(value, scratch, 0);

  const out = new Uint8Array(end);

  out.set(scratch.subarray(1, end));

  out[end - 1] = scratch[0];

  return out;
}

const HEADER = new Uint8Array(20);

// Absorbs bytepad(encode_string(X) || encode_string(Y), rate) (2.3.3), without Y when it is null,
// into s from the start of a block, which it leaves at the start of one.
function absorbPadded(s: Uint32Array, rate: number, x: Uint8Array, y: Uint8Array | null): void {
  let end = leftEncodeInto(rate, HEADER, 0);

  end = leftEncodeInto(8 * x.length, HEADER, end);

  let position = absorbBytes(s, rate, 0, HEADER, 0, end);

  position = absorbBytes(s, rate, position, x, 0, x.length);

  if (y !== null) {
    end = leftEncodeInto(8 * y.length, HEADER, 0);

    position = absorbBytes(s, rate, position, HEADER, 0, end);

    position = absorbBytes(s, rate, position, y, 0, y.length);
  }

  if (position > 0) {
    permute(s);
  }
}

// The state after the prefix bytepad(encode_string(N) || encode_string(S), rate) of cSHAKE (3.3),
// which configure computes once.
export function cshakePrefix(rate: number, functionName: Uint8Array, customization: Uint8Array): Uint32Array {
  const s = new Uint32Array(50);

  absorbPadded(s, rate, functionName, customization);

  return s;
}

export function kmacPrefix(rate: number, customization: Uint8Array): Uint32Array {
  return cshakePrefix(rate, KMAC, customization);
}

// cSHAKE over updates from its prefix state.
export function cshake(rate: number, prefix: Uint32Array): Keccak {
  return Keccak.fromState(rate, CSHAKE_SUFFIX, prefix);
}

// The state of one-shot digests, cleared after each: a digest runs to its end without calling out,
// so one serves every call.
const SPONGE = new Uint32Array(50);

export function cshakeDigest(rate: number, prefix: Uint32Array, data: Uint8Array, length: number): Uint8Array {
  const s = SPONGE;

  s.set(prefix);

  const out = new Uint8Array(length);

  squeezeBytes(s, rate, absorbBytes(s, rate, 0, data, 0, data.length), CSHAKE_SUFFIX, out);

  s.fill(0);

  return out;
}

// KMAC (4.3): cSHAKE of bytepad(encode_string(K), rate) || X || right_encode(L), with N = "KMAC",
// whose prefix with S is given; KMACXOF encodes L as 0. The key block, the data and the encoded
// length go into the state straight from where they are.
export function kmacDigest(
  rate: number,
  prefix: Uint32Array,
  xof: boolean,
  key: Uint8Array,
  data: Uint8Array,
  length: number,
): Uint8Array {
  const s = SPONGE;

  s.set(prefix);

  absorbPadded(s, rate, key, null);

  HEADER.fill(0);

  let position = absorbBytes(s, rate, 0, data, 0, data.length);

  const encodedLength = rightEncode(xof ? 0 : 8 * length);

  position = absorbBytes(s, rate, position, encodedLength, 0, encodedLength.length);

  const out = new Uint8Array(length);

  squeezeBytes(s, rate, position, CSHAKE_SUFFIX, out);

  s.fill(0);

  return out;
}

// KMAC over updates: the sponge after the key block, and a tag that reads a copy of it.
export class Kmac {
  readonly #sponge: Keccak;

  readonly #xof: boolean;

  readonly #length: number;

  constructor(rate: number, prefix: Uint32Array, xof: boolean, key: Uint8Array, length: number) {
    const s = prefix.slice();

    absorbPadded(s, rate, key, null);

    HEADER.fill(0);

    this.#sponge = Keccak.fromState(rate, CSHAKE_SUFFIX, s);

    s.fill(0);

    this.#xof = xof;

    this.#length = length;
  }

  update(data: Uint8Array): void {
    this.#sponge.update(data);
  }

  digest(): Uint8Array {
    const sponge = this.#sponge.copy();

    sponge.update(rightEncode(this.#xof ? 0 : 8 * this.#length));

    return sponge.read(this.#length);
  }
}
