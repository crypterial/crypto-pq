import { ASCON_INITIAL, asconAbsorb, asconPermute } from "./ascon-permute.ts";
import { CryptoPQError } from "./errors.ts";
import { storeLane, xorLane } from "./keccak.ts";

// Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232, 5): a sponge of rate 64 bits over
// Ascon-p[12], whose state is interleaved as in src/ascon-permute.ts. Message bytes enter x0
// little-endian; the last block is padded with a byte 0x01 after its data.

export const HASH_INITIAL = /* @__PURE__ */ Uint32Array.from(ASCON_INITIAL.subarray(0, 10));

export const XOF_INITIAL = /* @__PURE__ */ Uint32Array.from(ASCON_INITIAL.subarray(10, 20));

const CXOF_INITIAL = /* @__PURE__ */ Uint32Array.from(ASCON_INITIAL.subarray(20, 30));

// SP 800-232, 5.3: the customization string is at most 2048 bits.
export const MAX_CUSTOMIZATION = 256;

const LANE = new Uint8Array(8);

// XORs the last bytes of a message, data[from .. to) (at most seven), and the padding into x0, then
// permutes.
function absorbLast(s: Uint32Array, data: Uint8Array, from: number, to: number): void {
  let lo = 0;

  let hi = 0;

  const count = to - from;

  for (let k = 0; k < count; k++) {
    if (k < 4) {
      lo |= data[from + k] << (8 * k);
    } else {
      hi |= data[from + k] << (8 * (k - 4));
    }
  }

  if (count < 4) {
    lo |= 1 << (8 * count);
  } else {
    hi |= 1 << (8 * (count - 4));
  }

  xorLane(s, 0, lo, hi);

  asconPermute(s);
}

// Writes x0 as the next output bytes from out[offset] on, at most eight.
function squeezeLane(s: Uint32Array, out: Uint8Array, offset: number): void {
  if (out.length - offset >= 8) {
    storeLane(s, 0, out, offset);
  } else {
    storeLane(s, 0, LANE, 0);

    out.set(LANE.subarray(0, out.length - offset), offset);

    LANE.fill(0);
  }
}

// SP 800-232, Algorithm 7: the state of Ascon-CXOF128 after the customization string Z, which is
// its bit length as a first block and then Z itself, padded even when empty.
export function customize(customization: Uint8Array): Uint32Array {
  if (customization.length > MAX_CUSTOMIZATION) {
    throw new CryptoPQError("INVALID_OPTION", "an Ascon-CXOF128 customization has at most 256 bytes");
  }

  const s = CXOF_INITIAL.slice();

  const whole = customization.length & ~7;

  xorLane(s, 0, 8 * customization.length, 0);

  asconPermute(s);

  asconAbsorb(s, customization, 0, whole);

  absorbLast(s, customization, whole, customization.length);

  return s;
}

// The state of one-shot digests, cleared after each: a digest runs to its end without calling out,
// so one serves every call.
const STATE = new Uint32Array(10);

// The first out.length bytes of the output for a whole message, from an initial state (SP 800-232,
// Algorithms 5 to 7): the message blocks straight from data, then output blocks of x0 with a
// permutation between them, none after the last.
export function asconDigest(initial: Uint32Array, data: Uint8Array, out: Uint8Array): void {
  const s = STATE;

  const whole = data.length & ~7;

  s.set(initial);

  asconAbsorb(s, data, 0, whole);

  absorbLast(s, data, whole, data.length);

  for (let offset = 0; offset < out.length; offset += 8) {
    if (offset > 0) {
      asconPermute(s);
    }

    squeezeLane(s, out, offset);
  }

  s.fill(0);
}

// The sponge over updates and reads. The buffer collects the bytes of a partial block while
// absorbing, and holds the current block of output while squeezing.
export class AsconSponge {
  readonly #state: Uint32Array;

  readonly #buffer = new Uint8Array(8);

  #buffered = 0;

  // The unread bytes of the output block in the buffer, or -1 while absorbing.
  #available = -1;

  constructor(initial: Uint32Array) {
    this.#state = initial.slice();
  }

  update(data: Uint8Array): void {
    if (this.#available >= 0) {
      throw new CryptoPQError("UNSUPPORTED", "cannot update after read");
    }

    const buffer = this.#buffer;

    let offset = 0;

    if (this.#buffered > 0) {
      offset = Math.min(8 - this.#buffered, data.length);

      buffer.set(data.subarray(0, offset), this.#buffered);

      this.#buffered += offset;

      if (this.#buffered < 8) {
        return;
      }

      asconAbsorb(this.#state, buffer, 0, 8);

      this.#buffered = 0;
    }

    const whole = offset + ((data.length - offset) & ~7);

    asconAbsorb(this.#state, data, offset, whole);

    buffer.set(data.subarray(whole, data.length), 0);

    this.#buffered = data.length - whole;
  }

  read(length: number): Uint8Array {
    const out = new Uint8Array(length);

    const buffer = this.#buffer;

    if (length > 0 && this.#available < 0) {
      absorbLast(this.#state, buffer, 0, this.#buffered);

      storeLane(this.#state, 0, buffer, 0);

      this.#available = 8;
    }

    for (let offset = 0; offset < length; ) {
      if (this.#available === 0) {
        asconPermute(this.#state);

        storeLane(this.#state, 0, buffer, 0);

        this.#available = 8;
      }

      const take = Math.min(this.#available, length - offset);

      for (let i = 0; i < take; i++) {
        out[offset + i] = buffer[8 - this.#available + i];
      }

      this.#available -= take;

      offset += take;
    }

    return out;
  }

  copy(): AsconSponge {
    const other = new AsconSponge(this.#state);

    other.#buffer.set(this.#buffer);

    other.#buffered = this.#buffered;

    other.#available = this.#available;

    return other;
  }
}

// Ascon-Hash256 over updates: its digest reads 32 bytes from a copy of the sponge.
export class AsconHash {
  readonly #sponge: AsconSponge;

  constructor(sponge: AsconSponge = new AsconSponge(HASH_INITIAL)) {
    this.#sponge = sponge;
  }

  update(data: Uint8Array): void {
    this.#sponge.update(data);
  }

  digest(): Uint8Array {
    return this.#sponge.copy().read(32);
  }

  copy(): AsconHash {
    return new AsconHash(this.#sponge.copy());
  }
}
