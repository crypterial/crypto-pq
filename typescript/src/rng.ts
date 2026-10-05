import { CryptoPQError } from "./errors.ts";

interface RandomSource {
  getRandomValues(array: Uint8Array): unknown;
}

// getRandomValues fills at most 65536 bytes per call.
const CHUNK = 65536;

// Fills out in place, which may be a view of WebAssembly memory, so that the bytes never pass
// through another array.
export function randomInto(out: Uint8Array): void {
  const source = (globalThis as { crypto?: Partial<RandomSource> }).crypto;

  if (typeof source?.getRandomValues !== "function") {
    throw new CryptoPQError("RNG_FAILURE", "globalThis.crypto.getRandomValues is not available");
  }

  try {
    for (let offset = 0; offset < out.length; offset += CHUNK) {
      source.getRandomValues(out.subarray(offset, Math.min(offset + CHUNK, out.length)));
    }
  } catch (error) {
    throw new CryptoPQError("RNG_FAILURE", "the platform did not provide random bytes", { cause: error });
  }
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);

  randomInto(out);

  return out;
}
