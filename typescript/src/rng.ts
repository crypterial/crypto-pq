import { CryptoPQError } from "./errors.ts";

interface RandomSource {
  getRandomValues(array: Uint8Array): unknown;
}

// getRandomValues fills at most 65536 bytes per call.
const CHUNK = 65536;

export function randomBytes(length: number): Uint8Array {
  const source = (globalThis as { crypto?: Partial<RandomSource> }).crypto;

  if (typeof source?.getRandomValues !== "function") {
    throw new CryptoPQError("RNG_FAILURE", "globalThis.crypto.getRandomValues is not available");
  }

  const out = new Uint8Array(length);

  try {
    for (let offset = 0; offset < length; offset += CHUNK) {
      source.getRandomValues(out.subarray(offset, Math.min(offset + CHUNK, length)));
    }
  } catch (error) {
    throw new CryptoPQError("RNG_FAILURE", "the platform did not provide random bytes", { cause: error });
  }

  return out;
}
