// The hash functions that signatures accept as a pre-hash, which the hash module registers as it
// creates them, so that signatures need no hash module of their own: the pre-hash id of the C ABI,
// the last arc of the OID under 2.16.840.1.101.3.4.2, the collision strength in bits (SHAKE128 and
// SHAKE256 produce 256 and 512 bits, as FIPS 204 and FIPS 205 require) and the digest.
export interface PreHash {
  readonly id: number;

  readonly arc: number;

  readonly strength: number;

  digest(message: Uint8Array): Uint8Array;
}

export const PRE_HASHES = new WeakMap<object, PreHash>();
