import { wipe } from "./bytes.ts";
import { ML_KEM_768, checkEncapsulationKey, decapsInternal, encapsInternal, keygenInternal } from "./mlkem.ts";
import { sha3, shake256 } from "./primitives.ts";
import { BASE, x25519 } from "./x25519.ts";

const LABEL = Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c);

export const PUBLIC_KEY_SIZE = 1216;

export const CIPHERTEXT_SIZE = 1120;

export const SEED_SIZE = 32;

export interface PrivateKey {
  readonly dk: Uint8Array;

  readonly scalar: Uint8Array;

  readonly point: Uint8Array;
}

export function expand(seed: Uint8Array): [Uint8Array, PrivateKey] {
  const expanded = shake256(96, seed);

  const [ek, dk] = keygenInternal(expanded.subarray(0, 32), expanded.subarray(32, 64), ML_KEM_768);

  const scalar = expanded.slice(64);

  const point = x25519(scalar, BASE);

  const pk = new Uint8Array(PUBLIC_KEY_SIZE);

  pk.set(ek);

  pk.set(point, 1184);

  expanded.fill(0);

  return [pk, { dk, scalar, point }];
}

function combine(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array): Uint8Array {
  return sha3(32, ssM, ssX, ctX, pkX, LABEL);
}

export function checkPublicKey(pk: Uint8Array): boolean {
  return pk.length === PUBLIC_KEY_SIZE && checkEncapsulationKey(pk.subarray(0, 1184), ML_KEM_768);
}

export function encapsulate(pk: Uint8Array, eseed: Uint8Array): [Uint8Array, Uint8Array] {
  const pkX = pk.subarray(1184);

  const [ssM, ctM] = encapsInternal(pk.subarray(0, 1184), eseed.subarray(0, 32), ML_KEM_768);

  const ctX = x25519(eseed.subarray(32), BASE);

  const ssX = x25519(eseed.subarray(32), pkX);

  const ciphertext = new Uint8Array(CIPHERTEXT_SIZE);

  ciphertext.set(ctM);

  ciphertext.set(ctX, 1088);

  const sharedSecret = combine(ssM, ssX, ctX, pkX);

  wipe(ssM, ssX);

  return [sharedSecret, ciphertext];
}

export function decapsulate(key: PrivateKey, ct: Uint8Array): Uint8Array {
  const ctX = ct.subarray(1088);

  const ssM = decapsInternal(key.dk, ct.subarray(0, 1088), ML_KEM_768);

  const ssX = x25519(key.scalar, ctX);

  const sharedSecret = combine(ssM, ssX, ctX, key.point);

  wipe(ssM, ssX);

  return sharedSecret;
}
