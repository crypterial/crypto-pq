import { wipe } from "./bytes.ts";
import { Keccak } from "./keccak.ts";
import {
  ML_KEM_768,
  type PublicCache,
  type SecretCache,
  checkEncapsulationKey,
  decapsInternal,
  digestOf,
  encapsInternal,
  keygenInternal,
  publicCache,
} from "./mlkem.ts";
import { shake256 } from "./primitives.ts";
import { x25519, x25519Base } from "./x25519.ts";

const LABEL = Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c);

export const PUBLIC_KEY_SIZE = 1216;

export const CIPHERTEXT_SIZE = 1120;

export const SEED_SIZE = 32;

export interface PrivateKey {
  readonly dk: Uint8Array;

  readonly secret: SecretCache;

  readonly scalar: Uint8Array;

  readonly point: Uint8Array;
}

// The public key, the private key and the cache of the public key's ML-KEM part.
export function expand(seed: Uint8Array): [Uint8Array, PrivateKey, PublicCache] {
  const expanded = shake256(96, seed);

  const [ek, dk] = keygenInternal(expanded.subarray(0, 32), expanded.subarray(32, 64), ML_KEM_768);

  const scalar = expanded.slice(64);

  const point = x25519Base(scalar);

  const pk = new Uint8Array(PUBLIC_KEY_SIZE);

  pk.set(ek);

  pk.set(point, 1184);

  expanded.fill(0);

  return [pk, { dk, secret: { s: null }, scalar, point }, publicCache(digestOf(dk, ML_KEM_768))];
}

// The SHA3-256 sponge of the combiner, reset before each use and left cleared, and the encapsulation
// seed, read once and wiped after use.
const COMBINER = new Keccak(136, 0x06);

const ESEED = new Uint8Array(64);

const ESK_X = ESEED.subarray(32);

function combine(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array): Uint8Array {
  const sponge = COMBINER;

  sponge.reset();

  sponge.update(ssM);

  sponge.update(ssX);

  sponge.update(ctX);

  sponge.update(pkX);

  sponge.update(LABEL);

  const out = sponge.read(32);

  sponge.reset();

  return out;
}

export function checkPublicKey(pk: Uint8Array): boolean {
  return pk.length === PUBLIC_KEY_SIZE && checkEncapsulationKey(pk.subarray(0, 1184), ML_KEM_768);
}

// cache belongs to the ML-KEM part of pk, whose ciphertext fills the start of the X-Wing one.
export function encapsulate(pk: Uint8Array, cache: PublicCache, eseed: Uint8Array): [Uint8Array, Uint8Array] {
  const pkX = pk.subarray(1184);

  const ciphertext = new Uint8Array(CIPHERTEXT_SIZE);

  for (let i = 0; i < 64; i++) {
    ESEED[i] = eseed[i];
  }

  const ssM = encapsInternal(pk.subarray(0, 1184), cache, ESEED, ML_KEM_768, ciphertext)[0];

  const ctX = x25519Base(ESK_X);

  const ssX = x25519(ESK_X, pkX);

  ciphertext.set(ctX, 1088);

  const sharedSecret = combine(ssM, ssX, ctX, pkX);

  wipe(ssM, ssX, ESEED);

  return [sharedSecret, ciphertext];
}

export function decapsulate(key: PrivateKey, cache: PublicCache, ct: Uint8Array): Uint8Array {
  const ctX = ct.subarray(1088);

  const ssM = decapsInternal(key.dk, key.secret, cache, ct.subarray(0, 1088), ML_KEM_768);

  const ssX = x25519(key.scalar, ctX);

  const sharedSecret = combine(ssM, ssX, ctX, key.point);

  wipe(ssM, ssX);

  return sharedSecret;
}
