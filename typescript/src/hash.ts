import { bytes, equal } from "./bytes.ts";
import { CryptoPQError } from "./errors.ts";
import { Keccak } from "./keccak.ts";
import { IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512 } from "./sha2.ts";

export interface Engine {
  update(data: Uint8Array): void;

  digest(): Uint8Array;

  copy(): Engine;
}

export interface Spec {
  readonly digestSize: number;

  readonly blockSize: number;

  create(): Engine;
}

class Sha3 implements Engine {
  readonly #sponge: Keccak;

  readonly #size: number;

  constructor(sponge: Keccak, size: number) {
    this.#sponge = sponge;

    this.#size = size;
  }

  update(data: Uint8Array): void {
    this.#sponge.update(data);
  }

  digest(): Uint8Array {
    return this.#sponge.copy().read(this.#size);
  }

  copy(): Engine {
    return new Sha3(this.#sponge.copy(), this.#size);
  }
}

export class Hasher {
  readonly #engine: Engine;

  constructor(engine: Engine) {
    this.#engine = engine;
  }

  update(data: Uint8Array): this {
    this.#engine.update(bytes(data, "data"));

    return this;
  }

  digest(): Uint8Array {
    return this.#engine.digest();
  }
}

export class HashAlgorithm {
  readonly name: string;

  readonly digestSize: number;

  readonly #spec: Spec;

  constructor(name: string, spec: Spec) {
    this.name = name;

    this.digestSize = spec.digestSize;

    this.#spec = spec;

    Object.freeze(this);
  }

  digest(data: Uint8Array): Uint8Array {
    return this.create().update(data).digest();
  }

  create(): Hasher {
    return new Hasher(this.#spec.create());
  }
}

export class Xof {
  readonly #sponge: Keccak;

  constructor(sponge: Keccak) {
    this.#sponge = sponge;
  }

  update(data: Uint8Array): this {
    this.#sponge.update(bytes(data, "data"));

    return this;
  }

  read(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new CryptoPQError("INVALID_LENGTH", "length must be a non-negative integer");
    }

    return this.#sponge.read(length);
  }
}

export class XofAlgorithm {
  readonly name: string;

  readonly #rate: number;

  constructor(name: string, rate: number) {
    this.name = name;

    this.#rate = rate;

    Object.freeze(this);
  }

  digest(data: Uint8Array, length: number): Uint8Array {
    return this.create().update(data).read(length);
  }

  create(): Xof {
    return new Xof(new Keccak(this.#rate, 0x1f));
  }
}

export class Hmac {
  readonly #inner: Engine;

  readonly #outer: Engine;

  constructor(inner: Engine, outer: Engine) {
    this.#inner = inner;

    this.#outer = outer;
  }

  update(data: Uint8Array): this {
    this.#inner.update(bytes(data, "data"));

    return this;
  }

  digest(): Uint8Array {
    const outer = this.#outer.copy();

    outer.update(this.#inner.digest());

    return outer.digest();
  }

  verify(tag: Uint8Array): boolean {
    return equal(this.digest(), bytes(tag, "tag"));
  }
}

export class HmacAlgorithm {
  readonly name: string;

  readonly digestSize: number;

  readonly #spec: Spec;

  constructor(name: string, spec: Spec) {
    this.name = name;

    this.digestSize = spec.digestSize;

    this.#spec = spec;

    Object.freeze(this);
  }

  digest(key: Uint8Array, data: Uint8Array): Uint8Array {
    return this.create(key).update(data).digest();
  }

  // The padded key is zeroed before returning; JavaScript cannot promise that no other copy remains.
  create(key: Uint8Array): Hmac {
    const spec = this.#spec;

    const pad = new Uint8Array(spec.blockSize);

    if (bytes(key, "key").length > spec.blockSize) {
      const hash = spec.create();

      hash.update(key);

      const digest = hash.digest();

      pad.set(digest);

      digest.fill(0);
    } else {
      pad.set(key);
    }

    for (let i = 0; i < pad.length; i++) {
      pad[i] ^= 0x36;
    }

    const inner = spec.create();

    inner.update(pad);

    for (let i = 0; i < pad.length; i++) {
      pad[i] ^= 0x36 ^ 0x5c;
    }

    const outer = spec.create();

    outer.update(pad);

    pad.fill(0);

    return new Hmac(inner, outer);
  }

  verify(key: Uint8Array, data: Uint8Array, tag: Uint8Array): boolean {
    return this.create(key).update(data).verify(tag);
  }
}

function sha256(iv: Int32Array, digestSize: number): Spec {
  return { digestSize, blockSize: 64, create: () => new Sha256(iv, digestSize) };
}

function sha512(iv: Int32Array, digestSize: number): Spec {
  return { digestSize, blockSize: 128, create: () => new Sha512(iv, digestSize) };
}

function sha3(digestSize: number): Spec {
  const rate = 200 - 2 * digestSize;

  return { digestSize, blockSize: rate, create: () => new Sha3(new Keccak(rate, 0x06), digestSize) };
}

const SHA_224_SPEC = sha256(IV_224, 28);

const SHA_256_SPEC = sha256(IV_256, 32);

const SHA_384_SPEC = sha512(IV_384, 48);

const SHA_512_SPEC = sha512(IV_512, 64);

export const SHA_224 = new HashAlgorithm("SHA-224", SHA_224_SPEC);

export const SHA_256 = new HashAlgorithm("SHA-256", SHA_256_SPEC);

export const SHA_384 = new HashAlgorithm("SHA-384", SHA_384_SPEC);

export const SHA_512 = new HashAlgorithm("SHA-512", SHA_512_SPEC);

export const SHA_512_224 = new HashAlgorithm("SHA-512/224", sha512(IV_512_224, 28));

export const SHA_512_256 = new HashAlgorithm("SHA-512/256", sha512(IV_512_256, 32));

export const SHA3_224 = new HashAlgorithm("SHA3-224", sha3(28));

export const SHA3_256 = new HashAlgorithm("SHA3-256", sha3(32));

export const SHA3_384 = new HashAlgorithm("SHA3-384", sha3(48));

export const SHA3_512 = new HashAlgorithm("SHA3-512", sha3(64));

export const SHAKE128 = new XofAlgorithm("SHAKE128", 168);

export const SHAKE256 = new XofAlgorithm("SHAKE256", 136);

export const HMAC_SHA_224 = new HmacAlgorithm("HMAC-SHA-224", SHA_224_SPEC);

export const HMAC_SHA_256 = new HmacAlgorithm("HMAC-SHA-256", SHA_256_SPEC);

export const HMAC_SHA_384 = new HmacAlgorithm("HMAC-SHA-384", SHA_384_SPEC);

export const HMAC_SHA_512 = new HmacAlgorithm("HMAC-SHA-512", SHA_512_SPEC);
