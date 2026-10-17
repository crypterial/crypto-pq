import { CryptoPQError } from "./errors.ts";

const TYPED_ARRAY: object = Object.getPrototypeOf(Uint8Array.prototype);

function intrinsic<T>(key: string | symbol): (this: unknown) => T {
  return Object.getOwnPropertyDescriptor(TYPED_ARRAY, key)!.get as (this: unknown) => T;
}

// The built-in getters of %TypedArray%.prototype, which read an array's internal slots: no property
// that a subclass or the caller redefines is consulted, and no caller code runs.
const TAG = intrinsic<string | undefined>(Symbol.toStringTag);

const LENGTH = intrinsic<number>("length");

const BYTE_OFFSET = intrinsic<number>("byteOffset");

const BUFFER = intrinsic<ArrayBufferLike>("buffer");

// The built-in at(), which refuses an array whose buffer was detached, or resized so that the array
// no longer fits in it: the getters above read such an array as empty.
const AT = Object.getOwnPropertyDescriptor(TYPED_ARRAY, "at")!.value as (this: unknown, index: number) => unknown;

export function isBytes(value: unknown): value is Uint8Array {
  return TAG.call(value) === "Uint8Array";
}

// The type check of the input boundary, for an argument that a call reads with bytes() only after
// caller code that it runs first, such as option getters or a state store.
export function checkBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!isBytes(value)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

// The input boundary: a view of the caller's bytes made by this library, whose length, subarray, set,
// slice and species are the built-in ones. Length, offset and buffer are read once from the internal
// slots, so nothing that a subclass or the caller redefines runs. An array without readable bytes, its
// buffer detached or resized below it, is refused rather than read as empty.
export function bytes(value: unknown, name: string): Uint8Array {
  checkBytes(value, name);

  const length = LENGTH.call(value);

  if (length > 0) {
    return new Uint8Array(BUFFER.call(value), BYTE_OFFSET.call(value), length);
  }

  try {
    AT.call(value, 0);
  } catch (error) {
    if (!(error instanceof TypeError)) {
      throw error;
    }

    throw new CryptoPQError("INVALID_LENGTH", `${name} cannot be read: its buffer was detached or resized`, {
      cause: error,
    });
  }

  return new Uint8Array(0);
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;

  for (const part of parts) {
    length += part.length;
  }

  const out = new Uint8Array(length);

  let offset = 0;

  for (const part of parts) {
    out.set(part, offset);

    offset += part.length;
  }

  return out;
}

// JavaScript cannot promise that no other copy remains; this only clears the buffers it is given.
export function wipe(...buffers: { fill(value: number): unknown }[]): void {
  for (let i = 0; i < buffers.length; i++) {
    buffers[i].fill(0);
  }
}

export function readUint32(data: Uint8Array, offset: number): number {
  return ((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0;
}

export function writeUint32(data: Uint8Array, offset: number, value: number): void {
  data[offset] = value >>> 24;

  data[offset + 1] = value >>> 16;

  data[offset + 2] = value >>> 8;

  data[offset + 3] = value;
}

export function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);

  writeUint32(out, 0, value);

  return out;
}

export function writeUint64(data: Uint8Array, offset: number, value: bigint): void {
  writeUint32(data, offset, Number(value >> 32n));

  writeUint32(data, offset + 4, Number(value & 0xffffffffn));
}

export function uint64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);

  writeUint64(out, 0, value);

  return out;
}

export function readUint64(data: Uint8Array, offset: number): bigint {
  return (BigInt(readUint32(data, offset)) << 32n) | BigInt(readUint32(data, offset + 4));
}
