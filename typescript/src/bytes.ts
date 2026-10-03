export function bytes(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }

  return value;
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
  for (const buffer of buffers) {
    buffer.fill(0);
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

export function uint64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);

  writeUint32(out, 0, Number(value >> 32n));

  writeUint32(out, 4, Number(value & 0xffffffffn));

  return out;
}

export function readUint64(data: Uint8Array, offset: number): bigint {
  return (BigInt(readUint32(data, offset)) << 32n) | BigInt(readUint32(data, offset + 4));
}
