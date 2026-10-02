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

export function readUint32(data: Uint8Array, offset: number): number {
  return ((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0;
}

export function writeUint32(data: Uint8Array, offset: number, value: number): void {
  data[offset] = value >>> 24;

  data[offset + 1] = value >>> 16;

  data[offset + 2] = value >>> 8;

  data[offset + 3] = value;
}
