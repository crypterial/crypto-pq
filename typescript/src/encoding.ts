import { concat } from "./bytes.ts";
import { CryptoPQError } from "./errors.ts";

export type KeyFormat = "raw" | "der" | "pem";

export const SEQUENCE = 0x30;

const INTEGER = 0x02;

const BIT_STRING = 0x03;

export const OCTET_STRING = 0x04;

export const OBJECT_IDENTIFIER = 0x06;

export const CONTEXT_0 = 0x80;

const CONTEXT_0_CONSTRUCTED = 0xa0;

const CONTEXT_1 = 0x81;

export function keyFormat(value: unknown): KeyFormat {
  if (value !== "raw" && value !== "der" && value !== "pem") {
    throw new CryptoPQError("INVALID_OPTION", "format must be raw, der or pem");
  }

  return value;
}

export function invalid(message: string): CryptoPQError {
  return new CryptoPQError("INVALID_ENCODING", message);
}

export function objectIdentifier(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);

  const content = [40 * arcs[0] + arcs[1]];

  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];

    for (let rest = arc >>> 7; rest > 0; rest >>>= 7) {
      chunk.push(0x80 | (rest & 0x7f));
    }

    content.push(...chunk.reverse());
  }

  return Uint8Array.from(content);
}

export function element(tag: number, content: Uint8Array): Uint8Array {
  const header = [tag];

  if (content.length < 0x80) {
    header.push(content.length);
  } else {
    const size: number[] = [];

    for (let rest = content.length; rest > 0; rest = Math.floor(rest / 256)) {
      size.unshift(rest % 256);
    }

    header.push(0x80 | size.length, ...size);
  }

  return concat(Uint8Array.from(header), content);
}

export class Reader {
  readonly #data: Uint8Array;

  #offset = 0;

  constructor(data: Uint8Array) {
    this.#data = data;
  }

  // DER only: a single-byte tag and the shortest definite length.
  read(tag: number): Uint8Array {
    const data = this.#data;

    if (this.#offset + 2 > data.length || data[this.#offset] !== tag) {
      throw invalid("unexpected DER element");
    }

    const first = data[this.#offset + 1];

    let offset = this.#offset + 2;

    let length = first;

    if (first >= 0x80) {
      const size = first & 0x7f;

      if (size === 0 || size > 4 || offset + size > data.length || data[offset] === 0) {
        throw invalid("invalid DER length");
      }

      length = 0;

      for (let i = 0; i < size; i++) {
        length = length * 256 + data[offset + i];
      }

      offset += size;

      if (length < 0x80) {
        throw invalid("invalid DER length");
      }
    }

    if (offset + length > data.length) {
      throw invalid("truncated DER element");
    }

    this.#offset = offset + length;

    return data.subarray(offset, offset + length);
  }

  peek(): number | undefined {
    return this.#offset < this.#data.length ? this.#data[this.#offset] : undefined;
  }

  finish(): void {
    if (this.#offset !== this.#data.length) {
      throw invalid("trailing data after DER element");
    }
  }
}

export function only(data: Uint8Array, tag: number): Uint8Array {
  const reader = new Reader(data);

  const content = reader.read(tag);

  reader.finish();

  return content;
}

function algorithmIdentifier(oid: Uint8Array): Uint8Array {
  return element(SEQUENCE, element(OBJECT_IDENTIFIER, oid));
}

function readAlgorithm(reader: Reader): Uint8Array {
  return only(reader.read(SEQUENCE), OBJECT_IDENTIFIER);
}

function publicKeyBits(bits: Uint8Array): Uint8Array {
  if (bits.length === 0 || bits[0] !== 0) {
    throw invalid("public key BIT STRING must have no unused bits");
  }

  return bits.subarray(1);
}

export function encodePublicKey(oid: Uint8Array, key: Uint8Array): Uint8Array {
  return element(SEQUENCE, concat(algorithmIdentifier(oid), element(BIT_STRING, concat(Uint8Array.of(0), key))));
}

export function decodePublicKey(data: Uint8Array): [Uint8Array, Uint8Array] {
  const reader = new Reader(only(data, SEQUENCE));

  const oid = readAlgorithm(reader);

  const bits = reader.read(BIT_STRING);

  reader.finish();

  return [oid, publicKeyBits(bits)];
}

export function encodePrivateKey(oid: Uint8Array, key: Uint8Array): Uint8Array {
  return element(
    SEQUENCE,
    concat(element(INTEGER, Uint8Array.of(0)), algorithmIdentifier(oid), element(OCTET_STRING, key)),
  );
}

// PKCS#8 OneAsymmetricKey (RFC 5958): version 0 or 1, attributes ignored, and the optional
// public key returned so that the caller can check that it matches.
export function decodePrivateKey(data: Uint8Array): [Uint8Array, Uint8Array, Uint8Array | null] {
  const reader = new Reader(only(data, SEQUENCE));

  const version = reader.read(INTEGER);

  if (version.length !== 1 || version[0] > 1) {
    throw invalid("unsupported PKCS#8 version");
  }

  const oid = readAlgorithm(reader);

  const key = reader.read(OCTET_STRING);

  let publicKey: Uint8Array | null = null;

  if (reader.peek() === CONTEXT_0_CONSTRUCTED) {
    reader.read(CONTEXT_0_CONSTRUCTED);
  }

  if (reader.peek() === CONTEXT_1) {
    if (version[0] !== 1) {
      throw invalid("a PKCS#8 public key requires version 1");
    }

    publicKey = publicKeyBits(reader.read(CONTEXT_1));
  }

  reader.finish();

  return [oid, key, publicKey];
}

function base64Character(value: number): number {
  let character = value + 65;

  character += ((25 - value) >> 8) & 6;

  character -= ((51 - value) >> 8) & 75;

  character -= ((61 - value) >> 8) & 15;

  character += ((62 - value) >> 8) & 3;

  return character;
}

// Arithmetic instead of table lookups, so that decoding a private key does not index memory
// with secret values; -1 marks a character outside the alphabet.
function base64Value(character: number): number {
  let value = -1;

  value += (((0x40 - character) & (character - 0x5b)) >> 8) & (character - 64);

  value += (((0x60 - character) & (character - 0x7b)) >> 8) & (character - 70);

  value += (((0x2f - character) & (character - 0x3a)) >> 8) & (character + 5);

  value += (((0x2a - character) & (character - 0x2c)) >> 8) & 63;

  value += (((0x2e - character) & (character - 0x30)) >> 8) & 64;

  return value;
}

function base64Encode(data: Uint8Array): string {
  const characters = new Uint16Array(4 * Math.ceil(data.length / 3));

  for (let offset = 0, out = 0; offset < data.length; offset += 3, out += 4) {
    const used = Math.min(3, data.length - offset);

    let value = data[offset] << 16;

    if (used > 1) {
      value |= data[offset + 1] << 8;
    }

    if (used > 2) {
      value |= data[offset + 2];
    }

    for (let i = 0; i < 4; i++) {
      characters[out + i] = i <= used ? base64Character((value >>> (18 - 6 * i)) & 0x3f) : 0x3d;
    }
  }

  let text = "";

  for (let offset = 0; offset < characters.length; offset += 4096) {
    text += String.fromCharCode(...characters.subarray(offset, offset + 4096));
  }

  return text;
}

function base64Decode(text: Uint8Array): Uint8Array {
  if (text.length % 4 !== 0) {
    throw invalid("invalid base64 length");
  }

  const last = text.length - 1;

  const padding = text.length > 0 && text[last] === 0x3d ? (text[last - 1] === 0x3d ? 2 : 1) : 0;

  const out = new Uint8Array((text.length / 4) * 3 - padding);

  let bad = 0;

  for (let offset = 0, position = 0; offset < text.length; offset += 4, position += 3) {
    const used = offset + 4 === text.length ? 4 - padding : 4;

    let value = 0;

    for (let i = 0; i < used; i++) {
      const digit = base64Value(text[offset + i]);

      bad |= digit;

      value = (value << 6) | (digit & 0x3f);
    }

    value <<= 6 * (4 - used);

    bad |= -(value & ((1 << (8 * (4 - used))) - 1));

    for (let i = 0; i < used - 1; i++) {
      out[position + i] = value >>> (16 - 8 * i);
    }
  }

  if (bad < 0) {
    out.fill(0);

    throw invalid("invalid base64");
  }

  return out;
}

function isSpace(character: number): boolean {
  return character === 0x20 || (character >= 0x09 && character <= 0x0d);
}

export function pemEncode(label: string, der: Uint8Array): string {
  const body = base64Encode(der);

  const lines: string[] = [];

  for (let offset = 0; offset < body.length; offset += 64) {
    lines.push(body.slice(offset, offset + 64));
  }

  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);

  for (let i = 0; i < text.length; i++) {
    const character = text.charCodeAt(i);

    if (character > 0x7f) {
      out.fill(0);

      throw invalid("PEM must be ASCII");
    }

    out[i] = character;
  }

  return out;
}

function startsWith(data: Uint8Array, prefix: Uint8Array, offset: number): boolean {
  if (offset < 0 || offset + prefix.length > data.length) {
    return false;
  }

  for (let i = 0; i < prefix.length; i++) {
    if (data[offset + i] !== prefix[i]) {
      return false;
    }
  }

  return true;
}

function strip(data: Uint8Array): Uint8Array {
  let start = 0;

  let end = data.length;

  while (start < end && isSpace(data[start])) {
    start++;
  }

  while (end > start && isSpace(data[end - 1])) {
    end--;
  }

  return data.subarray(start, end);
}

// Returns the DER bytes in a new buffer that the caller may wipe.
export function pemDecode(label: string, data: Uint8Array | string): Uint8Array {
  const text = typeof data === "string" ? ascii(data) : data;

  const block = strip(text);

  const begin = ascii(`-----BEGIN ${label}-----`);

  const end = ascii(`-----END ${label}-----`);

  const compact = new Uint8Array(block.length);

  try {
    if (!startsWith(block, begin, 0) || !startsWith(block, end, block.length - end.length)) {
      throw invalid(`expected a ${label} PEM block`);
    }

    let length = 0;

    let high = 0;

    for (const character of block.subarray(begin.length, Math.max(begin.length, block.length - end.length))) {
      high |= character;

      if (!isSpace(character)) {
        compact[length++] = character;
      }
    }

    if (high > 0x7f) {
      throw invalid("PEM must be ASCII");
    }

    return base64Decode(compact.subarray(0, length));
  } finally {
    compact.fill(0);

    if (text !== data) {
      text.fill(0);
    }
  }
}
