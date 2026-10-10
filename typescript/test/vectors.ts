import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import process from "node:process";

import { concat } from "../src/bytes.ts";
import * as pq from "../src/index.ts";

export type Fields = Record<string, string>;

const VECTORS = new URL("../../vectors/", import.meta.url);

export const SLOW = Boolean(process.env.CRYPTO_PQ_SLOW);

export { concat };

// `[key = value]` header lines persist until replaced; records are `key = value` lines separated
// by blank lines; `#` starts a comment.
export function records(name: string, field: string): [Fields, Fields][] {
  const lines = readFileSync(new URL(name, VECTORS), "utf8").split(/\r?\n/);

  let header: Fields = {};

  let record: Fields = {};

  const found: [Fields, Fields][] = [];

  for (const raw of [...lines, ""]) {
    const line = raw.trim();

    if (line.startsWith("[") && line.endsWith("]")) {
      const content = line.slice(1, -1);

      const index = content.includes("=") ? content.indexOf("=") : content.length;

      header = { ...header, [content.slice(0, index).trim()]: content.slice(index + 1).trim() };
    } else if (line.includes("=") && !line.startsWith("#")) {
      const index = line.indexOf("=");

      record[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    } else if (Object.keys(record).length > 0) {
      found.push([header, record]);

      record = {};
    }
  }

  const expected = lines.filter((line) => line.startsWith(`${field} =`)).length;

  const parsed = found.filter(([, record]) => field in record).length;

  assert.ok(expected > 0 && parsed === expected, `${name}: parsed ${parsed}, expected ${expected}`);

  return found;
}

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES = [0, 1, 3, 64, 7, 136, 128, 168, 0, 200];

export function pieces(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (let offset = 0, index = 0; offset < data.length; index++) {
    const end = Math.min(offset + PIECES[index % PIECES.length], data.length);

    out.push(data.subarray(offset, end));

    offset = end;
  }

  return out;
}

export function hex(text: string): Uint8Array {
  assert.match(text, /^(?:[0-9a-f]{2})*$/i);

  const out = new Uint8Array(text.length / 2);

  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  }

  return out;
}

export function toHex(data: Uint8Array): string {
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

// A minimal DER writer, so that tests can build encodings the library itself never produces.
export function der(tag: number, content: Uint8Array): Uint8Array {
  if (content.length < 0x80) {
    return concat(Uint8Array.of(tag, content.length), content);
  }

  const size: number[] = [];

  for (let rest = content.length; rest > 0; rest = Math.floor(rest / 256)) {
    size.unshift(rest % 256);
  }

  return concat(Uint8Array.of(tag, 0x80 | size.length, ...size), content);
}

export const PRE_HASHES: Record<string, pq.HashAlgorithm | pq.XofAlgorithm> = {
  "SHA2-224": pq.SHA_224,
  "SHA2-256": pq.SHA_256,
  "SHA2-384": pq.SHA_384,
  "SHA2-512": pq.SHA_512,
  "SHA2-512/224": pq.SHA_512_224,
  "SHA2-512/256": pq.SHA_512_256,
  "SHA3-224": pq.SHA3_224,
  "SHA3-256": pq.SHA3_256,
  "SHA3-384": pq.SHA3_384,
  "SHA3-512": pq.SHA3_512,
  "SHAKE-128": pq.SHAKE128,
  "SHAKE-256": pq.SHAKE256,
};

export function preHash(header: Fields, record: Fields): pq.HashAlgorithm | pq.XofAlgorithm | undefined {
  return header.preHash === "pure" ? undefined : PRE_HASHES[record.hashAlg];
}

export function isCode(code: pq.ErrorCode): (error: unknown) => boolean {
  return (error: unknown) => error instanceof pq.CryptoPQError && error.code === code;
}

export function throwsCode(code: pq.ErrorCode, function_: () => unknown, message?: string): void {
  assert.throws(function_, isCode(code), message);
}

export class MemoryStore implements pq.StateStore {
  state: Uint8Array | null;

  constructor(state: Uint8Array | null = null) {
    this.state = state;
  }

  read(): Uint8Array | null {
    return this.state;
  }

  update(previous: Uint8Array | null, next: Uint8Array): boolean {
    const same =
      previous === null || this.state === null ? previous === this.state : toHex(previous) === toHex(this.state);

    if (!same) {
      return false;
    }

    this.state = next;

    return true;
  }
}
