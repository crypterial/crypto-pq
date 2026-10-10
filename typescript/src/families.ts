import { equal } from "./bytes.ts";
import { type Core, Family, OK, SECRET } from "./wasm.ts";
import { ML_DSA_WASM } from "./wasm-ml-dsa.ts";
import { ML_KEM_WASM } from "./wasm-ml-kem.ts";
import { SLH_DSA_WASM } from "./wasm-slh-dsa.ts";
import { STATEFUL_WASM } from "./wasm-stateful.ts";
import { X_WING_HASH_WASM } from "./wasm-x-wing-hash.ts";

// crypto-pq's Zig core as one WebAssembly module per family, each compiled on the family's first
// use. The known answers of the self-tests come from the TypeScript backend.

const KEM = [
  "cpq_kem_keygen",
  "cpq_kem_import_public",
  "cpq_kem_import_private",
  "cpq_kem_public_from_private",
  "cpq_kem_export_public",
  "cpq_kem_export_private",
  "cpq_kem_encapsulate",
  "cpq_kem_decapsulate",
  "cpq_kem_self_test",
];

const SIGNATURE = [
  "cpq_sig_keygen",
  "cpq_sig_import_public",
  "cpq_sig_import_private",
  "cpq_sig_public_from_private",
  "cpq_sig_export_public",
  "cpq_sig_export_private",
  "cpq_sig_sign",
  "cpq_sig_verify",
];

const STATEFUL = [
  "cpq_stateful_info",
  "cpq_stateful_signer_create",
  "cpq_stateful_signer_load",
  "cpq_stateful_signer_sign",
  "cpq_stateful_signer_public_key",
  "cpq_stateful_signer_tree_cache_size",
  "cpq_stateful_signer_export_tree_cache",
  "cpq_stateful_signer_free",
  "cpq_stateful_verify",
  "cpq_stateful_check_public_key",
];

const HASH = [
  "cpq_hash",
  "cpq_hash_init",
  "cpq_hash_update",
  "cpq_hash_final",
  "cpq_xof",
  "cpq_xof_init",
  "cpq_xof_update",
  "cpq_xof_read",
  "cpq_hash_configure",
  "cpq_hash_with",
  "cpq_hash_init_with",
  "cpq_xof_configure",
  "cpq_xof_with",
  "cpq_xof_init_with",
  "cpq_mac",
  "cpq_mac_verify",
  "cpq_mac_init",
  "cpq_mac_update",
  "cpq_mac_final",
  "cpq_mac_final_verify",
  "cpq_mac_configure",
  "cpq_mac_with",
  "cpq_mac_verify_with",
  "cpq_mac_init_with",
  "cpq_kdf_derive",
  "cpq_kdf_extract",
  "cpq_kdf_expand",
];

function range(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);
}

function fromHex(text: string): Uint8Array {
  return Uint8Array.from({ length: text.length / 2 }, (_, i) => parseInt(text.slice(2 * i, 2 * i + 2), 16));
}

// Key generation from bytes 0, 1, 2..., encapsulation with the next bytes through the private key's
// own public part, and decapsulation: both shared secrets must be the known one.
function kemTest(core: Core, id: number, sizes: readonly number[], start: number, expected: string): boolean {
  const [seedSize, randomnessSize, ciphertextSize] = sizes;

  const slot = core.size(2, id);

  return core.run(SECRET, [slot, seedSize, randomnessSize, ciphertextSize, 32, 32], (at) => {
    const [key, seed, randomness, ciphertext, encapsulated, decapsulated] = at;

    const x = core.x;

    core.write(seed, range(seedSize, 0));

    core.write(randomness, range(randomnessSize, start));

    const statuses = [
      x.cpq_kem_keygen(id, seed, seedSize, 0, key, slot),
      x.cpq_kem_encapsulate(key, slot, randomness, randomnessSize, ciphertext, ciphertextSize, encapsulated, 32),
      x.cpq_kem_decapsulate(key, slot, ciphertext, ciphertextSize, decapsulated, 32),
    ];

    const want = fromHex(expected);

    const shared = [core.read(encapsulated, 32), core.read(decapsulated, 32)];

    return statuses.every((status) => status === OK) && shared.every((secret) => equal(secret, want));
  });
}

// A deterministic ML-DSA signature whose challenge hash, which covers the whole signing path, must
// be the known one, and which must then verify.
function mlDsaTest(core: Core, id: number, signatureSize: number, expected: string): boolean {
  const slot = core.size(4, id);

  return core.run(SECRET, [slot, 32, 32, signatureSize], ([key, seed, message, signature]) => {
    const x = core.x;

    core.write(seed, range(32, 0));

    core.write(message, range(32, 32));

    const statuses = [
      x.cpq_sig_keygen(id, seed, 32, 0, key, slot),
      x.cpq_sig_sign(key, slot, message, 32, 0, 0, 0, 0, 0, 1, signature, signatureSize),
      x.cpq_sig_verify(key, slot, signature, signatureSize, message, 32, 0, 0, 0, 0),
    ];

    const want = fromHex(expected);

    return statuses.every((status) => status === OK) && equal(core.read(signature, want.length), want);
  });
}

// The public key, whose root is the top tree, of an SLH-DSA key generated from bytes 0, 1, 2...
function slhDsaTest(core: Core, id: number, expected: string): boolean {
  const slot = core.size(4, id);

  return core.run(SECRET, [slot, 48, 32], ([key, seed, publicKey]) => {
    const x = core.x;

    core.write(seed, range(48, 0));

    const statuses = [x.cpq_sig_keygen(id, seed, 48, 0, key, slot), x.cpq_sig_export_public(key, slot, publicKey, 32)];

    return statuses.every((status) => status === OK) && equal(core.read(publicKey, 32), fromHex(expected));
  });
}

// The public key of a one-level HSS key of height 5 over SHA-256/192 with Winternitz parameter 1,
// the cheapest tree to build.
function hssTest(core: Core, types: readonly number[], expected: string): boolean {
  const slot = core.size(8, 1);

  const parameters = Uint8Array.of(1, 0, 0, 0, types[0], 0, 0, 0, types[1]);

  return core.run(SECRET, [slot, parameters.length, 40, 75, 52], ([signer, section, seed, state, publicKey]) => {
    const x = core.x;

    core.write(section, parameters);

    core.write(seed, range(40, 0));

    const created = x.cpq_stateful_signer_create(1, section, parameters.length, seed, 40, 0n, state, 75, signer, slot);

    if (created !== OK) {
      return false;
    }

    const exported = x.cpq_stateful_signer_public_key(signer, slot, publicKey, 52);

    const freed = x.cpq_stateful_signer_free(signer, slot);

    return exported === OK && freed === OK && equal(core.read(publicKey, 52), fromHex(expected));
  });
}

// The digest of "abc" from cpq_hash or cpq_xof.
function digestTest(core: Core, call: string, id: number, size: number, expected: string): boolean {
  return core.run(SECRET, [3, size], ([data, digest]) => {
    core.write(data, Uint8Array.of(0x61, 0x62, 0x63));

    return core.x[call](id, data, 3, digest, size) === OK && equal(core.read(digest, size), fromHex(expected));
  });
}

// The tag of "abc" from cpq_mac with the key 0, 1, 2 ... 31.
function macTest(core: Core, id: number, size: number, expected: string): boolean {
  return core.run(SECRET, [32, 3, size], ([key, data, tag]) => {
    core.write(key, range(32, 0));

    core.write(data, Uint8Array.of(0x61, 0x62, 0x63));

    return core.x.cpq_mac(id, key, 32, data, 3, tag, size) === OK && equal(core.read(tag, size), fromHex(expected));
  });
}

export const ML_KEM = /* @__PURE__ */ new Family(
  "ML-KEM",
  ML_KEM_WASM,
  (core) => kemTest(core, 1, [64, 32, 1088], 64, "9cddd089ffe70e3996e76f7c8d06746df34d07e8657bc0fcf2bb0e1c3084aea1"),
  KEM,
);

export const ML_DSA = /* @__PURE__ */ new Family(
  "ML-DSA",
  ML_DSA_WASM,
  (core) =>
    mlDsaTest(
      core,
      1,
      3309,
      "da6cd8177e5a07be036e910ed99ddace0039eca58c22b1bb90ff9582b296c5081472230d94ff0cf3007ce724c02e9d89",
    ),
  SIGNATURE,
);

export const SLH_DSA = /* @__PURE__ */ new Family(
  "SLH-DSA",
  SLH_DSA_WASM,
  (core) =>
    slhDsaTest(core, 4, "202122232425262728292a2b2c2d2e2f3b56e816847f000386aeec2e2bb9e1b5") &&
    slhDsaTest(core, 10, "202122232425262728292a2b2c2d2e2fa90e4715b9a925c332801767fd786371"),
  SIGNATURE,
);

export const STATEFUL_SIGNATURES = /* @__PURE__ */ new Family(
  "HSS/LMS and XMSS",
  STATEFUL_WASM,
  (core) =>
    hssTest(
      core,
      [10, 5],
      "000000010000000a00000005000102030405060708090a0b0c0d0e0f224f2491ed07b8b55134c2b6ea3163d0e60e423ce46b051b",
    ),
  STATEFUL,
);

export const X_WING_HASH = /* @__PURE__ */ new Family(
  "X-Wing and the hash functions",
  X_WING_HASH_WASM,
  (core) =>
    kemTest(core, 3, [32, 64, 1120], 32, "9ef8c4373f751b482022f88f3e8cceeb4815a3c1afbc784324ac9eeb50932023") &&
    digestTest(core, "cpq_hash", 1, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") &&
    digestTest(core, "cpq_hash", 5, 32, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23") &&
    digestTest(core, "cpq_hash", 7, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532") &&
    digestTest(core, "cpq_xof", 0, 32, "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8") &&
    digestTest(core, "cpq_xof", 1, 32, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739") &&
    digestTest(
      core,
      "cpq_hash",
      13,
      64,
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ) &&
    digestTest(core, "cpq_hash", 17, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982") &&
    digestTest(core, "cpq_hash", 18, 32, "45aa03431c3c829b3b066f33e844b0cc4d20a45af92d3dcfdf34f40fc20935cf") &&
    macTest(core, 1, 32, "f0133729c4163dede81e21cd47839256da58171238c8a0d874397c73b14e1e47") &&
    macTest(core, 4, 32, "db7cef4050cab7f3c14c7ab3afa8dbc6f4a01c0aad60f79bc8186ec2fef516a7"),
  KEM,
  HASH,
);
