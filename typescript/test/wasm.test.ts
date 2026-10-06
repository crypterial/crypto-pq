import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import process from "node:process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { ML_DSA, ML_KEM, SLH_DSA, STATEFUL_SIGNATURES, X_WING_HASH } from "../src/families.ts";
import * as hazmat from "../src/hazmat.ts";
import * as pq from "../src/index.ts";
import * as mldsa from "../src/mldsa.ts";
import { sha256 } from "../src/primitives.ts";
import { type Core, HASHING, SECRET, check, decodeBase64, engineFlags } from "../src/wasm.ts";
import { ML_DSA_WASM } from "../src/wasm-ml-dsa.ts";
import { ML_KEM_WASM } from "../src/wasm-ml-kem.ts";
import { SLH_DSA_WASM } from "../src/wasm-slh-dsa.ts";
import { STATEFUL_WASM } from "../src/wasm-stateful.ts";
import { X_WING_HASH_WASM } from "../src/wasm-x-wing-hash.ts";
import { BACKEND } from "./backend.ts";
import { MemoryStore, throwsCode, toHex } from "./vectors.ts";

const CHILD = fileURLToPath(new URL("./child.ts", import.meta.url));

const FAMILIES = [ML_KEM, ML_DSA, SLH_DSA, STATEFUL_SIGNATURES, X_WING_HASH];

const H5: [string, string][] = [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"]];

function range(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);
}

function random(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// Runs a scenario of child.ts in a fresh process and returns what it printed.
function child(scenario: string, backend: string, ...rest: string[]): Record<string, unknown> {
  const flags = scenario === "memory" || scenario === "finalize" ? ["--expose-gc"] : [];

  const result = spawnSync(process.execPath, [...flags, CHILD, scenario, backend, ...rest], { encoding: "utf8" });

  assert.equal(result.status, 0, `${scenario} ${backend}: ${result.stderr}`);

  return JSON.parse(result.stdout);
}

// Runs body on WebAssembly, whatever the backend of the test run.
function onWasm<T>(body: () => T): T {
  pq.setBackend("wasm");

  try {
    return body();
  } finally {
    pq.setBackend(BACKEND);
  }
}

function contains(memory: Uint8Array, secret: Uint8Array): boolean {
  return Buffer.from(memory.buffer, memory.byteOffset, memory.byteLength).indexOf(Buffer.from(secret)) >= 0;
}

function stackIsClear(core: Core): boolean {
  const low = core.x.cpq_stack_low() >>> 0;

  const high = core.x.cpq_stack_high() >>> 0;

  return core
    .bytes()
    .subarray(low, high)
    .every((b) => b === 0);
}

test("embedded modules match wasm/SHA256SUMS", () => {
  const embedded: Record<string, string> = {
    "crypto_pq_ml_dsa.wasm": ML_DSA_WASM,
    "crypto_pq_ml_kem.wasm": ML_KEM_WASM,
    "crypto_pq_slh_dsa.wasm": SLH_DSA_WASM,
    "crypto_pq_stateful.wasm": STATEFUL_WASM,
    "crypto_pq_x_wing_hash.wasm": X_WING_HASH_WASM,
  };

  const lines = readFileSync(new URL("../wasm/SHA256SUMS", import.meta.url), "utf8")
    .trimEnd()
    .split("\n");

  assert.deepEqual(
    lines.map((line) => line.slice(66)),
    Object.keys(embedded),
  );

  for (const line of lines) {
    const name = line.slice(66);

    assert.equal(toHex(sha256(decodeBase64(embedded[name]))), line.slice(0, 64), name);
  }
});

// Engines without Uint8Array.fromBase64 or atob decode with the library's own loop.
test("base64 decoding without the platform's decoders", () => {
  const globals = globalThis as { atob?: unknown };

  const atob = globals.atob;

  const native = Object.getOwnPropertyDescriptor(Uint8Array, "fromBase64");

  try {
    delete globals.atob;

    delete (Uint8Array as { fromBase64?: unknown }).fromBase64;

    for (const text of [ML_KEM_WASM, "", "AA==", "AAA=", "AAAA", "/+/+"]) {
      assert.deepEqual(decodeBase64(text), new Uint8Array(Buffer.from(text, "base64")), text.slice(0, 8));
    }

    assert.throws(() => decodeBase64("AA*A"));
  } finally {
    globals.atob = atob;

    if (native !== undefined) {
      Object.defineProperty(Uint8Array, "fromBase64", native);
    }
  }
});

// The self-tests that decide whether a family runs on WebAssembly compare against these answers,
// which TypeScript gives.
test("the self-tests' known answers are TypeScript's", () => {
  pq.setBackend("js");

  try {
    const kem = hazmat.generateKeyPair(pq.ML_KEM_768, range(64, 0));

    const xWing = hazmat.generateKeyPair(pq.X_WING, range(32, 0));

    const mlDsa = hazmat
      .generateKeyPair(pq.ML_DSA_65, range(32, 0))
      .privateKey.sign(range(32, 32), { deterministic: true });

    const store = new MemoryStore();

    const hss = hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40, 0), {
      parameters: [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"]],
      stateStore: store,
    });

    const abc = Uint8Array.of(0x61, 0x62, 0x63);

    const answers = [
      hazmat.encapsulate(kem.publicKey, range(32, 64)).sharedSecret,
      mlDsa.subarray(0, 48),
      hazmat.generateKeyPair(pq.SLH_DSA_SHA2_128F, range(48, 0)).publicKey.exportKey("raw"),
      hazmat.generateKeyPair(pq.SLH_DSA_SHAKE_128F, range(48, 0)).publicKey.exportKey("raw"),
      hss.publicKey.exportKey("raw"),
      hazmat.encapsulate(xWing.publicKey, range(64, 32)).sharedSecret,
      pq.SHA_256.digest(abc),
      pq.SHA_512_256.digest(abc),
      pq.SHA3_256.digest(abc),
      pq.SHAKE128.digest(abc, 32),
      pq.SHAKE256.digest(abc, 32),
      pq.HMAC_SHA_256.digest(range(32, 0), abc),
    ];

    assert.deepEqual(answers.map(toHex), [
      "9cddd089ffe70e3996e76f7c8d06746df34d07e8657bc0fcf2bb0e1c3084aea1",
      "da6cd8177e5a07be036e910ed99ddace0039eca58c22b1bb90ff9582b296c5081472230d94ff0cf3007ce724c02e9d89",
      "202122232425262728292a2b2c2d2e2f3b56e816847f000386aeec2e2bb9e1b5",
      "202122232425262728292a2b2c2d2e2fa90e4715b9a925c332801767fd786371",
      "000000010000000a00000005000102030405060708090a0b0c0d0e0f224f2491ed07b8b55134c2b6ea3163d0e60e423ce46b051b",
      "9ef8c4373f751b482022f88f3e8cceeb4815a3c1afbc784324ac9eeb50932023",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
      "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
      "f0133729c4163dede81e21cd47839256da58171238c8a0d874397c73b14e1e47",
    ]);
  } finally {
    pq.setBackend(BACKEND);
  }
});

// Every code shape that cpq_wasm_tune can pick, against TypeScript: Keccak on one, two, three
// and four states (single hashes, ML-KEM-768's secret vectors, ML-DSA-87's masks, matrices and
// SLH-DSA-SHAKE's trees) and the stateful module's.
test("every engine tuning gives TypeScript's results", () => {
  const outputs = () => {
    const kem = hazmat.generateKeyPair(pq.ML_KEM_768, range(64, 1));

    const dsa = hazmat.generateKeyPair(pq.ML_DSA_87, range(32, 2));

    const slh = hazmat.generateKeyPair(pq.SLH_DSA_SHAKE_128F, range(48, 3));

    const lms = hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40, 4), {
      parameters: [["LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4"]],
      stateStore: new MemoryStore(),
    });

    const message = range(100, 5);

    return [
      pq.SHA3_256.digest(range(200, 6)),
      pq.SHAKE128.digest(range(300, 7), 400),
      pq.SHAKE256.digest(message, 64),
      kem.publicKey.exportKey("raw"),
      hazmat.encapsulate(kem.publicKey, range(32, 8)).ciphertext,
      dsa.publicKey.exportKey("raw"),
      dsa.privateKey.sign(message, { deterministic: true }),
      slh.privateKey.sign(message, { deterministic: true }),
      lms.publicKey.exportKey("raw"),
      lms.privateKey.sign(message),
    ].map(toHex);
  };

  pq.setBackend("js");

  let expected: string[];

  try {
    expected = outputs();
  } finally {
    pq.setBackend(BACKEND);
  }

  onWasm(() => {
    const cores = [ML_KEM, ML_DSA, SLH_DSA, STATEFUL_SIGNATURES, X_WING_HASH].map((family) => family.select()!);

    try {
      for (let flags = 0; flags < 8; flags++) {
        for (const core of cores) {
          core.x.cpq_wasm_tune(flags);
        }

        assert.deepEqual(outputs(), expected, `flags ${flags}`);
      }
    } finally {
      for (const core of cores) {
        core.x.cpq_wasm_tune(engineFlags());
      }
    }
  });
});

test("the backend option", () => {
  throwsCode("INVALID_OPTION", () => pq.setBackend("native" as pq.Backend));

  const algorithms = [
    pq.ML_KEM_768,
    pq.X_WING,
    pq.ML_DSA_65,
    pq.SLH_DSA_SHA2_128S,
    pq.HSS_LMS,
    pq.XMSS_MT,
    pq.SHA_256,
    pq.SHAKE128,
    pq.HMAC_SHA_256,
  ];

  try {
    for (const backend of ["js", "wasm", "auto"] as const) {
      pq.setBackend(backend);

      const expected = backend === "js" ? "js" : "wasm";

      assert.deepEqual(
        algorithms.map((algorithm) => algorithm.backend),
        algorithms.map(() => expected),
        backend,
      );
    }

    // Keys and hash states keep the backend that made them.
    const seed = random(64);

    const randomness = random(32);

    pq.setBackend("wasm");

    const onWasm = hazmat.generateKeyPair(pq.ML_KEM_768, seed);

    const hasher = pq.SHA3_256.create().update(seed);

    pq.setBackend("js");

    const onJs = hazmat.generateKeyPair(pq.ML_KEM_768, seed);

    const encapsulation = hazmat.encapsulate(onJs.publicKey, randomness);

    assert.deepEqual(onWasm.privateKey.decapsulate(encapsulation.ciphertext), encapsulation.sharedSecret);

    assert.deepEqual(hazmat.encapsulate(onWasm.publicKey, randomness), encapsulation);

    assert.deepEqual(hasher.update(randomness).digest(), pq.SHA3_256.create().update(seed).update(randomness).digest());
  } finally {
    pq.setBackend(BACKEND);
  }
});

// Each family's module is compiled once, on the family's first use, and never with backend "js".
test("modules compile on first use only", () => {
  for (const backend of ["auto", "wasm", "js"]) {
    const { families, compiled } = child("count", backend) as {
      families: Record<string, [unknown, unknown]>;
      compiled: number[];
    };

    const expected = backend === "js" ? "js" : "wasm";

    for (const [name, [chosen, works]] of Object.entries(families)) {
      assert.deepEqual([chosen, works], [expected, true], `${backend} ${name}`);
    }

    assert.equal(compiled.length, backend === "js" ? 0 : FAMILIES.length, backend);
  }
});

// Without WebAssembly, without SIMD, when the engine refuses to compile or instantiate (a content
// security policy without 'wasm-unsafe-eval'), when the self-tests fail or the ABI version differs,
// "auto" falls back to TypeScript, "wasm" refuses with UNSUPPORTED and "js" never notices.
test("fallback to TypeScript", () => {
  const scenarios = ["no-webassembly", "no-simd", "module-throws", "instance-throws", "self-test-fails", "abi-version"];

  for (const scenario of scenarios) {
    for (const backend of ["auto", "wasm", "js"]) {
      const { families } = child(scenario, backend) as { families: Record<string, [unknown, unknown]> };

      for (const [name, [chosen, works]] of Object.entries(families)) {
        const context = `${scenario} ${backend} ${name}`;

        if (backend === "wasm") {
          for (const result of [chosen, works]) {
            const { error, cause } = result as { error: string; cause?: string };

            assert.equal(error, "UNSUPPORTED", context);

            assert.ok(cause !== undefined && cause.length > 0, context);
          }
        } else {
          assert.deepEqual([chosen, works], ["js", true], context);
        }
      }
    }
  }
});

// A fault in the middle of an operation fails that call with an internal error and discards the
// instance; the same keys then work on a new instance.
test("a fault discards the instance", () => {
  const { failed, recovered, families } = child("trap", "wasm") as {
    failed: { error: string; cause: string };
    recovered: boolean;
    families: Record<string, [unknown, unknown]>;
  };

  assert.deepEqual([failed.error, failed.cause, recovered], ["Error", "unreachable", true]);

  for (const [name, result] of Object.entries(families)) {
    assert.deepEqual(result, ["wasm", true], name);
  }
});

// When the library has no room for another stateful signer, the instance stays: under "auto" the
// new key is made in TypeScript, under "wasm" the call fails with a RangeError.
test("stateful keys without room on WebAssembly", () => {
  const auto = child("signer-memory", "auto") as Record<string, unknown>;

  const wasm = child("signer-memory", "wasm") as Record<string, { error?: string }>;

  assert.deepEqual(auto, { ready: "wasm", created: true, loaded: 1384, after: "wasm" });

  assert.deepEqual(
    [wasm.ready, wasm.created.error, wasm.loaded.error, wasm.after],
    ["wasm", "RangeError", "RangeError", "wasm"],
  );
});

// Many stateful keys alive at once, each with its signer in one instance, more than the library's
// first table of signers holds.
test("many live stateful keys", () => {
  onWasm(() => {
    const message = Uint8Array.of(7);

    const pairs = Array.from({ length: 300 }, () =>
      pq.HSS_LMS.generateKeyPair({ parameters: H5, stateStore: new MemoryStore() }),
    );

    for (const pair of pairs) {
      assert.ok(pair.publicKey.verify(pair.privateKey.sign(message), message));
    }

    assert.equal(pq.HSS_LMS.backend, "wasm");
  });
});

// Keys keep their caches across calls: the library ties a cache to its slot's address, and every
// call places a key's slot copy at the same address, so after its first use no call fills or checks
// a cache again.
test("keys keep their caches", () => {
  assert.deepEqual(child("caches", "wasm"), { looked: 0 });
});

// A fault inside an instance: a forged signer slot, which only a broken binding could make. The
// library either traps on it or refuses it as BAD_SLOT, an internal error; either way the instance is
// discarded with its memory zeroed, and a stateful key whose trees it held builds them again and
// signs at its next index as TypeScript does.
test("a fault discards the instance and stateful keys rebuild their trees", () => {
  onWasm(() => {
    const seed = random(40);

    const message = random(10);

    const pair = hazmat.generateStatefulKeyPair(pq.HSS_LMS, seed, { parameters: H5, stateStore: new MemoryStore() });

    assert.ok(pair.publicKey.verify(pair.privateKey.sign(message), message));

    const core = STATEFUL_SIGNATURES.core();

    const size = core.size(8, 1);

    const forged = () =>
      core.run(SECRET, [size], ([slot]) => {
        const view = new DataView(core.bytes().buffer);

        [8, 0x63, 0x70, 0x71, 1, 0x61, 0x62, 0x69].forEach((b, i) => view.setUint8(slot + i, b));

        view.setUint32(slot + 8, 1, true);

        view.setUint32(slot + 12, size, true);

        view.setUint32(slot + 24, 0xfffffff0, true);

        view.setUint32(slot + 28, slot, true);

        check(core.x.cpq_stateful_signer_free(slot, size));
      });

    assert.throws(forged, (error: Error) => !(error instanceof pq.CryptoPQError) && error.cause instanceof Error);

    assert.equal(core.live, false);

    assert.ok(core.bytes().every((b) => b === 0));

    assert.notEqual(STATEFUL_SIGNATURES.core(), core);

    const second = pair.privateKey.sign(message);

    pq.setBackend("js");

    const reference = hazmat.generateStatefulKeyPair(pq.HSS_LMS, seed, {
      parameters: H5,
      stateStore: new MemoryStore(),
      index: 1n,
    });

    assert.deepEqual(second, reference.privateKey.sign(message));
  });
});

// The wipes cover the stack that every export uses: hashing stays within HASHING bytes of the top,
// and the deepest export within the stack.
test("every export stays within the stack that its wipe covers", (t) => {
  const deepest = child("stack", "wasm") as Record<string, number>;

  const hashing = Object.entries(deepest).filter(([name]) => /^cpq_(hash|xof|hmac)/.test(name));

  assert.ok(hashing.length >= 14);

  for (const [name, used] of hashing) {
    assert.ok(used <= HASHING, `${name} uses ${used} bytes of stack`);
  }

  const [name, used] = Object.entries(deepest).sort((a, b) => b[1] - a[1])[0];

  assert.ok(used < 65536, `${name} uses ${used} bytes of stack`);

  t.diagnostic(`deepest: ${name} ${used} bytes; hashing ${Math.max(...hashing.map(([, n]) => n))} bytes`);
});

// After an operation on secrets, neither the I/O block nor the stack holds them: the seeds, the
// randomness, the expanded keys and the shared secrets are nowhere in linear memory. A stateful
// signer holds its seed while it lives and gives it back when it is freed.
test("no secret stays in WebAssembly memory", () => {
  onWasm(() => {
    const memories = () => FAMILIES.map((family) => family.core());

    const absent = (secrets: Uint8Array[], context: string) => {
      for (const core of memories()) {
        assert.ok(stackIsClear(core), `${context}: stack`);

        for (const secret of secrets) {
          assert.ok(!contains(core.bytes(), secret), `${context}: ${toHex(secret).slice(0, 16)}`);
        }
      }
    };

    for (const algorithm of [pq.ML_KEM_512, pq.ML_KEM_768, pq.ML_KEM_1024, pq.X_WING]) {
      const seed = random(algorithm === pq.X_WING ? 32 : 64);

      const randomness = random(algorithm === pq.X_WING ? 64 : 32);

      const pair = hazmat.generateKeyPair(algorithm, seed);

      const { sharedSecret, ciphertext } = hazmat.encapsulate(pair.publicKey, randomness);

      const rejected = pair.privateKey.decapsulate(random(algorithm.ciphertextSize));

      pair.privateKey.decapsulate(ciphertext);

      const fresh = algorithm.generateKeyPair();

      const exported = fresh.privateKey.exportKey("raw");

      absent([seed.subarray(0, 32), randomness, sharedSecret, rejected, exported.subarray(0, 32)], algorithm.name);

      if (algorithm !== pq.X_WING) {
        const der = pair.privateKey.exportKey("der");

        const expanded = algorithm.importPrivateKey(der, "der");

        expanded.decapsulate(ciphertext);

        absent([der.subarray(-64, -32)], `${algorithm.name} PKCS#8`);
      }
    }

    for (const [algorithm, params] of [
      [pq.ML_DSA_44, mldsa.ML_DSA_44],
      [pq.ML_DSA_87, mldsa.ML_DSA_87],
    ] as const) {
      const seed = random(32);

      const [, sk] = mldsa.keygenInternal(seed, params);

      const pair = hazmat.generateKeyPair(algorithm, seed);

      const randomness = random(32);

      pair.privateKey.sign(random(100), { deterministic: true });

      hazmat.sign(pair.privateKey, random(100), randomness);

      algorithm.importPrivateKey(sk, "raw").sign(random(5));

      absent([seed, randomness, sk.subarray(32, 64), sk.subarray(-64, -32)], algorithm.name);
    }

    for (const algorithm of [pq.SLH_DSA_SHA2_128F, pq.SLH_DSA_SHAKE_192F]) {
      const pair = algorithm.generateKeyPair();

      const sk = pair.privateKey.exportKey("raw");

      pair.privateKey.sign(random(100));

      absent([sk.subarray(0, sk.length / 2)], algorithm.name);
    }

    const key = random(48);

    const data = random(1000);

    pq.HMAC_SHA_384.create(key).update(data).digest();

    pq.HMAC_SHA_256.verify(key, data, random(32));

    pq.SHA3_512.digest(data);

    pq.SHAKE256.create().update(data).read(64);

    absent([key, data.subarray(0, 32), data.subarray(-32)], "hashing");

    // A store that refuses the new key: its signer is freed at once.
    const seed = random(40);

    const refusing: pq.StateStore = { read: () => null, update: () => false };

    throwsCode("STATE_CONFLICT", () =>
      hazmat.generateStatefulKeyPair(pq.HSS_LMS, seed, { parameters: H5, stateStore: refusing }),
    );

    absent([seed.subarray(16)], "a freed stateful signer");
  });
});

// An input whose length property says less than it holds is copied only as far as it says: the
// regions next to it, the library's own memory and later calls stay intact.
test("inputs that misreport their length stay in their regions", () => {
  onWasm(() => {
    const forged = (size: number, claimed: number) => {
      const data = new Uint8Array(size).fill(0xa5);

      Object.defineProperty(data, "length", { value: claimed });

      return data;
    };

    const abc = Uint8Array.of(0x61, 0x62, 0x63);

    const expected = toHex(pq.SHA_256.digest(abc));

    pq.SHA_256.digest(forged(100000, 5));

    pq.SHA3_256.create().update(forged(70000, 3)).digest();

    pq.SHAKE128.create().update(forged(70000, 40000)).read(10);

    pq.HMAC_SHA_256.digest(forged(5000, 2), forged(100000, 1));

    const pair = pq.ML_DSA_44.generateKeyPair();

    const options = { context: forged(1000, 1) };

    const signature = pair.privateKey.sign(forged(100000, 4), options);

    assert.ok(pair.publicKey.verify(signature, forged(100000, 4), options));

    const kem = pq.ML_KEM_512.generateKeyPair();

    throwsCode("INVALID_LENGTH", () => kem.privateKey.decapsulate(forged(5000, 767)));

    assert.equal(kem.privateKey.decapsulate(forged(5000, 768)).length, 32);

    const hss = hazmat.generateStatefulKeyPair(pq.HSS_LMS, random(40), {
      parameters: H5,
      stateStore: new MemoryStore(),
    });

    assert.ok(hss.publicKey.verify(hss.privateKey.sign(forged(100000, 2)), forged(100000, 2)));

    assert.ok(FAMILIES.every((family) => family.core().live));

    assert.equal(toHex(pq.SHA_256.digest(abc)), expected);
  });
});

// Many keys and operations leave linear memory where the first ones put it; the JS heap returns to
// its size; a message larger than the I/O block is given its own block, and an instance grown past
// 32 MiB by one is replaced afterwards.
test("memory stays bounded", (t) => {
  const report = child("memory", "wasm") as Record<string, number[] | number>;

  t.diagnostic(JSON.stringify(report));

  const pages = report.pages as number[];

  const after = report.after as number[];

  assert.deepEqual(after, pages);

  assert.ok((report.heap as number) < 4 << 20, `the heap grew by ${report.heap} bytes`);

  assert.equal(report.signers, report.signer, "stateful signers were not freed");

  assert.ok((report.large as number) > 512 && (report.replaced as number) <= 4, "the large message's memory was kept");

  assert.equal(report.live, false);
});

// The first use of each family in a fresh process, from deciding its backend to the end of its
// first operation.
test("first-call latency", (t) => {
  for (const backend of ["wasm", "js"]) {
    for (const family of ["ML-KEM", "ML-DSA", "SLH-DSA", "stateful", "hash"]) {
      const {
        backend: chosen,
        load,
        first,
        result,
      } = child("latency", backend, family) as {
        backend: string;
        load: number;
        first: number;
        result: boolean;
      };

      assert.deepEqual([chosen, result], [backend, true]);

      t.diagnostic(`${backend} ${family}: load ${load.toFixed(1)} ms, first operation ${first.toFixed(1)} ms`);
    }
  }
});

// A random source may itself call the library, even the instance that asked it for bytes, and grow
// that instance's memory before it writes them.
test("a random source that calls the library", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto") as PropertyDescriptor;

  const source = globalThis.crypto;

  try {
    Object.defineProperty(globalThis, "crypto", {
      value: {
        getRandomValues(array: Uint8Array) {
          pq.HMAC_SHA_256.digest(new Uint8Array(2 << 20), Uint8Array.of(1));

          hazmat.generateKeyPair(pq.ML_KEM_512, new Uint8Array(64));

          return source.getRandomValues(array);
        },
      },
      configurable: true,
    });

    onWasm(() => {
      for (const algorithm of [pq.X_WING, pq.ML_KEM_768]) {
        const pair = algorithm.generateKeyPair();

        const { sharedSecret, ciphertext } = pair.publicKey.encapsulate();

        assert.deepEqual(pair.privateKey.decapsulate(ciphertext), sharedSecret, algorithm.name);
      }

      const pair = pq.ML_DSA_44.generateKeyPair();

      assert.ok(pair.publicKey.verify(pair.privateKey.sign(Uint8Array.of(1)), Uint8Array.of(1)));
    });
  } finally {
    Object.defineProperty(globalThis, "crypto", original);
  }
});

// A stateful signer holds its seed in WebAssembly memory while its key lives, and its trees are
// freed and wiped once the key has been garbage collected and the finalizer has run.
test("collected stateful keys free their signers", () => {
  assert.deepEqual(child("finalize", "wasm"), { held: true, freed: true, pair: null });
});
