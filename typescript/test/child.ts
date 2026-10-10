import { Buffer } from "node:buffer";
import process from "node:process";

// The scenarios of wasm.test.ts that need a fresh process: each changes the platform's
// WebAssembly before the library sees it, or measures a family from a cold start, and prints one
// line of JSON. Usage: node test/child.ts SCENARIO BACKEND [FAMILY].

const [scenario, backend, only] = process.argv.slice(2);

type Exports = Record<string, unknown>;

type Call = (...args: number[]) => number;

const api = WebAssembly as unknown as Record<string, unknown>;

const RealInstance = WebAssembly.Instance as unknown as new (module: unknown, imports: unknown) => { exports: Exports };

// An Instance whose exported functions pass through wrap first.
function wrapExports(wrap: (name: string, call: Call, exports: Exports) => Call): void {
  api.Instance = function (module: unknown, imports: unknown) {
    const { exports } = new RealInstance(module, imports);

    const wrapped: Exports = { memory: exports.memory };

    for (const [name, value] of Object.entries(exports)) {
      if (typeof value === "function") {
        wrapped[name] = wrap(name, value as Call, exports);
      }
    }

    return { exports: wrapped };
  };
}

function memory(exports: Exports): Uint8Array {
  return new Uint8Array((exports.memory as { buffer: ArrayBuffer }).buffer);
}

const compiled: number[] = [];

const calls: Record<string, number> = {};

const deepest: Record<string, number> = {};

let trap = false;

let full = false;

if (scenario === "no-webassembly") {
  delete (globalThis as { WebAssembly?: unknown }).WebAssembly;
} else if (scenario === "no-simd") {
  api.validate = () => false;
} else if (scenario === "module-throws") {
  api.Module = function () {
    throw new WebAssembly.CompileError("Refused to compile: 'wasm-unsafe-eval' is not an allowed source");
  };
} else if (scenario === "instance-throws") {
  api.Instance = function () {
    throw new WebAssembly.CompileError("Refused to instantiate: 'wasm-unsafe-eval' is not an allowed source");
  };
} else if (scenario === "self-test-fails") {
  // Key generation and hashing see their first input byte flipped, so that every known answer
  // differs.
  const inputs: Record<string, number> = {
    cpq_kem_keygen: 1,
    cpq_sig_keygen: 1,
    cpq_stateful_signer_create: 3,
    cpq_hash: 1,
  };

  wrapExports((name, call, exports) => (...args) => {
    if (name in inputs) {
      memory(exports)[args[inputs[name]]] ^= 1;
    }

    return call(...args);
  });
} else if (scenario === "abi-version") {
  wrapExports((name, call) => (name === "cpq_abi_version" ? () => 2 : call));
} else if (scenario === "trap") {
  wrapExports((name, call) => (...args) => {
    if (name === "cpq_kem_decapsulate" && trap) {
      trap = false;

      throw new WebAssembly.RuntimeError("unreachable");
    }

    return call(...args);
  });
} else if (scenario === "signer-memory") {
  // Once the family has loaded, the library has no room for another stateful signer.
  wrapExports((name, call) => (...args) => {
    const signer = name === "cpq_stateful_signer_create" || name === "cpq_stateful_signer_load";

    return full && signer ? 103 : call(...args);
  });
} else if (scenario === "caches") {
  wrapExports((name, call) => (...args) => {
    calls[name] = (calls[name] ?? 0) + 1;

    return call(...args);
  });
} else if (scenario === "count") {
  const RealModule = WebAssembly.Module as unknown as new (bytes: Uint8Array) => object;

  api.Module = function (bytes: Uint8Array) {
    compiled.push(bytes.length);

    return new RealModule(bytes);
  };
} else if (scenario === "stack") {
  // Paints the stack before every call and records how deep each export wrote into it.
  wrapExports((name, call, exports) => (...args) => {
    const low = (exports.cpq_stack_low as Call)() >>> 0;

    const high = (exports.cpq_stack_high as Call)() >>> 0;

    memory(exports).fill(0xa5, low, high);

    const result = call(...args);

    const after = memory(exports);

    let end = low;

    while (end < high && after[end] === 0xa5) {
      end++;
    }

    deepest[name] = Math.max(deepest[name] ?? 0, high - end);

    return result;
  });
}

const pq = await import("../src/index.ts");

const hazmat = await import("../src/hazmat.ts");

pq.setBackend(backend as pq.Backend);

class Store implements pq.StateStore {
  state: Uint8Array | null = null;

  read(): Uint8Array | null {
    return this.state;
  }

  update(_previous: Uint8Array | null, next: Uint8Array): boolean {
    this.state = next;

    return true;
  }
}

const H5: [string, string][] = [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"]];

function outcome(run: () => unknown): unknown {
  try {
    return run();
  } catch (error) {
    const { name, code, message, cause } = error as { name: string; code?: string; message: string; cause?: Error };

    return { error: code ?? name, message, cause: cause?.message };
  }
}

// Each family's algorithm and one operation that must work whatever the backend.
const FAMILIES: Record<string, [{ readonly backend: string }, () => unknown]> = {
  "ML-KEM": [
    pq.ML_KEM_768,
    () => {
      const pair = pq.ML_KEM_768.generateKeyPair();

      const { sharedSecret, ciphertext } = pair.publicKey.encapsulate();

      return pair.privateKey.decapsulate(ciphertext).every((b, i) => b === sharedSecret[i]);
    },
  ],
  "ML-DSA": [
    pq.ML_DSA_44,
    () => {
      const pair = pq.ML_DSA_44.generateKeyPair();

      return pair.publicKey.verify(pair.privateKey.sign(Uint8Array.of(1)), Uint8Array.of(1));
    },
  ],
  "SLH-DSA": [
    pq.SLH_DSA_SHAKE_128F,
    () => {
      const pair = pq.SLH_DSA_SHAKE_128F.generateKeyPair({ selfTest: false });

      return pair.publicKey.verify(pair.privateKey.sign(Uint8Array.of(1)), Uint8Array.of(1));
    },
  ],
  stateful: [
    pq.HSS_LMS,
    () => {
      const pair = pq.HSS_LMS.generateKeyPair({ parameters: H5, stateStore: new Store() });

      return pair.publicKey.verify(pair.privateKey.sign(Uint8Array.of(1)), Uint8Array.of(1));
    },
  ],
  hash: [pq.SHA3_256, () => pq.SHA3_256.digest(Uint8Array.of(0x61, 0x62, 0x63))[0] === 0x3a],
};

function exercise(): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(FAMILIES).map(([name, [algorithm, run]]) => [
      name,
      [outcome(() => algorithm.backend), outcome(run)],
    ]),
  );
}

let report: unknown;

if (scenario === "trap") {
  // A fault in the middle of a decapsulation: the call fails with an internal error, and the same
  // keys then work on a new instance.
  const pair = hazmat.generateKeyPair(pq.ML_KEM_768, new Uint8Array(64).fill(7));

  const { sharedSecret, ciphertext } = hazmat.encapsulate(pair.publicKey, new Uint8Array(32).fill(9));

  trap = true;

  const failed = outcome(() => pair.privateKey.decapsulate(ciphertext));

  const again = pair.privateKey.decapsulate(ciphertext);

  report = { failed, recovered: again.every((b, i) => b === sharedSecret[i]), families: exercise() };
} else if (scenario === "signer-memory") {
  const ready = pq.HSS_LMS.backend;

  const stored = new Store();

  pq.HSS_LMS.generateKeyPair({ parameters: H5, stateStore: stored });

  full = true;

  const message = Uint8Array.of(1, 2, 3);

  const created = outcome(() => {
    const pair = pq.HSS_LMS.generateKeyPair({ parameters: H5, stateStore: new Store() });

    return pair.publicKey.verify(pair.privateKey.sign(message), message);
  });

  const loaded = outcome(() => pq.HSS_LMS.loadPrivateKey(stored).sign(message).length);

  report = { ready, created, loaded, after: pq.HSS_LMS.backend };
} else if (scenario === "caches") {
  // Twenty uses of each key after its first: none may look at the slot's caches again, as the copy
  // holds them, filled at the address where every call places it.
  const kem = pq.ML_KEM_768.generateKeyPair();

  const signer = pq.ML_DSA_65.generateKeyPair();

  const message = Uint8Array.of(1);

  const signature = signer.privateKey.sign(message);

  const { ciphertext } = kem.publicKey.encapsulate();

  kem.privateKey.decapsulate(ciphertext);

  signer.publicKey.verify(signature, message);

  const before = calls.cpq_slot_info ?? 0;

  for (let i = 0; i < 20; i++) {
    kem.publicKey.encapsulate();

    kem.privateKey.decapsulate(ciphertext);

    signer.privateKey.sign(message);

    signer.publicKey.verify(signature, message);
  }

  report = { looked: (calls.cpq_slot_info ?? 0) - before };
} else if (scenario === "stack") {
  const store = new Store();

  for (const algorithm of [pq.ML_KEM_512, pq.ML_KEM_768, pq.ML_KEM_1024, pq.X_WING]) {
    const pair = algorithm.generateKeyPair();

    pair.privateKey.decapsulate(pair.publicKey.encapsulate().ciphertext);

    algorithm.importPrivateKey(pair.privateKey.exportKey("raw"), "raw");
  }

  for (const algorithm of [pq.ML_DSA_44, pq.ML_DSA_65, pq.ML_DSA_87, pq.SLH_DSA_SHA2_128F, pq.SLH_DSA_SHAKE_128F]) {
    const pair = algorithm.generateKeyPair();

    const options = { context: Uint8Array.of(1), preHash: pq.SHA3_512 };

    pair.publicKey.verify(pair.privateKey.sign(new Uint8Array(1000), options), new Uint8Array(1000), options);

    algorithm.importPrivateKey(pair.privateKey.exportKey("raw"), "raw");
  }

  const pair = pq.HSS_LMS.generateKeyPair({ parameters: [...H5, ...H5], stateStore: store });

  pair.publicKey.verify(pair.privateKey.sign(Uint8Array.of(1)), Uint8Array.of(1));

  pq.HSS_LMS.loadPrivateKey(store, { treeCache: pair.privateKey.exportTreeCache() }).sign(Uint8Array.of(2));

  const field = new Uint8Array(16).fill(1);

  const hashes = [
    pq.SHA_224,
    pq.SHA_256,
    pq.SHA_384,
    pq.SHA_512,
    pq.SHA_512_224,
    pq.SHA_512_256,
    pq.SHA3_224,
    pq.SHA3_256,
    pq.SHA3_384,
    pq.SHA3_512,
    pq.BLAKE2B_160,
    pq.BLAKE2B_512,
    pq.BLAKE2S_128,
    pq.BLAKE2S_256,
    pq.ASCON_HASH256,
    pq.BLAKE2B_512.configure({ salt: field, personalization: field }),
    pq.BLAKE2S_256.configure({ salt: field.subarray(8), personalization: field.subarray(8) }),
  ];

  const xofs = [
    pq.SHAKE128,
    pq.SHAKE256,
    pq.CSHAKE128,
    pq.CSHAKE256,
    pq.ASCON_XOF128,
    pq.ASCON_CXOF128,
    pq.CSHAKE256.configure({ customization: new Uint8Array(300) }),
    pq.ASCON_CXOF128.configure({ customization: new Uint8Array(256) }),
    hazmat.configureCshake(pq.CSHAKE128, new Uint8Array(200), new Uint8Array(200)),
  ];

  const macs = [
    pq.HMAC_SHA_224,
    pq.HMAC_SHA_256,
    pq.HMAC_SHA_384,
    pq.HMAC_SHA_512,
    pq.KMAC128,
    pq.KMAC256,
    pq.BLAKE2B_MAC,
    pq.BLAKE2S_MAC,
    pq.KMAC256.configure({ length: 300, customization: new Uint8Array(300), xof: true }),
    pq.BLAKE2B_MAC.configure({ length: 20, salt: field, personalization: field }),
    pq.BLAKE2S_MAC.configure({ length: 1, salt: field.subarray(8) }),
  ];

  for (const size of [0, 100, 5000, 70000]) {
    const data = new Uint8Array(size);

    for (const hash of hashes) {
      hash.create().update(data).digest();

      hash.digest(data);
    }

    for (const xof of xofs) {
      xof.create().update(data).read(size);

      xof.digest(data, 100);
    }

    for (const mac of macs) {
      const key = new Uint8Array(mac.name.startsWith("BLAKE2") ? 1 + (size % 32) : size % 300);

      const state = mac.create(key);

      state.update(data).verify(state.digest());

      mac.verify(key, data, mac.digest(key, data));
    }

    for (const kdf of [pq.HKDF_SHA_256, pq.HKDF_SHA_384, pq.HKDF_SHA_512]) {
      const prk = kdf.extract(data, { salt: data.subarray(0, 300) });

      kdf.expand(prk, 255 * kdf.prkSize, { info: data.subarray(0, 1000) });

      kdf.derive(data, 255 * kdf.prkSize, { salt: data, info: data });
    }
  }

  report = deepest;
} else if (scenario === "latency") {
  // The first use of one family in a fresh process: deciding its backend, which compiles its module
  // and runs its known-answer test, then its first operation.
  const [algorithm, run] = FAMILIES[only];

  const start = performance.now();

  const chosen = algorithm.backend;

  const loaded = performance.now();

  const result = run();

  report = { backend: chosen, load: loaded - start, first: performance.now() - loaded, result };
} else if (scenario === "memory" || scenario === "finalize") {
  const { ML_DSA, ML_KEM, SLH_DSA, STATEFUL_SIGNATURES, X_WING_HASH } = await import("../src/families.ts");

  const gc = (globalThis as unknown as { gc: () => void }).gc;

  const settle = async () => {
    for (let i = 0; i < 5; i++) {
      gc();

      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  };

  const families = [ML_KEM, ML_DSA, SLH_DSA, STATEFUL_SIGNATURES, X_WING_HASH];

  const pages = () => families.map((family) => family.select()!.bytes().length / 65536);

  const stateful = () => STATEFUL_SIGNATURES.select()!.bytes().length / 65536;

  const H10: [string, string][] = [["LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W1"]];

  if (scenario === "memory") {
    // Every family but the stateful one, which keeps its trees until a key is collected.
    const workload = () => {
      for (let i = 0; i < 100; i++) {
        for (const [name, [, run]] of Object.entries(FAMILIES)) {
          if (name !== "stateful" && (i % 20 === 0 || name === "ML-KEM" || name === "hash")) {
            run();
          }
        }

        const data = new Uint8Array(i * 37);

        pq.SHAKE128.create().update(data).read(i);

        pq.HMAC_SHA_512.create(data).update(data).digest();

        pq.X_WING.generateKeyPair();
      }
    };

    workload();

    await settle();

    const before = pages();

    const heapBefore = process.memoryUsage().heapUsed;

    for (let round = 0; round < 5; round++) {
      workload();
    }

    await settle();

    const heap = process.memoryUsage().heapUsed - heapBefore;

    const after = pages();

    // Stateful keys made and dropped one after another: their trees are freed and the memory reused.
    const keys = async (count: number) => {
      for (let i = 0; i < count; i++) {
        pq.HSS_LMS.generateKeyPair({ parameters: H10, stateStore: new Store() }).privateKey.sign(Uint8Array.of(i));

        await settle();
      }

      return stateful();
    };

    const signer = await keys(3);

    const signers = await keys(12);

    const old = ML_DSA.core();

    pq.ML_DSA_44.generateKeyPair().privateKey.sign(new Uint8Array(40 << 20));

    const large = old.bytes().length / 65536;

    const replaced = ML_DSA.core().bytes().length / 65536;

    report = { pages: before, after, heap, signer, signers, large, replaced, live: old.live };
  } else {
    const seed = crypto.getRandomValues(new Uint8Array(40));

    const secret = Buffer.from(seed.subarray(16));

    let pair: unknown = hazmat.generateStatefulKeyPair(pq.HSS_LMS, seed.slice(), {
      parameters: H5,
      stateStore: new Store(),
    });

    const held = Buffer.from(STATEFUL_SIGNATURES.core().bytes()).indexOf(secret) >= 0;

    pair = null;

    await settle();

    const freed = Buffer.from(STATEFUL_SIGNATURES.core().bytes()).indexOf(secret) < 0;

    report = { held, freed, pair };
  }
} else {
  report = { families: exercise(), compiled };
}

console.log(JSON.stringify(report));
