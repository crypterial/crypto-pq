// The browser side of runner.ts, served as JavaScript: runs one operation per family with the
// backend the page's URL names, then, where WebAssembly is available, compares it with TypeScript on
// fixed inputs, and writes one line of JSON into <pre id="out">.
import * as hazmat from "/dist/hazmat.js";
import * as pq from "/dist/index.js";

interface Outcome {
  backend?: string;
  error?: string;
  load?: number;
  first?: number;
  ok?: boolean;
}

function range(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);
}

function hex(data: Uint8Array): string {
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

class Store {
  state: Uint8Array | null = null;

  read(): Uint8Array | null {
    return this.state;
  }

  update(_previous: Uint8Array | null, next: Uint8Array): boolean {
    this.state = next;

    return true;
  }
}

const H5 = [["LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"]];

const FAMILIES: Record<string, [{ readonly backend: string }, () => boolean]> = {
  "ML-KEM": [
    pq.ML_KEM_768,
    () => {
      const pair = pq.ML_KEM_768.generateKeyPair();

      const { sharedSecret, ciphertext } = pair.publicKey.encapsulate();

      return hex(pair.privateKey.decapsulate(ciphertext)) === hex(sharedSecret);
    },
  ],
  "ML-DSA": [
    pq.ML_DSA_65,
    () => {
      const pair = pq.ML_DSA_65.generateKeyPair();

      return pair.publicKey.verify(pair.privateKey.sign(range(10, 0)), range(10, 0));
    },
  ],
  "SLH-DSA": [
    pq.SLH_DSA_SHA2_128F,
    () => {
      const pair = pq.SLH_DSA_SHA2_128F.generateKeyPair({ selfTest: false });

      return pair.publicKey.verify(pair.privateKey.sign(range(10, 0)), range(10, 0));
    },
  ],
  stateful: [
    pq.HSS_LMS,
    () => {
      const pair = pq.HSS_LMS.generateKeyPair({ parameters: H5, stateStore: new Store() });

      return pair.publicKey.verify(pair.privateKey.sign(range(10, 0)), range(10, 0));
    },
  ],
  "X-Wing and hashes": [
    pq.X_WING,
    () => {
      const pair = pq.X_WING.generateKeyPair();

      const { sharedSecret, ciphertext } = pair.publicKey.encapsulate();

      return hex(pair.privateKey.decapsulate(ciphertext)) === hex(sharedSecret) && pq.SHA3_256.digest(range(3, 0x61))[0] === 0x3a;
    },
  ],
};

// Results on fixed inputs, which the two backends must give alike.
function fixed(): string[] {
  const kem = hazmat.generateKeyPair(pq.ML_KEM_768, range(64, 0));

  const xWing = hazmat.generateKeyPair(pq.X_WING, range(32, 0));

  const store = new Store();

  const hss = hazmat.generateStatefulKeyPair(pq.HSS_LMS, range(40, 0), { parameters: H5, stateStore: store });

  return [
    hex(hazmat.encapsulate(kem.publicKey, range(32, 64)).ciphertext.subarray(0, 64)),
    hex(hazmat.encapsulate(xWing.publicKey, range(64, 0)).sharedSecret),
    hex(hazmat.generateKeyPair(pq.ML_DSA_44, range(32, 0)).privateKey.sign(range(5, 0), { deterministic: true }).subarray(0, 64)),
    hex(hazmat.generateKeyPair(pq.SLH_DSA_SHAKE_128F, range(48, 0)).publicKey.exportKey("raw")),
    hex(hss.privateKey.sign(range(5, 0)).subarray(-32)),
    hex(pq.SHA_512.digest(range(1000, 0))),
    hex(pq.HMAC_SHA_256.digest(range(32, 0), range(100, 0))),
    hex(pq.SHAKE256.digest(range(200, 0), 64)),
  ];
}

const backend = (new URLSearchParams(location.search).get("backend") ?? "auto") as "auto" | "wasm" | "js";

const results: { backend: string; families: Record<string, Outcome>; agree?: boolean; error?: string } = {
  backend,
  families: {},
};

try {
  pq.setBackend(backend);

  for (const [name, [algorithm, run]] of Object.entries(FAMILIES)) {
    const outcome: Outcome = {};

    try {
      const start = performance.now();

      outcome.backend = algorithm.backend;

      const loaded = performance.now();

      outcome.ok = run();

      outcome.load = +(loaded - start).toFixed(2);

      outcome.first = +(performance.now() - loaded).toFixed(2);
    } catch (error) {
      const { name: kind, code } = error as { name: string; code?: string };

      outcome.error = code ?? kind;
    }

    results.families[name] = outcome;
  }

  if (Object.values(results.families).every((outcome) => outcome.backend === "wasm")) {
    pq.setBackend("js");

    const onJs = fixed();

    pq.setBackend("wasm");

    results.agree = fixed().join() === onJs.join();
  }
} catch (error) {
  results.error = String(error);
}

document.getElementById("out")!.textContent = JSON.stringify(results);
