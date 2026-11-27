import { readFileSync } from "node:fs";

import { instantiate } from "./host.mjs";

const path = new URL("target/wasm32-wasip1/release/crypto_pq_wasm_example.wasm", import.meta.url);

const bytes = readFileSync(path);

let failures = 0;

function check(ok, what) {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);

  if (!ok) failures += 1;
}

const module = await instantiate(bytes);

check(module.ml_kem_768_round_trip() === 0, "ML-KEM-768 generates, encapsulates, decapsulates");

check(module.ml_dsa_65_round_trip() === 0, "ML-DSA-65 generates, signs hedged, verifies");

Object.defineProperty(crypto, "getRandomValues", {
  configurable: true,
  value: () => {
    throw new Error("no randomness");
  },
});

const failing = await instantiate(bytes);

const rng = failing.rng_failure_code();

check(failing.ml_kem_768_round_trip() === rng, "ML-KEM-768 without randomness: RngFailure");

check(failing.ml_dsa_65_round_trip() === rng, "ML-DSA-65 without randomness: RngFailure");

delete crypto.getRandomValues;

check(failing.ml_kem_768_round_trip() === 0, "the same instance recovers once randomness is back");

process.exit(failures === 0 ? 0 : 1);
