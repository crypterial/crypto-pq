import process from "node:process";

import { type Backend, setBackend } from "../src/index.ts";

// The backend of a test run: CRYPTO_PQ_BACKEND=auto (the default), wasm or js. npm test loads this
// module with --import, so that every test file and worker thread starts with it.
export const BACKEND = (process.env.CRYPTO_PQ_BACKEND ?? "auto") as Backend;

setBackend(BACKEND);
