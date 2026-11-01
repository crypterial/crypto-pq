// Runs a wasm32-wasip1 program under the WASI of Node.js (node:wasi, preview1), with the given
// arguments and this process's environment, and exits with the program's exit code.
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";
import { argv, env, exit } from "node:process";

const [file, ...args] = argv.slice(2);

const wasi = new WASI({ version: "preview1", args: [file, ...args], env, returnOnExit: true });

const module = await WebAssembly.compile(await readFile(file));

const instance = await WebAssembly.instantiate(module, wasi.getImportObject());

exit(wasi.start(instance));
