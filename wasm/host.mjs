// A host for a wasm32-wasip1 module that uses crypto-pq, in browsers and Node.js. crypto-pq
// imports random_get alone, filled here from crypto.getRandomValues. Rust's std imports others,
// which change between Rust versions: the environment is empty here, proc_exit throws, and every
// other function returns ENOSYS (52). A pointer or a length arrives as a signed 32-bit number,
// hence the `>>> 0`.
export async function instantiate(bytes) {
  let memory;

  const wasi = {
    random_get(pointer, length) {
      try {
        const end = (pointer >>> 0) + (length >>> 0);

        for (let at = pointer >>> 0; at < end; at += 65536) {
          crypto.getRandomValues(new Uint8Array(memory.buffer, at, Math.min(65536, end - at)));
        }

        return 0;
      } catch {
        return 29;
      }
    },
    environ_get: () => 0,
    environ_sizes_get(count, size) {
      const view = new DataView(memory.buffer);

      view.setUint32(count >>> 0, 0, true);

      view.setUint32(size >>> 0, 0, true);

      return 0;
    },
    proc_exit(code) {
      throw new Error(`proc_exit(${code})`);
    },
  };

  const module = await WebAssembly.compile(bytes);

  for (const { module: from, name, kind } of WebAssembly.Module.imports(module)) {
    if (from === "wasi_snapshot_preview1" && kind === "function" && !Object.hasOwn(wasi, name)) {
      wasi[name] = () => 52;
    }
  }

  const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi });

  memory = instance.exports.memory;

  instance.exports._initialize?.();

  return instance.exports;
}
