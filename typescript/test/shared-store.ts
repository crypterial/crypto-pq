import * as pq from "../src/index.ts";

// A state store in a SharedArrayBuffer, so that keys on several worker threads can share it, as
// processes share a file; robustness.test.ts runs signFromSharedStore on worker threads. Layout:
// a lock word, the state length, then the state, then one use counter per signature index.
const STATE = 8;

const MAX_STATE = 256;

export const COUNTERS = STATE + MAX_STATE;

export class SharedStore implements pq.StateStore {
  readonly #words: Int32Array;

  readonly #bytes: Uint8Array;

  constructor(buffer: SharedArrayBuffer) {
    this.#words = new Int32Array(buffer, 0, 2);

    this.#bytes = new Uint8Array(buffer, STATE, MAX_STATE);
  }

  #locked<T>(run: () => T): T {
    while (Atomics.compareExchange(this.#words, 0, 0, 1) !== 0) {
      Atomics.wait(this.#words, 0, 1, 1);
    }

    try {
      return run();
    } finally {
      Atomics.store(this.#words, 0, 0);

      Atomics.notify(this.#words, 0, 1);
    }
  }

  #state(): Uint8Array | null {
    const length = this.#words[1];

    return length === 0 ? null : this.#bytes.slice(0, length);
  }

  read(): Uint8Array | null {
    return this.#locked(() => this.#state());
  }

  update(previous: Uint8Array | null, next: Uint8Array): boolean {
    return this.#locked(() => {
      const state = this.#state();

      const same = state === null || previous === null ? state === previous : state.length === previous.length && state.every((byte, i) => byte === previous[i]);

      if (!same) {
        return false;
      }

      this.#bytes.set(next);

      this.#words[1] = next.length;

      return true;
    });
  }
}

// Loads the key from the shared store and signs until the key is exhausted, loading it again
// whenever another worker has used the stored index; counts every index it signs with.
export async function signFromSharedStore(buffer: SharedArrayBuffer): Promise<void> {
  const store = new SharedStore(buffer);

  const counters = new Int32Array(buffer, COUNTERS);

  let key = await pq.HSS_LMS.loadPrivateKey(store);

  for (;;) {
    try {
      const signature = await key.sign(Uint8Array.of(1));

      Atomics.add(counters, new DataView(signature.buffer).getUint32(4), 1);
    } catch (error) {
      if (!(error instanceof pq.CryptoPQError)) {
        throw error;
      }

      if (error.code === "KEY_EXHAUSTED") {
        return;
      }

      if (error.code !== "STATE_CONFLICT") {
        throw error;
      }

      key = await pq.HSS_LMS.loadPrivateKey(store);
    }
  }
}
