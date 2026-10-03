import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";

const WORKER = new URL("./worker.ts", import.meta.url);

// Runs check(task) of a module for every task on worker threads, one per CPU: the complete SLH-DSA
// and XMSS vector suites take minutes on a single core. Every task runs; failures are reported
// together.
export async function parallel(module: URL, check: string, tasks: readonly unknown[]): Promise<void> {
  const queue = [...tasks];

  const failures: string[] = [];

  const size = Math.min(availableParallelism(), queue.length);

  await Promise.all(Array.from({ length: size }, () => drain(module, check, queue, failures)));

  if (failures.length > 0) {
    throw new Error(`${failures.length} of ${tasks.length} tasks failed:\n\n${failures.join("\n\n")}`);
  }
}

function drain(module: URL, check: string, queue: unknown[], failures: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER, { workerData: { module: module.href, check } });

    let finished = false;

    const next = () => {
      if (queue.length === 0) {
        finished = true;

        worker.terminate().then(() => resolve(), reject);
      } else {
        worker.postMessage(queue.shift());
      }
    };

    worker.on("message", (failure: string | null) => {
      if (failure !== null) {
        failures.push(failure);
      }

      next();
    });

    worker.once("error", reject);

    worker.once("exit", (code) => {
      if (!finished) {
        reject(new Error(`a worker stopped with exit code ${code}`));
      }
    });

    next();
  });
}
