import { parentPort, workerData } from "node:worker_threads";

// The worker side of parallel(): runs one task per message and answers null or the failure.
const { module, check } = workerData as { module: string; check: string };

const checks = (await import(module)) as Record<string, (task: unknown) => unknown>;

const port = parentPort as NonNullable<typeof parentPort>;

port.on("message", async (task: unknown) => {
  try {
    await checks[check](task);

    port.postMessage(null);
  } catch (error) {
    port.postMessage(error instanceof Error ? (error.stack ?? error.message) : String(error));
  }
});
