"""Benchmarks with the same case names as the other implementations.

Run from the python directory: PYTHONPATH=src python bench/bench.py [filter] [--all]
Each line is: name, iterations, microseconds per operation.
"""

import sys
import time

import crypto_pq
from crypto_pq import hazmat

MIN_TIME = 1.0

MESSAGES = [f"crypto-pq benchmark message {i}".encode() for i in range(16)]

# Cases whose single iteration takes more than about 30 seconds run only with --all.
SLOW = frozenset()


class MemoryStore:
    def __init__(self):
        self.state = None

    def read(self):
        return self.state

    def update(self, previous, next):
        if self.state != previous:
            return False

        self.state = next

        return True


def data(length):
    return bytes(i & 0xFF for i in range(length))


def timed(operation):
    def run(count):
        start = time.perf_counter()

        for i in range(count):
            operation(i)

        return time.perf_counter() - start

    return run


class Runner:
    def __init__(self, arguments):
        self.everything = "--all" in arguments

        self.filter = next((argument for argument in arguments if not argument.startswith("--")), "")

    def selects(self, name):
        return self.filter in name and (self.everything or name not in SLOW)

    # Batches stay multiples of the period, so that every timed batch covers whole cycles of work
    # that repeats: the 16 ML-DSA messages, or the lower tree that a stateful key rebuilds.
    def case(self, name, prepare, period=1):
        if not self.selects(name):
            return

        run = prepare()

        iterations = 0

        elapsed = 0.0

        count = period

        while elapsed < MIN_TIME:
            elapsed += run(count)

            iterations += count

            remaining = (MIN_TIME - elapsed) * iterations / elapsed if elapsed > 0 else 10 * iterations

            count = period * max(1, min(-(-int(remaining) // period), 10 * iterations // period))

        print(f"{name:<32}  {iterations:>9}  {elapsed * 1e6 / iterations:>14.3f}", flush=True)


def hashes(runner):
    short, long = data(64), data(1024)

    cases = (
        ("sha-256/64B", lambda i: crypto_pq.SHA_256.digest(short)),
        ("sha-256/1KiB", lambda i: crypto_pq.SHA_256.digest(long)),
        ("sha-512/1KiB", lambda i: crypto_pq.SHA_512.digest(long)),
        ("sha3-256/1KiB", lambda i: crypto_pq.SHA3_256.digest(long)),
        ("shake128/1KiB", lambda i: crypto_pq.SHAKE128.digest(long, 32)),
        ("shake256/1KiB", lambda i: crypto_pq.SHAKE256.digest(long, 64)),
    )

    for name, operation in cases:
        runner.case(name, lambda operation=operation: timed(operation))


def kem(runner, algorithm, seed_size, randomness_size):
    seed, randomness = data(seed_size), data(randomness_size)

    runner.case(f"{algorithm.name}/keygen", lambda: timed(lambda i: hazmat.generate_key_pair(algorithm, seed)))

    def encapsulate():
        pair = hazmat.generate_key_pair(algorithm, seed)

        return timed(lambda i: hazmat.encapsulate(pair.public_key, randomness))

    def decapsulate():
        pair = hazmat.generate_key_pair(algorithm, seed)

        ciphertext = hazmat.encapsulate(pair.public_key, randomness).ciphertext

        return timed(lambda i: pair.private_key.decapsulate(ciphertext))

    runner.case(f"{algorithm.name}/encaps", encapsulate)

    runner.case(f"{algorithm.name}/decaps", decapsulate)


# ML-DSA signs the 16 messages in turn, because the number of rejection rounds depends on the
# message; SLH-DSA costs the same for every message and signs one.
def signature(runner, algorithm, seed_size, rotate):
    seed = data(seed_size)

    period = len(MESSAGES) if rotate else 1

    runner.case(f"{algorithm.name}/keygen", lambda: timed(lambda i: hazmat.generate_key_pair(algorithm, seed)))

    def sign():
        private_key = hazmat.generate_key_pair(algorithm, seed).private_key

        return timed(lambda i: private_key.sign(MESSAGES[i % period], deterministic=True))

    def verify():
        pair = hazmat.generate_key_pair(algorithm, seed)

        signatures = [pair.private_key.sign(message, deterministic=True) for message in MESSAGES[:period]]

        def operation(i):
            if not pair.public_key.verify(signatures[i % period], MESSAGES[i % period]):
                raise AssertionError(f"{algorithm.name} rejected its own signature")

        return timed(operation)

    runner.case(f"{algorithm.name}/sign", sign, period)

    runner.case(f"{algorithm.name}/verify", verify, period)


# A key signs once outside the timed region, so that each timed cycle of `period` signatures
# rebuilds the lowest tree exactly once, and an exhausted key is replaced outside it as well.
def stateful(runner, name, algorithm, parameters, seed_size, period):
    seed = data(seed_size)

    def generate():
        return hazmat.generate_key_pair(algorithm, seed, parameters=parameters, state_store=MemoryStore())

    runner.case(f"{name}/keygen", lambda: timed(lambda i: generate()))

    def sign():
        key = None

        def run(count):
            nonlocal key

            elapsed = 0.0

            for i in range(count):
                if key is None or key.remaining_signatures() == 0:
                    key = generate().private_key

                    key.sign(MESSAGES[-1])

                message = MESSAGES[i % len(MESSAGES)]

                start = time.perf_counter()

                key.sign(message)

                elapsed += time.perf_counter() - start

            return elapsed

        return run

    def verify():
        pair = generate()

        signatures = [pair.private_key.sign(message) for message in MESSAGES]

        def operation(i):
            if not pair.public_key.verify(signatures[i % len(MESSAGES)], MESSAGES[i % len(MESSAGES)]):
                raise AssertionError(f"{name} rejected its own signature")

        return timed(operation)

    runner.case(f"{name}/sign", sign, period)

    runner.case(f"{name}/verify", verify)


def main(arguments):
    runner = Runner(arguments)

    hashes(runner)

    for algorithm in (crypto_pq.ML_KEM_512, crypto_pq.ML_KEM_768, crypto_pq.ML_KEM_1024):
        kem(runner, algorithm, 64, 32)

    kem(runner, crypto_pq.X_WING, 32, 64)

    for algorithm in (crypto_pq.ML_DSA_44, crypto_pq.ML_DSA_65, crypto_pq.ML_DSA_87):
        signature(runner, algorithm, 32, True)

    for algorithm in (
        crypto_pq.SLH_DSA_SHA2_128S,
        crypto_pq.SLH_DSA_SHA2_128F,
        crypto_pq.SLH_DSA_SHA2_192S,
        crypto_pq.SLH_DSA_SHA2_192F,
        crypto_pq.SLH_DSA_SHA2_256S,
        crypto_pq.SLH_DSA_SHA2_256F,
        crypto_pq.SLH_DSA_SHAKE_128S,
        crypto_pq.SLH_DSA_SHAKE_128F,
        crypto_pq.SLH_DSA_SHAKE_192S,
        crypto_pq.SLH_DSA_SHAKE_192F,
        crypto_pq.SLH_DSA_SHAKE_256S,
        crypto_pq.SLH_DSA_SHAKE_256F,
    ):
        signature(runner, algorithm, 3 * algorithm.public_key_size // 2, False)

    stateful(runner, "HSS-H10-W4", crypto_pq.HSS_LMS, [("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4")], 48, 1)

    stateful(runner, "HSS-H5H5-W8", crypto_pq.HSS_LMS, [("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")] * 2, 48, 32)

    stateful(runner, "XMSS-SHA2_10_256", crypto_pq.XMSS, "XMSS-SHA2_10_256", 96, 1)

    stateful(runner, "XMSSMT-SHA2_20/4_256", crypto_pq.XMSS_MT, "XMSSMT-SHA2_20/4_256", 96, 32)


if __name__ == "__main__":
    main(sys.argv[1:])
