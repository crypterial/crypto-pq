import hashlib
import os
import random
import subprocess
import sys
import unittest
from functools import partial
from unittest import mock

import crypto_pq
from crypto_pq import _keccak, _lanes, _mldsa, _mlkem, _primitives, _sha2, _slhdsa

# Lengths around the block sizes of SHA-256 (64), SHA-512 (128) and the Keccak rates (72 to 168).
LENGTHS = (0, 1, 55, 56, 63, 64, 65, 71, 72, 73, 103, 104, 111, 112, 127, 128, 129, 135, 136, 137, 143, 144, 167, 168, 169, 300, 1000)

SHAKES = ("shake_128", "shake_256")


# crypto-pq's own engines serve every pure algorithm; hashlib, a test-only oracle here, checks them.
class OwnEngineTest(unittest.TestCase):
    def setUp(self):
        self.random = random.Random(20261006)

    def expected(self, name, data, length):
        oracle = hashlib.new(name, data)

        return oracle.digest(length) if name in SHAKES else oracle.digest()

    def test_one_shot(self):
        for name, own in _primitives.OWN.items():
            for length in LENGTHS:
                with self.subTest(name=name, length=length):
                    data = self.random.randbytes(length)

                    for size in (0, 1, 32, 167, 168, 169, 500) if name in SHAKES else (None,):
                        found = own(data).digest(size) if name in SHAKES else own(data).digest()

                        self.assertEqual(found, self.expected(name, data, size))

    # Updates in pieces, digests that leave the state as it was, and copies that go on alone.
    def test_incremental(self):
        for name, own in _primitives.OWN.items():
            with self.subTest(name=name):
                data = self.random.randbytes(700)

                state = own()

                offset = 0

                while offset < len(data):
                    size = self.random.randrange(1, 200)

                    state.update(data[offset : offset + size])

                    offset += size

                    if self.random.randrange(3) == 0:
                        copy = state.copy()

                        copy.update(b"extra")

                        self.assertEqual(self.digest(name, copy), self.expected(name, data[:offset] + b"extra", 100))

                    self.assertEqual(self.digest(name, state), self.expected(name, data[:offset], 100))

                self.assertEqual(self.digest(name, state), self.expected(name, data, 100))

    def digest(self, name, state):
        return state.digest(100) if name in SHAKES else state.digest()


class ProviderTest(unittest.TestCase):
    # The pure algorithms take crypto-pq's own engines, whatever the backend.
    def test_choice(self):
        for name, own in _primitives.OWN.items():
            with self.subTest(name=name):
                self.assertIs(getattr(_primitives, name), own)

    # The pure backend imports neither hashlib nor hmac: in a new process that uses every kind of
    # pure algorithm, neither module is loaded.
    def test_no_hashlib(self):
        code = (
            "import sys, crypto_pq\n"
            "from crypto_pq import hazmat\n"
            "assert crypto_pq.BACKEND == 'pure'\n"
            "for algorithm in (crypto_pq.SHA_256, crypto_pq.SHA3_256, crypto_pq.BLAKE2B_512, crypto_pq.BLAKE2S_256):\n"
            "    algorithm.digest(b'm')\n"
            "crypto_pq.SHAKE256.digest(b'm', 32)\n"
            "for algorithm in (crypto_pq.HMAC_SHA_256, crypto_pq.BLAKE2B_MAC, crypto_pq.KMAC128):\n"
            "    algorithm.verify(b'k', b'm', algorithm.digest(b'k', b'm'))\n"
            "crypto_pq.HKDF_SHA_256.derive(b'k', 32)\n"
            "hazmat.generate_key_pair(crypto_pq.ML_KEM_512, bytes(64))\n"
            "print(sorted({'hashlib', 'hmac', '_hashlib'} & set(sys.modules)))\n"
        )

        found = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, CRYPTO_PQ_BACKEND="pure"), capture_output=True, text=True, check=True)

        self.assertEqual(found.stdout.strip(), "[]")


# The lane engines give each lane the hash that hashlib gives its input, at lane counts that take
# one computation or several (more than 64 lanes, 32 for SHA-512).
class LanesTest(unittest.TestCase):
    COUNTS = (1, 2, 3, 17, 33, 64, 65, 130)

    def setUp(self):
        self.random = random.Random(20261010)

    def blocks(self, n, size):
        return [self.random.randbytes(size) for _ in range(n)]

    def test_join(self):
        for n in self.COUNTS:
            with self.subTest(n=n):
                state = _sha2.chain256(_sha2.IV_256, self.random.randbytes(64))

                blocks = self.blocks(n, 64)

                self.assertEqual(_lanes.sha256_join(state, b"".join(blocks), n), b"".join(_sha2.last256(state, block) for block in blocks))

                state = _sha2.chain512(_sha2.IV_512, self.random.randbytes(128))

                blocks = self.blocks(n, 128)

                self.assertEqual(_lanes.sha512_join(state, b"".join(blocks), n), b"".join(_sha2.last512(state, block) for block in blocks))

                for rate, name, size in ((136, "shake_256", 32), (168, "shake_128", 504), (136, "shake_256", 13)):
                    messages = self.blocks(n, rate - 2)

                    joined = b"".join(message + _keccak.shake_tail(rate, rate - 2) for message in messages)

                    self.assertEqual(_lanes.keccak_join(joined, n, rate, size), b"".join(hashlib.new(name, message).digest(size) for message in messages))

    def test_many(self):
        for n in self.COUNTS:
            for length in (0, 1, 55, 56, 64, 119, 135, 136, 167, 168, 300):
                with self.subTest(n=n, length=length):
                    messages = self.blocks(n, length)

                    prefix = self.random.randbytes(64)

                    state = _sha2.chain256(_sha2.IV_256, prefix)

                    self.assertEqual(_lanes.sha256_many(messages), [hashlib.sha256(message).digest() for message in messages])

                    self.assertEqual(_lanes.sha256_many(messages, state, 64), [hashlib.sha256(prefix + message).digest() for message in messages])

                    for rate, name, size in ((136, "shake_256", 24), (168, "shake_128", 170)):
                        self.assertEqual(_lanes.shake_many(rate, messages, size), [hashlib.new(name, message).digest(size) for message in messages])

    def test_one_block(self):
        for length in (0, 1, 133, 134, 135):
            message = self.random.randbytes(length)

            self.assertEqual(_keccak.one_block(message + _keccak.shake_tail(136, length), 136, 32), hashlib.shake_256(message).digest(32))


# The provider's constructors replaced: hashlib's (an oracle in tests, whatever the backend), or
# crypto-pq's own engines.
def on_hashlib():
    return mock.patch.multiple(_primitives, **{name: getattr(hashlib, name, partial(hashlib.new, name)) for name in _primitives.OWN})


def on_own_engines():
    return mock.patch.multiple(_primitives, **_primitives.OWN)


# The pure algorithms give the same results whether their single hashes run on crypto-pq's own
# engines or on hashlib's, a test-only oracle; their batched hashes run on the lane engines either
# way, which LanesTest checks.
class OracleTest(unittest.TestCase):
    # The parts of a signature are compared one by one: the FORS signature and one layer of the
    # hypertree signature.
    def test_slh_dsa(self):
        message = bytes([0, 0]) + b"message"

        for params in (_slhdsa.SHA2[1], _slhdsa.SHAKE[1]):
            with self.subTest(params=params.name):
                parts = []

                for provider in (on_hashlib, on_own_engines):
                    with provider():
                        sk, pk = _slhdsa.keygen_internal(bytes(16), bytes(range(16)), bytes(range(16, 32)), params)

                        hashes = _slhdsa._hashes(params, pk[:16], sk[:16])

                        fors, xmss = bytearray(params.k * (1 + params.a) * 16), bytearray((params.length + params.hp) * 16)

                        roots = _slhdsa.fors_sign(hashes, params, bytes(range(25)), 5, 3, fors, 0), _slhdsa.xmss_sign(hashes, params, 0, 5, bytes(16), 3, xmss, 0)

                        parts.append((pk, roots, fors, xmss))

                        if provider is on_hashlib:
                            signature = _slhdsa.sign_internal(message, sk, pk[:16], params)
                        else:
                            self.assertTrue(_slhdsa.verify_internal(message, signature, pk, params))

                self.assertEqual(parts[0], parts[1])

    def test_ml_kem(self):
        params = _mlkem.ML_KEM_512

        with on_hashlib():
            ek, dk = _mlkem.keygen_internal(bytes(32), bytes(range(32)), params)

            secret, c = _mlkem.encaps_internal(_mlkem.public_state(ek, params), bytes(32), params)

        with on_own_engines():
            self.assertEqual(_mlkem.keygen_internal(bytes(32), bytes(range(32)), params), (ek, dk))

            self.assertEqual(_mlkem.encaps_internal(_mlkem.public_state(ek, params), bytes(32), params), (secret, c))

            self.assertEqual(_mlkem.decaps_internal(_mlkem.private_state(dk, params), c, params), secret)

            self.assertNotEqual(_mlkem.decaps_internal(_mlkem.private_state(dk, params), bytes(len(c)), params), secret)

    def test_ml_dsa(self):
        params = _mldsa.ML_DSA_44

        with on_hashlib():
            pk, sk = _mldsa.keygen_internal(bytes(range(32)), params)

            signature = _mldsa.sign_internal(_mldsa.private_state(sk, pk, params), b"message", bytes(32), params)

        with on_own_engines():
            self.assertEqual(_mldsa.keygen_internal(bytes(range(32)), params), (pk, sk))

            self.assertEqual(_mldsa.sign_internal(_mldsa.private_state(sk, pk, params), b"message", bytes(32), params), signature)

            self.assertTrue(_mldsa.verify_internal(_mldsa.public_state(pk, params), b"message", signature, params))


if __name__ == "__main__":
    unittest.main()
