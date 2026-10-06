import hashlib
import random
import unittest
from functools import partial
from unittest import mock

import crypto_pq
from crypto_pq import _mldsa, _mlkem, _primitives, _slhdsa, _xmss

# Lengths around the block sizes of SHA-256 (64), SHA-512 (128) and the Keccak rates (72 to 168).
LENGTHS = (0, 1, 55, 56, 63, 64, 65, 71, 72, 73, 103, 104, 111, 112, 127, 128, 129, 135, 136, 137, 143, 144, 167, 168, 169, 300, 1000)

SHAKES = ("shake_128", "shake_256")


# crypto-pq's own engines serve the pure algorithms wherever hashlib cannot and under the native
# backend; hashlib, a test-only oracle here, checks them.
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
    # The pure backend takes hashlib's constructors; the native backend never imports hashlib.
    def test_choice(self):
        for name, own in _primitives.OWN.items():
            with self.subTest(name=name):
                constructor = getattr(_primitives, name)

                if crypto_pq.BACKEND == "pure":
                    self.assertIn(constructor, _primitives._FROM_HASHLIB)

                    self.assertEqual(constructor(b"abc").digest(*((10,) if name in SHAKES else ())), hashlib.new(name, b"abc").digest(*((10,) if name in SHAKES else ())))
                else:
                    self.assertIs(constructor, own)

    # Where states copy and update slowly (hashlib on PyPy), the SHA-2 sets of SLH-DSA and the keyed
    # hashes of XMSS hash their whole inputs instead of continuing copies; both give the same values.
    def test_whole_inputs(self):
        for params in (_slhdsa.SHA2[1], _slhdsa.SHA2[3], _slhdsa.SHA2[5]):
            with self.subTest(params=params.name):
                n = params.n

                keys = bytes(range(n)), bytes(range(1, n + 1))

                copied, whole = _slhdsa._Sha2Hashes(params, *keys), _slhdsa._Sha2WholeHashes(params, *keys)

                head, value = copied.head(1, 2, 3), bytes(range(2, n + 2))

                adrs = head + bytes(12)

                for name in ("f", "h", "t"):
                    self.assertEqual(getattr(copied, name)(adrs, value), getattr(whole, name)(adrs, value))

                self.assertEqual(copied.prf(adrs), whole.prf(adrs))

                self.assertEqual(copied.chain(head + bytes(8), value, 3, 15), whole.chain(head + bytes(8), value, 3, 15))

                nodes = [bytes([i]) * n for i in range(8)]

                self.assertEqual(copied.parents(head + bytes(8), 5, nodes), whole.parents(head + bytes(8), 5, nodes))

        def slow():
            return mock.patch.object(_primitives, "copies_cheaply", lambda constructor: False)

        with slow():
            self.assertIsInstance(_slhdsa._hashes(_slhdsa.SHA2[1], bytes(16), bytes(16)), _slhdsa._Sha2WholeHashes)

        for name in ("XMSS-SHA2_10_256", "XMSS-SHA2_10_192", "XMSS-SHAKE256_10_256"):
            with self.subTest(name=name):
                params = _xmss.XMSS_SETS[name]

                keys = bytes(range(params.n)), bytes(range(1, params.n + 1))

                copied = _xmss._Hashes(params, *keys)

                with slow():
                    whole = _xmss._Hashes(params, *keys)

                self.assertIsNone(whole._prf_state)

                self.assertEqual(whole.prf(bytes(32)), copied.prf(bytes(32)))

                self.assertEqual(whole.prf_keygen(bytes(32)), copied.prf_keygen(bytes(32)))


# The provider's constructors replaced: hashlib's (an oracle in tests, whatever the backend), or
# crypto-pq's own engines.
def on_hashlib():
    return mock.patch.multiple(_primitives, **{name: getattr(hashlib, name, partial(hashlib.new, name)) for name in _primitives.OWN})


def on_own_engines():
    return mock.patch.multiple(_primitives, **_primitives.OWN)


# The pure algorithms give the same results on crypto-pq's own engines as on hashlib's.
class FallbackTest(unittest.TestCase):
    # Signing on the own engines takes seconds, so its parts are compared one by one: the FORS
    # signature and one layer of the hypertree signature.
    def test_slh_dsa(self):
        message = bytes([0, 0]) + b"message"

        for params in (_slhdsa.SHA2[1], _slhdsa.SHAKE[1]):
            with self.subTest(params=params.name):
                parts = []

                for provider in (on_hashlib, on_own_engines):
                    with provider():
                        sk, pk = _slhdsa.keygen_internal(bytes(16), bytes(range(16)), bytes(range(16, 32)), params)

                        hashes = _slhdsa._hashes(params, pk[:16], sk[:16])

                        parts.append((pk, _slhdsa.fors_sign(hashes, params, bytes(range(25)), 5, 3), _slhdsa.xmss_levels(hashes, params, 0, 5, bytes(16), 3)))

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
