import os
import random
import unittest

from crypto_pq._x25519 import BASE, x25519, x25519_base
from vectors import records, unhex

ORDER = 2**252 + 27742317777372353535851937790883648493


# Scalars for the fixed-base path: the extremes of clamping, every signed digit -8 (with a carry
# through all of them) or 7, alternating nibbles, and clamped values next to 4..7 times the group
# order, whose products lie next to the neutral point.
def edge_scalars():
    scalars = [bytes(32), b"\xff" * 32, b"\x78" + b"\x77" * 31, b"\x77" * 32, b"\x88" * 32, b"\xf0\x0f" * 16, b"\x0f\xf0" * 16]

    for multiple in range(4, 8):
        for offset in (-8, 0, 8):
            value = (multiple * ORDER & ~7) + offset

            scalars.append(value.to_bytes(32, "little"))

    return scalars


class X25519Test(unittest.TestCase):
    def test_rfc7748(self):
        for header, record in records("rfc/x25519.txt", "output"):
            kind = header["kind"]

            if kind == "multiply":
                self.assertEqual(x25519(unhex(record["scalar"]), unhex(record["u"])), unhex(record["output"]))
            elif kind == "iterate":
                count = int(record["iterations"])

                if count > 1000 and not os.environ.get("CRYPTO_PQ_SLOW"):
                    continue

                k = u = BASE

                for _ in range(count):
                    k, u = x25519(k, u), k

                self.assertEqual(k, unhex(record["output"]))
            elif kind == "exchange":
                alice, bob = unhex(record["alicePrivate"]), unhex(record["bobPrivate"])

                for function in (lambda scalar: x25519(scalar, BASE), x25519_base):
                    self.assertEqual(function(alice), unhex(record["alicePublic"]))

                    self.assertEqual(function(bob), unhex(record["bobPublic"]))

                self.assertEqual(x25519(alice, unhex(record["bobPublic"])), unhex(record["shared"]))

                self.assertEqual(x25519(bob, unhex(record["alicePublic"])), unhex(record["shared"]))

    # Wycheproof marks low-order and twist points "acceptable"; X25519 itself is defined for them.
    def test_wycheproof(self):
        for _, record in records("wycheproof/x25519.txt", "tcId"):
            with self.subTest(tcId=record["tcId"]):
                self.assertEqual(x25519(unhex(record["private"]), unhex(record["public"])), unhex(record["shared"]))

    # The fixed-base table must give the ladder's public key for every scalar.
    def test_fixed_base(self):
        rng = random.Random(20261004)

        count = 2000 if os.environ.get("CRYPTO_PQ_SLOW") else 200

        for scalar in [rng.randbytes(32) for _ in range(count)] + edge_scalars():
            with self.subTest(scalar=scalar.hex()):
                self.assertEqual(x25519_base(scalar), x25519(scalar, BASE))


if __name__ == "__main__":
    unittest.main()
