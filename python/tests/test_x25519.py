import os
import unittest

from crypto_pq._x25519 import BASE, x25519
from vectors import records, unhex


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

                self.assertEqual(x25519(alice, BASE), unhex(record["alicePublic"]))

                self.assertEqual(x25519(bob, BASE), unhex(record["bobPublic"]))

                self.assertEqual(x25519(alice, unhex(record["bobPublic"])), unhex(record["shared"]))

                self.assertEqual(x25519(bob, unhex(record["alicePublic"])), unhex(record["shared"]))

    # Wycheproof marks low-order and twist points "acceptable"; X25519 itself is defined for them.
    def test_wycheproof(self):
        for _, record in records("wycheproof/x25519.txt", "tcId"):
            with self.subTest(tcId=record["tcId"]):
                self.assertEqual(x25519(unhex(record["private"]), unhex(record["public"])), unhex(record["shared"]))


if __name__ == "__main__":
    unittest.main()
