import os
import unittest

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode, hazmat
from test_mldsa import PRE_HASHES
from vectors import records, unhex

ALGORITHMS = {algorithm.name: algorithm for algorithm in (
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
)}

# An "s" key takes about a second and an "s" signature 5 to 15 seconds in pure Python, so by
# default every "f" vector runs, each "s" set builds one key and signs one message, and every
# set verifies. CRYPTO_PQ_SLOW=1 runs everything.
SLOW = bool(os.environ.get("CRYPTO_PQ_SLOW"))


def pre_hash(header, record):
    return None if header["preHash"] == "pure" else PRE_HASHES[record["hashAlg"]]


class SlhDsaTest(unittest.TestCase):
    def test_acvp_key_generation(self):
        seen = set()

        for header, record in records("acvp/SLH-DSA-keyGen.txt", "sk"):
            name = header["parameterSet"]

            if not SLOW and name.endswith("s") and name in seen:
                continue

            seen.add(name)

            with self.subTest(tcId=record["tcId"], parameterSet=name):
                algorithm = ALGORITHMS[name]

                seed = unhex(record["skSeed"]) + unhex(record["skPrf"]) + unhex(record["pkSeed"])

                pair = hazmat.generate_key_pair(algorithm, seed)

                self.assertEqual(pair.public_key.export_key("raw"), unhex(record["pk"]))

                self.assertEqual(pair.private_key.export_key("raw"), unhex(record["sk"]))

                imported = algorithm.import_private_key(unhex(record["sk"]), "raw")

                self.assertEqual(imported.public_key, pair.public_key)

                corrupted = bytearray(unhex(record["sk"]))

                corrupted[-1] ^= 1

                with self.assertRaises(CryptoPQError) as caught:
                    algorithm.import_private_key(bytes(corrupted), "raw")

                self.assertEqual(caught.exception.code, ErrorCode.INVALID_PRIVATE_KEY)

    def test_acvp_signature_generation(self):
        seen = set()

        for header, record in records("acvp/SLH-DSA-sigGen.txt", "signature"):
            name = header["parameterSet"]

            if not SLOW and name.endswith("s") and name in seen:
                continue

            seen.add(name)

            with self.subTest(tcId=record["tcId"], parameterSet=name):
                algorithm = ALGORITHMS[name]

                sk = unhex(record["sk"])

                private_key = algorithm.import_private_key(sk, "raw")

                n = len(sk) // 4

                randomness = sk[2 * n : 3 * n] if header["deterministic"] == "true" else unhex(record["additionalRandomness"])

                message, context = unhex(record["message"]), unhex(record["context"])

                signature = hazmat.sign(private_key, message, randomness, context=context, pre_hash=pre_hash(header, record))

                self.assertEqual(signature, unhex(record["signature"]))

    def test_acvp_signature_verification(self):
        for header, record in records("acvp/SLH-DSA-sigVer.txt", "signature"):
            with self.subTest(tcId=record["tcId"], reason=record["reason"]):
                public_key = ALGORITHMS[header["parameterSet"]].import_public_key(unhex(record["pk"]), "raw")

                result = hazmat.verify(
                    public_key,
                    unhex(record["signature"]),
                    unhex(record["message"]),
                    context=unhex(record["context"]),
                    pre_hash=pre_hash(header, record),
                )

                self.assertEqual(result, record["testPassed"] == "true")

    def test_round_trip(self):
        algorithm = crypto_pq.SLH_DSA_SHAKE_128F

        pair = algorithm.generate_key_pair(self_test=False)

        signature = pair.private_key.sign(b"message", context=b"context", deterministic=True)

        self.assertTrue(pair.public_key.verify(signature, b"message", context=b"context"))

        self.assertFalse(pair.public_key.verify(signature, b"message"))

        self.assertFalse(pair.public_key.verify(signature[:-1], b"message", context=b"context"))

        for format in ("raw", "der", "pem"):
            self.assertEqual(algorithm.import_public_key(pair.public_key.export_key(format), format), pair.public_key)

            private_key = algorithm.import_private_key(pair.private_key.export_key(format), format)

            self.assertEqual(private_key.export_key("raw"), pair.private_key.export_key("raw"))

        self.assertEqual(len(pair.private_key.export_key("raw")), 64)

        with self.assertRaises(CryptoPQError) as caught:
            pair.private_key.sign(b"m", pre_hash=crypto_pq.SHA_224)

        self.assertEqual(caught.exception.code, ErrorCode.INVALID_OPTION)

    # RFC 9909, Appendix C: an SLH-DSA-SHA2-128s private key in PKCS#8.
    def test_rfc9909_private_key(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N\n"
            "HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU\n"
            "-----END PRIVATE KEY-----\n"
        )

        private_key = crypto_pq.SLH_DSA_SHA2_128S.import_private_key(pem, "pem")

        self.assertEqual(private_key.export_key("pem").decode(), pem)


if __name__ == "__main__":
    unittest.main()
