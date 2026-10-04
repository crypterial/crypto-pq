import threading
import unittest

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode, hazmat
from vectors import der, records, unhex

ALGORITHMS = {
    "ML-DSA-44": crypto_pq.ML_DSA_44,
    "ML-DSA-65": crypto_pq.ML_DSA_65,
    "ML-DSA-87": crypto_pq.ML_DSA_87,
}

PRE_HASHES = {
    "SHA2-224": crypto_pq.SHA_224,
    "SHA2-256": crypto_pq.SHA_256,
    "SHA2-384": crypto_pq.SHA_384,
    "SHA2-512": crypto_pq.SHA_512,
    "SHA2-512/224": crypto_pq.SHA_512_224,
    "SHA2-512/256": crypto_pq.SHA_512_256,
    "SHA3-224": crypto_pq.SHA3_224,
    "SHA3-256": crypto_pq.SHA3_256,
    "SHA3-384": crypto_pq.SHA3_384,
    "SHA3-512": crypto_pq.SHA3_512,
    "SHAKE-128": crypto_pq.SHAKE128,
    "SHAKE-256": crypto_pq.SHAKE256,
}

OIDS = {name: der(0x06, bytes.fromhex("6086480165030403") + bytes([17 + i])) for i, name in enumerate(ALGORITHMS)}


def pkcs8(name, private_key):
    return der(0x30, der(0x02, b"\x00") + der(0x30, OIDS[name]) + der(0x04, private_key))


def pre_hash(header, record):
    return None if header["preHash"] == "pure" else PRE_HASHES[record["hashAlg"]]


class MlDsaTest(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args, **kwargs)

        self.assertEqual(caught.exception.code, code)

    def test_acvp_key_generation(self):
        for header, record in records("acvp/ML-DSA-keyGen.txt", "sk"):
            with self.subTest(tcId=record["tcId"]):
                name = header["parameterSet"]

                algorithm = ALGORITHMS[name]

                seed, pk, sk = unhex(record["seed"]), unhex(record["pk"]), unhex(record["sk"])

                pair = hazmat.generate_key_pair(algorithm, seed)

                self.assertEqual(pair.public_key.export_key("raw"), pk)

                self.assertEqual(pair.private_key.export_key("raw"), seed)

                expanded = algorithm.import_private_key(sk, "raw")

                self.assertEqual(expanded.public_key.export_key("raw"), pk)

                self.assertEqual(expanded.export_key("raw"), sk)

                both = pkcs8(name, der(0x30, der(0x04, seed) + der(0x04, sk)))

                self.assertEqual(algorithm.import_private_key(both, "der").export_key("raw"), seed)

                corrupted = bytearray(sk)

                corrupted[-1] ^= 1

                self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, algorithm.import_private_key, bytes(corrupted), "raw")

    def test_acvp_signature_generation(self):
        for header, record in records("acvp/ML-DSA-sigGen.txt", "signature"):
            with self.subTest(tcId=record["tcId"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                if header["keyFormat"] == "seed":
                    private_key = hazmat.generate_key_pair(algorithm, unhex(record["seed"])).private_key
                else:
                    private_key = algorithm.import_private_key(unhex(record["sk"]), "raw")

                self.assertEqual(private_key.public_key.export_key("raw"), unhex(record["pk"]))

                randomness = bytes(32) if header["deterministic"] == "true" else unhex(record["rnd"])

                message, context = unhex(record["message"]), unhex(record["context"])

                signature = hazmat.sign(private_key, message, randomness, context=context, pre_hash=pre_hash(header, record))

                self.assertEqual(signature, unhex(record["signature"]))

                self.assertTrue(hazmat.verify(private_key.public_key, signature, message, context=context, pre_hash=pre_hash(header, record)))

    def test_acvp_signature_verification(self):
        for header, record in records("acvp/ML-DSA-sigVer.txt", "signature"):
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

    def test_wycheproof_verification(self):
        for header, record in records("wycheproof/mldsa_verify.txt", "tcId"):
            with self.subTest(tcId=record["tcId"], parameterSet=header["parameterSet"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                key = unhex(header["publicKey"])

                if len(key) != algorithm.public_key_size:
                    self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.import_public_key, key, "raw")

                    continue

                public_key = algorithm.import_public_key(key, "raw")

                if header["publicKeyDer"]:
                    self.assertEqual(algorithm.import_public_key(unhex(header["publicKeyDer"]), "der"), public_key)

                context = unhex(record.get("ctx", ""))

                result = public_key.verify(unhex(record["sig"]), unhex(record["msg"]), context=context)

                self.assertEqual(result, record["result"] == "valid")

    def test_wycheproof_deterministic_signing(self):
        for header, record in records("wycheproof/mldsa_sign_seed.txt", "tcId"):
            if "msg" not in record:
                continue

            with self.subTest(tcId=record["tcId"], parameterSet=header["parameterSet"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                seed, context = unhex(header["privateSeed"]), unhex(record.get("ctx", ""))

                flags = record.get("flags", "")

                if "IncorrectPrivateKeyLength" in flags:
                    self.assertCode(ErrorCode.INVALID_LENGTH, hazmat.generate_key_pair, algorithm, seed)

                    continue

                if header["privateKeyPkcs8"]:
                    private_key = algorithm.import_private_key(unhex(header["privateKeyPkcs8"]), "der")
                else:
                    private_key = hazmat.generate_key_pair(algorithm, seed).private_key

                self.assertEqual(private_key.public_key.export_key("raw"), unhex(header["publicKey"]))

                if "InvalidContext" in flags:
                    self.assertCode(ErrorCode.INVALID_CONTEXT, private_key.sign, unhex(record["msg"]), context=context)
                elif "Randomized" in flags:
                    self.assertTrue(private_key.public_key.verify(unhex(record["sig"]), unhex(record["msg"]), context=context))
                else:
                    signature = private_key.sign(unhex(record["msg"]), context=context, deterministic=True)

                    self.assertEqual(signature, unhex(record["sig"]))


class SignatureApiTest(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args, **kwargs)

        self.assertEqual(caught.exception.code, code)

    # A key keeps what its operations derive from it: using it again, through the public key of
    # its private key, or from several threads at its first use gives what fresh keys give.
    def test_reused_keys(self):
        for algorithm in ALGORITHMS.values():
            with self.subTest(algorithm=algorithm.name):
                pair = hazmat.generate_key_pair(algorithm, bytes(range(32)))

                public, private = pair.public_key.export_key("raw"), pair.private_key._private

                messages = [bytes([i]) * 10 for i in range(3)]

                expected = [algorithm.import_private_key(private, "raw").sign(m, deterministic=True) for m in messages]

                for key in (algorithm.import_private_key(private, "raw"), pair.private_key):
                    for _ in range(2):
                        self.assertEqual([key.sign(m, deterministic=True) for m in messages], expected)

                for key in (algorithm.import_public_key(public, "raw"), pair.private_key.public_key):
                    for _ in range(2):
                        self.assertTrue(all(key.verify(sig, m) for sig, m in zip(expected, messages)))

                        self.assertFalse(key.verify(expected[0], messages[1]))

                public_key, private_key = algorithm.import_public_key(public, "raw"), algorithm.import_private_key(private, "raw")

                barrier = threading.Barrier(3)

                results = [None] * 3

                def work(index):
                    barrier.wait()

                    signature = private_key.sign(messages[index], deterministic=True)

                    results[index] = (signature, public_key.verify(signature, messages[index]))

                threads = [threading.Thread(target=work, args=(i,)) for i in range(3)]

                for thread in threads:
                    thread.start()

                for thread in threads:
                    thread.join()

                self.assertEqual(results, [(sig, True) for sig in expected])

    def test_round_trip(self):
        for algorithm in ALGORITHMS.values():
            with self.subTest(algorithm=algorithm.name):
                pair = algorithm.generate_key_pair()

                message = b"message"

                signature = pair.private_key.sign(message, context=b"context")

                self.assertEqual(len(signature), algorithm.signature_size)

                self.assertTrue(pair.public_key.verify(signature, message, context=b"context"))

                self.assertFalse(pair.public_key.verify(signature, message))

                self.assertFalse(pair.public_key.verify(signature, b"other", context=b"context"))

                self.assertFalse(pair.public_key.verify(signature[:-1], message, context=b"context"))

                self.assertFalse(pair.public_key.verify(signature, message, context=bytes(256)))

                self.assertCode(ErrorCode.INVALID_CONTEXT, pair.private_key.sign, message, context=bytes(256))

                deterministic = pair.private_key.sign(message, deterministic=True)

                self.assertEqual(deterministic, pair.private_key.sign(message, deterministic=True))

                self.assertNotEqual(pair.private_key.sign(message), pair.private_key.sign(message))

                hashed = pair.private_key.sign(message, pre_hash=crypto_pq.SHA_512)

                self.assertTrue(pair.public_key.verify(hashed, message, pre_hash=crypto_pq.SHA_512))

                self.assertFalse(pair.public_key.verify(hashed, message))

                self.assertCode(ErrorCode.INVALID_OPTION, pair.private_key.sign, message, pre_hash=crypto_pq.SHA_224)

                self.assertCode(ErrorCode.INVALID_OPTION, pair.public_key.verify, hashed, message, pre_hash="SHA-512")

                self.assertCode(ErrorCode.INVALID_OPTION, pair.private_key.sign, message, deterministic=1)

    def test_pre_hash_strength(self):
        allowed = {
            "ML-DSA-44": {"SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/256", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256"},
            "ML-DSA-65": {"SHA2-384", "SHA2-512", "SHA3-384", "SHA3-512", "SHAKE-256"},
            "ML-DSA-87": {"SHA2-512", "SHA3-512", "SHAKE-256"},
        }

        for name, algorithm in ALGORITHMS.items():
            private_key = hazmat.generate_key_pair(algorithm, bytes(32)).private_key

            for label, function in PRE_HASHES.items():
                with self.subTest(algorithm=name, pre_hash=label):
                    if label in allowed[name]:
                        signature = private_key.sign(b"m", pre_hash=function)

                        self.assertTrue(private_key.public_key.verify(signature, b"m", pre_hash=function))
                    else:
                        self.assertCode(ErrorCode.INVALID_OPTION, private_key.sign, b"m", pre_hash=function)

                        signature = hazmat.sign(private_key, b"m", bytes(32), pre_hash=function)

                        self.assertTrue(hazmat.verify(private_key.public_key, signature, b"m", pre_hash=function))

                        self.assertFalse(private_key.public_key.verify(signature, b"m", pre_hash=function))

    def test_formats(self):
        for name, algorithm in ALGORITHMS.items():
            with self.subTest(algorithm=name):
                pair = algorithm.generate_key_pair(self_test=False)

                for format in ("raw", "der", "pem"):
                    self.assertEqual(algorithm.import_public_key(pair.public_key.export_key(format), format), pair.public_key)

                    private = algorithm.import_private_key(pair.private_key.export_key(format), format)

                    self.assertEqual(private.export_key("raw"), pair.private_key.export_key("raw"))

                self.assertEqual(pair.private_key.export_key("der")[-34:-32], b"\x80\x20")

                expanded = hazmat.generate_key_pair(algorithm, pair.private_key.export_key("raw"))

                self.assertEqual(expanded.public_key, pair.public_key)

                other = crypto_pq.ML_DSA_44 if algorithm is not crypto_pq.ML_DSA_44 else crypto_pq.ML_DSA_65

                self.assertCode(ErrorCode.ALGORITHM_MISMATCH, other.import_public_key, pair.public_key.export_key("der"), "der")

                self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.import_private_key, bytes(33), "raw")


if __name__ == "__main__":
    unittest.main()
