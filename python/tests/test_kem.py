import threading
import unittest

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode, hazmat
from vectors import der, records, unhex

ALGORITHMS = {
    "ML-KEM-512": crypto_pq.ML_KEM_512,
    "ML-KEM-768": crypto_pq.ML_KEM_768,
    "ML-KEM-1024": crypto_pq.ML_KEM_1024,
}

OIDS = {name: der(0x06, bytes.fromhex("6086480165030404") + bytes([i + 1])) for i, name in enumerate(ALGORITHMS)}


def pkcs8(name, private_key):
    return der(0x30, der(0x02, b"\x00") + der(0x30, OIDS[name]) + der(0x04, private_key))


class MlKemTest(unittest.TestCase):
    def assertCode(self, code, function, *args):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args)

        self.assertEqual(caught.exception.code, code)

    def test_acvp_key_generation(self):
        for header, record in records("acvp/ML-KEM-keyGen.txt", "dk"):
            with self.subTest(tcId=record["tcId"]):
                name = header["parameterSet"]

                algorithm = ALGORITHMS[name]

                seed = unhex(record["d"]) + unhex(record["z"])

                ek, dk = unhex(record["ek"]), unhex(record["dk"])

                pair = hazmat.generate_key_pair(algorithm, seed)

                self.assertEqual(pair.public_key.export_key("raw"), ek)

                self.assertEqual(pair.private_key.export_key("raw"), seed)

                expanded = algorithm.import_private_key(dk, "raw")

                self.assertEqual(expanded.public_key.export_key("raw"), ek)

                self.assertEqual(expanded.export_key("raw"), dk)

                both = pkcs8(name, der(0x30, der(0x04, seed) + der(0x04, dk)))

                self.assertEqual(algorithm.import_private_key(both, "der").export_key("raw"), seed)

    def test_acvp_encapsulation_and_decapsulation(self):
        for header, record in records("acvp/ML-KEM-encapDecap.txt", "tcId"):
            with self.subTest(tcId=record["tcId"], function=header["function"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                function = header["function"]

                if function == "encapsulation":
                    public_key = algorithm.import_public_key(unhex(record["ek"]), "raw")

                    result = hazmat.encapsulate(public_key, unhex(record["m"]))

                    self.assertEqual(result.ciphertext, unhex(record["c"]))

                    self.assertEqual(result.shared_secret, unhex(record["k"]))
                elif function == "decapsulation":
                    if header["keyFormat"] == "seed":
                        seed = unhex(record["d"]) + unhex(record["z"])

                        private_key = hazmat.generate_key_pair(algorithm, seed).private_key
                    else:
                        private_key = algorithm.import_private_key(unhex(record["dk"]), "raw")

                    self.assertEqual(private_key.decapsulate(unhex(record["c"])), unhex(record["k"]))
                elif function == "encapsulationKeyCheck":
                    self.check_import(algorithm.import_public_key, unhex(record["ek"]), record["testPassed"])
                else:
                    self.check_import(algorithm.import_private_key, unhex(record["dk"]), record["testPassed"])

    def check_import(self, function, data, passed):
        if passed == "true":
            function(data, "raw")
        else:
            with self.assertRaises(CryptoPQError):
                function(data, "raw")

    def test_wycheproof_decapsulation(self):
        for header, record in records("wycheproof/mlkem.txt", "tcId"):
            with self.subTest(tcId=record["tcId"], parameterSet=header["parameterSet"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                seed, c = unhex(record["seed"]), unhex(record["c"])

                if record["result"] == "valid":
                    pair = hazmat.generate_key_pair(algorithm, seed)

                    self.assertEqual(pair.public_key.export_key("raw"), unhex(record["ek"]))

                    self.assertEqual(pair.private_key.decapsulate(c), unhex(record["K"]))
                elif len(seed) != 64:
                    self.assertCode(ErrorCode.INVALID_LENGTH, hazmat.generate_key_pair, algorithm, seed)
                else:
                    private_key = hazmat.generate_key_pair(algorithm, seed).private_key

                    self.assertCode(ErrorCode.INVALID_LENGTH, private_key.decapsulate, c)

    def test_wycheproof_encapsulation(self):
        for header, record in records("wycheproof/mlkem_encaps.txt", "tcId"):
            with self.subTest(tcId=record["tcId"], parameterSet=header["parameterSet"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                ek = unhex(record["ek"])

                if record["result"] == "valid":
                    result = hazmat.encapsulate(algorithm.import_public_key(ek, "raw"), unhex(record["m"]))

                    self.assertEqual(result.ciphertext, unhex(record["c"]))

                    self.assertEqual(result.shared_secret, unhex(record["K"]))
                else:
                    code = ErrorCode.INVALID_LENGTH if len(ek) != algorithm.public_key_size else ErrorCode.INVALID_PUBLIC_KEY

                    self.assertCode(code, algorithm.import_public_key, ek, "raw")

    def test_wycheproof_expanded_decapsulation(self):
        for header, record in records("wycheproof/mlkem_semi_expanded_decaps.txt", "tcId"):
            with self.subTest(tcId=record["tcId"], parameterSet=header["parameterSet"]):
                algorithm = ALGORITHMS[header["parameterSet"]]

                dk, c = unhex(record["dk"]), unhex(record["c"])

                flags = record.get("flags", "")

                if record["result"] == "valid":
                    private_key = algorithm.import_private_key(dk, "raw")

                    self.assertEqual(private_key.public_key.export_key("raw"), unhex(record["ek"]))

                    self.assertEqual(private_key.decapsulate(c), unhex(record["K"]))
                elif "IncorrectCiphertextLength" in flags:
                    self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.import_private_key(dk, "raw").decapsulate, c)
                elif "IncorrectDecapsulationKeyLength" in flags:
                    self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.import_private_key, dk, "raw")
                else:
                    self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, algorithm.import_private_key, dk, "raw")


class KemApiTest(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args, **kwargs)

        self.assertEqual(caught.exception.code, code)

    def test_round_trip(self):
        for algorithm in (*ALGORITHMS.values(), crypto_pq.X_WING):
            with self.subTest(algorithm=algorithm.name):
                pair = algorithm.generate_key_pair()

                encapsulation = pair.public_key.encapsulate()

                self.assertEqual(len(encapsulation.ciphertext), algorithm.ciphertext_size)

                self.assertEqual(len(encapsulation.shared_secret), algorithm.shared_secret_size)

                self.assertEqual(pair.private_key.decapsulate(encapsulation.ciphertext), encapsulation.shared_secret)

                tampered = bytearray(encapsulation.ciphertext)

                tampered[0] ^= 1

                self.assertNotEqual(pair.private_key.decapsulate(tampered), encapsulation.shared_secret)

                self.assertCode(ErrorCode.INVALID_LENGTH, pair.private_key.decapsulate, encapsulation.ciphertext[:-1])

                self.assertEqual(len(pair.public_key.export_key("raw")), algorithm.public_key_size)

                self.assertEqual(algorithm.generate_key_pair(self_test=False).public_key.algorithm, algorithm)

                self.assertCode(ErrorCode.INVALID_OPTION, algorithm.generate_key_pair, self_test=1)

    # A key keeps what its operations derive from it: using it again, through the public key of
    # its private key, or from several threads at its first use gives what fresh keys give.
    def test_reused_keys(self):
        for algorithm in (*ALGORITHMS.values(), crypto_pq.X_WING):
            with self.subTest(algorithm=algorithm.name):
                pair = hazmat.generate_key_pair(algorithm, bytes(range(algorithm._backend.seed_size)))

                public, private = pair.public_key.export_key("raw"), pair.private_key.export_key("raw")

                randomness = [bytes([i]) * algorithm._backend.randomness_size for i in range(3)]

                expected = [hazmat.encapsulate(algorithm.import_public_key(public, "raw"), r) for r in randomness]

                secrets = [algorithm.import_private_key(private, "raw").decapsulate(e.ciphertext) for e in expected]

                self.assertEqual(secrets, [e.shared_secret for e in expected])

                for key in (algorithm.import_public_key(public, "raw"), pair.private_key.public_key):
                    for _ in range(2):
                        self.assertEqual([hazmat.encapsulate(key, r) for r in randomness], expected)

                key = algorithm.import_private_key(private, "raw")

                for _ in range(2):
                    self.assertEqual([key.decapsulate(e.ciphertext) for e in expected], secrets)

                public_key, private_key = algorithm.import_public_key(public, "raw"), algorithm.import_private_key(private, "raw")

                barrier = threading.Barrier(4)

                results = [None] * 4

                def work(index):
                    barrier.wait()

                    encapsulation = hazmat.encapsulate(public_key, randomness[index % 3])

                    results[index] = (encapsulation, private_key.decapsulate(encapsulation.ciphertext))

                threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]

                for thread in threads:
                    thread.start()

                for thread in threads:
                    thread.join()

                self.assertEqual(results, [(expected[i % 3], secrets[i % 3]) for i in range(4)])

    def test_formats(self):
        for algorithm in ALGORITHMS.values():
            with self.subTest(algorithm=algorithm.name):
                pair = algorithm.generate_key_pair()

                for format in ("raw", "der", "pem"):
                    public = algorithm.import_public_key(pair.public_key.export_key(format), format)

                    self.assertEqual(public, pair.public_key)

                    private = algorithm.import_private_key(pair.private_key.export_key(format), format)

                    self.assertEqual(private.public_key, pair.public_key)

                pem = pair.public_key.export_key("pem")

                self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----\n"))

                self.assertEqual(algorithm.import_public_key(pem.decode(), "pem"), pair.public_key)

                self.assertTrue(pair.private_key.export_key("pem").startswith(b"-----BEGIN PRIVATE KEY-----\n"))

                self.assertEqual(pair.private_key.export_key("der")[-66:-64], b"\x80\x40")

                self.assertCode(ErrorCode.INVALID_OPTION, pair.public_key.export_key, "jwk")

                self.assertCode(ErrorCode.INVALID_ENCODING, algorithm.import_public_key, pair.public_key.export_key("der") + b"\x00", "der")

                self.assertCode(ErrorCode.INVALID_ENCODING, algorithm.import_public_key, pair.private_key.export_key("pem"), "pem")

                self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.import_private_key, b"\x00" * 63, "raw")

                short = der(0x30, der(0x30, OIDS[algorithm.name]) + der(0x03, b"\x00" + pair.public_key.export_key("raw")[:-1]))

                self.assertCode(ErrorCode.INVALID_ENCODING, algorithm.import_public_key, short, "der")

                self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.import_public_key, pair.public_key.export_key("raw")[:-1], "raw")

        pair = crypto_pq.ML_KEM_768.generate_key_pair()

        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, crypto_pq.ML_KEM_512.import_public_key, pair.public_key.export_key("der"), "der")

        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, crypto_pq.ML_KEM_1024.import_private_key, pair.private_key.export_key("pem"), "pem")

    def test_x_wing(self):
        for _, record in records("xwing/test-vectors.txt", "seed"):
            with self.subTest(seed=record["seed"][:16]):
                pair = hazmat.generate_key_pair(crypto_pq.X_WING, unhex(record["seed"]))

                self.assertEqual(pair.public_key.export_key("raw"), unhex(record["pk"]))

                self.assertEqual(pair.private_key.export_key("raw"), unhex(record["sk"]))

                result = hazmat.encapsulate(pair.public_key, unhex(record["eseed"]))

                self.assertEqual(result.ciphertext, unhex(record["ct"]))

                self.assertEqual(result.shared_secret, unhex(record["ss"]))

                self.assertEqual(pair.private_key.decapsulate(result.ciphertext), result.shared_secret)

        pair = crypto_pq.X_WING.generate_key_pair()

        for format in ("der", "pem"):
            self.assertCode(ErrorCode.UNSUPPORTED, pair.public_key.export_key, format)

            self.assertCode(ErrorCode.UNSUPPORTED, crypto_pq.X_WING.import_private_key, b"", format)

        self.assertEqual(crypto_pq.X_WING.import_private_key(pair.private_key.export_key("raw"), "raw").public_key, pair.public_key)


if __name__ == "__main__":
    unittest.main()
