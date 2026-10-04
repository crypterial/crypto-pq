import os
import unittest

import crypto_pq
from crypto_pq import CryptoPQError, KemAlgorithm, SignatureAlgorithm, hazmat
from test_mldsa import PRE_HASHES
from test_stateful import MemoryStore
from vectors import records, unhex

# Python builds an SLH-DSA "s" key in a second or more and signs with it in 5 to 15 seconds, signs
# with an "f" key in up to a second and a half, and spends seconds per XMSS tree of height 5 and
# ten per tree of height 10. By default "s" signatures are only verified, each "f" key signs
# again only its first message, and only the 20/4 XMSS^MT keys are rebuilt; CRYPTO_PQ_SLOW=1
# reproduces everything and reloads every stateful key.
SLOW = bool(os.environ.get("CRYPTO_PQ_SLOW"))

ALGORITHMS = {
    algorithm.name: algorithm
    for algorithm in (
        crypto_pq.ML_KEM_512,
        crypto_pq.ML_KEM_768,
        crypto_pq.ML_KEM_1024,
        crypto_pq.X_WING,
        crypto_pq.ML_DSA_44,
        crypto_pq.ML_DSA_65,
        crypto_pq.ML_DSA_87,
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
        crypto_pq.HSS_LMS,
        crypto_pq.XMSS,
        crypto_pq.XMSS_MT,
    )
}

ENCODINGS = (("der", "Der"), ("pem", "Pem"))


def pre_hash(name):
    return None if name == "none" else PRE_HASHES[name]


def parameters(record):
    if "parameters" in record:
        return record["parameters"]

    return list(zip(record["lms"].split(","), record["ots"].split(",")))


def slow_signer(algorithm):
    return algorithm.name.startswith("SLH-DSA") and algorithm.name.endswith("s") and not SLOW


def execute(algorithm, record, data):
    """Runs one record of cross/errors.txt, whose input is `data` (bytes, or str for PEM)."""

    def get(name):
        return unhex(record.get(name, ""))

    operation = record["operation"]

    context, function = get("context"), pre_hash(record.get("preHash", "none"))

    output, remaining = None, None

    try:
        if operation == "importPublicKey":
            output = algorithm.import_public_key(data, record["format"]).export_key("raw")
        elif operation == "importPrivateKey":
            output = algorithm.import_private_key(data, record["format"]).public_key.export_key("raw")
        elif operation == "exportPublicKey":
            output = hazmat.generate_key_pair(algorithm, get("key")).public_key.export_key(record["format"])
        elif operation == "exportPrivateKey":
            output = hazmat.generate_key_pair(algorithm, get("key")).private_key.export_key(record["format"])
        elif operation == "generate" and isinstance(algorithm, (KemAlgorithm, SignatureAlgorithm)):
            output = hazmat.generate_key_pair(algorithm, data).public_key.export_key("raw")
        elif operation == "generate":
            pair = hazmat.generate_key_pair(algorithm, data, parameters=parameters(record), state_store=MemoryStore(), index=int(record["index"]))

            output, remaining = pair.public_key.export_key("raw"), pair.private_key.remaining_signatures()
        elif operation == "encapsulate":
            encapsulation = hazmat.encapsulate(algorithm.import_public_key(get("key"), "raw"), get("randomness"))

            output = encapsulation.shared_secret + encapsulation.ciphertext
        elif operation == "decapsulate":
            output = algorithm.import_private_key(get("key"), "raw").decapsulate(data)
        elif operation == "sign" and isinstance(algorithm, SignatureAlgorithm):
            output = algorithm.import_private_key(get("key"), "raw").sign(get("message"), context=context, deterministic=True, pre_hash=function)
        elif operation == "sign":
            output = algorithm.load_private_key(MemoryStore(data)).sign(get("message"))
        elif operation == "hazmatSign":
            output = hazmat.sign(algorithm.import_private_key(get("key"), "raw"), get("message"), get("randomness"), context=context, pre_hash=function)
        elif operation == "verify" and isinstance(algorithm, SignatureAlgorithm):
            return str(algorithm.import_public_key(get("key"), "raw").verify(data, get("message"), context=context, pre_hash=function)).lower(), None, None
        elif operation == "verify":
            return str(algorithm.import_public_key(get("key"), "raw").verify(data, get("message"))).lower(), None, None
        elif operation == "hazmatVerify":
            return str(hazmat.verify(algorithm.import_public_key(get("key"), "raw"), data, get("message"), context=context, pre_hash=function)).lower(), None, None
        elif operation == "loadPrivateKey":
            private_key = algorithm.load_private_key(MemoryStore(data))

            output, remaining = private_key.public_key.export_key("raw"), private_key.remaining_signatures()
        else:
            raise AssertionError(f"unknown operation {operation}")
    except CryptoPQError as error:
        return str(error.code), None, None

    return "ok", output, remaining


class CrossTest(unittest.TestCase):
    def test_kem(self):
        for header, record in records("cross/kem.txt", "seed"):
            algorithm = ALGORITHMS[header["algorithm"]]

            with self.subTest(algorithm=algorithm.name, tcId=record["tcId"]):
                seed, public = unhex(record["seed"]), unhex(record["publicKey"])

                pair = hazmat.generate_key_pair(algorithm, seed)

                self.assertEqual(pair.public_key.export_key("raw"), public)

                self.assertEqual(pair.private_key.export_key("raw"), seed)

                self.assertEqual(algorithm.import_public_key(public, "raw"), pair.public_key)

                keys = [pair.private_key, algorithm.import_private_key(seed, "raw")]

                if "expandedKey" in record:
                    keys.append(self.check_expanded(algorithm, pair, seed, record))

                encapsulation = hazmat.encapsulate(pair.public_key, unhex(record["randomness"]))

                self.assertEqual(encapsulation.ciphertext, unhex(record["ciphertext"]))

                self.assertEqual(encapsulation.shared_secret, unhex(record["sharedSecret"]))

                for key in keys:
                    self.assertEqual(key.decapsulate(encapsulation.ciphertext), encapsulation.shared_secret)

                    self.assertEqual(key.decapsulate(unhex(record["tamperedCiphertext"])), unhex(record["rejectedSecret"]))

    # The DER and PEM exports of a key pair and their imports; a private import must give back
    # the raw key `private`, unless it is None.
    def check_encoded(self, algorithm, pair, record, private):
        for format, suffix in ENCODINGS:
            public, secret = unhex(record[f"publicKey{suffix}"]), unhex(record[f"privateKey{suffix}"])

            self.assertEqual(pair.public_key.export_key(format), public)

            self.assertEqual(algorithm.import_public_key(public, format), pair.public_key)

            self.assertEqual(pair.private_key.export_key(format), secret)

            if private is not None:
                self.assertEqual(algorithm.import_private_key(secret, format).export_key("raw"), private)

        self.assertEqual(algorithm.import_public_key(unhex(record["publicKeyPem"]).decode(), "pem"), pair.public_key)

    # ML-KEM and ML-DSA: the seed forms, the expanded forms and the "both" form of PKCS#8.
    def check_expanded(self, algorithm, pair, seed, record):
        self.check_encoded(algorithm, pair, record, seed)

        expanded = unhex(record["expandedKey"])

        key = algorithm.import_private_key(expanded, "raw")

        self.assertEqual(key.export_key("raw"), expanded)

        self.assertEqual(key.public_key, pair.public_key)

        for format, suffix in ENCODINGS:
            encoded = unhex(record[f"expandedKey{suffix}"])

            self.assertEqual(key.export_key(format), encoded)

            self.assertEqual(algorithm.import_private_key(encoded, format).export_key("raw"), expanded)

        self.assertEqual(algorithm.import_private_key(unhex(record["bothKeyDer"]), "der").export_key("der"), unhex(record["privateKeyDer"]))

        return key

    def test_mldsa(self):
        self.check_signatures("cross/mldsa.txt")

    def test_slhdsa(self):
        self.check_signatures("cross/slhdsa.txt")

    def check_signatures(self, name):
        pairs, public_keys, signed = {}, {}, set()

        for header, record in records(name, "signature"):
            algorithm = ALGORITHMS[header["algorithm"]]

            seed = unhex(header["seed"])

            if seed not in pairs:
                pairs[seed] = None if slow_signer(algorithm) else hazmat.generate_key_pair(algorithm, seed)

            pair = pairs[seed]

            with self.subTest(algorithm=algorithm.name, mode=record.get("mode", "key"), preHash=record.get("preHash")):
                if "publicKey" in record:
                    public_keys[seed] = algorithm.import_public_key(unhex(record["publicKey"]), "raw")

                    self.check_signature_key(algorithm, pair, public_keys[seed], seed, record)
                elif SLOW or not algorithm.name.startswith("SLH-DSA") or seed not in signed:
                    signed.add(seed)

                    self.check_signature(public_keys[seed], pair, record)
                else:
                    self.check_signature(public_keys[seed], None, record)

    def check_signature_key(self, algorithm, pair, public_key, seed, record):
        for format, suffix in ENCODINGS:
            encoded = unhex(record[f"publicKey{suffix}"])

            self.assertEqual(public_key.export_key(format), encoded)

            self.assertEqual(algorithm.import_public_key(encoded, format), public_key)

        if pair is None:
            return

        self.assertEqual(pair.public_key, public_key)

        if "expandedKey" in record:
            self.assertEqual(pair.private_key.export_key("raw"), seed)

            self.check_expanded(algorithm, pair, seed, record)

            return

        private = unhex(record["privateKey"])

        self.assertEqual(pair.private_key.export_key("raw"), private)

        self.assertEqual(algorithm.import_private_key(private, "raw").public_key, public_key)

        self.check_encoded(algorithm, pair, record, private)

    def check_signature(self, public_key, pair, record):
        message, context, signature = unhex(record["message"]), unhex(record["context"]), unhex(record["signature"])

        function = pre_hash(record["preHash"])

        if pair is not None and record["mode"] == "hazmat":
            self.assertEqual(hazmat.sign(pair.private_key, message, unhex(record["randomness"]), context=context, pre_hash=function), signature)
        elif pair is not None:
            self.assertEqual(pair.private_key.sign(message, context=context, deterministic=True, pre_hash=function), signature)

        self.assertTrue(hazmat.verify(public_key, signature, message, context=context, pre_hash=function))

        self.assertEqual(public_key.verify(signature, message, context=context, pre_hash=function), record["publicVerify"] == "true")

    def test_hss(self):
        self.check_stateful("cross/hss.txt")

    def test_xmss(self):
        self.check_stateful("cross/xmss.txt")

    def check_stateful(self, name):
        for header, record in records(name, "stateAfter"):
            algorithm = ALGORITHMS[header["algorithm"]]

            with self.subTest(algorithm=algorithm.name, tcId=record["tcId"]):
                public, signature, message = unhex(record["publicKey"]), unhex(record["signature"]), unhex(record["message"])

                public_key = algorithm.import_public_key(public, "raw")

                for format, suffix in ENCODINGS:
                    encoded = unhex(record[f"publicKey{suffix}"])

                    self.assertEqual(public_key.export_key(format), encoded)

                    self.assertEqual(algorithm.import_public_key(encoded, format), public_key)

                self.assertTrue(public_key.verify(signature, message))

                if not SLOW and "parameters" in record and "_20/4_" not in record["parameters"]:
                    continue

                store = MemoryStore()

                index, remaining = int(record["index"]), int(record["remaining"])

                pair = hazmat.generate_key_pair(algorithm, unhex(record["seed"]), parameters=parameters(record), state_store=store, index=index)

                self.assertEqual(store.state, unhex(record["state"]))

                self.assertEqual(pair.public_key, public_key)

                self.assertEqual(pair.private_key.remaining_signatures(), remaining)

                self.assertEqual(pair.private_key.sign(message), signature)

                self.assertEqual(store.state, unhex(record["stateAfter"]))

                self.assertEqual(pair.private_key.remaining_signatures(), remaining - 1)

                if not SLOW:
                    continue

                # The key loaded from the first state signs at the same index, the same way.
                store = MemoryStore(unhex(record["state"]))

                loaded = algorithm.load_private_key(store)

                self.assertEqual(loaded.public_key, public_key)

                self.assertEqual(loaded.remaining_signatures(), remaining)

                self.assertEqual(loaded.sign(message), signature)

                self.assertEqual(store.state, unhex(record["stateAfter"]))

                self.assertEqual(loaded.remaining_signatures(), remaining - 1)

    # Each export is made again where the key is cheap to build, and every cache loads, or fails to,
    # as the reference decided; a key that loads signs as the reference did.
    def test_tree_cache(self):
        for header, record in records("cross/treecache.txt", "treeCache"):
            algorithm = ALGORITHMS[header["algorithm"]]

            with self.subTest(algorithm=algorithm.name, name=record["name"]):
                state, cache = unhex(record["state"]), unhex(record["treeCache"])

                cheap = "parameters" not in record or "_20/4_" in record["parameters"]

                if record["operation"] == "export" and (SLOW or cheap):
                    store = MemoryStore()

                    pair = hazmat.generate_key_pair(algorithm, unhex(record["seed"]), parameters=parameters(record), state_store=store, index=int(record["index"]))

                    if record["signed"] == "true":
                        pair.private_key.sign(unhex(record["message"]))

                    self.assertEqual(pair.private_key.export_tree_cache(), cache)

                    self.assertEqual(store.state, state)

                try:
                    key = algorithm.load_private_key(MemoryStore(state), tree_cache=cache)
                except CryptoPQError as error:
                    self.assertEqual(str(error.code), record["result"])

                    continue

                self.assertEqual(record["result"], "ok")

                self.assertEqual(key.public_key.export_key("raw"), unhex(record["publicKey"]))

                self.assertEqual(key.remaining_signatures(), int(record["remaining"]))

                if "signature" in record:
                    self.assertEqual(key.sign(unhex(record["message"])), unhex(record["signature"]))

    def test_errors(self):
        for header, record in records("cross/errors.txt", "result"):
            algorithm = ALGORITHMS[header["algorithm"]]

            with self.subTest(algorithm=algorithm.name, name=record["name"]):
                data = unhex(record.get("input", ""))

                for value in [data, data.decode("latin-1")] if record.get("format") == "pem" else [data]:
                    result, output, remaining = execute(algorithm, record, value)

                    self.assertEqual(result, record["result"])

                    if "output" in record:
                        self.assertEqual(output, unhex(record["output"]))

                    if "remaining" in record:
                        self.assertEqual(remaining, int(record["remaining"]))


if __name__ == "__main__":
    unittest.main()
