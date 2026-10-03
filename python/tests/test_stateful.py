import os
import unittest

import crypto_pq
from crypto_pq import HSS_LMS, XMSS, XMSS_MT, CryptoPQError, ErrorCode, hazmat
from vectors import records, unhex

SLOW = bool(os.environ.get("CRYPTO_PQ_SLOW"))

SMALL = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")]


class MemoryStore:
    def __init__(self, state=None):
        self.state = state

    def read(self):
        return self.state

    def update(self, previous, next):
        if self.state != previous:
            return False

        self.state = next

        return True


class BrokenStore(MemoryStore):
    def update(self, previous, next):
        if previous is None:
            return super().update(previous, next)

        raise OSError("disk full")


def lms_names(public_key):
    lms = int.from_bytes(public_key[4:8], "big")

    ots = int.from_bytes(public_key[8:12], "big")

    return lms, ots


class HssTest(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args, **kwargs)

        self.assertEqual(caught.exception.code, code)

    def test_acvp_key_generation(self):
        for header, record in records("acvp/LMS-keyGen.txt", "publicKey"):
            if not SLOW and header["lmsMode"].endswith("H10"):
                continue

            with self.subTest(tcId=record["tcId"]):
                pair = hazmat.generate_key_pair(
                    HSS_LMS,
                    unhex(record["i"]) + unhex(record["seed"]),
                    parameters=[(header["lmsMode"], header["lmOtsMode"])],
                    state_store=MemoryStore(),
                )

                self.assertEqual(pair.public_key.export_key("raw"), b"\x00\x00\x00\x01" + unhex(record["publicKey"]))

    def test_acvp_verification(self):
        for header, record in records("acvp/LMS-sigVer.txt", "signature"):
            with self.subTest(tcId=record["tcId"], reason=record["reason"]):
                public_key = HSS_LMS.import_public_key(b"\x00\x00\x00\x01" + unhex(header["publicKey"]), "raw")

                result = public_key.verify(b"\x00\x00\x00\x00" + unhex(record["signature"]), unhex(record["message"]))

                self.assertEqual(result, record["testPassed"] == "true")

    def test_rfc_vectors(self):
        for _, record in records("rfc/hss.txt", "signature"):
            with self.subTest(name=record["name"]):
                public = unhex(record["publicKey"])

                message, signature = unhex(record["message"]), unhex(record["signature"])

                public_key = HSS_LMS.import_public_key(public, "raw")

                self.assertTrue(public_key.verify(signature, message))

                tampered = bytearray(signature)

                tampered[-1] ^= 1

                self.assertFalse(public_key.verify(bytes(tampered), message))

                self.assertFalse(public_key.verify(signature, message + b"\x00"))

                if "seed" not in record:
                    continue

                levels = self.levels(public, signature)

                index = self.index(levels, signature)

                if not SLOW and sum(lms.h for lms, _ in levels) > 5:
                    continue

                pair = hazmat.generate_key_pair(
                    HSS_LMS,
                    unhex(record["i"]) + unhex(record["seed"]),
                    parameters=[(lms.name, ots.name) for lms, ots in levels],
                    state_store=MemoryStore(),
                    index=index,
                )

                self.assertEqual(pair.public_key.export_key("raw"), public)

                self.assertEqual(pair.private_key.sign(message), signature)

    # The parameters of every level, read from the public key and the signed child keys.
    def levels(self, public, signature):
        from crypto_pq import _lms

        count = int.from_bytes(public[:4], "big")

        key = public[4:]

        levels = []

        offset = 4

        for level in range(count):
            lms, ots, _, _ = _lms.parse_public_key(key)

            levels.append((lms, ots))

            if level + 1 < count:
                offset += _lms.lms_signature_size(lms, ots)

                child = _lms.LMS_TYPES[int.from_bytes(signature[offset : offset + 4], "big")]

                key = signature[offset : offset + child.public_key_size]

                offset += child.public_key_size

        return levels

    def index(self, levels, signature):
        from crypto_pq import _lms

        offset = 4

        index = 0

        for lms, ots in levels:
            index = (index << lms.h) | int.from_bytes(signature[offset : offset + 4], "big")

            offset += _lms.lms_signature_size(lms, ots) + lms.public_key_size

        return index

    def test_state_handling(self):
        store = MemoryStore()

        pair = HSS_LMS.generate_key_pair(parameters=SMALL, state_store=store)

        self.assertEqual(pair.private_key.remaining_signatures(), 32)

        first = pair.private_key.sign(b"one")

        second = pair.private_key.sign(b"two")

        self.assertTrue(pair.public_key.verify(first, b"one"))

        self.assertTrue(pair.public_key.verify(second, b"two"))

        self.assertFalse(pair.public_key.verify(first, b"two"))

        self.assertEqual(pair.private_key.remaining_signatures(), 30)

        loaded = HSS_LMS.load_private_key(store)

        self.assertEqual(loaded.public_key, pair.public_key)

        self.assertEqual(loaded.remaining_signatures(), 30)

        third = loaded.sign(b"three")

        self.assertEqual(int.from_bytes(third[4:8], "big"), 2)

        self.assertCode(ErrorCode.STATE_CONFLICT, pair.private_key.sign, b"stale")

        while loaded.remaining_signatures():
            loaded.sign(b"m")

        self.assertCode(ErrorCode.KEY_EXHAUSTED, loaded.sign, b"m")

        self.assertCode(ErrorCode.STATE_CONFLICT, HSS_LMS.generate_key_pair, parameters=SMALL, state_store=store)

    def test_store_failures(self):
        broken = BrokenStore()

        pair = HSS_LMS.generate_key_pair(parameters=SMALL, state_store=broken)

        self.assertCode(ErrorCode.STATE_PERSIST_FAILED, pair.private_key.sign, b"m")

        self.assertEqual(pair.private_key.remaining_signatures(), 32)

        damaged = bytearray(broken.state)

        damaged[-20] ^= 1

        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, HSS_LMS.load_private_key, MemoryStore(bytes(damaged)))

        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, HSS_LMS.load_private_key, MemoryStore())

        truncated = b"\x01\x01" + crypto_pq.SHA_256.digest(b"\x01\x01")[:16]

        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, HSS_LMS.load_private_key, MemoryStore(truncated))

        self.assertCode(ErrorCode.INVALID_OPTION, hazmat.generate_key_pair, HSS_LMS, bytes(40), parameters=SMALL, state_store=MemoryStore(), index=33)

        self.assertCode(ErrorCode.INVALID_OPTION, HSS_LMS.generate_key_pair, parameters=SMALL, state_store=None)

        self.assertCode(ErrorCode.INVALID_OPTION, HSS_LMS.load_private_key, None)

        with self.assertRaises(TypeError):
            HSS_LMS.load_private_key(object())

        exhausted = hazmat.generate_key_pair(HSS_LMS, bytes(40), parameters=SMALL, state_store=MemoryStore(), index=32)

        self.assertEqual(exhausted.private_key.remaining_signatures(), 0)

        self.assertCode(ErrorCode.KEY_EXHAUSTED, exhausted.private_key.sign, b"m")

        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, XMSS.load_private_key, MemoryStore(broken.state))

    def test_parameters(self):
        for parameters in ([], [SMALL[0]] * 9, [("LMS_SHA256_M32_H5", "LMOTS_SHA256_N24_W1")], [("LMS_SHA256_M24_H5", "LMOTS_SHAKE_N24_W1")], "LMS_SHA256_M24_H5", [("LMS_SHA256_M24_H5",)], [("LMS_X", "LMOTS_SHA256_N24_W1")], [("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"), ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"), ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8")]):
            with self.subTest(parameters=parameters):
                self.assertCode(ErrorCode.INVALID_OPTION, HSS_LMS.generate_key_pair, parameters=parameters, state_store=MemoryStore())

    def test_tree_boundary(self):
        levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4")] * 2

        pair = hazmat.generate_key_pair(HSS_LMS, bytes(40), parameters=levels, state_store=MemoryStore(), index=31)

        signatures = [pair.private_key.sign(bytes([i])) for i in range(2)]

        for i, signature in enumerate(signatures):
            self.assertTrue(pair.public_key.verify(signature, bytes([i])))

        self.assertNotEqual(signatures[0][4:8], signatures[1][4:8])

    def test_formats(self):
        pair = HSS_LMS.generate_key_pair(parameters=SMALL, state_store=MemoryStore())

        for format in ("raw", "der", "pem"):
            self.assertEqual(HSS_LMS.import_public_key(pair.public_key.export_key(format), format), pair.public_key)

        der = pair.public_key.export_key("der")

        self.assertIn(bytes.fromhex("060b2a864886f70d0109100311"), der)

        self.assertCode(ErrorCode.INVALID_PUBLIC_KEY, HSS_LMS.import_public_key, b"\x00\x00\x00\x09" + pair.public_key.export_key("raw")[4:], "raw")

        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, XMSS.import_public_key, der, "der")


class XmssTest(unittest.TestCase):
    def test_reference_vectors(self):
        for _, record in records("xmss/xmss.txt", "signature"):
            name = record["name"]

            algorithm = XMSS_MT if name.startswith("XMSSMT") else XMSS

            index, message = int(record["index"]), unhex(record["message"])

            public, signature = unhex(record["publicKey"]), unhex(record["signature"])

            with self.subTest(name=name, index=index):
                public_key = algorithm.import_public_key(public, "raw")

                self.assertTrue(public_key.verify(signature, message))

                tampered = bytearray(signature)

                tampered[-1] ^= 1

                self.assertFalse(public_key.verify(bytes(tampered), message))

                if not SLOW and (name != "XMSSMT-SHA2_20/4_256" or index > 1):
                    continue

                pair = hazmat.generate_key_pair(algorithm, unhex(record["seed"]), parameters=name, state_store=MemoryStore(), index=index)

                self.assertEqual(pair.public_key.export_key("raw"), public)

                self.assertEqual(pair.private_key.sign(message), signature)

    def test_state_handling(self):
        store = MemoryStore()

        pair = XMSS_MT.generate_key_pair(parameters="XMSSMT-SHAKE256_20/4_192", state_store=store)

        signature = pair.private_key.sign(b"message")

        self.assertTrue(pair.public_key.verify(signature, b"message"))

        loaded = XMSS_MT.load_private_key(store)

        self.assertEqual(loaded.remaining_signatures(), (1 << 20) - 1)

        for format in ("raw", "der", "pem"):
            self.assertEqual(XMSS_MT.import_public_key(pair.public_key.export_key(format), format), pair.public_key)

        with self.assertRaises(CryptoPQError) as caught:
            XMSS.generate_key_pair(parameters="XMSSMT-SHAKE256_20/4_192", state_store=MemoryStore())

        self.assertEqual(caught.exception.code, ErrorCode.INVALID_OPTION)


if __name__ == "__main__":
    unittest.main()
