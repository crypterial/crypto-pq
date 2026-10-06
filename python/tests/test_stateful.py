import os
import struct
import threading
import time
import unittest
from unittest import mock

import crypto_pq
from crypto_pq import HMAC_SHA_256, HSS_LMS, XMSS, XMSS_MT, CryptoPQError, ErrorCode, _lms, _xmss, hazmat
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


class RecordingStore(MemoryStore):
    def __init__(self, state=None):
        super().__init__(state)

        self.written = []

    def update(self, previous, next):
        self.written.append(next)

        return super().update(previous, next)

    # The index of each HSS state written: its last 8 bytes before the 16-byte checksum.
    def indices(self):
        return [int.from_bytes(state[-24:-16], "big") for state in self.written]


class CallbackStore(MemoryStore):
    def __init__(self, callback):
        super().__init__()

        self.callback = callback

    def update(self, previous, next):
        if previous is not None:
            self.callback()

        return super().update(previous, next)


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

                # RFC 9858, A.4, has a tree of height 20: about a million leaves.
                if not SLOW and sum(lms.h for lms, _ in levels) > 15:
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

    # With reserve = 3 one store write claims three indices, and the signatures are those of
    # reserve = 1. A key loaded after a stop resumes at the stored index: the indices claimed and
    # never used are lost, not reused.
    def test_reserve(self):
        seed = bytes(range(40))

        store = RecordingStore()

        pair = hazmat.generate_key_pair(HSS_LMS, seed, parameters=SMALL, state_store=store, reserve=3)

        signatures = [pair.private_key.sign(bytes([i])) for i in range(7)]

        self.assertEqual(store.indices(), [0, 3, 6, 9])

        self.assertEqual(pair.private_key.remaining_signatures(), 25)

        reference = hazmat.generate_key_pair(HSS_LMS, seed, parameters=SMALL, state_store=MemoryStore()).private_key

        self.assertEqual(signatures, [reference.sign(bytes([i])) for i in range(7)])

        loaded = HSS_LMS.load_private_key(store, reserve=4)

        self.assertEqual(loaded.remaining_signatures(), 23)

        resumed = hazmat.generate_key_pair(HSS_LMS, seed, parameters=SMALL, state_store=MemoryStore(), index=9).private_key

        self.assertEqual(loaded.sign(b"m"), resumed.sign(b"m"))

        self.assertEqual(store.indices()[-1], 13)

        # A reservation stops at the capacity.
        store = RecordingStore()

        last = hazmat.generate_key_pair(HSS_LMS, seed, parameters=SMALL, state_store=store, index=30, reserve=5).private_key

        for message in (b"a", b"b"):
            last.sign(message)

        self.assertEqual(store.indices(), [30, 32])

        self.assertCode(ErrorCode.KEY_EXHAUSTED, last.sign, b"c")

    def test_reserve_option(self):
        for reserve in (0, -1, 1.5, True, None, "2"):
            with self.subTest(reserve=reserve):
                store = MemoryStore()

                self.assertCode(ErrorCode.INVALID_OPTION, HSS_LMS.generate_key_pair, parameters=SMALL, state_store=store, reserve=reserve)

                self.assertCode(ErrorCode.INVALID_OPTION, hazmat.generate_key_pair, HSS_LMS, bytes(40), parameters=SMALL, state_store=store, reserve=reserve)

                self.assertIsNone(store.state)

                self.assertCode(ErrorCode.INVALID_OPTION, XMSS_MT.load_private_key, store, reserve=reserve)

    # A sign that finds the key busy fails at once, whether it comes from inside the store's
    # update() or from another thread, and remaining_signatures() answers from inside update().
    # The outer call runs in a daemon thread so that a deadlock fails the test instead of hanging.
    def test_busy_key(self):
        seen = []

        def attempt():
            try:
                key.sign(b"inner")
            except CryptoPQError as error:
                seen.append(error.code)

        def during_update():
            seen.append(key.remaining_signatures())

            attempt()

            other = threading.Thread(target=attempt)

            other.start()

            other.join(10)

            seen.append(other.is_alive())

        pair = HSS_LMS.generate_key_pair(parameters=SMALL, state_store=CallbackStore(during_update))

        key = pair.private_key

        signed = []

        outer = threading.Thread(target=lambda: signed.append(key.sign(b"outer")), daemon=True)

        outer.start()

        outer.join(60)

        self.assertFalse(outer.is_alive())

        self.assertEqual(seen, [32, ErrorCode.STATE_CONFLICT, ErrorCode.STATE_CONFLICT, False])

        self.assertTrue(pair.public_key.verify(signed[0], b"outer"))

        self.assertEqual(key.remaining_signatures(), 31)

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
        following = None

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

                # By default only the sets with 4 layers of height 5 build keys and sign: one tree
                # of height 10 takes about ten seconds in pure Python.
                if not SLOW and name.split("_")[1] != "20/4":
                    continue

                # The vectors at consecutive indices come from one key, so the key that made the
                # first signs the next as well, with the upper-layer parts it kept.
                if (name, record["seed"], index) != following:
                    pair = hazmat.generate_key_pair(algorithm, unhex(record["seed"]), parameters=name, state_store=MemoryStore(), index=index)

                    self.assertEqual(pair.public_key.export_key("raw"), public)

                self.assertEqual(pair.private_key.sign(message), signature)

                following = (name, record["seed"], index + 1)

    # From index 31 to 33 the signatures cross the edge of a lowest tree: the layer-1 part is
    # signed again at 32 only, and the parts above it are signed once.
    @unittest.skipUnless(crypto_pq.BACKEND == "pure", "counts the pure backend's WOTS+ signatures")
    def test_layer_cache(self):
        pair = hazmat.generate_key_pair(XMSS_MT, bytes(range(72)), parameters="XMSSMT-SHA2_20/4_192", state_store=MemoryStore(), index=31)

        with mock.patch.object(_xmss, "wots_sign", wraps=_xmss.wots_sign) as wots_sign:
            for index, layers in ((31, 4), (32, 2), (33, 1)):
                wots_sign.reset_mock()

                signature = pair.private_key.sign(bytes([index]))

                self.assertEqual(wots_sign.call_count, layers)

                self.assertEqual(int.from_bytes(signature[:3], "big"), index)

                self.assertTrue(pair.public_key.verify(signature, bytes([index])))

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


TWO = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"), ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2")]

THREE = [("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"), ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1"), ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2")]

MT = "XMSSMT-SHA2_20/4_192"

# A cached tree's header: level, tree number, lowest cached height, height, n and node count.
TREE = struct.Struct(">BQBBBI")


class Cache:
    """A tree cache taken apart, so that a test can change one field and seal it again with the
    key's seed: only then do the checks after the tag see the change. The parameters are an HSS
    level count and a pair of type codes per level, or an XMSS OID; a tree is [level, tree number,
    low, height, n, node count, nodes]."""

    def __init__(self, data):
        end = 3 + 8 * data[2] if data[1] == 1 else 6

        self.version, self.kind, self.parameters = data[0], data[1], data[2:end]

        size = int.from_bytes(data[end : end + 4], "big")

        self.public_key = data[end + 4 : end + 4 + size]

        self.trees = []

        offset = end + 5 + size

        for _ in range(data[end + 4 + size]):
            fields = list(TREE.unpack_from(data, offset))

            end = offset + TREE.size + fields[4] * fields[5]

            self.trees.append([*fields, data[offset + TREE.size : end]])

            offset = end

        self.tag = data[offset:]

    # Where the nodes of tree i start.
    def nodes_at(self, i):
        before = 7 + len(self.parameters) + len(self.public_key)

        return before + sum(TREE.size + len(tree[6]) for tree in self.trees[:i]) + TREE.size

    def body(self):
        body = bytes([self.version, self.kind]) + self.parameters + len(self.public_key).to_bytes(4, "big") + self.public_key + bytes([len(self.trees)])

        return body + b"".join(TREE.pack(*tree[:6]) + tree[6] for tree in self.trees)

    def seal(self, seed):
        key = HMAC_SHA_256.digest(b"crypto-pq tree cache v1", seed)

        return self.body() + HMAC_SHA_256.digest(key, self.body())


def flip(data, position, mask=1):
    out = bytearray(data)

    out[position] ^= mask

    return bytes(out)


class TreeCacheTest(unittest.TestCase):
    assertCode = HssTest.assertCode

    # A key at `index` that signed there, so that it holds a tree on every level, the state it
    # stored and its cache.
    def exported(self, algorithm, parameters, seed, index, sign=True):
        store = MemoryStore()

        pair = hazmat.generate_key_pair(algorithm, seed, parameters=parameters, state_store=store, index=index)

        if sign:
            pair.private_key.sign(b"first")

        return pair, store.state, pair.private_key.export_tree_cache()

    def load(self, algorithm, state, cache):
        return algorithm.load_private_key(MemoryStore(state), tree_cache=cache)

    def assertLoads(self, algorithm, state, cache):
        loaded, plain = self.load(algorithm, state, cache), algorithm.load_private_key(MemoryStore(state))

        self.assertEqual(loaded.public_key, plain.public_key)

        self.assertEqual(loaded.remaining_signatures(), plain.remaining_signatures())

        if plain.remaining_signatures():
            self.assertEqual(loaded.sign(b"next"), plain.sign(b"next"))

    # A key loaded with the cache signs as one loaded without it, and exports the same cache.
    def test_round_trip(self):
        for algorithm, parameters, size, index in ((HSS_LMS, TWO, 40, 40), (HSS_LMS, THREE, 48, 5000), (XMSS_MT, MT, 72, 0x12345)):
            with self.subTest(algorithm=algorithm.name, index=index):
                seed = bytes(range(size))

                pair, state, cache = self.exported(algorithm, parameters, seed, index)

                loaded, plain = self.load(algorithm, state, cache), algorithm.load_private_key(MemoryStore(state))

                self.assertEqual(loaded.public_key, pair.public_key)

                self.assertEqual(loaded.export_tree_cache(), cache)

                for message in (b"second", b"third"):
                    signature = loaded.sign(message)

                    self.assertTrue(pair.public_key.verify(signature, message))

                    self.assertEqual(signature, plain.sign(message))

                self.assertEqual(loaded.export_tree_cache(), plain.export_tree_cache())

                self.assertEqual(self.load(algorithm, state, bytearray(cache)).public_key, pair.public_key)

                self.assertEqual(self.load(algorithm, state, memoryview(cache)).public_key, pair.public_key)

    def test_format(self):
        seed = bytes(range(40))

        pair, state, cache = self.exported(HSS_LMS, TWO, seed, 40)

        parts = Cache(cache)

        public = pair.public_key.export_key("raw")

        self.assertEqual((parts.version, parts.kind, parts.public_key), (1, 1, public))

        self.assertEqual(parts.parameters.hex(), "02" + "0000000a00000007" + "0000000a00000006")

        self.assertEqual([tree[:6] for tree in parts.trees], [[0, 0, 0, 5, 24, 63], [1, 1, 0, 5, 24, 63]])

        self.assertEqual(parts.trees[0][6][-24:], public[-24:])

        self.assertEqual(parts.seal(seed), cache)

        _, _, fresh = self.exported(HSS_LMS, TWO, seed, 40, sign=False)

        self.assertEqual(Cache(fresh).trees, parts.trees[:1])

        pair, state, cache = self.exported(XMSS_MT, MT, bytes(range(72)), 0x12345)

        parts = Cache(cache)

        self.assertEqual((parts.version, parts.kind, parts.parameters), (1, 3, bytes.fromhex("00000022")))

        self.assertEqual([tree[:6] for tree in parts.trees], [[3, 0, 0, 5, 24, 63], [2, 2, 0, 5, 24, 63], [1, 72, 0, 5, 24, 63], [0, 2330, 0, 5, 24, 63]])

        self.assertEqual(parts.trees[0][6][-24:], pair.public_key.export_key("raw")[4:28])

        self.assertEqual(parts.seal(bytes(range(72))), cache)

    def test_rejections(self):
        seed = bytes(range(40))

        pair, state, cache = self.exported(HSS_LMS, TWO, seed, 40)

        parts = Cache(cache)

        # The level-1 tree of index 40 is tree 1, which index 64 has left.
        later = HSS_LMS._backend.encode(HSS_LMS._backend.parameters(TWO), seed, 64)

        invalid = [
            ("level 0 node changed", flip(cache, parts.nodes_at(0) + 5)),
            ("level 1 node changed", flip(cache, parts.nodes_at(1) + 30)),
            ("first tag byte changed", flip(cache, len(cache) - 32)),
            ("last tag byte changed", flip(cache, len(cache) - 1)),
            ("version 0", flip(cache, 0)),
            ("version 2", flip(cache, 0, 3)),
            ("version 2 and kind 2", flip(flip(cache, 0, 3), 1, 3)),
            ("cut and kind 2", flip(cache, 1, 3)[:-1]),
            ("cut in the parameters", cache[:10]),
            ("one byte appended", cache + b"\x00"),
            ("a second tag appended", cache + cache[-32:]),
            ("another key", self.exported(HSS_LMS, TWO, bytes(40), 40)[2]),
        ]

        for name, data in invalid:
            with self.subTest(name=name):
                self.assertCode(ErrorCode.INVALID_ENCODING, self.load, HSS_LMS, state, data)

        for length in range(len(cache)):
            self.assertCode(ErrorCode.INVALID_ENCODING, self.load, HSS_LMS, state, cache[:length])

        # Another kind reads the HSS parameters with its own layout, or with none, and finds the
        # cache malformed; a cache made for another algorithm is ALGORITHM_MISMATCH.
        for kind in (0, 2, 3, 4):
            with self.subTest(kind=kind):
                self.assertCode(ErrorCode.INVALID_ENCODING, self.load, HSS_LMS, state, cache[:1] + bytes([kind]) + cache[2:])

        _, mt_state, mt_cache = self.exported(XMSS_MT, MT, bytes(range(72)), 0x12345)

        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, self.load, HSS_LMS, state, mt_cache)

        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, self.load, XMSS_MT, mt_state, cache)

        # The same seed with another type below the top: the public key and the tag key are the
        # same, and only the parameters tell the keys apart.
        for lower in (("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8"), ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2")):
            with self.subTest(lower=lower):
                other = HSS_LMS._backend.encode(HSS_LMS._backend.parameters([TWO[0], lower]), seed, 41)

                self.assertCode(ErrorCode.INVALID_ENCODING, self.load, HSS_LMS, other, cache)

        # The same I with another SEED: the public parts match, the tag does not.
        other = HSS_LMS._backend.encode(HSS_LMS._backend.parameters(TWO), seed[:16] + bytes(24), 41)

        self.assertCode(ErrorCode.INVALID_ENCODING, self.load, HSS_LMS, other, cache)

        # The state is checked before the cache.
        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, self.load, HSS_LMS, state[:-1], cache)

        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, self.load, HSS_LMS, HSS_LMS._backend.encode(HSS_LMS._backend.parameters(TWO), seed, 1025), cache)

        self.assertEqual(self.load(HSS_LMS, HSS_LMS._backend.encode(HSS_LMS._backend.parameters(TWO), seed, 1024), cache).remaining_signatures(), 0)

        for value in ("text", 7, [1]):
            with self.assertRaises(TypeError):
                self.load(HSS_LMS, state, value)

        self.assertLoads(HSS_LMS, later, cache)

    # Changes sealed with the key's seed, which only the checks after the tag can catch.
    def test_sealed_changes(self):
        seed = bytes(range(40))

        _, state, cache = self.exported(HSS_LMS, TWO, seed, 40)

        later = HSS_LMS._backend.encode(HSS_LMS._backend.parameters(TWO), seed, 64)

        # At the capacity no lower tree is needed, and the top tree is still tree 0.
        capacity = HSS_LMS._backend.encode(HSS_LMS._backend.parameters(TWO), seed, 1024)

        def changed(*edits):
            parts = Cache(cache)

            for edit in edits:
                edit(parts)

            return parts.seal(seed)

        def node(i, position):
            def edit(parts):
                parts.trees[i][6] = flip(parts.trees[i][6], position)

            return edit

        def field(i, index, value):
            def edit(parts):
                parts.trees[i][index] = value

            return edit

        def shape(i, low, height, n, count):
            def edit(parts):
                parts.trees[i][2:7] = [low, height, n, count, (parts.trees[i][6] * 3)[: n * count]]

            return edit

        def trees(*order):
            def edit(parts):
                parts.trees = [parts.trees[i] for i in order]

            return edit

        def renumber(i, level):
            def edit(parts):
                parts.trees[i][0] = level

            return edit

        def public_key(value):
            def edit(parts):
                parts.public_key = value(parts.public_key)

            return edit

        def parameters(value):
            def edit(parts):
                parts.parameters = bytes.fromhex(value)

            return edit

        for name, edit, at, code in (
            ("level 1 node changed", node(1, 7), state, ErrorCode.INVALID_ENCODING),
            ("level 1 root changed", node(1, 62 * 24), state, ErrorCode.INVALID_ENCODING),
            ("level 0 leaf changed", node(0, 0), state, ErrorCode.INVALID_ENCODING),
            ("level 0 root changed", node(0, 62 * 24 + 23), state, ErrorCode.INVALID_ENCODING),
            ("stale level 1 node changed", node(1, 7), later, None),
            ("level 1 claimed as tree 2", field(1, 1, 2), later, ErrorCode.INVALID_ENCODING),
            ("level 1 as tree 2 for index 41", field(1, 1, 2), state, None),
            ("top tree numbered 1", field(0, 1, 1), state, None),
            ("no trees", trees(), state, None),
            ("top tree only", trees(0), state, None),
            ("level 1 only", trees(1), state, None),
            ("levels swapped", trees(1, 0), state, ErrorCode.INVALID_ENCODING),
            ("level 0 twice", trees(0, 0), state, ErrorCode.INVALID_ENCODING),
            ("level 2", renumber(1, 2), state, ErrorCode.INVALID_ENCODING),
            ("height 6", shape(1, 0, 6, 24, 127), state, ErrorCode.INVALID_ENCODING),
            ("height 4", shape(1, 0, 4, 24, 31), state, ErrorCode.INVALID_ENCODING),
            ("n 32", shape(1, 0, 5, 32, 63), state, ErrorCode.INVALID_ENCODING),
            ("lowest height 1", shape(1, 1, 5, 24, 31), state, ErrorCode.INVALID_ENCODING),
            ("one node less", shape(1, 0, 5, 24, 62), state, ErrorCode.INVALID_ENCODING),
            ("one node more", shape(1, 0, 5, 24, 64), state, ErrorCode.INVALID_ENCODING),
            ("public key one byte longer", public_key(lambda key: key + b"\x00"), state, ErrorCode.INVALID_ENCODING),
            ("public key one byte shorter", public_key(lambda key: key[:-1]), state, ErrorCode.INVALID_ENCODING),
            ("public key of three levels", public_key(lambda key: b"\x00\x00\x00\x03" + key[4:]), state, ErrorCode.INVALID_ENCODING),
            ("public key root changed", public_key(lambda key: flip(key, len(key) - 1)), state, ErrorCode.INVALID_ENCODING),
            ("lower level of another LM-OTS type", parameters("02" + "0000000a00000007" + "0000000a00000008"), state, ErrorCode.INVALID_ENCODING),
            ("one level", parameters("01" + "0000000a00000007"), state, ErrorCode.INVALID_ENCODING),
            ("levels in another order", parameters("02" + "0000000a00000006" + "0000000a00000007"), state, ErrorCode.INVALID_ENCODING),
            ("top node changed at the capacity", node(0, 5), capacity, ErrorCode.INVALID_ENCODING),
            ("top tree 1 changed at the capacity", (field(0, 1, 1), node(0, 5)), capacity, None),
        ):
            with self.subTest(name=name):
                data = changed(*edit) if isinstance(edit, tuple) else changed(edit)

                if code is None:
                    self.assertLoads(HSS_LMS, at, data)
                else:
                    self.assertCode(code, self.load, HSS_LMS, at, data)

    def test_xmss_rejections(self):
        seed = bytes(range(72))

        pair, state, cache = self.exported(XMSS_MT, MT, seed, 0x12345)

        parameters = XMSS_MT._backend.parameters(MT)

        # 0x12360 signs with the next tree of layer 0.
        later = XMSS_MT._backend.encode(parameters, seed, 0x12360)

        capacity = XMSS_MT._backend.encode(parameters, seed, 1 << 20)

        parts = Cache(cache)

        for name, data in (
            ("layer 0 node changed", flip(cache, parts.nodes_at(3) + 100)),
            ("tag changed", flip(cache, len(cache) - 7)),
            ("one byte appended", cache + b"\x00"),
            ("cut", cache[:-1]),
            ("another key", self.exported(XMSS_MT, MT, bytes(72), 0x12345)[2]),
        ):
            with self.subTest(name=name):
                self.assertCode(ErrorCode.INVALID_ENCODING, self.load, XMSS_MT, state, data)

        # XMSS shares the layout, so its kind is a mismatch; the HSS layout misreads the OID, and
        # no other kind has a layout.
        self.assertCode(ErrorCode.ALGORITHM_MISMATCH, self.load, XMSS_MT, state, cache[:1] + b"\x02" + cache[2:])

        for kind in (0, 1, 4):
            self.assertCode(ErrorCode.INVALID_ENCODING, self.load, XMSS_MT, state, cache[:1] + bytes([kind]) + cache[2:])

        # Another parameter set from the same seed.
        self.assertCode(ErrorCode.INVALID_ENCODING, self.load, XMSS_MT, XMSS_MT._backend.encode(XMSS_MT._backend.parameters("XMSSMT-SHA2_20/2_192"), seed, 7), cache)

        # The same PUB_SEED with other secret seeds: the public parts match, the tag does not.
        other = XMSS_MT._backend.encode(parameters, bytes(48) + seed[48:], 0x12346)

        self.assertCode(ErrorCode.INVALID_ENCODING, self.load, XMSS_MT, other, cache)

        def changed(edit):
            parts = Cache(cache)

            edit(parts)

            return parts.seal(seed)

        def bottom_node(parts):
            parts.trees[3][6] = flip(parts.trees[3][6], 40)

        def swapped(parts):
            parts.trees[1], parts.trees[2] = parts.trees[2], parts.trees[1]

        def doubled(parts):
            parts.trees.insert(1, parts.trees[1])

        def layer_4(parts):
            parts.trees[0][0] = 4

        def top_only(parts):
            parts.trees = parts.trees[:1]

        def without_top(parts):
            parts.trees = parts.trees[1:]

        def top_node(parts):
            parts.trees[0][6] = flip(parts.trees[0][6], 9)

        def top_node_tree_1(parts):
            top_node(parts)

            parts.trees[0][1] = 1

        def oid_20_2(parts):
            parts.parameters = bytes.fromhex("00000021")

        for name, edit, at, code in (
            ("layer 0 node changed", bottom_node, state, ErrorCode.INVALID_ENCODING),
            ("stale layer 0 node changed", bottom_node, later, None),
            ("layers swapped", swapped, state, ErrorCode.INVALID_ENCODING),
            ("layer 2 twice", doubled, state, ErrorCode.INVALID_ENCODING),
            ("layer 4", layer_4, state, ErrorCode.INVALID_ENCODING),
            ("top layer only", top_only, state, None),
            ("no top layer", without_top, state, None),
            ("top node changed at the capacity", top_node, capacity, ErrorCode.INVALID_ENCODING),
            ("top tree 1 changed at the capacity", top_node_tree_1, capacity, None),
            ("parameters of another set", oid_20_2, state, ErrorCode.INVALID_ENCODING),
        ):
            with self.subTest(name=name):
                data = changed(edit)

                if code is None:
                    self.assertLoads(XMSS_MT, at, data)
                else:
                    self.assertCode(code, self.load, XMSS_MT, at, data)

        self.assertLoads(XMSS_MT, later, cache)

    # Every change of one byte gives INVALID_ENCODING and never loads: the kind byte becomes 0 or
    # 0x81, no kind at all.
    def test_every_change(self):
        _, state, cache = self.exported(HSS_LMS, [TWO[0]], bytes(range(40)), 5)

        for position in range(len(cache)):
            for mask in (0x01, 0x80):
                self.assertCode(ErrorCode.INVALID_ENCODING, self.load, HSS_LMS, state, flip(cache, position, mask))

    # A load with the cache computes no leaf; the trees that the next index has left are built.
    @unittest.skipUnless(crypto_pq.BACKEND == "pure", "counts the pure backend's leaves")
    def test_cache_skips_the_build(self):
        for algorithm, module, parameters, size, index, later, trees in ((HSS_LMS, _lms, TWO, 40, 40, 64, 2), (XMSS_MT, _xmss, MT, 72, 0x12345, 0x12360, 4)):
            with self.subTest(algorithm=algorithm.name):
                seed = bytes(range(size))

                pair, state, cache = self.exported(algorithm, parameters, seed, index)

                stale = algorithm._backend.encode(algorithm._backend.parameters(parameters), seed, later)

                with mock.patch.object(module, "leaves", wraps=module.leaves) as leaves:

                    def computed():
                        count = sum(call.args[-1] for call in leaves.call_args_list)

                        leaves.reset_mock()

                        return count

                    self.load(algorithm, state, cache).sign(b"m")

                    self.assertEqual(computed(), 0)

                    algorithm.load_private_key(MemoryStore(state)).sign(b"m")

                    self.assertEqual(computed(), 32 * trees)

                    self.load(algorithm, stale, cache).sign(b"m")

                    self.assertEqual(computed(), 32)

    # A sign holds the trees as they change, so an export from inside the store fails at once.
    def test_export_while_signing(self):
        seen = []

        def during_update():
            try:
                key.export_tree_cache()
            except CryptoPQError as error:
                seen.append(error.code)

        pair = HSS_LMS.generate_key_pair(parameters=SMALL, state_store=CallbackStore(during_update))

        key = pair.private_key

        self.assertTrue(pair.public_key.verify(key.sign(b"m"), b"m"))

        self.assertEqual(seen, [ErrorCode.STATE_CONFLICT])

        self.assertEqual(Cache(key.export_tree_cache()).public_key, pair.public_key.export_key("raw"))

    # The load that the cache saves, for one tree of height 15 (10 by default): every leaf against
    # the parents only. The fastest of three loads each, as shared CI runners pause at random.
    def test_load_time(self):
        height = 15 if SLOW else 10

        _, state, cache = self.exported(HSS_LMS, [(f"LMS_SHA256_M24_H{height}", "LMOTS_SHA256_N24_W2")], bytes(40), 0, sign=False)

        plain_times, cached_times = [], []

        for _ in range(3):
            start = time.perf_counter()

            plain = HSS_LMS.load_private_key(MemoryStore(state))

            middle = time.perf_counter()

            cached = self.load(HSS_LMS, state, cache)

            end = time.perf_counter()

            self.assertEqual(cached.public_key, plain.public_key)

            plain_times.append(middle - start)

            cached_times.append(end - middle)

        self.assertLess(4 * min(cached_times), min(plain_times), f"H{height}: {min(plain_times):.3f} s without the cache, {min(cached_times):.3f} s with it")


if __name__ == "__main__":
    unittest.main()
