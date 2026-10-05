import binascii
import copy
import gc
import inspect
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from functools import partial
from unittest import mock

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode, hazmat
from crypto_pq import _bits, _blocks, _hash, _keccak, _kem, _lanes, _lms, _merkle, _mldsa, _mlkem, _native, _ntt, _primitives, _sha2, _signature, _slhdsa, _stateful, _x25519, _xmss, _xwing
from test_robustness import MemoryStore, Random, mutate, mutate_state, pattern
from vectors import expanded_key

NATIVE = crypto_pq.BACKEND == "native"

# CRYPTO_PQ_FUZZ=1 runs many more differential rounds, and every SLH-DSA set.
FUZZ = bool(os.environ.get("CRYPTO_PQ_FUZZ"))

SCALE = 20 if FUZZ else 1

HASHES = (crypto_pq.SHA_224, crypto_pq.SHA_256, crypto_pq.SHA_384, crypto_pq.SHA_512, crypto_pq.SHA_512_224, crypto_pq.SHA_512_256, crypto_pq.SHA3_224, crypto_pq.SHA3_256, crypto_pq.SHA3_384, crypto_pq.SHA3_512)

XOFS = (crypto_pq.SHAKE128, crypto_pq.SHAKE256)

HMACS = (crypto_pq.HMAC_SHA_224, crypto_pq.HMAC_SHA_256, crypto_pq.HMAC_SHA_384, crypto_pq.HMAC_SHA_512)

KEMS = (crypto_pq.ML_KEM_512, crypto_pq.ML_KEM_768, crypto_pq.ML_KEM_1024, crypto_pq.X_WING)

ML_DSA = (crypto_pq.ML_DSA_44, crypto_pq.ML_DSA_65, crypto_pq.ML_DSA_87)

SLH_DSA = (
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
)

PRE_HASHES = (None, *HASHES, *XOFS)

SMALL = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")]

TWO = [("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2"), ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1")]


# The same algorithms with the pure backend, built from its classes, whatever backend the package
# chose: the reference that the native one must match byte for byte.
def pure_twins():
    engines = {
        crypto_pq.SHA_224: partial(_sha2.Sha256, _sha2.IV_224, 28),
        crypto_pq.SHA_256: partial(_sha2.Sha256, _sha2.IV_256, 32),
        crypto_pq.SHA_384: partial(_sha2.Sha512, _sha2.IV_384, 48),
        crypto_pq.SHA_512: partial(_sha2.Sha512, _sha2.IV_512, 64),
        crypto_pq.SHA_512_224: partial(_sha2.Sha512, _sha2.IV_512_224, 28),
        crypto_pq.SHA_512_256: partial(_sha2.Sha512, _sha2.IV_512_256, 32),
        crypto_pq.SHA3_224: partial(_keccak.Keccak, 144, 0x06, 28),
        crypto_pq.SHA3_256: partial(_keccak.Keccak, 136, 0x06, 32),
        crypto_pq.SHA3_384: partial(_keccak.Keccak, 104, 0x06, 48),
        crypto_pq.SHA3_512: partial(_keccak.Keccak, 72, 0x06, 64),
    }

    twins = {algorithm: _hash.HashAlgorithm(algorithm.name, algorithm.digest_size, engine, partial(_hash._pure_digest, engine)) for algorithm, engine in engines.items()}

    for algorithm, rate in zip(XOFS, (168, 136)):
        engine = partial(_keccak.Keccak, rate, 0x1F, 0)

        twins[algorithm] = _hash.XofAlgorithm(algorithm.name, engine, partial(_hash._pure_xof, engine))

    for algorithm, hash_algorithm in zip(HMACS, HASHES[:4]):
        engine = engines[hash_algorithm]

        twins[algorithm] = _hash.HmacAlgorithm(algorithm.name, algorithm.digest_size, partial(_hash._PureHmac, engine), partial(_hash._pure_hmac, engine), partial(_hash._pure_hmac_verify, engine))

    for algorithm, params, arc in zip(KEMS, (_mlkem.ML_KEM_512, _mlkem.ML_KEM_768, _mlkem.ML_KEM_1024), (1, 2, 3)):
        twins[algorithm] = crypto_pq.KemAlgorithm(algorithm.name, _kem._MlKem(params, arc))

    twins[crypto_pq.X_WING] = crypto_pq.KemAlgorithm("X-Wing", _kem._XWing())

    for algorithm, params, arc in zip(ML_DSA, (_mldsa.ML_DSA_44, _mldsa.ML_DSA_65, _mldsa.ML_DSA_87), (17, 18, 19)):
        twins[algorithm] = crypto_pq.SignatureAlgorithm(algorithm.name, _signature._MlDsa(params, arc))

    for algorithm, params, arc in zip(SLH_DSA, _slhdsa.SHA2 + _slhdsa.SHAKE, range(20, 32)):
        twins[algorithm] = crypto_pq.SignatureAlgorithm(algorithm.name, _signature._SlhDsa(params, arc))

    twins[crypto_pq.HSS_LMS] = crypto_pq.StatefulSignatureAlgorithm("HSS/LMS", _stateful._Hss())

    twins[crypto_pq.XMSS] = crypto_pq.StatefulSignatureAlgorithm("XMSS", _stateful._Xmss(False))

    twins[crypto_pq.XMSS_MT] = crypto_pq.StatefulSignatureAlgorithm("XMSS^MT", _stateful._Xmss(True))

    return twins


def outcome(function, *args, **kwargs):
    try:
        return "ok", function(*args, **kwargs)
    except CryptoPQError as error:
        return error.code, None


# Whether the pure backend builds the trees of a stored state in a few seconds at most: the hash
# calls of every tree on a signing path, counted as test_robustness counts them.
def affordable(algorithm, state):
    try:
        parameters, _, _ = algorithm._backend.decode(state)
    except CryptoPQError:
        return True

    if algorithm.name == "HSS/LMS":
        return sum(ots.p << (lms.h + ots.w) for lms, ots in parameters) <= 1 << 17

    return (parameters.d << (parameters.h // parameters.d)) * (2 * parameters.n + 3) * 16 <= 1 << 17


class KnownAnswerTest(unittest.TestCase):
    # The load-time test of the native library expects what the pure backend computes.
    def test_self_test_digest(self):
        twins = pure_twins()

        pair = hazmat.generate_key_pair(twins[crypto_pq.X_WING], bytes(range(32)))

        public = pair.public_key.export_key("raw")

        sealed = hazmat.encapsulate(pair.public_key, bytes(range(32, 96)))

        dsa = hazmat.generate_key_pair(twins[crypto_pq.ML_DSA_44], bytes(range(32)))

        key = dsa.public_key.export_key("raw")

        signature = dsa.private_key.sign(_native.SELF_TEST_MESSAGE, deterministic=True)

        tag = twins[crypto_pq.HMAC_SHA_512].digest(sealed.shared_secret, signature)

        transcript = public + sealed.ciphertext + sealed.shared_secret + key + signature + tag

        self.assertEqual(twins[crypto_pq.SHA_256].digest(transcript).hex(), _native.SELF_TEST_DIGEST)

    def test_backend_attributes(self):
        self.assertIn(crypto_pq.BACKEND, ("native", "pure"))

        self.assertEqual(crypto_pq.LOAD_ERROR is None, NATIVE or os.environ.get("CRYPTO_PQ_BACKEND") == "pure")


@unittest.skipUnless(NATIVE, "compares the native backend with the pure one")
class DifferentialTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.twins = pure_twins()

    def test_hashes(self):
        rng = Random(301)

        sizes = [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 135, 136, 137, 143, 144, 167, 168, 169] + [rng.below(3000) for _ in range(10 * SCALE)]

        for size in sizes:
            data = rng.bytes(size)

            for algorithm in HASHES:
                twin = self.twins[algorithm]

                self.assertEqual(algorithm.digest(data), twin.digest(data), (algorithm.name, size))

                hasher, reference = algorithm.create(), twin.create()

                for piece in self.pieces(rng, data):
                    hasher.update(piece)

                    reference.update(piece)

                    if rng.below(4) == 0:
                        self.assertEqual(hasher.digest(), reference.digest())

                self.assertEqual(hasher.digest(), reference.digest())

            for algorithm in XOFS:
                twin, length = self.twins[algorithm], rng.below(600)

                self.assertEqual(algorithm.digest(data, length), twin.digest(data, length), (algorithm.name, size, length))

                xof, reference = algorithm.create(), twin.create()

                for piece in self.pieces(rng, data):
                    xof.update(piece)

                    reference.update(piece)

                for _ in range(3):
                    length = rng.below(400)

                    self.assertEqual(xof.read(length), reference.read(length))

                self.assertEqual(outcome(xof.update, b"x"), outcome(reference.update, b"x"))

            for algorithm in HMACS:
                twin, key = self.twins[algorithm], rng.bytes(rng.below(300))

                tag = algorithm.digest(key, data)

                self.assertEqual(tag, twin.digest(key, data), (algorithm.name, size, len(key)))

                hmac, reference = algorithm.create(key), twin.create(key)

                for piece in self.pieces(rng, data):
                    hmac.update(piece)

                    reference.update(piece)

                self.assertEqual(hmac.digest(), reference.digest())

                for candidate in (tag, mutate(rng, tag), tag[:-1], tag + b"\x00", b""):
                    self.assertEqual(algorithm.verify(key, data, candidate), twin.verify(key, data, candidate))

                    self.assertEqual(hmac.verify(candidate), reference.verify(candidate))

    def pieces(self, rng, data):
        offset = 0

        while offset < len(data):
            size = rng.below(300)

            yield data[offset : offset + size]

            offset += size

    def test_kem(self):
        rng = Random(302)

        for algorithm in KEMS:
            twin, backend = self.twins[algorithm], algorithm._backend

            formats = ("raw", "der", "pem") if backend.oid is not None else ("raw",)

            for _ in range(3 * SCALE):
                seed = rng.bytes(backend.seed_size)

                native, pure = hazmat.generate_key_pair(algorithm, seed), hazmat.generate_key_pair(twin, seed)

                for format in formats:
                    self.assertEqual(native.public_key.export_key(format), pure.public_key.export_key(format))

                    self.assertEqual(native.private_key.export_key(format), pure.private_key.export_key(format))

                keys = [(native.private_key, pure.private_key)]

                if backend.expanded_size is not None:
                    expanded = expanded_key(native.private_key)

                    self.assertEqual(expanded, expanded_key(pure.private_key))

                    keys.append((algorithm.import_private_key(expanded, "raw"), twin.import_private_key(expanded, "raw")))

                    for data in (mutate(rng, expanded), expanded[:-32] + rng.bytes(32), rng.bytes(len(expanded))):
                        self.check_kem_import(algorithm, twin, data)

                randomness = rng.bytes(backend.randomness_size)

                sealed = hazmat.encapsulate(native.public_key, randomness)

                self.assertEqual(sealed, hazmat.encapsulate(pure.public_key, randomness))

                public = native.public_key.export_key("raw")

                for data in (public, mutate(rng, public), public[:-2] + b"\xff\xff", rng.bytes(len(public))):
                    found = outcome(lambda: hazmat.encapsulate(algorithm.import_public_key(data, "raw"), randomness))

                    self.assertEqual(found, outcome(lambda: hazmat.encapsulate(twin.import_public_key(data, "raw"), randomness)))

                for native_key, pure_key in keys:
                    for ciphertext in (sealed.ciphertext, mutate(rng, sealed.ciphertext), rng.bytes(algorithm.ciphertext_size), sealed.ciphertext[:-1]):
                        self.assertEqual(outcome(native_key.decapsulate, ciphertext), outcome(pure_key.decapsulate, ciphertext))

    def check_kem_import(self, algorithm, twin, data):
        def imported(target):
            key = target.import_private_key(data, "raw")

            return key.export_key("raw"), key.public_key.export_key("raw"), key.decapsulate(bytes(algorithm.ciphertext_size))

        self.assertEqual(outcome(imported, algorithm), outcome(imported, twin))

    def test_signatures(self):
        rng = Random(303)

        algorithms = ML_DSA + (SLH_DSA if FUZZ else (crypto_pq.SLH_DSA_SHA2_128F, crypto_pq.SLH_DSA_SHAKE_128F))

        for algorithm in algorithms:
            twin, backend = self.twins[algorithm], algorithm._backend

            rounds = 3 * SCALE if backend.expanded_size else 1

            for _ in range(rounds):
                seed = rng.bytes(backend.seed_size)

                native, pure = hazmat.generate_key_pair(algorithm, seed), hazmat.generate_key_pair(twin, seed)

                for format in ("raw", "der", "pem"):
                    self.assertEqual(native.public_key.export_key(format), pure.public_key.export_key(format))

                    self.assertEqual(native.private_key.export_key(format), pure.private_key.export_key(format))

                message, context = rng.bytes(rng.below(200)), rng.bytes(rng.choice((0, 1, 255, 256, rng.below(40))))

                pre_hash = rng.choice(PRE_HASHES)

                signed = outcome(native.private_key.sign, message, context=context, deterministic=True, pre_hash=pre_hash)

                self.assertEqual(signed, outcome(pure.private_key.sign, message, context=context, deterministic=True, pre_hash=pre_hash))

                randomness = rng.bytes(backend.randomness_size)

                hedged = outcome(hazmat.sign, native.private_key, message, randomness, context=context, pre_hash=pre_hash)

                self.assertEqual(hedged, outcome(hazmat.sign, pure.private_key, message, randomness, context=context, pre_hash=pre_hash))

                if backend.expanded_size is not None:
                    expanded = expanded_key(native.private_key)

                    self.assertEqual(expanded, expanded_key(pure.private_key))

                    for data in (expanded, mutate(rng, expanded)):
                        sign = lambda target: target.import_private_key(data, "raw").sign(message, deterministic=True)

                        self.assertEqual(outcome(sign, algorithm), outcome(sign, twin))

                signature = hedged[1] or signed[1] or bytes(algorithm.signature_size)

                for candidate in (signature, mutate(rng, signature), signature[:-1], rng.bytes(len(signature))):
                    for verify in (lambda key: key.verify(candidate, message, context=context, pre_hash=pre_hash), lambda key: hazmat.verify(key, candidate, message, context=context, pre_hash=pre_hash)):
                        self.assertEqual(verify(native.public_key), verify(pure.public_key))

    def test_stateful(self):
        rng = Random(304)

        cases = [(crypto_pq.HSS_LMS, SMALL, 40), (crypto_pq.HSS_LMS, TWO, 40)]

        if FUZZ:
            cases.append((crypto_pq.XMSS_MT, "XMSSMT-SHA2_20/4_192", 72))

        for algorithm, parameters, size in cases:
            twin = self.twins[algorithm]

            for _ in range(2 * SCALE):
                seed, capacity = rng.bytes(size), 1 << (sum(int(lms.rsplit("H", 1)[1]) for lms, _ in parameters) if algorithm is crypto_pq.HSS_LMS else 20)

                index = rng.choice((0, rng.below(capacity), capacity - 1, capacity))

                native_store, pure_store = MemoryStore(), MemoryStore()

                reserve = 1 + rng.below(3)

                native = hazmat.generate_key_pair(algorithm, seed, parameters=parameters, state_store=native_store, index=index, reserve=reserve)

                pure = hazmat.generate_key_pair(twin, seed, parameters=parameters, state_store=pure_store, index=index, reserve=reserve)

                self.assertEqual(native.public_key.export_key("raw"), pure.public_key.export_key("raw"))

                self.assertEqual(native_store.state, pure_store.state)

                self.assertEqual(native.private_key.export_tree_cache(), pure.private_key.export_tree_cache())

                for _ in range(3):
                    message = rng.bytes(rng.below(100))

                    signed = outcome(native.private_key.sign, message)

                    self.assertEqual(signed, outcome(pure.private_key.sign, message))

                    self.assertEqual(native_store.state, pure_store.state)

                    self.assertEqual(native.private_key.remaining_signatures(), pure.private_key.remaining_signatures())

                    if signed[1] is not None:
                        for candidate in (signed[1], mutate(rng, signed[1])):
                            self.assertEqual(native.public_key.verify(candidate, message), pure.public_key.verify(candidate, message))

                cache = native.private_key.export_tree_cache()

                self.assertEqual(cache, pure.private_key.export_tree_cache())

                for state in (native_store.state, mutate_state(rng, native_store.state), mutate_state(rng, native_store.state)):
                    if not affordable(twin, state):
                        continue

                    self.assertEqual(self.loaded(algorithm, state, None), self.loaded(twin, state, None))

                    for data in (cache, mutate(rng, cache)):
                        self.assertEqual(self.loaded(algorithm, state, data), self.loaded(twin, state, data))

    def loaded(self, algorithm, state, cache):
        def load():
            key = algorithm.load_private_key(MemoryStore(state), tree_cache=cache)

            return key.public_key.export_key("raw"), key.remaining_signatures(), key.sign(b"next") if key.remaining_signatures() else None

        return outcome(load)


@unittest.skipUnless(NATIVE, "the native backend")
class IsolationTest(unittest.TestCase):
    PURE_MODULES = (_bits, _blocks, _keccak, _lanes, _lms, _merkle, _mldsa, _mlkem, _ntt, _primitives, _sha2, _slhdsa, _x25519, _xmss, _xwing)

    # Byte packing that the stateful parameter sections share with the pure LMS code.
    ALLOWED = {(_lms, "u32")}

    # Every public operation, with every function and class of the pure algorithm modules made to
    # fail: the native backend must compute everything in the library.
    def test_no_pure_computation(self):
        def failing(name):
            def fail(*args, **kwargs):
                raise AssertionError(f"the native backend called {name}")

            return fail

        patches = []

        for module in self.PURE_MODULES:
            for name, value in vars(module).items():
                if (module, name) in self.ALLOWED:
                    continue

                if inspect.isfunction(value) or (inspect.isclass(value) and not issubclass(value, tuple) and value.__module__.startswith("crypto_pq.")):
                    patches.append(mock.patch.object(module, name, failing(f"{module.__name__}.{name}")))

        for patch in patches:
            patch.start()

        try:
            self.exercise()
        finally:
            for patch in patches:
                patch.stop()

    def exercise(self):
        for algorithm in HASHES:
            hasher = algorithm.create()

            hasher.update(b"abc")

            self.assertEqual(hasher.digest(), algorithm.digest(b"abc"))

        for algorithm in XOFS:
            xof = algorithm.create()

            xof.update(b"abc")

            self.assertEqual(xof.read(64), algorithm.digest(b"abc", 64))

        for algorithm in HMACS:
            hmac = algorithm.create(b"key")

            hmac.update(b"data")

            self.assertTrue(hmac.verify(algorithm.digest(b"key", b"data")))

            self.assertTrue(algorithm.verify(b"key", b"data", hmac.digest()))

        for algorithm in KEMS:
            pair = algorithm.generate_key_pair()

            sealed = pair.public_key.encapsulate()

            self.assertEqual(pair.private_key.decapsulate(sealed.ciphertext), sealed.shared_secret)

            for format in ("raw", "der", "pem") if algorithm._backend.oid else ("raw",):
                key = algorithm.import_private_key(pair.private_key.export_key(format), format)

                self.assertEqual(algorithm.import_public_key(key.public_key.export_key(format), format), pair.public_key)

            if algorithm._backend.expanded_size:
                key = algorithm.import_private_key(expanded_key(pair.private_key), "raw")

                self.assertEqual(key.decapsulate(sealed.ciphertext), sealed.shared_secret)

                self.assertEqual(key.export_key("raw"), expanded_key(key))

            self.assertEqual(hazmat.encapsulate(pair.public_key, bytes(algorithm._backend.randomness_size)), hazmat.encapsulate(pair.private_key.public_key, bytes(algorithm._backend.randomness_size)))

        for algorithm in ML_DSA + (crypto_pq.SLH_DSA_SHA2_128F, crypto_pq.SLH_DSA_SHAKE_128F):
            pair = algorithm.generate_key_pair()

            self.assertTrue(pair.public_key.verify(pair.private_key.sign(b"m"), b"m"))

            signature = pair.private_key.sign(b"m", context=b"c", deterministic=True, pre_hash=crypto_pq.SHA_512)

            self.assertTrue(pair.public_key.verify(signature, b"m", context=b"c", pre_hash=crypto_pq.SHA_512))

            self.assertFalse(pair.public_key.verify(signature, b"m"))

            signature = hazmat.sign(pair.private_key, b"m", bytes(algorithm._backend.randomness_size), pre_hash=crypto_pq.SHA_224)

            self.assertTrue(hazmat.verify(pair.public_key, signature, b"m", pre_hash=crypto_pq.SHA_224))

            for format in ("raw", "der", "pem"):
                key = algorithm.import_private_key(pair.private_key.export_key(format), format)

                self.assertTrue(algorithm.import_public_key(key.public_key.export_key(format), format).verify(key.sign(b"x"), b"x"))

            if algorithm._backend.expanded_size:
                self.assertTrue(pair.public_key.verify(algorithm.import_private_key(expanded_key(pair.private_key), "raw").sign(b"y"), b"y"))

        for algorithm, parameters in ((crypto_pq.HSS_LMS, TWO), (crypto_pq.XMSS_MT, "XMSSMT-SHA2_20/4_192")):
            store = MemoryStore()

            pair = algorithm.generate_key_pair(parameters=parameters, state_store=store, reserve=2)

            signatures = [pair.private_key.sign(bytes([i])) for i in range(3)]

            self.assertTrue(all(pair.public_key.verify(s, bytes([i])) for i, s in enumerate(signatures)))

            loaded = algorithm.load_private_key(store, tree_cache=pair.private_key.export_tree_cache())

            self.assertTrue(algorithm.import_public_key(pair.public_key.export_key("der"), "der").verify(loaded.sign(b"z"), b"z"))

            self.assertEqual(loaded.remaining_signatures(), (1 << 10 if algorithm is crypto_pq.HSS_LMS else 1 << 20) - 5)

        pair = hazmat.generate_key_pair(crypto_pq.XMSS, pattern(96), parameters="XMSS-SHA2_10_256", state_store=MemoryStore(), index=1023)

        self.assertTrue(pair.public_key.verify(pair.private_key.sign(b"last"), b"last"))


@unittest.skipUnless(NATIVE, "the native backend's slots")
class WipeTest(unittest.TestCase):
    # The slot memory of an object, which outlives the slot while the test holds it.
    def memory_of(self, slot):
        memory = slot._memory

        start = slot.address - _native._c.addressof(memory)

        return memory, memory.raw[start : start + slot.size]

    def assertWiped(self, make, slot_of):
        holder = [make()]

        slot = slot_of(holder[0])

        memory, content = self.memory_of(slot)

        self.assertTrue(any(content), "the slot holds nothing to wipe")

        del slot

        holder.clear()

        gc.collect()

        self.assertEqual(memory.raw, bytes(len(memory)))

    def test_slots(self):
        self.assertWiped(lambda: crypto_pq.ML_KEM_768.generate_key_pair().private_key, lambda key: key._private)

        self.assertWiped(lambda: crypto_pq.X_WING.generate_key_pair().private_key, lambda key: key._private)

        self.assertWiped(lambda: crypto_pq.ML_KEM_512.import_private_key(expanded_key(crypto_pq.ML_KEM_512.generate_key_pair().private_key), "raw"), lambda key: key._private)

        self.assertWiped(lambda: crypto_pq.ML_DSA_65.generate_key_pair().private_key, lambda key: key._private)

        self.assertWiped(lambda: crypto_pq.SLH_DSA_SHA2_128F.generate_key_pair(self_test=False).private_key, lambda key: key._private)

        self.assertWiped(lambda: crypto_pq.ML_DSA_44.generate_key_pair(), lambda pair: pair.public_key._state)

        self.assertWiped(lambda: crypto_pq.HMAC_SHA_512.create(b"secret key"), lambda hmac: hmac._engine._slot)

        self.assertWiped(lambda: crypto_pq.SHA3_256.create(), lambda hasher: hasher._engine._slot)

        self.assertWiped(lambda: crypto_pq.SHAKE256.create(), lambda xof: xof._engine._slot)

        self.assertWiped(lambda: crypto_pq.HSS_LMS.generate_key_pair(parameters=SMALL, state_store=MemoryStore()).private_key, lambda key: key._signer._slot)

    # A copy of a slot would keep its address and wipe it when it goes, so keys and states refuse
    # deep copies and pickling; a shallow copy shares the slot, which lives as long as either.
    def test_copies(self):
        pair = crypto_pq.ML_KEM_768.generate_key_pair()

        for value in (pair.private_key, pair.public_key, crypto_pq.ML_DSA_44.generate_key_pair().private_key):
            for function in (copy.deepcopy, pickle.dumps):
                with self.assertRaises(TypeError):
                    function(value)

        shallow = copy.copy(pair.private_key)

        sealed = pair.public_key.encapsulate()

        self.assertEqual(shallow.decapsulate(sealed.ciphertext), sealed.shared_secret)

        del shallow

        gc.collect()

        self.assertEqual(pair.private_key.decapsulate(sealed.ciphertext), sealed.shared_secret)

    # A wipe that the library refuses, as it does for a slot that a call holds, leaves the memory
    # allocated instead of freeing it under that call.
    def test_refused_wipe(self):
        slot = _native.Slot(_native.HASHER, 1)

        memory = slot._memory

        with mock.patch.object(_native.Slot, "wipe", staticmethod(lambda address, size: 104)):
            del slot

            gc.collect()

        self.assertEqual(len(_native.Slot.kept), 1)

        self.assertIs(_native.Slot.kept.pop(), memory)

    # A wiped slot is refused, never read as a key.
    def test_wiped_slot_is_refused(self):
        private_key = crypto_pq.ML_KEM_768.generate_key_pair().private_key

        sealed = private_key.public_key.encapsulate()

        slot = private_key._private

        _native.Slot.wipe(slot.address, slot.size)

        with self.assertRaises(RuntimeError):
            private_key.decapsulate(sealed.ciphertext)

        with self.assertRaises(RuntimeError):
            private_key.export_key("raw")

    def recorded(self, function):
        buffers, original = [], _native.output

        def record(size):
            buffer = original(size)

            buffers.append(buffer)

            return buffer

        with mock.patch.object(_native, "output", record):
            result = function()

        return result, buffers

    # The buffers that held secrets are zeroed once the secret is copied out.
    def test_secret_outputs(self):
        pair = crypto_pq.ML_KEM_768.generate_key_pair()

        sealed, buffers = self.recorded(pair.public_key.encapsulate)

        self.assertEqual([len(buffer) for buffer in buffers], [1088, 32])

        self.assertTrue(any(buffers[0].raw))

        self.assertEqual(buffers[1].raw, bytes(32))

        secret, buffers = self.recorded(lambda: pair.private_key.decapsulate(sealed.ciphertext))

        self.assertEqual((secret, [buffer.raw for buffer in buffers]), (sealed.shared_secret, [bytes(32)]))

        for key, size in ((pair.private_key, 64), (crypto_pq.ML_DSA_44.generate_key_pair().private_key, 32), (crypto_pq.SLH_DSA_SHAKE_128F.generate_key_pair(self_test=False).private_key, 64)):
            exported, buffers = self.recorded(lambda: key.export_key("raw"))

            self.assertEqual((len(exported), any(exported)), (size, True))

            self.assertEqual([buffer.raw for buffer in buffers], [bytes(size)])

        expanded, buffers = self.recorded(lambda: expanded_key(pair.private_key))

        self.assertEqual([buffer.raw for buffer in buffers], [bytes(len(expanded))])

        store = MemoryStore()

        pair, buffers = self.recorded(lambda: crypto_pq.HSS_LMS.generate_key_pair(parameters=SMALL, state_store=store))

        self.assertIn(bytes(len(store.state)), [buffer.raw for buffer in buffers])

        _, buffers = self.recorded(lambda: pair.private_key.sign(b"m"))

        self.assertIn(bytes(len(store.state)), [buffer.raw for buffer in buffers])


@unittest.skipUnless(NATIVE, "the native backend's caches")
class CacheTest(unittest.TestCase):
    def flags(self, slot):
        return _native.slot_info(slot)[2]

    # A key made from a seed holds its public cache at once, from the matrix that key generation
    # samples anyway; a key imported without a seed, and an imported public key, fill theirs at
    # first use; the public key of a private key copies the cache that it finds.
    def test_kem(self):
        for algorithm in KEMS:
            with self.subTest(algorithm=algorithm.name):
                pair = hazmat.generate_key_pair(algorithm, bytes(algorithm._backend.seed_size))

                self.assertEqual(self.flags(pair.private_key._private), 0x101)

                self.assertEqual(self.flags(pair.public_key._state), 0x100)

                public = algorithm.import_public_key(pair.public_key.export_key("raw"), "raw")

                self.assertEqual(self.flags(public._state), 0)

                public.encapsulate()

                self.assertEqual(self.flags(public._state), 0x100)

                if algorithm._backend.expanded_size is None:
                    continue

                private = algorithm.import_private_key(expanded_key(pair.private_key), "raw")

                self.assertEqual(self.flags(private._private), 0)

                self.assertEqual(self.flags(private.public_key._state), 0)

                private.decapsulate(bytes(algorithm.ciphertext_size))

                self.assertEqual(self.flags(private._private), 0x100)

    def test_ml_dsa(self):
        for algorithm in ML_DSA:
            with self.subTest(algorithm=algorithm.name):
                pair = hazmat.generate_key_pair(algorithm, bytes(32))

                self.assertEqual(self.flags(pair.private_key._private), 0x101)

                pair.private_key.sign(b"m")

                self.assertEqual(self.flags(pair.private_key._private), 0x301)

                public = algorithm.import_public_key(pair.public_key.export_key("raw"), "raw")

                self.assertEqual(self.flags(public._state), 0)

                public.verify(bytes(algorithm.signature_size), b"m")

                self.assertEqual(self.flags(public._state), 0x100)


class ThreadTest(unittest.TestCase):
    THREADS = 8

    ROUNDS = 6 if NATIVE else 2

    def run_threads(self, work, count=THREADS):
        barrier, errors = threading.Barrier(count), []

        def run(number):
            barrier.wait()

            try:
                work(number)
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=run, args=(number,)) for number in range(count)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        if errors:
            raise errors[0]

    # One key, used by every thread at once from its first use: the lazy caches are claimed by one
    # call and computed again by the others, never torn.
    def test_one_key(self):
        for algorithm in (crypto_pq.ML_KEM_768, crypto_pq.X_WING):
            pair = hazmat.generate_key_pair(algorithm, pattern(algorithm._backend.seed_size))

            public_key = algorithm.import_public_key(pair.public_key.export_key("raw"), "raw")

            private_key = algorithm.import_private_key(pair.private_key.export_key("raw"), "raw")

            randomness = [pattern(algorithm._backend.randomness_size, i) for i in range(self.ROUNDS)]

            expected = [hazmat.encapsulate(pair.public_key, r) for r in randomness]

            def work(number):
                for r, sealed in zip(randomness, expected):
                    self.assertEqual(hazmat.encapsulate(public_key, r), sealed)

                    self.assertEqual(private_key.decapsulate(sealed.ciphertext), sealed.shared_secret)

            self.run_threads(work)

        for algorithm in (crypto_pq.ML_DSA_65,):
            pair = hazmat.generate_key_pair(algorithm, pattern(32))

            private_key = algorithm.import_private_key(expanded_key(pair.private_key), "raw")

            public_key = algorithm.import_public_key(pair.public_key.export_key("raw"), "raw")

            messages = [bytes([i]) * 20 for i in range(self.ROUNDS)]

            expected = [pair.private_key.sign(m, deterministic=True) for m in messages]

            def work(number):
                for message, signature in zip(messages, expected):
                    self.assertEqual(private_key.sign(message, deterministic=True), signature)

                    self.assertTrue(public_key.verify(signature, message))

                    self.assertTrue(public_key.verify(private_key.sign(message), message))

            self.run_threads(work)

    # Hash states take one call at a time: concurrent updates land whole, in some order.
    def test_shared_hash_states(self):
        chunk = pattern(1000)

        for algorithm, digest in ((crypto_pq.SHA_256, lambda: crypto_pq.SHA_256.digest(chunk * self.THREADS * 50)), (crypto_pq.SHAKE128, lambda: crypto_pq.SHAKE128.digest(chunk * self.THREADS * 50, 100))):
            state = algorithm.create()

            self.run_threads(lambda number: [state.update(chunk) for _ in range(50)])

            self.assertEqual(state.read(100) if algorithm is crypto_pq.SHAKE128 else state.digest(), digest())

        hmac = crypto_pq.HMAC_SHA_384.create(b"key")

        self.run_threads(lambda number: [hmac.update(chunk) for _ in range(50)])

        self.assertTrue(hmac.verify(crypto_pq.HMAC_SHA_384.digest(b"key", chunk * self.THREADS * 50)))

    # Many keys at once, each made, used and dropped in its own thread.
    def test_many_keys(self):
        def work(number):
            for _ in range(self.ROUNDS):
                pair = crypto_pq.ML_KEM_512.generate_key_pair()

                sealed = pair.public_key.encapsulate()

                self.assertEqual(pair.private_key.decapsulate(sealed.ciphertext), sealed.shared_secret)

                signer = crypto_pq.ML_DSA_44.generate_key_pair()

                self.assertTrue(signer.public_key.verify(signer.private_key.sign(b"m"), b"m"))

                digest = crypto_pq.SHA3_512.create()

                digest.update(bytes([number]))

                self.assertEqual(digest.digest(), crypto_pq.SHA3_512.digest(bytes([number])))

        self.run_threads(work)

    # musl gives a thread 128 KiB of stack by default: the largest parameter sets fit in it.
    def test_small_stack(self):
        def work(number):
            for algorithm in (crypto_pq.ML_KEM_1024, crypto_pq.X_WING):
                pair = algorithm.generate_key_pair()

                sealed = pair.public_key.encapsulate()

                self.assertEqual(pair.private_key.decapsulate(sealed.ciphertext), sealed.shared_secret)

            for algorithm in (crypto_pq.ML_DSA_87, crypto_pq.SLH_DSA_SHA2_128F):
                pair = algorithm.generate_key_pair()

                self.assertTrue(pair.public_key.verify(pair.private_key.sign(b"m", pre_hash=crypto_pq.SHA3_512), b"m", pre_hash=crypto_pq.SHA3_512))

            pair = crypto_pq.HSS_LMS.generate_key_pair(parameters=SMALL, state_store=MemoryStore())

            self.assertTrue(pair.public_key.verify(pair.private_key.sign(b"m"), b"m"))

        previous = threading.stack_size(128 << 10)

        try:
            self.run_threads(work, 1)
        finally:
            threading.stack_size(previous)

    # One stateful key from many threads: a busy key fails at once, and no index signs twice.
    def test_stateful_key(self):
        store = MemoryStore()

        pair = crypto_pq.HSS_LMS.generate_key_pair(parameters=SMALL, state_store=store, reserve=4)

        signatures, lock = [], threading.Lock()

        def work(number):
            for _ in range(4):
                try:
                    signature = pair.private_key.sign(bytes([number]))
                except CryptoPQError as error:
                    self.assertIn(error.code, (ErrorCode.STATE_CONFLICT, ErrorCode.KEY_EXHAUSTED))

                    continue

                self.assertTrue(pair.public_key.verify(signature, bytes([number])))

                with lock:
                    signatures.append(signature)

        self.run_threads(work)

        indices = sorted(int.from_bytes(signature[4:8], "big") for signature in signatures)

        self.assertEqual(indices, list(range(len(indices))))

        self.assertEqual(pair.private_key.remaining_signatures(), 32 - len(indices))


# Each case runs in a fresh interpreter on a copy of the installed package, changed as the case
# needs: the backend is chosen once, at import.
PROBE = """
import sys
{prelude}
try:
    import crypto_pq
except ImportError as error:
    print("ImportError", error)
    raise SystemExit(0)
print(crypto_pq.BACKEND, "ctypes" in sys.modules, repr(crypto_pq.LOAD_ERROR))
"""


class ProbeCase(unittest.TestCase):
    PACKAGE = os.path.dirname(os.path.abspath(crypto_pq.__file__))

    HAS_LIBRARY = os.path.exists(os.path.join(PACKAGE, _native.RECORD))

    def setUp(self):
        self.directory = tempfile.mkdtemp()

        self.addCleanup(shutil.rmtree, self.directory)

        self.package = os.path.join(self.directory, "crypto_pq")

        shutil.copytree(self.PACKAGE, self.package, ignore=shutil.ignore_patterns("__pycache__"))

    def probe(self, backend=None, prelude=""):
        env = {key: value for key, value in os.environ.items() if key not in ("CRYPTO_PQ_BACKEND", "PYTHONPATH")}

        env["PYTHONPATH"] = self.directory

        if backend is not None:
            env["CRYPTO_PQ_BACKEND"] = backend

        result = subprocess.run([sys.executable, "-c", PROBE.format(prelude=prelude)], env=env, cwd=self.directory, capture_output=True, text=True, timeout=120)

        self.assertEqual(result.returncode, 0, result.stderr)

        return result.stdout.strip()

    def record(self):
        with open(os.path.join(self.package, _native.RECORD)) as handle:
            return dict(line.partition(" ")[::2] for line in handle.read().splitlines()[1:])

    def library(self):
        return os.path.join(self.package, self.record()["file"])

    def write_library(self, data, target=None, recorded=True):
        fields = self.record()

        with open(os.path.join(self.package, fields["file"]), "wb") as handle:
            handle.write(data)

        if recorded:
            fields.update(size=str(len(data)), crc32=f"{binascii.crc32(data):08x}", target=target or fields["target"])

            with open(os.path.join(self.package, _native.RECORD), "w") as handle:
                handle.write(_native.RECORD_FORMAT + "\n" + "".join(f"{key} {value}\n" for key, value in fields.items()))

    def read_library(self):
        with open(self.library(), "rb") as handle:
            return handle.read()

    def patch_module(self, old, new):
        path = os.path.join(self.package, "_native.py")

        with open(path) as handle:
            source = handle.read()

        self.assertIn(old, source)

        with open(path, "w") as handle:
            handle.write(source.replace(old, new))

    def assertPure(self, output, reason):
        backend, ctypes_loaded, error = output.split(" ", 2)

        self.assertEqual(backend, "pure", output)

        self.assertIn(reason, error)


class SelectionTest(ProbeCase):
    def test_choices(self):
        for value in ("typo", "", "NATIVE", "Pure"):
            with self.subTest(value=value):
                self.assertTrue(self.probe(value).startswith("ImportError CRYPTO_PQ_BACKEND must be auto, native or pure"))

        # The pure backend never maps the library, nor even imports ctypes.
        self.assertEqual(self.probe("pure"), "pure False None")

        if not self.HAS_LIBRARY:
            self.assertPure(self.probe(), "the package holds no native library")

            self.assertIn("the package holds no native library", self.probe("native"))

            return

        self.assertEqual(self.probe(), "native True None")

        self.assertEqual(self.probe("auto"), "native True None")

        self.assertEqual(self.probe("native"), "native True None")

    def test_no_library(self):
        if self.HAS_LIBRARY:
            os.remove(os.path.join(self.package, _native.RECORD))

        self.assertPure(self.probe(), "the package holds no native library")

        self.assertTrue(self.probe("native").startswith("ImportError CRYPTO_PQ_BACKEND is native, but the native library cannot be used: the package holds no native library"))


@unittest.skipUnless(ProbeCase.HAS_LIBRARY, "the package holds no native library")
class FallbackTest(ProbeCase):
    def check(self, reason, prelude=""):
        self.assertPure(self.probe(prelude=prelude), reason)

        self.assertTrue(self.probe("native", prelude).startswith("ImportError CRYPTO_PQ_BACKEND is native, but the native library cannot be used"), reason)

    def test_missing(self):
        os.remove(self.library())

        self.check("No such file")

    def test_truncated(self):
        data = self.read_library()

        self.write_library(data[: len(data) // 3], recorded=False)

        self.check("the native library is damaged")

        self.write_library(data[:4096], recorded=False)

        self.check("the native library is damaged")

    def test_bit_flipped(self):
        data = bytearray(self.read_library())

        data[len(data) // 2] ^= 0x10

        self.write_library(bytes(data), recorded=False)

        self.check("the native library is damaged")

    def test_record(self):
        record = os.path.join(self.package, _native.RECORD)

        with open(record) as handle:
            text = handle.read()

        for changed, reason in (
            (text.replace(_native.RECORD_FORMAT, "crypto-pq native library 2"), "unknown format"),
            ("".join(line + "\n" for line in text.splitlines() if not line.startswith("crc32")), "malformed"),
            (text.replace("file ", "file ../"), "names no crypto-pq library"),
        ):
            with open(record, "w") as handle:
                handle.write(changed)

            self.check(reason)

    # A library built for another platform is refused before it is mapped; one that claims this
    # platform is refused by the dynamic loader.
    def test_foreign_platform(self):
        running = _native.platform_target()

        other = "aarch64-linux" if running != "aarch64-linux" else "x86_64-linux"

        data = self.read_library()

        self.write_library(data, target=other)

        self.check(f"built for {other}")

        foreign = os.environ.get("CRYPTO_PQ_FOREIGN_LIBRARY")

        if foreign:
            with open(foreign, "rb") as handle:
                self.write_library(handle.read(), target=running)

            self.check("OSError")

    def test_garbage(self):
        data = self.read_library()

        self.write_library(data[:4] + Random(9).bytes(len(data) - 4))

        self.check("OSError")

    def test_abi_version(self):
        self.patch_module("ABI_VERSION = 1", "ABI_VERSION = 2")

        self.check("ABI version 1, and this package needs 2")

    def test_self_test(self):
        self.patch_module(_native.SELF_TEST_DIGEST, "00" * 32)

        self.check("the known-answer test failed")

    def test_no_ctypes(self):
        self.check("import of ctypes halted", prelude="sys.modules['ctypes'] = None")


if __name__ == "__main__":
    unittest.main()
