import ast
import binascii
import copy
import gc
import hashlib
import importlib
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
from crypto_pq import _hash, _keccak, _kem, _lms, _mldsa, _mlkem, _native, _sha2, _signature, _slhdsa, _stateful
from test_primitives import on_hashlib
from test_robustness import MemoryStore, Random, mutate, mutate_state, pattern
from vectors import expanded_key

NATIVE = crypto_pq.BACKEND == "native"

EXTENSION = _native.BINDING == "extension"

# CRYPTO_PQ_FUZZ=1 runs many more differential rounds, and every SLH-DSA set.
FUZZ = bool(os.environ.get("CRYPTO_PQ_FUZZ"))

SCALE = 20 if FUZZ else 1

HASHES = (crypto_pq.SHA_224, crypto_pq.SHA_256, crypto_pq.SHA_384, crypto_pq.SHA_512, crypto_pq.SHA_512_224, crypto_pq.SHA_512_256, crypto_pq.SHA3_224, crypto_pq.SHA3_256, crypto_pq.SHA3_384, crypto_pq.SHA3_512)

XOFS = (crypto_pq.SHAKE128, crypto_pq.SHAKE256)

HMACS = (crypto_pq.HMAC_SHA_224, crypto_pq.HMAC_SHA_256, crypto_pq.HMAC_SHA_384, crypto_pq.HMAC_SHA_512)

# The hash functions, XOFs and MACs after SHA-2, SHA-3 and HMAC, in the order of the C ABI's ids.
BLAKE2_HASHES = (
    crypto_pq.BLAKE2B_160,
    crypto_pq.BLAKE2B_256,
    crypto_pq.BLAKE2B_384,
    crypto_pq.BLAKE2B_512,
    crypto_pq.BLAKE2S_128,
    crypto_pq.BLAKE2S_160,
    crypto_pq.BLAKE2S_224,
    crypto_pq.BLAKE2S_256,
)

MORE_HASHES = (*BLAKE2_HASHES, crypto_pq.ASCON_HASH256)

MORE_XOFS = (crypto_pq.CSHAKE128, crypto_pq.CSHAKE256, crypto_pq.ASCON_XOF128, crypto_pq.ASCON_CXOF128)

MORE_MACS = (crypto_pq.KMAC128, crypto_pq.KMAC256, crypto_pq.BLAKE2B_MAC, crypto_pq.BLAKE2S_MAC)

KDFS = (crypto_pq.HKDF_SHA_256, crypto_pq.HKDF_SHA_384, crypto_pq.HKDF_SHA_512)

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
        twins[algorithm] = _hash._pure_hmac(algorithm.name, algorithm.digest_size, engines[hash_algorithm])

    # BLAKE2 on hashlib, a test-only oracle here, as in the pure backend.
    for algorithm in BLAKE2_HASHES:
        field, constructor = (16, hashlib.blake2b) if algorithm.name.startswith("BLAKE2b") else (8, hashlib.blake2s)

        twins[algorithm] = _hash._pure_blake2(algorithm.name, algorithm.digest_size, field, constructor)

    twins[crypto_pq.ASCON_HASH256] = _hash._pure_ascon_hash()

    twins[crypto_pq.CSHAKE128] = _hash._pure_cshake("cSHAKE128", 168, twins[crypto_pq.SHAKE128])

    twins[crypto_pq.CSHAKE256] = _hash._pure_cshake("cSHAKE256", 136, twins[crypto_pq.SHAKE256])

    twins[crypto_pq.ASCON_XOF128] = _hash._pure_ascon_xof()

    twins[crypto_pq.ASCON_CXOF128] = _hash._pure_ascon_cxof()

    twins[crypto_pq.KMAC128] = _hash._pure_kmac("KMAC128", 32, 168)

    twins[crypto_pq.KMAC256] = _hash._pure_kmac("KMAC256", 64, 136)

    twins[crypto_pq.BLAKE2B_MAC] = _hash._pure_blake2_mac("BLAKE2b-MAC", 64, 16, hashlib.blake2b)

    twins[crypto_pq.BLAKE2S_MAC] = _hash._pure_blake2_mac("BLAKE2s-MAC", 32, 8, hashlib.blake2s)

    for algorithm, hmac in zip(KDFS, HMACS[1:]):
        twins[algorithm] = _hash._pure_hkdf(algorithm.name, hmac.digest_size, twins[hmac])

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


def sysconfig_gil_disabled():
    import sysconfig

    return bool(sysconfig.get_config_var("Py_GIL_DISABLED"))


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

        self.assertEqual(_native.BINDING, ("extension" if _native.EXTENSION_ERROR is None else "ctypes") if NATIVE else None)

    # The extension module serves CPython with the GIL, and ctypes every other interpreter.
    def test_binding(self):
        refusal = _native.extension_refusal()

        if sys.implementation.name != "cpython":
            self.assertIn("needs CPython", refusal)
        elif sysconfig_gil_disabled():
            self.assertIn("free-threaded", refusal)
        else:
            self.assertIsNone(refusal)

        if NATIVE and refusal is not None:
            self.assertEqual((_native.BINDING, _native.EXTENSION_ERROR), ("ctypes", refusal))

    # A build whose objects lie otherwise than in the stable ABI is refused by its configuration,
    # before anything is loaded.
    @unittest.skipUnless(sys.implementation.name == "cpython", "CPython's build configuration")
    def test_refused_builds(self):
        import sysconfig

        for name, reason in (("Py_GIL_DISABLED", "free-threaded"), ("Py_TRACE_REFS", "Py_TRACE_REFS")):
            with self.subTest(name=name), mock.patch.object(sysconfig, "get_config_var", lambda key, name=name: 1 if key == name else 0):
                self.assertIn(reason, _native.extension_refusal())


# Whether the native library's own detection finds DIT: bit 16 of cpq_cpu_features, read through
# ctypes from the plain library in the package, which the extension module is built beside.
def library_has_dit():
    import ctypes

    directory = os.path.dirname(os.path.abspath(crypto_pq.__file__))

    _, files = _native.read_record(directory)

    return bool(ctypes.CDLL(os.path.join(directory, files["library"][0])).cpq_cpu_features() & 16)


class DataIndependentTimingTest(unittest.TestCase):
    # The switch answers whether MAC and KDF calls now run under DIT: where the library finds DIT,
    # and never with the pure backend. It answers the same every time and changes no output.
    def test_switch(self):
        def outputs():
            return [algorithm.digest(b"key", b"data") for algorithm in HMACS + MORE_MACS] + [algorithm.derive(b"ikm", 42, salt=b"salt", info=b"info") for algorithm in KDFS]

        before = outputs()

        enabled = crypto_pq.enable_data_independent_timing()

        self.assertIs(enabled, NATIVE and library_has_dit())

        self.assertIs(crypto_pq.enable_data_independent_timing(), enabled)

        self.assertEqual(outputs(), before)

        self.assertIn("enable_data_independent_timing", crypto_pq.__all__)


@unittest.skipUnless(NATIVE, "compares the native backend with the pure one")
class DifferentialTest(unittest.TestCase):
    # The pure algorithms hash through hashlib here, a test-only oracle apart from both of
    # crypto-pq's engines: on crypto-pq's own pure engines, which test_primitives checks against
    # hashlib, every SLH-DSA signature would take seconds.
    @classmethod
    def setUpClass(cls):
        cls.twins = pure_twins()

        cls.enterClassContext(on_hashlib())

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

    # Each new algorithm, plain and configured with random options, against its pure twin: digests
    # one-shot and streamed, XOF reads in pieces, tags and their verification, and HKDF.
    def test_symmetric(self):
        rng = Random(303)

        def options(*names, field=16):
            return {name: rng.bytes(rng.below(field + 1)) for name in names if rng.below(2)}

        hashes, xofs, macs = [], [], []

        for _ in range(2 * SCALE):
            for algorithm in MORE_HASHES:
                chosen = options("salt", "personalization", field=16 if algorithm.name.startswith("BLAKE2b") else 8) if algorithm in BLAKE2_HASHES else {}

                hashes.append((algorithm.configure(**chosen), self.twins[algorithm].configure(**chosen)))

            for algorithm in MORE_XOFS:
                chosen = {"customization": rng.bytes(rng.below(257 if algorithm is crypto_pq.ASCON_CXOF128 else 400))} if algorithm in (crypto_pq.CSHAKE128, crypto_pq.CSHAKE256, crypto_pq.ASCON_CXOF128) else {}

                xofs.append((algorithm.configure(**chosen), self.twins[algorithm].configure(**chosen)))

            for algorithm in MORE_XOFS[:2]:
                function_name, customization = rng.bytes(rng.below(200)), rng.bytes(rng.below(200))

                xofs.append((hazmat.configure_cshake(algorithm, function_name, customization), hazmat.configure_cshake(self.twins[algorithm], function_name, customization)))

            for algorithm in MORE_MACS:
                if algorithm.name.startswith("KMAC"):
                    chosen = {"length": 4 + rng.below(300), "customization": rng.bytes(rng.below(300)), "xof": bool(rng.below(2))}
                else:
                    chosen = {"length": 1 + rng.below(algorithm.digest_size), **options("salt", "personalization", field=algorithm.digest_size // 4)}

                macs.append((algorithm, self.twins[algorithm]))

                macs.append((algorithm.configure(**chosen), self.twins[algorithm].configure(**chosen)))

        sizes = [0, 1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 135, 136, 137, 167, 168, 169] + [rng.below(3000) for _ in range(5 * SCALE)]

        for size in sizes:
            data = rng.bytes(size)

            for algorithm, twin in hashes:
                self.assertEqual(algorithm.digest(data), twin.digest(data), (algorithm.name, size))

                hasher, reference = algorithm.create(), twin.create()

                for piece in self.pieces(rng, data):
                    hasher.update(piece)

                    reference.update(piece)

                self.assertEqual(hasher.digest(), reference.digest())

            for algorithm, twin in xofs:
                length = rng.below(600)

                self.assertEqual(algorithm.digest(data, length), twin.digest(data, length), (algorithm.name, size, length))

                xof, reference = algorithm.create(), twin.create()

                for piece in self.pieces(rng, data):
                    xof.update(piece)

                    reference.update(piece)

                for _ in range(3):
                    length = rng.below(400)

                    self.assertEqual(xof.read(length), reference.read(length))

                self.assertEqual(outcome(xof.update, b"x"), outcome(reference.update, b"x"))

            for algorithm, twin in macs:
                maximum = 400 if algorithm.name.startswith("KMAC") else 64 if algorithm.name.startswith("BLAKE2b") else 32

                key = rng.bytes(rng.below(maximum + 2))

                self.assertEqual(outcome(algorithm.digest, key, data), outcome(twin.digest, key, data), (algorithm.name, size, len(key)))

                if outcome(algorithm.create, key)[0] != "ok":
                    self.assertEqual(outcome(algorithm.create, key)[0], outcome(twin.create, key)[0])

                    self.assertFalse(algorithm.verify(key, data, bytes(algorithm.digest_size)))

                    continue

                tag = algorithm.digest(key, data)

                mac, reference = algorithm.create(key), twin.create(key)

                for piece in self.pieces(rng, data):
                    mac.update(piece)

                    reference.update(piece)

                self.assertEqual(mac.digest(), reference.digest())

                for candidate in (tag, mutate(rng, tag), tag[:-1], tag + b"\x00", b""):
                    self.assertEqual(algorithm.verify(key, data, candidate), twin.verify(key, data, candidate))

                    self.assertEqual(mac.verify(candidate), reference.verify(candidate))

            for algorithm in KDFS:
                twin, length, salt, info = self.twins[algorithm], rng.below(9000), rng.bytes(rng.below(300)), rng.bytes(rng.below(300))

                self.assertEqual(outcome(algorithm.derive, data, length, salt=salt, info=info), outcome(twin.derive, data, length, salt=salt, info=info), (algorithm.name, size, length))

                self.assertEqual(algorithm.extract(data, salt=salt), twin.extract(data, salt=salt))

                prk = data[: rng.below(100)]

                self.assertEqual(outcome(algorithm.expand, prk, length, info=info), outcome(twin.expand, prk, length, info=info), (algorithm.name, len(prk), length))

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


# The modules of the public API, the shared helpers and the bindings; every other module of the
# package holds pure algorithm code.
NOT_PURE = {"__init__", "_bytes", "_encoding", "_errors", "_hash", "_keys", "_kem", "_native", "_native_ctypes", "_native_extension", "_rng", "_signature", "_stateful", "hazmat"}


def pure_modules():
    names = sorted(name[:-3] for name in os.listdir(os.path.dirname(crypto_pq.__file__)) if name.endswith(".py") and name[:-3] not in NOT_PURE)

    return tuple(importlib.import_module(f"crypto_pq.{name}") for name in names)


@unittest.skipUnless(NATIVE, "the native backend")
class IsolationTest(unittest.TestCase):
    PURE_MODULES = pure_modules()

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

        configured = (crypto_pq.BLAKE2B_256.configure(salt=b"s", personalization=b"p"), crypto_pq.BLAKE2S_128.configure(salt=b"s"))

        for algorithm in MORE_HASHES + configured:
            hasher = algorithm.create()

            hasher.update(b"abc")

            self.assertEqual(hasher.digest(), algorithm.digest(b"abc"))

        configured = (crypto_pq.CSHAKE128.configure(customization=b"c"), hazmat.configure_cshake(crypto_pq.CSHAKE256, b"N", b"S"), crypto_pq.ASCON_CXOF128.configure(customization=b"z"))

        for algorithm in MORE_XOFS + configured:
            xof = algorithm.create()

            xof.update(b"abc")

            self.assertEqual(xof.read(64), algorithm.digest(b"abc", 64))

        configured = (crypto_pq.KMAC128.configure(length=20, customization=b"c", xof=True), crypto_pq.BLAKE2S_MAC.configure(length=7, salt=b"s"))

        for algorithm in MORE_MACS + configured:
            mac = algorithm.create(b"key")

            mac.update(b"data")

            self.assertTrue(mac.verify(algorithm.digest(b"key", b"data")))

            self.assertTrue(algorithm.verify(b"key", b"data", mac.digest()))

            self.assertFalse(algorithm.verify(bytes(65), b"data", mac.digest()))

        for algorithm in KDFS:
            prk = algorithm.extract(b"ikm", salt=b"salt")

            self.assertEqual(algorithm.expand(prk, 100, info=b"info"), algorithm.derive(b"ikm", 100, salt=b"salt", info=b"info"))

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
    # The memory that holds a slot (a ctypes buffer or the extension's bytearray), which outlives
    # the slot while the test holds it.
    def memory_of(self, slot):
        memory = slot._memory

        return memory, bytes(memory)[slot.offset : slot.offset + slot.size]

    def assertWiped(self, make, slot_of):
        holder = [make()]

        slot = slot_of(holder[0])

        memory, content = self.memory_of(slot)

        self.assertTrue(any(content), "the slot holds nothing to wipe")

        del slot

        holder.clear()

        gc.collect()

        self.assertEqual(bytes(memory), bytes(len(memory)))

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

        self.assertWiped(lambda: crypto_pq.KMAC256.create(b"secret key"), lambda mac: mac._engine._slot)

        self.assertWiped(lambda: crypto_pq.BLAKE2S_MAC.configure(length=9).create(b"secret key"), lambda mac: mac._engine._slot)

        self.assertWiped(lambda: crypto_pq.BLAKE2B_512.configure(salt=b"s"), lambda algorithm: algorithm._digest.args[0])

        self.assertWiped(lambda: crypto_pq.ASCON_CXOF128.configure(customization=b"c"), lambda algorithm: algorithm._digest.args[0])

        self.assertWiped(lambda: crypto_pq.KMAC128.configure(customization=b"c"), lambda algorithm: algorithm._verify.args[0])

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

    # A wipe that the library refuses, as it does for a slot that a call is inside, keeps the
    # memory allocated rather than free it under that call: the ctypes binding keeps the buffer in
    # Slot.kept, and the extension module keeps its bytearray exported for good. The test counts a
    # call in the users field of the slot's header (after the magic, the algorithm, the size and
    # the flags), which no call leaves.
    def test_refused_wipe(self):
        hasher = crypto_pq.SHA3_256.create()

        hasher.update(b"a state to keep")

        slot = hasher._engine._slot

        memory, users = slot._memory, slot.offset + 20

        memory[users] = 1 if isinstance(memory, bytearray) else b"\x01"

        before = bytes(memory)

        kept = [] if EXTENSION else _native.Slot.kept

        count = len(kept)

        del slot, hasher

        gc.collect()

        if EXTENSION:
            with self.assertRaises(BufferError):
                memory.append(0)
        else:
            self.assertTrue(any(item is memory for item in kept[count:]))

            del kept[count:]

        after = bytes(memory)

        # The wipe marked the call's count and stopped there.
        self.assertEqual(after[:users] + after[users + 4 :], before[:users] + before[users + 4 :])

    # A wiped slot is refused, never read as a key.
    def test_wiped_slot_is_refused(self):
        private_key = crypto_pq.ML_KEM_768.generate_key_pair().private_key

        sealed = private_key.public_key.encapsulate()

        self.assertEqual(_native.wipe(private_key._private), 0)

        with self.assertRaises(RuntimeError):
            private_key.decapsulate(sealed.ciphertext)

        with self.assertRaises(RuntimeError):
            private_key.export_key("raw")

    def recorded(self, function):
        buffers, original = [], _native.binding.output

        def record(size):
            buffer = original(size)

            buffers.append(buffer)

            return buffer

        with mock.patch.object(_native.binding, "output", record):
            result = function()

        return result, buffers

    # The buffers that held secrets are zeroed once the secret is copied out. The extension module
    # writes each output straight into the bytes object that it returns.
    @unittest.skipIf(EXTENSION, "the extension module has no output buffers to zero")
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

        prk, buffers = self.recorded(lambda: crypto_pq.HKDF_SHA_384.extract(b"ikm"))

        self.assertEqual((len(prk), [buffer.raw for buffer in buffers]), (48, [bytes(48)]))

        for function in (lambda: crypto_pq.HKDF_SHA_384.expand(prk, 100), lambda: crypto_pq.HKDF_SHA_256.derive(b"ikm", 100)):
            okm, buffers = self.recorded(function)

            self.assertEqual((len(okm), any(okm), [buffer.raw for buffer in buffers]), (100, True, [bytes(100)]))


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

    # A configured algorithm's slot serves every thread at once: the calls only read it.
    def test_shared_configured(self):
        algorithms = (crypto_pq.BLAKE2B_256.configure(salt=b"salt"), crypto_pq.KMAC256.configure(length=40, customization=b"c"), crypto_pq.ASCON_CXOF128.configure(customization=b"z"))

        messages = [pattern(3000, i) for i in range(self.ROUNDS)]

        expected = [(algorithms[0].digest(m), algorithms[1].digest(b"key", m), algorithms[2].digest(m, 50)) for m in messages]

        def work(number):
            for message, values in zip(messages, expected):
                self.assertEqual((algorithms[0].digest(message), algorithms[1].digest(b"key", message), algorithms[2].digest(message, 50)), values)

                self.assertTrue(algorithms[1].verify(b"key", message, values[1]))

        self.run_threads(work)

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
# needs: the backend and its binding are chosen once, at import.
PROBE = """
import sys
{prelude}
try:
    import crypto_pq
    from crypto_pq import _native
except ImportError as error:
    print(repr(("ImportError", str(error))))
    raise SystemExit(0)
print(repr((crypto_pq.BACKEND, _native.BINDING, sys.modules.get("ctypes") is not None, crypto_pq.LOAD_ERROR, _native.EXTENSION_ERROR)))
"""

# Whether this interpreter can load the extension module, and why not.
REFUSAL = _native.extension_refusal()


class ProbeCase(unittest.TestCase):
    PACKAGE = os.path.dirname(os.path.abspath(crypto_pq.__file__))

    HAS_LIBRARY = os.path.exists(os.path.join(PACKAGE, _native.RECORD))

    def setUp(self):
        self.directory = tempfile.mkdtemp()

        self.addCleanup(shutil.rmtree, self.directory)

        self.package = os.path.join(self.directory, "crypto_pq")

        shutil.copytree(self.PACKAGE, self.package, ignore=shutil.ignore_patterns("__pycache__"))

    # (backend, binding, whether ctypes was imported, LOAD_ERROR, EXTENSION_ERROR), or
    # ("ImportError", message).
    def probe(self, backend=None, prelude=""):
        env = {key: value for key, value in os.environ.items() if key not in ("CRYPTO_PQ_BACKEND", "PYTHONPATH")}

        env["PYTHONPATH"] = self.directory

        if backend is not None:
            env["CRYPTO_PQ_BACKEND"] = backend

        result = subprocess.run([sys.executable, "-c", PROBE.format(prelude=prelude)], env=env, cwd=self.directory, capture_output=True, text=True, timeout=120)

        self.assertEqual(result.returncode, 0, result.stderr)

        return ast.literal_eval(result.stdout.strip())

    def record_lines(self):
        with open(os.path.join(self.package, _native.RECORD)) as handle:
            return handle.read().splitlines()

    def write_record(self, lines):
        with open(os.path.join(self.package, _native.RECORD), "w") as handle:
            handle.write("".join(line + "\n" for line in lines))

    def entry(self, role):
        return next(line.split(" ")[1:] for line in self.record_lines() if line.startswith(role + " "))

    def path(self, role):
        return os.path.join(self.package, self.entry(role)[0])

    def read(self, role):
        with open(self.path(role), "rb") as handle:
            return handle.read()

    # Replaces a native file, and its line in the record unless `recorded` is false.
    def write(self, role, data, recorded=True):
        name = self.entry(role)[0]

        with open(self.path(role), "wb") as handle:
            handle.write(data)

        if recorded:
            self.write_record([f"{role} {name} {len(data)} {binascii.crc32(data):08x}" if line.startswith(role + " ") else line for line in self.record_lines()])

    def patch_module(self, old, new):
        path = os.path.join(self.package, "_native.py")

        with open(path) as handle:
            source = handle.read()

        self.assertIn(old, source)

        with open(path, "w") as handle:
            handle.write(source.replace(old, new))

    def assertPure(self, found, reason):
        self.assertEqual(found[:2], ("pure", None), found)

        self.assertIn(reason, found[3])

    def assertRefused(self, reason, prelude=""):
        found = self.probe("native", prelude)

        self.assertEqual(found[0], "ImportError", found)

        self.assertTrue(found[1].startswith("CRYPTO_PQ_BACKEND is native, but the native library cannot be used"), found)

        self.assertIn(reason, found[1])


class SelectionTest(ProbeCase):
    def test_choices(self):
        for value in ("typo", "", "NATIVE", "Pure", "ctypes"):
            with self.subTest(value=value):
                self.assertEqual(self.probe(value), ("ImportError", f"CRYPTO_PQ_BACKEND must be auto, native or pure, not {value!r}"))

        # The pure backend never maps a native file, nor even imports ctypes.
        self.assertEqual(self.probe("pure"), ("pure", None, False, None, None))

        if not self.HAS_LIBRARY:
            self.assertPure(self.probe(), "the package holds no native library")

            self.assertRefused("the package holds no native library")

            return

        # The extension module needs no ctypes.
        expected = ("native", "extension", False, None, None) if REFUSAL is None else ("native", "ctypes", True, None, REFUSAL)

        for backend in (None, "auto", "native"):
            self.assertEqual(self.probe(backend), expected)

    def test_no_library(self):
        if self.HAS_LIBRARY:
            os.remove(os.path.join(self.package, _native.RECORD))

        self.assertPure(self.probe(), "the package holds no native library")

        self.assertRefused("the native library cannot be used: the package holds no native library")


@unittest.skipUnless(ProbeCase.HAS_LIBRARY, "the package holds no native library")
class FallbackTest(ProbeCase):
    # The extension module is unusable for `reason`: ctypes serves instead.
    def without_extension(self, reason, prelude=""):
        found = self.probe(prelude=prelude)

        self.assertEqual(found[:4], ("native", "ctypes", True, None), found)

        self.assertIn(reason if REFUSAL is None else REFUSAL, found[4])

    # The library is unusable for `reason`: the extension module serves where it can, and the pure
    # backend elsewhere, as it does where the extension module is blocked.
    def without_library(self, reason, prelude=""):
        if REFUSAL is None:
            self.assertEqual(self.probe(prelude=prelude), ("native", "extension", False, None, None))

            prelude += "\nsys.modules['crypto_pq._cpq'] = None"

        self.assertPure(self.probe(prelude=prelude), reason)

        self.assertRefused(reason, prelude)

    # Neither file is usable: the pure backend, with both reasons.
    def without_either(self, library_reason, extension_reason, prelude=""):
        found = self.probe(prelude=prelude)

        self.assertPure(found, library_reason)

        self.assertIn(extension_reason if REFUSAL is None else REFUSAL, found[4])

        self.assertRefused(library_reason, prelude)

    def test_missing(self):
        extension, library = self.path("extension"), self.path("library")

        os.rename(extension, extension + ".gone")

        self.without_extension("No such file")

        os.rename(extension + ".gone", extension)

        os.remove(library)

        self.without_library("No such file")

        os.remove(extension)

        self.without_either("No such file", "No such file")

    def test_truncated(self):
        extension, library = self.read("extension"), self.read("library")

        for size in (len(extension) // 3, 4096):
            self.write("extension", extension[:size], recorded=False)

            self.without_extension("the extension module is damaged")

        self.write("extension", extension, recorded=False)

        self.write("library", library[: len(library) // 3], recorded=False)

        self.without_library("the native library is damaged")

    def test_bit_flipped(self):
        for role, reason in (("extension", "the extension module is damaged"), ("library", "the native library is damaged")):
            data = self.read(role)

            flipped = bytearray(data)

            flipped[len(data) // 2] ^= 0x10

            self.write(role, bytes(flipped), recorded=False)

            (self.without_extension if role == "extension" else self.without_library)(reason)

            self.write(role, data, recorded=False)

    def test_record(self):
        lines = self.record_lines()

        for changed, reason in (
            ([lines[0].replace("files 1", "files 2")] + lines[1:], "unknown format"),
            ([line.rsplit(" ", 1)[0] if line.startswith("library ") else line for line in lines], "malformed"),
            ([line for line in lines if not line.startswith("target ")], "malformed"),
            (lines + [lines[-1]], "malformed"),
        ):
            with self.subTest(reason=reason, record=changed):
                self.write_record(changed)

                found = self.probe()

                self.assertPure(found, reason)

                self.assertIsNone(found[4])

                self.assertRefused(reason)

        self.write_record([line.replace("library ", "library ../") for line in lines])

        self.without_library("names no crypto-pq native library")

        self.write_record([line.replace("extension ", "extension ../") for line in lines])

        self.without_extension("names no crypto-pq extension module")

        self.write_record([line for line in lines if not line.startswith("extension ")])

        self.without_extension("the package holds no extension module")

    # Files built for another platform are refused before they are mapped; files that claim this
    # platform are refused by the dynamic loader. CRYPTO_PQ_FOREIGN_DIST names the `zig build dist`
    # directory of another platform, for the second check.
    def test_foreign_platform(self):
        running = _native.platform_target()

        other = "aarch64-linux" if running != "aarch64-linux" else "x86_64-linux"

        lines = self.record_lines()

        self.write_record([f"target {other}" if line.startswith("target ") else line for line in lines])

        self.assertPure(self.probe(), f"built for {other}")

        self.assertRefused(f"built for {other}")

        foreign = os.environ.get("CRYPTO_PQ_FOREIGN_DIST")

        if not foreign:
            return

        self.write_record(lines)

        names = {entry.name for entry in os.scandir(foreign)}

        for role, names_of_role, error in (("extension", _native.EXTENSIONS, "ImportError"), ("library", _native.LIBRARIES, "OSError")):
            original = self.read(role)

            with open(os.path.join(foreign, next(name for name in names_of_role if name in names)), "rb") as handle:
                self.write(role, handle.read())

            (self.without_extension if role == "extension" else self.without_library)(error)

            self.write(role, original)

    def test_garbage(self):
        for role, error in (("extension", "ImportError"), ("library", "OSError")):
            data = self.read(role)

            self.write(role, data[:4] + Random(9).bytes(len(data) - 4))

            (self.without_extension if role == "extension" else self.without_library)(error)

            self.write(role, data)

    def test_abi_version(self):
        self.patch_module("ABI_VERSION = 2", "ABI_VERSION = 3")

        self.without_either("the native library has ABI version 2, and this package needs 3", "the extension module has ABI version 2, and this package needs 3")

    def test_self_test(self):
        self.patch_module(_native.SELF_TEST_DIGEST, "00" * 32)

        self.without_either("the known-answer test failed", "the known-answer test failed")

    def test_no_ctypes(self):
        self.without_library("import of ctypes halted", prelude="sys.modules['ctypes'] = None")

    # A None in sys.modules blocks the extension module, as it blocks an import: the test suite's
    # way to run with ctypes where the extension would serve.
    def test_blocked_extension(self):
        self.without_extension("import of crypto_pq._cpq halted", prelude="sys.modules['crypto_pq._cpq'] = None")


@unittest.skipUnless(EXTENSION, "the extension module")
class ExtensionTest(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module("crypto_pq._cpq")

    # The switch is the module's own function, which calls the library in place.
    def test_data_independent_timing(self):
        self.assertIs(_native.binding.enable_data_independent_timing, self.module.enable_data_independent_timing)

        self.assertIs(self.module.enable_data_independent_timing(), library_has_dit())

    # The module that passed the known-answer test is the one that an import finds.
    def test_registered(self):
        self.assertIs(self.module.Slot, _native.Slot)

        self.assertIs(getattr(crypto_pq, "_cpq"), self.module)

        with self.assertRaises(TypeError):
            self.module.Slot()

    # A one-shot hash, XOF or MAC is one call of the module.
    def test_shortest_path(self):
        for number, algorithm in enumerate(HASHES + MORE_HASHES):
            self.assertIs(algorithm._digest, getattr(self.module, f"hash{number}"))

        for number, algorithm in enumerate(XOFS + MORE_XOFS):
            self.assertIs(algorithm._digest, getattr(self.module, f"xof{number}"))

        for number, algorithm in enumerate(HMACS + MORE_MACS):
            self.assertIs(algorithm._digest, getattr(self.module, f"mac{number}"))

            self.assertIs(algorithm._verify, getattr(self.module, f"mac_verify{number}"))

    def test_arguments(self):
        data = b"crypto-pq"

        self.assertEqual(crypto_pq.SHA_256.digest(memoryview(b"x" + data)[1:]), crypto_pq.SHA_256.digest(bytearray(data)))

        for wrong in ("text", 3, None, memoryview(data)[::2]):
            with self.subTest(wrong=wrong), self.assertRaises(TypeError):
                crypto_pq.SHA_256.digest(wrong)

        with self.assertRaises(TypeError):
            crypto_pq.SHAKE128.digest(data, 1.5)

        with self.assertRaises(CryptoPQError) as caught:
            crypto_pq.SHAKE128.digest(data, -1)

        self.assertEqual(caught.exception.code, ErrorCode.INVALID_LENGTH)

        self.assertEqual(crypto_pq.SHAKE128.digest(data, True), crypto_pq.SHAKE128.digest(data, 1))

        for call in (lambda: self.module.hash1(), lambda: self.module.hash1(data, data), lambda: self.module.kem_decapsulate(data, data), lambda: self.module.kem_generate(-1, bytes(64))):
            with self.assertRaises((TypeError, OverflowError)):
                call()

        with self.assertRaises(OverflowError):
            self.module.kem_generate(1 << 32, bytes(64))

        with self.assertRaisesRegex(RuntimeError, "status 101"):
            self.module.kem_generate(4, bytes(64))

    # A long hash leaves the GIL to other threads and keeps its input exported meanwhile: another
    # thread can run during the call, and finds that it cannot resize the bytearray being hashed.
    def test_gil(self):
        data, seen, done = bytearray(8 << 20), [], threading.Event()

        def resize():
            while not done.is_set():
                try:
                    data.append(0)

                    del data[-1]
                except BufferError:
                    seen.append(True)

                    return

        thread = threading.Thread(target=resize)

        thread.start()

        try:
            for _ in range(200):
                if seen:
                    break

                crypto_pq.SHA3_512.digest(data)
        finally:
            done.set()

            thread.join()

        self.assertTrue(seen)


if __name__ == "__main__":
    unittest.main()
