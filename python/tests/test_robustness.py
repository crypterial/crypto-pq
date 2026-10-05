import os
import threading
import time
import tracemalloc
import unittest

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode, hazmat
from crypto_pq import _encoding as encoding
from crypto_pq import _keys as keys
from vectors import expanded_key

# Untrusted input gets only the defined errors: random and mutated encodings, signatures,
# ciphertexts and state blobs through every parsing path. A deterministic generator keeps each run
# reproducible; CRYPTO_PQ_FUZZ=1 runs many more rounds, CRYPTO_PQ_SLOW=1 the 16 MiB inputs.
FUZZ = bool(os.environ.get("CRYPTO_PQ_FUZZ"))

SLOW = bool(os.environ.get("CRYPTO_PQ_SLOW"))

SCALE = 50 if FUZZ else 1

MASK = (1 << 64) - 1

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

# The fast sets by default; every set in a long run.
SIGNATURES = ML_DSA + (SLH_DSA if FUZZ else (crypto_pq.SLH_DSA_SHA2_128F, crypto_pq.SLH_DSA_SHAKE_128F))

STATEFUL = (crypto_pq.HSS_LMS, crypto_pq.XMSS, crypto_pq.XMSS_MT)

PRE_HASHES = (
    None,
    crypto_pq.SHA_224,
    crypto_pq.SHA_256,
    crypto_pq.SHA_384,
    crypto_pq.SHA_512,
    crypto_pq.SHA_512_224,
    crypto_pq.SHA_512_256,
    crypto_pq.SHA3_224,
    crypto_pq.SHA3_256,
    crypto_pq.SHA3_384,
    crypto_pq.SHA3_512,
    crypto_pq.SHAKE128,
    crypto_pq.SHAKE256,
)

STRENGTH = {
    crypto_pq.SHA_224: 112,
    crypto_pq.SHA_512_224: 112,
    crypto_pq.SHA3_224: 112,
    crypto_pq.SHA_256: 128,
    crypto_pq.SHA_512_256: 128,
    crypto_pq.SHA3_256: 128,
    crypto_pq.SHAKE128: 128,
    crypto_pq.SHA_384: 192,
    crypto_pq.SHA3_384: 192,
    crypto_pq.SHA_512: 256,
    crypto_pq.SHA3_512: 256,
    crypto_pq.SHAKE256: 256,
}

TAGS = (0x02, 0x03, 0x04, 0x06, 0x30, 0x80, 0x81, 0xA0)

# Indefinite, gigabytes, non-minimal, five bytes long, and plain wrong lengths.
LENGTHS = (b"\x80", b"\x84\xff\xff\xff\xff", b"\x84\x7f\xff\xff\xff", b"\x83\xff\xff\xff", b"\x82\xff\xff", b"\x81\x05", b"\x81\x7f", b"\x82\x00\x80", b"\x85\x01\x00\x00\x00\x00", b"\x00", b"\x01", b"\x7f")

OIDS = tuple(
    encoding.element(0x06, encoding.object_identifier(dotted))
    for dotted in (
        *(f"2.16.840.1.101.3.4.4.{arc}" for arc in (1, 2, 3, 4)),
        *(f"2.16.840.1.101.3.4.3.{arc}" for arc in range(16, 48)),
        "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.9.16.3.17",
        "1.3.6.1.5.5.7.6.34",
        "1.3.6.1.5.5.7.6.35",
    )
) + (b"\x06\x00", b"\x06\x01\x00", b"\x06\x81\x01\x2a")

SPACES = (b" ", b"\t", b"\n", b"\r\n", b"\x0b", b"\x0c")

# LM-OTS and LMS type codes: the hash output size, and Winternitz width or tree height.
OTS_W = {1 + 4 * family + j: w for family in range(4) for j, w in enumerate((1, 2, 4, 8))}

LMS_H = {5 + 5 * family + j: h for family in range(4) for j, h in enumerate((5, 10, 15, 20, 25))}

# The XMSS^MT 20/4 code points: four layers of height 5, the only XMSS keys cheap enough to load
# here.
XMSS_MT_SMALL = {0x02, 0x22, 0x2A, 0x32}


class Random:
    """SplitMix64, the generator of every implementation's robustness tests."""

    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK

        z = self.state

        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK

        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK

        return z ^ (z >> 31)

    def below(self, bound):
        return self.next() % bound

    def bytes(self, size):
        return bytes(self.next() & 0xFF for _ in range(size))

    def choice(self, items):
        return items[self.below(len(items))]


def pattern(size, first=0):
    return bytes((first + i) & 0xFF for i in range(size))


def tag_position(rng, data):
    for _ in range(16):
        position = rng.below(len(data))

        if data[position] in TAGS and position + 1 < len(data):
            return position

    return None


def oid_position(rng, data):
    starts = [i for i in range(len(data) - 1) if data[i] == 0x06 and data[i + 1] < 0x10 and i + 2 + data[i + 1] <= len(data)]

    return rng.choice(starts) if starts else None


# One random edit: bits, bytes, insertions, deletions, truncation, DER length fields (huge,
# indefinite, non-minimal), tags, OIDs, or a slice of another valid encoding.
def mutate(rng, data, others=()):
    data = bytearray(data)

    if not data:
        return rng.bytes(rng.below(16))

    operation = rng.below(11)

    position = rng.below(len(data))

    if operation == 0:
        data[position] ^= 1 << rng.below(8)
    elif operation == 1:
        data[position] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFF, rng.below(256)))
    elif operation == 2:
        data[position:position] = rng.bytes(1 + rng.below(4))
    elif operation == 3:
        del data[position : position + 1 + rng.below(4)]
    elif operation == 4:
        del data[position:]
    elif operation == 5:
        data += rng.bytes(1 + rng.below(32))
    elif operation in (6, 7) and (header := tag_position(rng, data)) is not None:
        if operation == 6:
            first = data[header + 1]

            size = 1 + (first & 0x7F if first & 0x80 else 0)

            data[header + 1 : header + 1 + size] = rng.choice(LENGTHS) if rng.below(2) else bytes([rng.below(256)])
        else:
            random = rng.below(256)

            data[header] = rng.choice(TAGS) if rng.below(2) else random
    elif operation == 8 and (start := oid_position(rng, data)) is not None:
        data[start : start + 2 + data[start + 1]] = rng.choice(OIDS)
    elif operation == 9 and others:
        other = rng.choice(others)

        start = rng.below(len(other) + 1)

        data[position : position + rng.below(64)] = other[start : start + rng.below(64)]
    else:
        end = min(len(data), position + 1 + rng.below(16))

        data[position:position] = data[position:end]

    return bytes(data)


def mutate_pem(rng, text):
    text = bytearray(text)

    operation = rng.below(8)

    position = rng.below(len(text) + 1)

    if operation == 0:
        text[position:position] = rng.choice(SPACES) * (1 + rng.below(3))
    elif operation == 1:
        text[position:position] = bytes([0x80 + rng.below(128)])
    elif operation == 2:
        text[position:position] = b"="
    elif operation == 3:
        text = text.replace(b"PUBLIC", b"PRIVATE") if rng.below(2) else text.replace(b"PRIVATE", b"PUBLIC")
    elif operation == 4:
        text = text.replace(b"\n", b"", text.count(b"\n") - 2)
    elif operation == 5:
        width = 1 + rng.below(80)

        compact = b"".join(text.split())

        text = bytearray(b"\n".join(compact[i : i + width] for i in range(0, len(compact), width)))
    else:
        text = bytearray(mutate(rng, text))

    return bytes(text)


def sealed(body):
    return bytes(body) + crypto_pq.SHA_256.digest(bytes(body))[:16]


def index_offset(state):
    return len(state) - 24 if state[1] == 1 and len(state) >= 24 else 6


# Random edits of a state blob, mostly resealed so that they reach the parser behind the
# checksum: level counts, type codes, indices at and beyond the capacity, and byte edits.
def mutate_state(rng, state):
    body = bytearray(state[:-16])

    operation = rng.below(6)

    if operation == 0 and len(body) > 2:
        body[2] = rng.choice((0, 1, 2, 3, 8, 9, 0x80, 0xFF))
    elif operation == 1 and len(body) > 6:
        offset = 3 + 8 * rng.below(max(1, body[2])) + 4 * rng.below(2) if body[1] == 1 else 2

        value = rng.choice((rng.below(48), rng.below(1 << 32), 0))

        if offset + 4 <= len(body):
            body[offset : offset + 4] = value.to_bytes(4, "big")
    elif operation == 2 and len(body) >= index_offset(state) + 8:
        offset = index_offset(state)

        height = rng.choice((5, 10, 20, 40, 60, 64))

        value = rng.choice((0, 1, (1 << height) - 1, 1 << height, (1 << height) + 1, MASK)) & MASK

        body[offset : offset + 8] = value.to_bytes(8, "big")
    else:
        body = bytearray(mutate(rng, body))

    return sealed(body) if rng.below(4) else bytes(body) + state[-16:]


class MemoryStore:
    def __init__(self, state=None):
        self.state = state

        self.lock = threading.Lock()

    def read(self):
        with self.lock:
            return self.state

    def update(self, previous, next):
        with self.lock:
            if self.state != previous:
                return False

            self.state = next

            return True


def kem_fixtures():
    fixtures = []

    for algorithm in KEMS:
        pair = hazmat.generate_key_pair(algorithm, pattern(algorithm._backend.seed_size))

        encapsulation = hazmat.encapsulate(pair.public_key, pattern(algorithm._backend.randomness_size, 0x80))

        fixtures.append((algorithm, pair, encapsulation))

    return fixtures


# SLH-DSA keys are expensive here, so verification gets a public key of the right size, which is
# all that it checks, and an all-zero signature.
def signature_fixtures():
    fixtures = []

    for algorithm in SIGNATURES:
        backend = algorithm._backend

        if backend.expanded_size is None:
            public_key = algorithm.import_public_key(pattern(backend.public_key_size, 0x20), "raw")

            fixtures.append((algorithm, None, public_key, b"", bytes(backend.signature_size)))

            continue

        pair = hazmat.generate_key_pair(algorithm, pattern(backend.seed_size))

        message = b"crypto-pq robustness"

        signature = hazmat.sign(pair.private_key, message, pattern(backend.randomness_size, 0x60), context=b"context")

        fixtures.append((algorithm, pair.private_key, pair.public_key, message, signature))

    return fixtures


class RobustnessCase(unittest.TestCase):
    def guarded(self, codes, what, data, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except CryptoPQError as error:
            if error.code not in codes:
                self.fail(f"{what}: {error.code} for {bytes(data).hex()}")
        except Exception as error:
            self.fail(f"{what}: {error!r} for {bytes(data).hex()}")

        return None

    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args, **kwargs)

        self.assertEqual(caught.exception.code, code)

    # The decoded DER of a PEM input, to compare encodings that may differ in whitespace.
    def same_encoding(self, key, data, format, label):
        exported = key.export_key(format)

        if format == "pem":
            self.assertEqual(encoding.pem_decode(label, data), encoding.pem_decode(label, exported))
        else:
            self.assertEqual(exported, bytes(data))

    def stable_exports(self, key, load):
        for format in ("raw", "der", "pem"):
            try:
                exported = key.export_key(format)
            except CryptoPQError as error:
                self.assertEqual(error.code, ErrorCode.UNSUPPORTED)

                continue

            again = load(exported, format)

            self.assertEqual(again.export_key("raw"), key.export_key("raw"))


def import_codes(format, check, der=True):
    if format == "raw":
        return (ErrorCode.INVALID_LENGTH, check)

    if not der:
        return (ErrorCode.UNSUPPORTED,)

    return (ErrorCode.INVALID_ENCODING, ErrorCode.ALGORITHM_MISMATCH, check)


# Random bytes, or a seed with up to three edits.
def next_input(rng, seeds):
    if rng.below(8) == 0:
        return rng.bytes(rng.below(96))

    data = rng.choice(seeds)

    for _ in range(1 + rng.below(3)):
        data = mutate(rng, data, seeds)

    return data


def inputs(rng, seeds, rounds):
    for _ in range(rounds):
        yield next_input(rng, seeds)


class EncodingRobustnessTest(RobustnessCase):
    def test_der(self):
        pair = hazmat.generate_key_pair(crypto_pq.ML_KEM_512, pattern(64))

        seeds = [pair.public_key.export_key("der"), pair.private_key.export_key("der"), keys.encode_seed_choice(None, bytes(1632))]

        rng = Random(1)

        for data in inputs(rng, seeds, 2000 * SCALE):
            reader = encoding.Reader(data)

            tag = rng.choice(TAGS)

            while True:
                start = reader._offset

                content = self.guarded((ErrorCode.INVALID_ENCODING,), "read", data, reader.read, tag)

                if content is None:
                    break

                self.assertEqual(encoding.element(tag, content), data[start : reader._offset])

            decoded = self.guarded((ErrorCode.INVALID_ENCODING,), "public key", data, encoding.decode_public_key, data)

            if decoded is not None:
                self.assertEqual(encoding.encode_public_key(*decoded), data)

            self.guarded((ErrorCode.INVALID_ENCODING,), "private key", data, encoding.decode_private_key, data)

            choice = self.guarded((ErrorCode.INVALID_ENCODING,), "seed choice", data, keys.decode_seed_choice, data, 64, 1632)

            if choice is not None:
                seed, expanded = choice

                both = encoding.element(0x30, encoding.element(0x04, seed) + encoding.element(0x04, expanded)) if seed and expanded else None

                self.assertEqual(both or keys.encode_seed_choice(seed, expanded), data)

    def test_pem_and_base64(self):
        pair = hazmat.generate_key_pair(crypto_pq.ML_DSA_44, pattern(32))

        seeds = [pair.public_key.export_key("pem"), pair.private_key.export_key("pem"), b"-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----"]

        rng = Random(2)

        for _ in range(1000 * SCALE):
            text = rng.choice(seeds)

            for _ in range(1 + rng.below(3)):
                text = mutate_pem(rng, text)

            label = rng.choice((b"PUBLIC KEY", b"PRIVATE KEY"))

            der = self.guarded((ErrorCode.INVALID_ENCODING,), "pem", text, encoding.pem_decode, label, text)

            if der is not None:
                self.assertEqual(encoding.pem_decode(label, encoding.pem_encode(label, der)), der)

            body = rng.bytes(4 * rng.below(8)) if rng.below(2) else encoding.base64_encode(rng.bytes(rng.below(40)))

            body = mutate(rng, body) if rng.below(2) else body

            decoded = self.guarded((ErrorCode.INVALID_ENCODING,), "base64", body, encoding.base64_decode, body)

            if decoded is not None:
                self.assertEqual(encoding.base64_encode(decoded), body)


class ImportRobustnessTest(RobustnessCase):
    def test_kem(self):
        rng = Random(3)

        for algorithm, pair, _ in kem_fixtures():
            der = algorithm._backend.oid is not None

            expanded = algorithm.import_private_key(expanded_key(pair.private_key), "raw") if der else None

            for private in (False, True):
                key = pair.private_key if private else pair.public_key

                for format in ("raw", "der", "pem"):
                    seeds = [key.export_key(format)] if der or format == "raw" else [pair.public_key.export_key("raw")]

                    if private and expanded is not None:
                        seeds.append(expanded.export_key(format))

                    for data in inputs(rng, seeds, 15 * SCALE):
                        if private:
                            self.check_kem_private(algorithm, data, format, der)
                        else:
                            self.check_kem_public(algorithm, data, format, der)

    # FIPS 203 checks only the hash of the public part of an expanded key, so one whose secret
    # vector was changed is accepted and decapsulates to the implicit rejection, SHAKE256(z || c).
    def test_inconsistent_expanded_kem_key(self):
        for algorithm in KEMS[:3]:
            dk = bytearray(expanded_key(hazmat.generate_key_pair(algorithm, pattern(64)).private_key))

            dk[0] ^= 1

            key = algorithm.import_private_key(bytes(dk), "raw")

            encapsulation = hazmat.encapsulate(key.public_key, pattern(32, 0x80))

            self.assertEqual(key.decapsulate(encapsulation.ciphertext), crypto_pq.SHAKE256.digest(bytes(dk[-32:]) + encapsulation.ciphertext, 32))

    def check_kem_public(self, algorithm, data, format, der):
        key = self.guarded(import_codes(format, ErrorCode.INVALID_PUBLIC_KEY, der), algorithm.name, data, algorithm.import_public_key, data, format)

        if key is None:
            return

        self.same_encoding(key, data, format, b"PUBLIC KEY")

        self.stable_exports(key, algorithm.import_public_key)

        encapsulation = hazmat.encapsulate(key, bytes(algorithm._backend.randomness_size))

        self.assertEqual(len(encapsulation.ciphertext), algorithm.ciphertext_size)

    def check_kem_private(self, algorithm, data, format, der):
        key = self.guarded(import_codes(format, ErrorCode.INVALID_PRIVATE_KEY, der), algorithm.name, data, algorithm.import_private_key, data, format)

        if key is None:
            return

        if format == "raw":
            self.assertEqual(key.export_key("raw"), data)

        self.stable_exports(key, algorithm.import_private_key)

        # A key from a seed decapsulates what its public key encapsulates. FIPS 203 checks only the
        # hash of the public part of an expanded key, so one with another secret vector is accepted
        # and gives the implicit rejection, SHAKE256(z || c).
        encapsulation = hazmat.encapsulate(key.public_key, bytes(algorithm._backend.randomness_size))

        secret = key.decapsulate(encapsulation.ciphertext)

        raw = key.export_key("raw")

        if secret != encapsulation.shared_secret:
            self.assertNotEqual(len(raw), algorithm._backend.seed_size)

            self.assertEqual(secret, crypto_pq.SHAKE256.digest(raw[-32:] + encapsulation.ciphertext, 32))

    def test_signature(self):
        rng = Random(4)

        for algorithm in SIGNATURES:
            backend = algorithm._backend

            private_key = hazmat.generate_key_pair(algorithm, pattern(backend.seed_size)).private_key

            # An SLH-DSA private key costs a tree to check, a large one about a second here.
            rounds = (15 if backend.expanded_size else 1 if algorithm.name.endswith("s") else 4) * SCALE

            for private in (False, True):
                key = private_key if private else private_key.public_key

                for format in ("raw", "der", "pem"):

                    for data in inputs(rng, [key.export_key(format)], rounds):
                        if private:
                            self.check_signature_private(algorithm, data, format)
                        else:
                            self.check_signature_public(algorithm, data, format)

    def check_signature_public(self, algorithm, data, format):
        key = self.guarded(import_codes(format, ErrorCode.INVALID_LENGTH), algorithm.name, data, algorithm.import_public_key, data, format)

        if key is None:
            return

        self.same_encoding(key, data, format, b"PUBLIC KEY")

        self.stable_exports(key, algorithm.import_public_key)

    def check_signature_private(self, algorithm, data, format):
        key = self.guarded(import_codes(format, ErrorCode.INVALID_PRIVATE_KEY), algorithm.name, data, algorithm.import_private_key, data, format)

        if key is None:
            return

        if format == "raw":
            self.assertEqual(key.export_key("raw"), data)

        self.stable_exports(key, algorithm.import_private_key)

        backend = algorithm._backend

        if backend.expanded_size is None:
            self.assertEqual(key.export_key("raw")[2 * backend.params.n :], key.public_key.export_key("raw"))

            return

        signature = hazmat.sign(key, b"accepted", bytes(32))

        self.assertTrue(key.public_key.verify(signature, b"accepted"))

    def test_stateful_public_key(self):
        rng = Random(5)

        seeds = {
            crypto_pq.HSS_LMS: [bytes.fromhex("000000010000000a00000005") + pattern(40), bytes.fromhex("000000080000001400000010") + pattern(40)],
            crypto_pq.XMSS: [bytes.fromhex("00000001") + pattern(64), bytes.fromhex("00000015") + pattern(48)],
            crypto_pq.XMSS_MT: [bytes.fromhex("00000031") + pattern(48), bytes.fromhex("00000008") + pattern(64)],
        }

        for algorithm, raw in seeds.items():
            for format in ("raw", "der", "pem"):
                encoded = [raw_key if format == "raw" else algorithm.import_public_key(raw_key, "raw").export_key(format) for raw_key in raw]

                for data in inputs(rng, encoded, 100 * SCALE):
                    codes = (ErrorCode.INVALID_PUBLIC_KEY,) if format == "raw" else (ErrorCode.INVALID_ENCODING, ErrorCode.ALGORITHM_MISMATCH, ErrorCode.INVALID_PUBLIC_KEY)

                    key = self.guarded(codes, algorithm.name, data, algorithm.import_public_key, data, format)

                    if key is not None:
                        self.same_encoding(key, data, format, b"PUBLIC KEY")

                        self.stable_exports(key, algorithm.import_public_key)

                        self.assertFalse(key.verify(bytes(64), b""))

    def test_options(self):
        public_key = crypto_pq.ML_KEM_512.import_public_key(kem_fixtures()[0][1].public_key.export_key("raw"), "raw")

        for format in ("jwk", "RAW", "", None, 1):
            self.assertCode(ErrorCode.INVALID_OPTION, crypto_pq.ML_KEM_512.import_public_key, b"", format)

            self.assertCode(ErrorCode.INVALID_OPTION, public_key.export_key, format)

        for value in ("text", 1, None, [1]):
            with self.assertRaises(TypeError):
                crypto_pq.ML_KEM_512.import_public_key(value, "der")


class VerifyRobustnessTest(RobustnessCase):
    def test_signatures(self):
        rng = Random(6)

        for algorithm, private_key, public_key, message, signature in signature_fixtures():
            backend = algorithm._backend

            rounds = (40 if private_key else 3) * SCALE

            for _ in range(rounds):
                candidate = signature

                if rng.below(8):
                    for _ in range(1 + rng.below(2)):
                        candidate = mutate(rng, candidate)
                else:
                    candidate = rng.bytes(rng.below(backend.signature_size + 2))

                if rng.below(2):
                    candidate = candidate[: backend.signature_size].ljust(backend.signature_size, b"\x00")

                text = mutate(rng, message) if rng.below(2) else message

                context = rng.choice((b"context", b"", rng.bytes(rng.below(300)), bytes(255), bytes(256)))

                pre_hash = rng.choice(PRE_HASHES)

                policy = rng.below(4) != 0

                verify = public_key.verify if policy else (lambda *args, **kwargs: hazmat.verify(public_key, *args, **kwargs))

                valid = self.guarded((), algorithm.name, candidate, verify, candidate, text, context=context, pre_hash=pre_hash)

                self.assertIsInstance(valid, bool)

                weak = policy and pre_hash is not None and STRENGTH[pre_hash] < backend.strength

                if valid:
                    self.assertFalse(weak or len(context) > 255 or len(candidate) != backend.signature_size)

                    self.assertEqual((candidate, text, context, pre_hash), (signature, message, b"context", None))

            self.assertCode(ErrorCode.INVALID_OPTION, public_key.verify, signature, message, pre_hash="SHA-512")

            with self.assertRaises(TypeError):
                public_key.verify(signature.hex(), message)

    def test_stateful(self):
        rng = Random(7)

        store = MemoryStore()

        levels = [("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2"), ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1")]

        pair = hazmat.generate_key_pair(crypto_pq.HSS_LMS, pattern(40), parameters=levels, state_store=store, index=33)

        message = b"crypto-pq robustness"

        cases = [(crypto_pq.HSS_LMS, pair.public_key.export_key("raw"), pair.private_key.sign(message))]

        cases.append((crypto_pq.XMSS_MT, bytes.fromhex("00000022") + pattern(48), bytes(3 + 24 + (4 * 51 + 20) * 24)))

        cases.append((crypto_pq.XMSS, bytes.fromhex("0000000d") + pattern(48), bytes(4 + 24 + (51 + 10) * 24)))

        for algorithm, raw, signature in cases:
            public_key = algorithm.import_public_key(raw, "raw")

            for _ in range((40 if algorithm is crypto_pq.HSS_LMS else 3) * SCALE):
                candidate = mutate(rng, signature) if rng.below(8) else rng.bytes(rng.below(len(signature) + 2))

                text = mutate(rng, message) if rng.below(2) else message

                valid = self.guarded((), algorithm.name, candidate, public_key.verify, candidate, text)

                self.assertIsInstance(valid, bool)

                if valid:
                    self.assertEqual((candidate, text), (signature, message))

        for _ in range(200 * SCALE):
            algorithm = rng.choice(STATEFUL)

            raw = mutate(rng, rng.choice([case[1] for case in cases]))

            public_key = self.guarded((ErrorCode.INVALID_PUBLIC_KEY,), algorithm.name, raw, algorithm.import_public_key, raw, "raw")

            if public_key is not None:
                self.assertIsInstance(public_key.verify(rng.bytes(rng.below(4096)), b""), bool)


class DecapsulationRobustnessTest(RobustnessCase):
    def test_ciphertexts(self):
        rng = Random(8)

        for algorithm, pair, encapsulation in kem_fixtures():
            for _ in range(25 * SCALE):
                ciphertext = mutate(rng, encapsulation.ciphertext) if rng.below(8) else rng.bytes(rng.below(algorithm.ciphertext_size + 2))

                if rng.below(2):
                    ciphertext = ciphertext[: algorithm.ciphertext_size].ljust(algorithm.ciphertext_size, b"\x00")

                codes = () if len(ciphertext) == algorithm.ciphertext_size else (ErrorCode.INVALID_LENGTH,)

                secret = self.guarded(codes, algorithm.name, ciphertext, pair.private_key.decapsulate, ciphertext)

                if codes:
                    self.assertIsNone(secret)
                else:
                    self.assertEqual(len(secret), 32)

                    self.assertEqual(secret == encapsulation.shared_secret, ciphertext == encapsulation.ciphertext)


class StateRobustnessTest(RobustnessCase):
    def test_random_states(self):
        rng = Random(9)

        seeds = []

        for algorithm, parameters, seed_size in (
            (crypto_pq.HSS_LMS, [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")], 40),
            (crypto_pq.HSS_LMS, [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"), ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")], 40),
            (crypto_pq.XMSS, "XMSS-SHA2_10_256", 96),
            (crypto_pq.XMSS_MT, "XMSSMT-SHAKE256_20/4_192", 72),
        ):
            backend = algorithm._backend

            seeds.append(backend.encode(backend.parameters(parameters), pattern(seed_size), 3))

        for _ in range(150 * SCALE):
            state = rng.choice(seeds)

            for _ in range(1 + rng.below(2)):
                state = mutate_state(rng, state) if len(state) >= 18 else rng.bytes(rng.below(160))

            # Mostly the algorithm the blob names, so that more blobs get past the kind check.
            named = state[1] - 1 if len(state) > 1 and 1 <= state[1] <= 3 else None

            self.check_state(STATEFUL[named] if named is not None and rng.below(4) else rng.choice(STATEFUL), state)

    def check_state(self, algorithm, state):
        codes = (ErrorCode.INVALID_PRIVATE_KEY, ErrorCode.ALGORITHM_MISMATCH)

        backend = algorithm._backend

        decoded = self.guarded(codes, algorithm.name, state, backend.decode, state)

        if decoded is None:
            self.guarded(codes, algorithm.name, state, algorithm.load_private_key, MemoryStore(state))

            return

        parameters, seed, index = decoded

        self.assertEqual(backend.encode(parameters, seed, index), state)

        if not self.cheap(algorithm, state):
            return

        store = MemoryStore(state)

        key = self.guarded(codes, algorithm.name, state, algorithm.load_private_key, store)

        capacity = 1 << (sum(lms.h for lms, _ in parameters) if algorithm is crypto_pq.HSS_LMS else parameters.h)

        if index > capacity:
            self.assertIsNone(key)

            return

        self.assertEqual(key.remaining_signatures(), capacity - index)

        if index == capacity:
            self.assertCode(ErrorCode.KEY_EXHAUSTED, key.sign, b"m")

            return

        signature = key.sign(b"m")

        self.assertTrue(key.public_key.verify(signature, b"m"))

        self.assertEqual(store.state, backend.encode(parameters, seed, index + 1))

    # Building the trees of a large key takes minutes in Python: only HSS keys of height-5 trees
    # load here, and the XMSS^MT keys with height-5 layers in a long run.
    def cheap(self, algorithm, state):
        if algorithm is crypto_pq.HSS_LMS:
            count = state[2]

            codes = [int.from_bytes(state[3 + 8 * i + 4 * j : 7 + 8 * i + 4 * j], "big") for i in range(count) for j in (0, 1)]

            return count <= (3 if FUZZ else 2) and all(LMS_H[code] == 5 for code in codes[0::2]) and all(OTS_W[code] <= (4 if FUZZ else 2) for code in codes[1::2])

        return FUZZ and algorithm is crypto_pq.XMSS_MT and int.from_bytes(state[2:6], "big") in XMSS_MT_SMALL

    def test_claimed_sizes(self):
        hss = crypto_pq.HSS_LMS._backend

        state = hss.encode(hss.parameters([("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")]), bytes(40), 0)

        body = bytearray(state[:-16])

        for count in (0, 2, 9, 0xFF):
            claimed = bytearray(body)

            claimed[2] = count

            self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.HSS_LMS.load_private_key, MemoryStore(sealed(claimed)))

            if count != 2:
                padded = claimed[:3] + bytes.fromhex("0000000a00000005") * count + claimed[11:]

                self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.HSS_LMS.load_private_key, MemoryStore(sealed(padded)))

        tall = body[:3] + bytes.fromhex("0000000900000005") + body[11:]

        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.HSS_LMS.load_private_key, MemoryStore(sealed(tall)))

        heights = bytearray(b"\x01\x01\x03" + bytes.fromhex("0000000e00000005") * 3 + bytes(40 + 8))

        self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.HSS_LMS.load_private_key, MemoryStore(sealed(heights)))

        for index in (33, MASK):
            beyond = body[:-8] + index.to_bytes(8, "big")

            self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.HSS_LMS.load_private_key, MemoryStore(sealed(beyond)))

        xmss = crypto_pq.XMSS_MT._backend

        state = xmss.encode(xmss.parameters("XMSSMT-SHA2_60/12_256"), bytes(96), 0)

        for index in ((1 << 60) + 1, MASK):
            beyond = state[:6] + index.to_bytes(8, "big") + state[14:-16]

            self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.XMSS_MT.load_private_key, MemoryStore(sealed(beyond)))

        for value in (b"", b"\x01" * 17, bytearray(18), memoryview(state), "text", 7):
            self.assertCode(ErrorCode.INVALID_PRIVATE_KEY, crypto_pq.XMSS_MT.load_private_key, MemoryStore(value))


# Structures that random edits rarely build: an HSS signature cut inside a field or inside a signed
# child key, counts and leaf indices beyond their range, and hint sections that claim more than
# omega hints, repeat an index or leave padding. Verification refuses every one.
class EdgeStructureTest(RobustnessCase):
    MESSAGE = b"crypto-pq edge"

    def test_hss(self):
        levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")] * 2

        pair = hazmat.generate_key_pair(crypto_pq.HSS_LMS, pattern(40), parameters=levels, state_store=MemoryStore(), index=33)

        signature = pair.private_key.sign(self.MESSAGE)

        # Nspk, then the first LMS signature (4956 bytes), the signed child key (48) and the second.
        end = 4 + 4956

        for length in (0, 1, 3, 4, 5, 8, 12, len(signature) - 1, *range(end - 1, end + 50)):
            self.assertFalse(pair.public_key.verify(signature[:length], self.MESSAGE), length)

        self.assertTrue(pair.public_key.verify(signature, self.MESSAGE))

        self.assertFalse(pair.public_key.verify(signature + b"\x00", self.MESSAGE))

        for offset, value in ((0, 0), (0, 2), (0, 0x7FFFFFFF), (0, 0xFFFFFFFF), (4, 32), (4, 0xFFFFFFFF), (end + 48, 32), (end + 48, 0xFFFFFFFF)):
            edited = signature[:offset] + value.to_bytes(4, "big") + signature[offset + 4 :]

            self.assertFalse(pair.public_key.verify(edited, self.MESSAGE), (offset, value))

        # Level counts outside 1 to 8 make a malformed public key.
        for count in (0, 9, 0xFFFFFFFF):
            raw = count.to_bytes(4, "big") + pair.public_key.export_key("raw")[4:]

            self.assertCode(ErrorCode.INVALID_PUBLIC_KEY, crypto_pq.HSS_LMS.import_public_key, raw, "raw")

    def test_ml_dsa_hints(self):
        private_key = hazmat.generate_key_pair(crypto_pq.ML_DSA_44, pattern(32)).private_key

        valid = hazmat.sign(private_key, self.MESSAGE, bytes(32))

        # ML-DSA-44: omega = 80 hint positions, then k = 4 cumulative counts.
        for counts in ((81, 82, 83, 84), (200, 201, 202, 203), (80, 80, 80, 80), (255, 255, 255, 255), (5, 3, 3, 3), (0, 0, 0, 0)):
            for repeat in (False, True):
                positions = bytearray(range(80))

                if repeat:
                    positions[1] = 0

                edited = valid[:-84] + positions + bytes(counts)

                self.assertFalse(private_key.public_key.verify(edited, self.MESSAGE), counts)

        # The valid signature with a nonzero byte after its last hint: the encoding must be canonical.
        used = valid[-1]

        if used < 80:
            edited = bytearray(valid)

            edited[len(edited) - 84 + used] = 1

            self.assertTrue(private_key.public_key.verify(valid, self.MESSAGE))

            self.assertFalse(private_key.public_key.verify(bytes(edited), self.MESSAGE))

    def test_xmss_indices(self):
        for algorithm, oid, size, index in (
            (crypto_pq.XMSS, 0x0D, 4 + 24 + 61 * 24, b"\x00\x00\x04\x00"),
            (crypto_pq.XMSS, 0x0D, 4 + 24 + 61 * 24, b"\xff\xff\xff\xff"),
            (crypto_pq.XMSS_MT, 0x22, 3 + 24 + (4 * 51 + 20) * 24, b"\x10\x00\x00"),
            (crypto_pq.XMSS_MT, 0x22, 3 + 24 + (4 * 51 + 20) * 24, b"\xff\xff\xff"),
        ):
            key = algorithm.import_public_key(oid.to_bytes(4, "big") + pattern(48), "raw")

            self.assertFalse(key.verify(index + bytes(size - len(index)), self.MESSAGE))


class LargeInputTest(RobustnessCase):
    # Digests of the 16 MiB message whose byte i is i mod 251, from an independent implementation.
    DIGESTS = {
        crypto_pq.SHA_224: "81e763ef9866bdefa03f5c58819e12ba2bc7dd6913eb36e8ec666036",
        crypto_pq.SHA_256: "287507f403176f1f5b22b9a4d9cb49f7d7f88ac19e406b5ae87ce109564846bd",
        crypto_pq.SHA_384: "4bc9798cec40d12e4f7198b89e0a5d4b7e7474ec255f3280b126bd3bc141103ca9a906d12fa05c0c5eb50f2bef840908",
        crypto_pq.SHA_512: "ef9941360046598bd9a89eb56a4440e46255bfa79529f9d3a8813aa899d5c64d8cc75f0c023b8d82ec41cc60ae69d311a80fb9ad372bf3d149574a87bc195c08",
        crypto_pq.SHA_512_224: "181650285d94081ca60b6dad6cb501607c0b47b793d95f4b3fe703ef",
        crypto_pq.SHA_512_256: "61fb65258a2a6ca095a709e2d1026483ef0d5dab44e374f55599d867e0d5d2f9",
        crypto_pq.SHA3_224: "3e121e54d1b7d67d8a6489426c33d7a5078089e9f7ff736786fc2cf3",
        crypto_pq.SHA3_256: "acade24d564f1dae78e26ca4615bc8061dda3835de1bb7afde3ef0d32a931191",
        crypto_pq.SHA3_384: "4934100bb50d9a97d1463c521a58ca562a59e07b6753076e45a824d8545df2358c346274ad7809ffeaac2e56a9cef7fb",
        crypto_pq.SHA3_512: "314cd6d2e1cc05dfc4c8429541a2877becd82e9def2333f26a4eb7f72cffe758289f9185ddae4bb5017ad7019933404f241787ac650e505530f2973d3233a88d",
    }

    XOFS = {
        crypto_pq.SHAKE128: "8a38dce3e6592d50867536f5f352abd74e486bdbfe48c43b8372d55e6547110a",
        crypto_pq.SHAKE256: "525fa10737fa7538afe5df929cfadb606e52a2b2e2f0e4c5626510e720319b7366c387167707535aa23a5d027a155150fe5c73c329f2113d1220a8d9d7b9a5e3",
    }

    HMAC_SHA_256 = "e9fb7e5b1f5d2702eba341df5e51ec9e4ed48db395f66dff93e30808b88f0750"

    # Pure Python hashes about 1 MB/s, so the default run uses 64 KiB and checks that one-shot
    # and streaming agree; CRYPTO_PQ_SLOW=1 checks the 16 MiB digests.
    def message(self):
        size = 16 << 20 if SLOW else 64 << 10

        return (bytes(range(251)) * (size // 251 + 1))[:size]

    def test_hashes(self):
        message = self.message()

        for algorithm, expected in {**self.DIGESTS, **self.XOFS}.items():
            with self.subTest(algorithm=algorithm.name):
                length = len(expected) // 2

                is_xof = algorithm in self.XOFS

                digest = algorithm.digest(message, length) if is_xof else algorithm.digest(message)

                streaming = algorithm.create()

                for offset in range(0, len(message), 1 << 20 if SLOW else 4093):
                    streaming.update(message[offset : offset + (1 << 20 if SLOW else 4093)])

                self.assertEqual(streaming.read(length) if is_xof else streaming.digest(), digest)

                if SLOW:
                    self.assertEqual(digest.hex(), expected)

        tag = crypto_pq.HMAC_SHA_256.digest(bytes(range(32)), message)

        self.assertTrue(crypto_pq.HMAC_SHA_256.verify(bytes(range(32)), message, tag))

        if SLOW:
            self.assertEqual(tag.hex(), self.HMAC_SHA_256)

    def test_messages(self):
        message = self.message()

        changed = message[:-1] + bytes([message[-1] ^ 1])

        signers = [hazmat.generate_key_pair(crypto_pq.ML_DSA_44, pattern(32)).private_key]

        if SLOW:
            signers.append(hazmat.generate_key_pair(crypto_pq.SLH_DSA_SHA2_128F, pattern(48)).private_key)

        for private_key in signers:
            for text, context, pre_hash in ((message, b"", None), (b"", bytes(255), None), (message, bytes(range(255)), crypto_pq.SHA_512), (b"", b"", crypto_pq.SHAKE256)):
                with self.subTest(algorithm=private_key.algorithm.name, size=len(text), pre_hash=pre_hash):
                    signature = private_key.sign(text, context=context, pre_hash=pre_hash)

                    self.assertTrue(private_key.public_key.verify(signature, text, context=context, pre_hash=pre_hash))

                    self.assertFalse(private_key.public_key.verify(signature, changed if text else b"\x00", context=context, pre_hash=pre_hash))

                    self.assertFalse(private_key.public_key.verify(signature, text, context=context + b"\x00", pre_hash=pre_hash))

            self.assertCode(ErrorCode.INVALID_CONTEXT, private_key.sign, b"", context=bytes(256))

        for algorithm, parameters in ((crypto_pq.HSS_LMS, [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")]), (crypto_pq.XMSS_MT, "XMSSMT-SHA2_20/4_192")):
            if algorithm is crypto_pq.XMSS_MT and not SLOW:
                continue

            pair = algorithm.generate_key_pair(parameters=parameters, state_store=MemoryStore())

            for text in (message, b""):
                signature = pair.private_key.sign(text)

                self.assertTrue(pair.public_key.verify(signature, text))

                self.assertFalse(pair.public_key.verify(signature, changed if text else b"\x00"))

    def test_pem(self):
        # The last base64 quantum of an ML-DSA-44 key carries two unused bits, which must be zero.
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        pem = bytearray(hazmat.generate_key_pair(crypto_pq.ML_DSA_44, pattern(32)).public_key.export_key("pem"))

        last = pem.rindex(b"=") - 1

        pem[last] = alphabet[alphabet.index(pem[last]) ^ 1]

        self.assertCode(ErrorCode.INVALID_ENCODING, crypto_pq.ML_DSA_44.import_public_key, bytes(pem), "pem")

        pair = hazmat.generate_key_pair(crypto_pq.ML_KEM_768, pattern(64))

        der = pair.public_key.export_key("der")

        body = encoding.base64_encode(der)

        narrow = b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(body[i : i + 1] for i in range(len(body))) + b"\n-----END PUBLIC KEY-----\n"

        self.assertEqual(crypto_pq.ML_KEM_768.import_public_key(narrow, "pem"), pair.public_key)

        wide = b"-----BEGIN PUBLIC KEY-----" + body + b"-----END PUBLIC KEY-----"

        self.assertEqual(crypto_pq.ML_KEM_768.import_public_key(wide, "pem"), pair.public_key)

        huge = encoding.base64_encode(b"\x30\x84\x00\xff\xff\xff" + bytes((4 << 20) if SLOW else (64 << 10)))

        for text in (b"-----BEGIN PUBLIC KEY-----\n" + huge + b"\n-----END PUBLIC KEY-----\n", b"-----BEGIN PUBLIC KEY-----\n" + huge[:-1] + b"\n-----END PUBLIC KEY-----\n"):
            self.assertCode(ErrorCode.INVALID_ENCODING, crypto_pq.ML_KEM_768.import_public_key, text, "pem")

    # A length field that claims gigabytes must be refused before anything that large is
    # allocated; one with a needless leading zero byte, and a PKCS#8 version above 1, are refused
    # too.
    def test_claimed_der_lengths(self):
        pair = hazmat.generate_key_pair(crypto_pq.ML_DSA_65, pattern(32))

        public = pair.public_key.export_key("der")

        private = pair.private_key.export_key("der")

        cases = [
            b"\x30\x84\xff\xff\xff\xff" + public[4:],
            b"\x30\x84\x7f\xff\xff\xff" + public[4:],
            public[:4] + b"\x30\x84\xff\xff\xff\xf0" + public[6:],
            public[:17] + b"\x03\x84\xff\xff\xff\xff" + public[21:],
            private[:2] + b"\x02\x84\xff\xff\xff\xff\x00",
            private[:20] + b"\x04\x84\x40\x00\x00\x00" + private[22:],
            b"\x30\x85\x01\x00\x00\x00\x00" + public[4:],
            b"\x30\x80" + public[4:] + b"\x00\x00",
            b"\x30\x83\x00\x07\xb2" + public[4:],
            b"\x30\x82\x07\xb3" + public[4:17] + b"\x03\x83\x00\x07\xa1" + public[21:],
            private[:4] + b"\x02" + private[5:],
        ]

        tracemalloc.start()

        try:
            for data in cases:
                with self.subTest(data=data[:24].hex()):
                    tracemalloc.reset_peak()

                    self.assertCode(ErrorCode.INVALID_ENCODING, crypto_pq.ML_DSA_65.import_public_key, data, "der")

                    self.assertCode(ErrorCode.INVALID_ENCODING, crypto_pq.ML_DSA_65.import_private_key, data, "der")

                    self.assertLess(tracemalloc.get_traced_memory()[1], 1 << 20)
        finally:
            tracemalloc.stop()


class ConcurrencyTest(RobustnessCase):
    LEVELS = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")]

    def indices(self, signatures):
        return [int.from_bytes(signature[4:8], "big") for signature in signatures]

    # One key shared by many threads: a call that finds the key busy fails at once with
    # STATE_CONFLICT and changes nothing, so callers that try again still get every index once,
    # and the store sees each write.
    def test_shared_key(self):
        store = MemoryStore()

        pair = crypto_pq.HSS_LMS.generate_key_pair(parameters=self.LEVELS, state_store=store)

        signatures, failures = [], []

        def sign(i):
            while True:
                try:
                    signatures.append(pair.private_key.sign(bytes([i])))

                    return
                except CryptoPQError as error:
                    if error.code is not ErrorCode.STATE_CONFLICT:
                        failures.append(error.code)

                        return

                time.sleep(0.001)

        threads = [threading.Thread(target=sign, args=(i,)) for i in range(40)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        self.assertEqual(sorted(self.indices(signatures)), list(range(32)))

        self.assertEqual(failures, [ErrorCode.KEY_EXHAUSTED] * 8)

        self.assertEqual(crypto_pq.HSS_LMS.load_private_key(store).remaining_signatures(), 0)

    # Keys loaded from one store in different threads: the compare-and-swap lets only one of them
    # use each index; the others get STATE_CONFLICT.
    def test_keys_sharing_a_store(self):
        store = MemoryStore()

        crypto_pq.HSS_LMS.generate_key_pair(parameters=self.LEVELS, state_store=store)

        signatures, failures = [], []

        barrier = threading.Barrier(6)

        def work():
            key = crypto_pq.HSS_LMS.load_private_key(store)

            barrier.wait()

            for _ in range(8):
                try:
                    signatures.append(key.sign(b"m"))
                except CryptoPQError as error:
                    failures.append(error.code)

                    if error.code is ErrorCode.STATE_CONFLICT:
                        key = crypto_pq.HSS_LMS.load_private_key(store)

        threads = [threading.Thread(target=work) for _ in range(6)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        indices = sorted(self.indices(signatures))

        self.assertEqual(indices, list(range(len(indices))))

        self.assertTrue(set(failures) <= {ErrorCode.STATE_CONFLICT, ErrorCode.KEY_EXHAUSTED})

        self.assertEqual(crypto_pq.HSS_LMS.load_private_key(store).remaining_signatures(), 32 - len(indices))


# Every implementation runs these rounds on the same inputs, made by the same generator from
# byte-identical keys, and hashes each input with its outcome: an error code, true or false, or
# OK and the result. Equal digests mean that all five implementations accept, refuse and compute
# alike on untrusted input.
TRANSCRIPT_ROUNDS = 96

TRANSCRIPT_BUDGET = 1 << 14

TRANSCRIPTS = (
    "4d454f3aca564e383f51723ee3814f1fe105a61b1fd38c536e2ea675d78fabe7",
    "db3f28b7c8f7949f104d15d6de629e0dea7fca38f38c970d520278617dc99474",
    "aafe47ac9480c88402b7974385fac0547b2f4d611f36ec692ca2748e5dec949e",
    "ce9fd19a166b8a384fab4dafffed98c85dd9fb7f3e2ab789f33c832cda8b199d",
    "14d657260a5c207db5e73e9dbaac6d3458b0ba16e507f256bea8fac9fd0f2a0a",
    "19d93bae7a287d14492808654d0580f1043443ad3cf6710e043ea34c462b3307",
    "38a35f3547d4414788484ce0b4b836a27f72fba19931a9f3680cbcadd6d5d97a",
    "7b468ce2966d2edd458ed4a62183bf6d4c06e182509a7773c505a3cb2ae12e58",
    "b2ecff951172fdfdd464c3b4bed07055c3041b64d0c11dc6c9bc62eae7cc0b0e",
    "57986f97a5d291a67f8a875f558d59a535f2157155e13b83b364a6a1cca5dc7d",
    "b46878b67dab92d46731b18b1c63b71f24e7ec4cb53bca10ec36540ca1b4b054",
)

FORMATS = ("raw", "der", "pem")


class Transcript:
    def __init__(self):
        self.hasher = crypto_pq.SHA_256.create()

    def add(self, data, selector, code, output=b""):
        for part in (data, bytes([selector]), code.encode(), output):
            self.hasher.update(len(part).to_bytes(4, "big") + part)

    def hex(self):
        return self.hasher.digest().hex()


def outcome(function, *args):
    try:
        return "OK", function(*args)
    except CryptoPQError as error:
        return error.code.value, None


# Random bytes, or the seed with up to three edits, so that some inputs stay valid.
def edited(rng, seed, others):
    if rng.below(8) == 0:
        return rng.bytes(rng.below(96))

    data = seed

    for _ in range(rng.below(4)):
        data = mutate(rng, data, others)

    return data


def resized(rng, data, size):
    return data[:size].ljust(size, b"\x00") if rng.below(2) else data


class TranscriptTest(RobustnessCase):
    def test_transcripts(self):
        message = b"crypto-pq transcript"

        kem = hazmat.generate_key_pair(crypto_pq.ML_KEM_768, pattern(64))

        encapsulation = hazmat.encapsulate(kem.public_key, pattern(32, 0x80))

        xwing = hazmat.generate_key_pair(crypto_pq.X_WING, pattern(32))

        dsa = hazmat.generate_key_pair(crypto_pq.ML_DSA_44, pattern(32))

        signature = hazmat.sign(dsa.private_key, message, pattern(32, 0x60), context=b"context")

        slh = hazmat.generate_key_pair(crypto_pq.SLH_DSA_SHA2_128F, pattern(48))

        levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")] * 2

        hss = hazmat.generate_key_pair(crypto_pq.HSS_LMS, pattern(40), parameters=levels, state_store=MemoryStore(), index=33)

        hss_signature = hss.private_key.sign(message)

        store = MemoryStore()

        hazmat.generate_key_pair(crypto_pq.HSS_LMS, pattern(40), parameters=levels[:1], state_store=store, index=3)

        # (encoding, import function, format) triples.
        def encodings(key, function=0):
            return [(key.export_key(format), function, number) for number, format in enumerate(FORMATS)]

        xwing_seeds = [(xwing.public_key.export_key("raw"), 0, 0), (xwing.private_key.export_key("raw"), 1, 0)]

        stateful = (crypto_pq.HSS_LMS, crypto_pq.XMSS, crypto_pq.XMSS_MT)

        xmss_public = bytes.fromhex("00000001") + pattern(64)

        xmss_mt_public = bytes.fromhex("00000031") + pattern(48)

        stateful_seeds = encodings(hss.public_key) + [(xmss_public, 1, 0), (xmss_mt_public, 2, 0), (crypto_pq.XMSS_MT.import_public_key(xmss_mt_public, "raw").export_key("der"), 2, 1)]

        slh_dsa = crypto_pq.SLH_DSA_SHA2_128F

        cases = (
            lambda rng, t: self.import_case(rng, t, encodings(kem.public_key), [crypto_pq.ML_KEM_768.import_public_key]),
            lambda rng, t: self.import_case(rng, t, encodings(kem.private_key), [crypto_pq.ML_KEM_768.import_private_key]),
            lambda rng, t: self.import_case(rng, t, xwing_seeds, [crypto_pq.X_WING.import_public_key, crypto_pq.X_WING.import_private_key]),
            lambda rng, t: self.import_case(rng, t, encodings(dsa.public_key), [crypto_pq.ML_DSA_44.import_public_key]),
            lambda rng, t: self.import_case(rng, t, encodings(dsa.private_key), [crypto_pq.ML_DSA_44.import_private_key]),
            lambda rng, t: self.import_case(rng, t, encodings(slh.public_key) + encodings(slh.private_key, 1), [slh_dsa.import_public_key, slh_dsa.import_private_key]),
            lambda rng, t: self.import_case(rng, t, stateful_seeds, [algorithm.import_public_key for algorithm in stateful]),
            lambda rng, t: self.signature_case(rng, t, signature, lambda data, context: dsa.public_key.verify(data, message, context=context)),
            lambda rng, t: self.decapsulation_case(rng, t, kem.private_key, encapsulation.ciphertext),
            lambda rng, t: self.signature_case(rng, t, hss_signature, lambda data, context: hss.public_key.verify(data, message + context)),
            lambda rng, t: self.state_case(rng, t, store.state),
        )

        digests = []

        for number, case in enumerate(cases):
            transcript = Transcript()

            case(Random(101 + number), transcript)

            digests.append(transcript.hex())

        self.assertEqual(tuple(digests), TRANSCRIPTS)

    def import_case(self, rng, transcript, seeds, imports):
        others = [encoding for encoding, _, _ in seeds]

        for _ in range(TRANSCRIPT_ROUNDS):
            encoding, function, format = seeds[rng.below(len(seeds))]

            data = edited(rng, encoding, others)

            if rng.below(4) == 0:
                format = rng.below(3)

            code, key = outcome(imports[function], data, FORMATS[format])

            transcript.add(data, 3 * function + format, code, key.export_key("raw") if key else b"")

    def signature_case(self, rng, transcript, signature, verify):
        for _ in range(TRANSCRIPT_ROUNDS):
            data = resized(rng, edited(rng, signature, [signature]), len(signature))

            context = (b"context", b"")[rng.below(2)]

            transcript.add(data, len(context), "true" if verify(data, context) else "false")

    def decapsulation_case(self, rng, transcript, private_key, ciphertext):
        for _ in range(TRANSCRIPT_ROUNDS):
            data = resized(rng, edited(rng, ciphertext, [ciphertext]), len(ciphertext))

            code, secret = outcome(private_key.decapsulate, data)

            transcript.add(data, 0, code, secret or b"")

    # Loading builds the key's trees, so a valid state of a key larger than the budget is only
    # recorded as skipped.
    def state_case(self, rng, transcript, base):
        stateful = (crypto_pq.HSS_LMS, crypto_pq.XMSS, crypto_pq.XMSS_MT)

        for _ in range(TRANSCRIPT_ROUNDS):
            state = base

            for _ in range(1 + rng.below(2)):
                state = mutate_state(rng, state) if len(state) >= 18 else rng.bytes(rng.below(160))

            named = state[1] - 1 if len(state) > 1 and 1 <= state[1] <= 3 else None

            choice = named if named is not None and rng.below(4) else rng.below(3)

            algorithm = stateful[choice]

            try:
                parameters, _, _ = algorithm._backend.decode(state)
            except CryptoPQError:
                parameters = None

            if parameters is not None and self.cost(algorithm, parameters) > TRANSCRIPT_BUDGET:
                transcript.add(state, choice, "SKIP")

                continue

            code, key = outcome(algorithm.load_private_key, MemoryStore(state))

            output = key.public_key.export_key("raw") + key.remaining_signatures().to_bytes(8, "big") if key else b""

            transcript.add(state, choice, code, output)

    # Hash calls to build every tree on a signing path, as the other implementations count them.
    def cost(self, algorithm, parameters):
        if algorithm is crypto_pq.HSS_LMS:
            return sum(ots.p << (lms.h + ots.w) for lms, ots in parameters)

        return (parameters.d << (parameters.h // parameters.d)) * (2 * parameters.n + 3) * 16

if __name__ == "__main__":
    unittest.main()
