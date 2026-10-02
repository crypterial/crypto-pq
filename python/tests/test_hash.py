import pathlib
import unittest

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode

CAVP = pathlib.Path(__file__).resolve().parents[2] / "vectors" / "cavp"

HASHES = {
    "SHA224": crypto_pq.SHA_224,
    "SHA256": crypto_pq.SHA_256,
    "SHA384": crypto_pq.SHA_384,
    "SHA512": crypto_pq.SHA_512,
    "SHA512_224": crypto_pq.SHA_512_224,
    "SHA512_256": crypto_pq.SHA_512_256,
    "SHA3_224": crypto_pq.SHA3_224,
    "SHA3_256": crypto_pq.SHA3_256,
    "SHA3_384": crypto_pq.SHA3_384,
    "SHA3_512": crypto_pq.SHA3_512,
}

XOFS = {"SHAKE128": crypto_pq.SHAKE128, "SHAKE256": crypto_pq.SHAKE256}

# HMAC.rsp labels each group by digest length in bytes; L=20 is SHA-1, which is out of scope.
HMACS = {
    "28": crypto_pq.HMAC_SHA_224,
    "32": crypto_pq.HMAC_SHA_256,
    "48": crypto_pq.HMAC_SHA_384,
    "64": crypto_pq.HMAC_SHA_512,
}

# Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
PIECES = (0, 1, 3, 64, 7, 136, 128, 168, 0, 200)


def records(name, field):
    lines = (CAVP / name).read_text().splitlines()

    header = {}

    record = {}

    found = []

    for line in [*lines, ""]:
        line = line.strip()

        if line.startswith("[") and line.endswith("]"):
            key, _, value = line[1:-1].partition("=")

            header[key.strip()] = value.strip()
        elif "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")

            record[key.strip()] = value.strip()
        elif record:
            found.append((dict(header), record))

            record = {}

    expected = sum(1 for line in lines if line.startswith(f"{field} ="))

    parsed = sum(1 for _, record in found if field in record)

    if expected == 0 or parsed != expected:
        raise AssertionError(f"{name}: parsed {parsed} records, expected {expected}")

    return found


def message(record):
    bits = int(record["Len"])

    if bits % 8:
        raise AssertionError("bit-oriented message")

    return bytes.fromhex(record["Msg"])[: bits // 8]


def pieces(data):
    offset = 0

    index = 0

    while offset < len(data):
        size = PIECES[index % len(PIECES)]

        yield data[offset : offset + size]

        offset += size

        index += 1


class HashTest(unittest.TestCase):
    def test_vectors(self):
        for prefix, algorithm in HASHES.items():
            for kind in ("ShortMsg", "LongMsg"):
                for _, record in records(f"{prefix}{kind}.rsp", "MD"):
                    with self.subTest(file=f"{prefix}{kind}", bits=record["Len"]):
                        data = message(record)

                        expected = bytes.fromhex(record["MD"])

                        self.assertEqual(algorithm.digest(data), expected)

                        hasher = algorithm.create()

                        for piece in pieces(data):
                            hasher.update(piece)

                        self.assertEqual(hasher.digest(), expected)

    # SHAVS 6.4 and SHA3VS 6.2.3: each checkpoint chains 1000 digests from the previous one.
    def test_monte_carlo(self):
        for prefix, algorithm in HASHES.items():
            (_, first), *checkpoints = records(f"{prefix}Monte.rsp", "MD")

            seed = bytes.fromhex(first["Seed"])

            for _, record in checkpoints:
                if prefix.startswith("SHA3_"):
                    for _ in range(1000):
                        seed = algorithm.digest(seed)
                else:
                    md = [seed, seed, seed]

                    for _ in range(1000):
                        md = [md[1], md[2], algorithm.digest(md[0] + md[1] + md[2])]

                    seed = md[2]

                self.assertEqual(seed.hex(), record["MD"].lower(), f"{prefix}Monte COUNT = {record['COUNT']}")

    def test_digest_is_repeatable(self):
        for algorithm in HASHES.values():
            hasher = algorithm.create()

            hasher.update(b"abc")

            first = hasher.digest()

            self.assertEqual(hasher.digest(), first)

            self.assertEqual(first, algorithm.digest(b"abc"))

            hasher.update(b"def")

            self.assertEqual(hasher.digest(), algorithm.digest(b"abcdef"))

    def test_properties(self):
        names = ("SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256")

        names += ("SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512")

        for name, algorithm in zip(names, HASHES.values()):
            self.assertEqual(algorithm.name, name)

            self.assertEqual(len(algorithm.digest(b"")), algorithm.digest_size)

    def test_input_types(self):
        expected = crypto_pq.SHA_256.digest(b"abc")

        self.assertEqual(crypto_pq.SHA_256.digest(bytearray(b"abc")), expected)

        self.assertEqual(crypto_pq.SHA_256.digest(memoryview(b"xabcx")[1:4]), expected)

        for wrong in ("abc", 3, None):
            with self.assertRaises(TypeError):
                crypto_pq.SHA_256.digest(wrong)


class XofTest(unittest.TestCase):
    def test_vectors(self):
        for prefix, algorithm in XOFS.items():
            for kind in ("ShortMsg", "LongMsg"):
                for header, record in records(f"{prefix}{kind}.rsp", "Output"):
                    with self.subTest(file=f"{prefix}{kind}", bits=record["Len"]):
                        data = message(record)

                        expected = bytes.fromhex(record["Output"])

                        self.assertEqual(int(header["Outputlen"]), 8 * len(expected))

                        self.assertEqual(algorithm.digest(data, len(expected)), expected)

                        xof = algorithm.create()

                        for piece in pieces(data):
                            xof.update(piece)

                        self.assertEqual(xof.read(1) + xof.read(len(expected) - 1), expected)

            for _, record in records(f"{prefix}VariableOut.rsp", "Output"):
                with self.subTest(file=f"{prefix}VariableOut", count=record["COUNT"]):
                    expected = bytes.fromhex(record["Output"])

                    self.assertEqual(int(record["Outputlen"]), 8 * len(expected))

                    self.assertEqual(algorithm.digest(bytes.fromhex(record["Msg"]), len(expected)), expected)

    # SHA3VS 6.3.3: the next input is the first 16 output bytes, zero-padded, and the last two
    # output bytes pick the next output length.
    def test_monte_carlo(self):
        for prefix, algorithm in XOFS.items():
            (header, first), *checkpoints = records(f"{prefix}Monte.rsp", "Output")

            minimum = int(header["Minimum Output Length (bits)"]) // 8

            maximum = int(header["Maximum Output Length (bits)"]) // 8

            output = bytes.fromhex(first["Msg"])

            length = maximum

            for _, record in checkpoints:
                for _ in range(1000):
                    output = algorithm.digest((output + bytes(16))[:16], length)

                    length = minimum + int.from_bytes(output[-2:], "big") % (maximum - minimum + 1)

                self.assertEqual(output.hex(), record["Output"].lower(), f"{prefix}Monte COUNT = {record['COUNT']}")

                self.assertEqual(8 * len(output), int(record["Outputlen"]))

    def test_streaming_read(self):
        for algorithm in XOFS.values():
            xof = algorithm.create()

            xof.update(b"abc")

            out = b"".join(xof.read(n) for n in (0, 1, 135, 1, 167, 200, 496))

            self.assertEqual(out, algorithm.digest(b"abc", 1000))

    def test_update_after_read(self):
        xof = crypto_pq.SHAKE128.create()

        xof.read(1)

        with self.assertRaises(CryptoPQError) as caught:
            xof.update(b"x")

        self.assertEqual(caught.exception.code, ErrorCode.UNSUPPORTED)

    def test_lengths(self):
        self.assertEqual(crypto_pq.SHAKE256.digest(b"", 0), b"")

        with self.assertRaises(CryptoPQError) as caught:
            crypto_pq.SHAKE256.digest(b"", -1)

        self.assertEqual(caught.exception.code, ErrorCode.INVALID_LENGTH)

        with self.assertRaises(TypeError):
            crypto_pq.SHAKE256.digest(b"", 1.5)

    def test_properties(self):
        self.assertEqual(crypto_pq.SHAKE128.name, "SHAKE128")

        self.assertEqual(crypto_pq.SHAKE256.name, "SHAKE256")


class HmacTest(unittest.TestCase):
    def test_vectors(self):
        tested = 0

        for header, record in records("HMAC.rsp", "Mac"):
            if header["L"] == "20":
                continue

            with self.subTest(L=header["L"], count=record["Count"]):
                algorithm = HMACS[header["L"]]

                key = bytes.fromhex(record["Key"])

                data = bytes.fromhex(record["Msg"])

                mac = bytes.fromhex(record["Mac"])

                self.assertEqual(len(key), int(record["Klen"]))

                self.assertEqual(len(mac), int(record["Tlen"]))

                tag = algorithm.digest(key, data)

                self.assertEqual(tag[: len(mac)], mac)

                hmac = algorithm.create(key)

                for piece in pieces(data):
                    hmac.update(piece)

                self.assertEqual(hmac.digest(), tag)

                self.assertTrue(hmac.verify(tag))

                self.assertTrue(algorithm.verify(key, data, tag))

            tested += 1

        self.assertEqual(tested, 1275)

    def test_verify_rejects(self):
        tag = crypto_pq.HMAC_SHA_256.digest(b"key", b"data")

        self.assertFalse(crypto_pq.HMAC_SHA_256.verify(b"key", b"data", tag[:-1]))

        self.assertFalse(crypto_pq.HMAC_SHA_256.verify(b"key", b"data", tag + b"\x00"))

        self.assertFalse(crypto_pq.HMAC_SHA_256.verify(b"kez", b"data", tag))

        for index in range(len(tag)):
            flipped = bytearray(tag)

            flipped[index] ^= 0x80

            self.assertFalse(crypto_pq.HMAC_SHA_256.verify(b"key", b"data", flipped))

    def test_properties(self):
        names = ("HMAC-SHA-224", "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512")

        for name, algorithm in zip(names, HMACS.values()):
            self.assertEqual(algorithm.name, name)

            self.assertEqual(len(algorithm.digest(b"k", b"")), algorithm.digest_size)


if __name__ == "__main__":
    unittest.main()
