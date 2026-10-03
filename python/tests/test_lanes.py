import random
import unittest

from crypto_pq import SHAKE128, SHAKE256, _keccak, _lanes, _sha2

# The lane engines must agree with the scalar code, which the CAVP vectors cover, in every lane.
COUNTS = (1, 2, 3, 17, 64)


class LanesTest(unittest.TestCase):
    def setUp(self):
        self.random = random.Random(20261003)

    def words(self, count, length, bits):
        return [[self.random.getrandbits(bits) for _ in range(length)] for _ in range(count)]

    def test_sha256(self):
        for count in COUNTS:
            with self.subTest(count=count):
                states, blocks = self.words(count, 8, 32), self.words(count, 16, 32)

                out = _lanes.sha256_engine(count).compress(
                    [_lanes.pack([s[j] for s in states], 64) for j in range(8)],
                    [_lanes.pack([b[j] for b in blocks], 64) for j in range(16)],
                )

                for i, (state, block) in enumerate(zip(states, blocks)):
                    _sha2._compress256(state, b"".join(x.to_bytes(4, "big") for x in block), 0)

                    self.assertEqual([_lanes.unpack(x, count, 64)[i] for x in out], state)

    def test_sha512(self):
        for count in COUNTS:
            with self.subTest(count=count):
                states, blocks = self.words(count, 8, 64), self.words(count, 16, 64)

                out = _lanes.sha512_engine(count).compress(
                    [_lanes.pack([s[j] for s in states], 128) for j in range(8)],
                    [_lanes.pack([b[j] for b in blocks], 128) for j in range(16)],
                )

                for i, (state, block) in enumerate(zip(states, blocks)):
                    _sha2._compress512(state, b"".join(x.to_bytes(8, "big") for x in block), 0)

                    self.assertEqual([_lanes.unpack(x, count, 128)[i] for x in out], state)

    def test_keccak(self):
        for count in COUNTS:
            with self.subTest(count=count):
                states = self.words(count, 25, 64)

                out = _lanes.keccak_engine(count).permute([_lanes.pack([s[j] for s in states], 64) for j in range(25)])

                for i, state in enumerate(states):
                    _keccak.permute(state)

                    self.assertEqual([_lanes.unpack(x, count, 64)[i] for x in out], state)

    # Messages whose first words are the same in every lane take the path that runs those rounds
    # once; the rest of each message differs per lane.
    def test_sha256_messages(self):
        for count in COUNTS:
            for shared in (0, 3, 9, 16, 20):
                with self.subTest(count=count, shared=shared):
                    common = self.random.randbytes(4 * shared)

                    messages = [common + self.random.randbytes(4 * (21 - shared)) for _ in range(count)]

                    words = _lanes.words([m + b"\x80\x00\x00\x00" for m in messages], 4, 64)

                    out = _lanes.sha256(_sha2.IV_256, words, count, 8 * len(messages[0]))

                    digests = _lanes.chunks(out, count, 4, 64)

                    for message, digest in zip(messages, digests):
                        engine = _sha2.Sha256(_sha2.IV_256, 32)

                        engine.update(message)

                        self.assertEqual(digest, engine.digest())

    def test_squeeze(self):
        for count in COUNTS:
            for algorithm, rate in ((SHAKE128, 168), (SHAKE256, 136)):
                with self.subTest(count=count, rate=rate):
                    seeds = [self.random.randbytes(34) for _ in range(count)]

                    stream = _lanes.Squeeze(seeds, rate)

                    out = [a + b for a, b in zip(stream.blocks(2), stream.blocks(1))]

                    self.assertEqual(out, [algorithm.digest(seed, 3 * rate) for seed in seeds])

    def test_conversions(self):
        for count in COUNTS:
            with self.subTest(count=count):
                data = [self.random.randbytes(48) for _ in range(count)]

                for size, width in ((4, 64), (8, 128)):
                    self.assertEqual(_lanes.chunks(_lanes.words(data, size, width), count, size, width), data)

                self.assertEqual(_lanes.chunks64(_lanes.lanes64(data), count), data)

                values = [self.random.getrandbits(64) for _ in range(count)]

                self.assertEqual(_lanes.unpack(_lanes.widen(_lanes.pack(values, 64), count), count, 128), values)


if __name__ == "__main__":
    unittest.main()
