"""BLAKE2b and BLAKE2s (RFC 7693) in sequential mode, keyed or not, with a salt and a
personalization, as typescript/src/blake2.ts computes them. A chaining value is a list of eight
words, whose little-endian bytes are the digest. Python cannot promise that no copy of a key
remains; the key blocks that this module holds are zeroed after use."""

import struct
from typing import NamedTuple

from ._sha2 import IV_256, IV_512

_M64 = 0xFFFFFFFFFFFFFFFF

_M32 = 0xFFFFFFFF

# RFC 7693, 2.7: the message word order of each round; BLAKE2b's rounds 10 and 11 take the first
# two rows again.
SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)

_ROUNDS_B = (*SIGMA, SIGMA[0], SIGMA[1])

_WORDS64 = struct.Struct("<16Q")

_WORDS32 = struct.Struct("<16I")

# Multiplying a word by 2^w + 1 puts a copy of it above itself, so that a right rotation is one
# shift and a mask.
_COPY64 = (1 << 64) + 1

_COPY32 = (1 << 32) + 1


# The BLAKE2b compression of the 128-byte block at data[offset] into h, with the counter (the bytes
# hashed so far, this block included) and the final-block flag.
def compress_b(h, data, offset, counter, last):
    m = _WORDS64.unpack_from(data, offset)

    v0, v1, v2, v3, v4, v5, v6, v7 = h

    v8, v9, v10, v11, v12, v13, v14, v15 = IV_512

    v12 ^= counter & _M64

    v13 ^= counter >> 64

    if last:
        v14 ^= _M64

    for s in _ROUNDS_B:
        v0 = (v0 + v4 + m[s[0]]) & _M64

        x = (v12 ^ v0) * _COPY64

        v12 = (x >> 32) & _M64

        v8 = (v8 + v12) & _M64

        x = (v4 ^ v8) * _COPY64

        v4 = (x >> 24) & _M64

        v0 = (v0 + v4 + m[s[1]]) & _M64

        x = (v12 ^ v0) * _COPY64

        v12 = (x >> 16) & _M64

        v8 = (v8 + v12) & _M64

        x = (v4 ^ v8) * _COPY64

        v4 = (x >> 63) & _M64

        v1 = (v1 + v5 + m[s[2]]) & _M64

        x = (v13 ^ v1) * _COPY64

        v13 = (x >> 32) & _M64

        v9 = (v9 + v13) & _M64

        x = (v5 ^ v9) * _COPY64

        v5 = (x >> 24) & _M64

        v1 = (v1 + v5 + m[s[3]]) & _M64

        x = (v13 ^ v1) * _COPY64

        v13 = (x >> 16) & _M64

        v9 = (v9 + v13) & _M64

        x = (v5 ^ v9) * _COPY64

        v5 = (x >> 63) & _M64

        v2 = (v2 + v6 + m[s[4]]) & _M64

        x = (v14 ^ v2) * _COPY64

        v14 = (x >> 32) & _M64

        v10 = (v10 + v14) & _M64

        x = (v6 ^ v10) * _COPY64

        v6 = (x >> 24) & _M64

        v2 = (v2 + v6 + m[s[5]]) & _M64

        x = (v14 ^ v2) * _COPY64

        v14 = (x >> 16) & _M64

        v10 = (v10 + v14) & _M64

        x = (v6 ^ v10) * _COPY64

        v6 = (x >> 63) & _M64

        v3 = (v3 + v7 + m[s[6]]) & _M64

        x = (v15 ^ v3) * _COPY64

        v15 = (x >> 32) & _M64

        v11 = (v11 + v15) & _M64

        x = (v7 ^ v11) * _COPY64

        v7 = (x >> 24) & _M64

        v3 = (v3 + v7 + m[s[7]]) & _M64

        x = (v15 ^ v3) * _COPY64

        v15 = (x >> 16) & _M64

        v11 = (v11 + v15) & _M64

        x = (v7 ^ v11) * _COPY64

        v7 = (x >> 63) & _M64

        v0 = (v0 + v5 + m[s[8]]) & _M64

        x = (v15 ^ v0) * _COPY64

        v15 = (x >> 32) & _M64

        v10 = (v10 + v15) & _M64

        x = (v5 ^ v10) * _COPY64

        v5 = (x >> 24) & _M64

        v0 = (v0 + v5 + m[s[9]]) & _M64

        x = (v15 ^ v0) * _COPY64

        v15 = (x >> 16) & _M64

        v10 = (v10 + v15) & _M64

        x = (v5 ^ v10) * _COPY64

        v5 = (x >> 63) & _M64

        v1 = (v1 + v6 + m[s[10]]) & _M64

        x = (v12 ^ v1) * _COPY64

        v12 = (x >> 32) & _M64

        v11 = (v11 + v12) & _M64

        x = (v6 ^ v11) * _COPY64

        v6 = (x >> 24) & _M64

        v1 = (v1 + v6 + m[s[11]]) & _M64

        x = (v12 ^ v1) * _COPY64

        v12 = (x >> 16) & _M64

        v11 = (v11 + v12) & _M64

        x = (v6 ^ v11) * _COPY64

        v6 = (x >> 63) & _M64

        v2 = (v2 + v7 + m[s[12]]) & _M64

        x = (v13 ^ v2) * _COPY64

        v13 = (x >> 32) & _M64

        v8 = (v8 + v13) & _M64

        x = (v7 ^ v8) * _COPY64

        v7 = (x >> 24) & _M64

        v2 = (v2 + v7 + m[s[13]]) & _M64

        x = (v13 ^ v2) * _COPY64

        v13 = (x >> 16) & _M64

        v8 = (v8 + v13) & _M64

        x = (v7 ^ v8) * _COPY64

        v7 = (x >> 63) & _M64

        v3 = (v3 + v4 + m[s[14]]) & _M64

        x = (v14 ^ v3) * _COPY64

        v14 = (x >> 32) & _M64

        v9 = (v9 + v14) & _M64

        x = (v4 ^ v9) * _COPY64

        v4 = (x >> 24) & _M64

        v3 = (v3 + v4 + m[s[15]]) & _M64

        x = (v14 ^ v3) * _COPY64

        v14 = (x >> 16) & _M64

        v9 = (v9 + v14) & _M64

        x = (v4 ^ v9) * _COPY64

        v4 = (x >> 63) & _M64

    h[:] = (h[0] ^ v0 ^ v8, h[1] ^ v1 ^ v9, h[2] ^ v2 ^ v10, h[3] ^ v3 ^ v11, h[4] ^ v4 ^ v12, h[5] ^ v5 ^ v13, h[6] ^ v6 ^ v14, h[7] ^ v7 ^ v15)


# The BLAKE2s compression of the 64-byte block at data[offset] into h, as compress_b.
def compress_s(h, data, offset, counter, last):
    m = _WORDS32.unpack_from(data, offset)

    v0, v1, v2, v3, v4, v5, v6, v7 = h

    v8, v9, v10, v11, v12, v13, v14, v15 = IV_256

    v12 ^= counter & _M32

    v13 ^= counter >> 32

    if last:
        v14 ^= _M32

    for s in SIGMA:
        v0 = (v0 + v4 + m[s[0]]) & _M32

        x = (v12 ^ v0) * _COPY32

        v12 = (x >> 16) & _M32

        v8 = (v8 + v12) & _M32

        x = (v4 ^ v8) * _COPY32

        v4 = (x >> 12) & _M32

        v0 = (v0 + v4 + m[s[1]]) & _M32

        x = (v12 ^ v0) * _COPY32

        v12 = (x >> 8) & _M32

        v8 = (v8 + v12) & _M32

        x = (v4 ^ v8) * _COPY32

        v4 = (x >> 7) & _M32

        v1 = (v1 + v5 + m[s[2]]) & _M32

        x = (v13 ^ v1) * _COPY32

        v13 = (x >> 16) & _M32

        v9 = (v9 + v13) & _M32

        x = (v5 ^ v9) * _COPY32

        v5 = (x >> 12) & _M32

        v1 = (v1 + v5 + m[s[3]]) & _M32

        x = (v13 ^ v1) * _COPY32

        v13 = (x >> 8) & _M32

        v9 = (v9 + v13) & _M32

        x = (v5 ^ v9) * _COPY32

        v5 = (x >> 7) & _M32

        v2 = (v2 + v6 + m[s[4]]) & _M32

        x = (v14 ^ v2) * _COPY32

        v14 = (x >> 16) & _M32

        v10 = (v10 + v14) & _M32

        x = (v6 ^ v10) * _COPY32

        v6 = (x >> 12) & _M32

        v2 = (v2 + v6 + m[s[5]]) & _M32

        x = (v14 ^ v2) * _COPY32

        v14 = (x >> 8) & _M32

        v10 = (v10 + v14) & _M32

        x = (v6 ^ v10) * _COPY32

        v6 = (x >> 7) & _M32

        v3 = (v3 + v7 + m[s[6]]) & _M32

        x = (v15 ^ v3) * _COPY32

        v15 = (x >> 16) & _M32

        v11 = (v11 + v15) & _M32

        x = (v7 ^ v11) * _COPY32

        v7 = (x >> 12) & _M32

        v3 = (v3 + v7 + m[s[7]]) & _M32

        x = (v15 ^ v3) * _COPY32

        v15 = (x >> 8) & _M32

        v11 = (v11 + v15) & _M32

        x = (v7 ^ v11) * _COPY32

        v7 = (x >> 7) & _M32

        v0 = (v0 + v5 + m[s[8]]) & _M32

        x = (v15 ^ v0) * _COPY32

        v15 = (x >> 16) & _M32

        v10 = (v10 + v15) & _M32

        x = (v5 ^ v10) * _COPY32

        v5 = (x >> 12) & _M32

        v0 = (v0 + v5 + m[s[9]]) & _M32

        x = (v15 ^ v0) * _COPY32

        v15 = (x >> 8) & _M32

        v10 = (v10 + v15) & _M32

        x = (v5 ^ v10) * _COPY32

        v5 = (x >> 7) & _M32

        v1 = (v1 + v6 + m[s[10]]) & _M32

        x = (v12 ^ v1) * _COPY32

        v12 = (x >> 16) & _M32

        v11 = (v11 + v12) & _M32

        x = (v6 ^ v11) * _COPY32

        v6 = (x >> 12) & _M32

        v1 = (v1 + v6 + m[s[11]]) & _M32

        x = (v12 ^ v1) * _COPY32

        v12 = (x >> 8) & _M32

        v11 = (v11 + v12) & _M32

        x = (v6 ^ v11) * _COPY32

        v6 = (x >> 7) & _M32

        v2 = (v2 + v7 + m[s[12]]) & _M32

        x = (v13 ^ v2) * _COPY32

        v13 = (x >> 16) & _M32

        v8 = (v8 + v13) & _M32

        x = (v7 ^ v8) * _COPY32

        v7 = (x >> 12) & _M32

        v2 = (v2 + v7 + m[s[13]]) & _M32

        x = (v13 ^ v2) * _COPY32

        v13 = (x >> 8) & _M32

        v8 = (v8 + v13) & _M32

        x = (v7 ^ v8) * _COPY32

        v7 = (x >> 7) & _M32

        v3 = (v3 + v4 + m[s[14]]) & _M32

        x = (v14 ^ v3) * _COPY32

        v14 = (x >> 16) & _M32

        v9 = (v9 + v14) & _M32

        x = (v4 ^ v9) * _COPY32

        v4 = (x >> 12) & _M32

        v3 = (v3 + v4 + m[s[15]]) & _M32

        x = (v14 ^ v3) * _COPY32

        v14 = (x >> 8) & _M32

        v9 = (v9 + v14) & _M32

        x = (v4 ^ v9) * _COPY32

        v4 = (x >> 7) & _M32

    h[:] = (h[0] ^ v0 ^ v8, h[1] ^ v1 ^ v9, h[2] ^ v2 ^ v10, h[3] ^ v3 ^ v11, h[4] ^ v4 ^ v12, h[5] ^ v5 ^ v13, h[6] ^ v6 ^ v14, h[7] ^ v7 ^ v15)


class Variant(NamedTuple):
    block: int

    # The longest digest and key, and the size of the salt and personalization fields.
    max_size: int

    field: int

    iv: tuple

    compress: object

    words: struct.Struct


BLAKE2B = Variant(128, 64, 16, IV_512, compress_b, struct.Struct("<8Q"))

BLAKE2S = Variant(64, 32, 8, IV_256, compress_s, struct.Struct("<8I"))


# The chaining value of the parameter block (RFC 7693, 2.5) for sequential hashing to `size` bytes:
# fanout and depth 1, the salt and personalization zero-padded. The key length field stays zero;
# keying adds it.
def initial(variant, size, salt, personalization):
    block = bytearray(variant.words.size)

    block[0] = size

    block[2] = 1

    block[3] = 1

    block[2 * variant.field : 2 * variant.field + len(salt)] = salt

    block[3 * variant.field : 3 * variant.field + len(personalization)] = personalization

    return tuple(i ^ p for i, p in zip(variant.iv, variant.words.unpack(block)))


def _finish(variant, h, size):
    return variant.words.pack(*h)[:size]


# The digest of a whole message: the key block (RFC 7693, 3.3) first when there is a key, then the
# message's whole blocks where they are, and its last block always with the final flag, padded with
# zeros (a message of no bytes has one zero block unless a key block came first).
def digest(variant, h0, key, data, size):
    block, compress = variant.block, variant.compress

    h = [*h0]

    h[0] ^= len(key) << 8

    length = len(data)

    counter = 0

    if key:
        padded = bytearray(block)

        padded[: len(key)] = key

        counter = block

        compress(h, padded, 0, counter, not length)

        padded[:] = bytes(block)

    if length or not key:
        rest = length - block * ((length - 1) // block) if length else 0

        whole = length - rest

        for offset in range(0, whole, block):
            counter += block

            compress(h, data, offset, counter, False)

        counter += rest

        if rest == block:
            compress(h, data, whole, counter, True)
        else:
            padded = bytearray(block)

            padded[:rest] = data[whole:]

            compress(h, padded, 0, counter, True)

    return _finish(variant, h, size)


class Blake2:
    """A BLAKE2 hash over updates. The last block is compressed only once the next update shows that
    it is not the last, or by digest, which works on a copy and so can be called again."""

    __slots__ = ("_variant", "_h", "_buffer", "_size", "_counter")

    # A key is the first block; an empty key means none.
    def __init__(self, variant, h0, key, size):
        self._variant = variant

        self._h = [*h0]

        self._h[0] ^= len(key) << 8

        self._buffer = bytearray(variant.block) if key else bytearray()

        self._buffer[: len(key)] = key

        self._size = size

        self._counter = 0

    def update(self, data):
        block, compress = self._variant.block, self._variant.compress

        buffer, length, offset = self._buffer, len(data), 0

        while offset < length:
            if len(buffer) == block:
                self._counter += block

                compress(self._h, buffer, 0, self._counter, False)

                buffer[:] = bytes(block)

                buffer.clear()

            if not buffer:
                while length - offset > block:
                    self._counter += block

                    compress(self._h, data, offset, self._counter, False)

                    offset += block

            take = min(block - len(buffer), length - offset)

            buffer += data[offset : offset + take]

            offset += take

    def digest(self):
        variant = self._variant

        h = self._h[:]

        last = bytearray(variant.block)

        last[: len(self._buffer)] = self._buffer

        variant.compress(h, last, 0, self._counter + len(self._buffer), True)

        last[:] = bytes(variant.block)

        return _finish(variant, h, self._size)

    def copy(self):
        other = Blake2.__new__(Blake2)

        other._variant, other._h, other._buffer = self._variant, self._h[:], bytearray(self._buffer)

        other._size, other._counter = self._size, self._counter

        return other
