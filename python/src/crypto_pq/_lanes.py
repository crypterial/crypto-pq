"""Many independent SHA-256, SHA-512 and Keccak-f[1600] computations at once, for the pure
algorithms whose hashes come in independent batches (the chains of a one-time signature, the leaves
and nodes of a tree level, the streams of a sampled matrix).

Word j of the n lanes is one integer, lane i in field i, so that each operation of the scalar code,
a few big-integer operations, acts on every lane: big-integer arithmetic costs much less per lane
than one small operation each, about 15 times less for SHA-256 at 35 lanes (measured). SHA-256
keeps its 32-bit words in 64-bit fields, whose upper half takes the carries of a sum and the copy
that turns a rotation into one shift; SHA-512 does the same with 64-bit words in 128-bit fields.
Keccak keeps its 64-bit lanes in 64-bit fields and rotates each field through masks. Every result
is masked back into its field before it meets another lane.

A context holds the masks of one lane count and lives for one call: the round constants are
multiplied out where they are used, and no table outlives the call. The scratch bytearrays, which
hold secret-derived words, are zeroed before they are dropped; Python cannot wipe its integers.
"""

from ._bytes import wipe
from ._keccak import ROUND_CONSTANTS, shake_tail
from ._sha2 import IV_256, IV_512, K256, K512

_COPY32 = (1 << 32) + 1

_COPY64 = (1 << 64) + 1


def _ones(n, width):
    return int.from_bytes((b"\x01" + bytes(width // 8 - 1)) * n, "little")


class Sha256Lanes:
    """n SHA-256 compressions: a state and a block are lists of 8 and 16 packed words."""

    __slots__ = ("ones", "mask")

    def __init__(self, n):
        self.ones = _ones(n, 64)

        self.mask = self.ones * 0xFFFFFFFF

    # The schedule keeps 16 words, each group of 16 rounds' words computed in place from the last.
    def compress(self, state, words):
        m, ones = self.mask, self.ones

        w = [*words]

        a, b, c, d, e, f, g, h = state

        for group in range(4):
            if group:
                for t in range(16):
                    x = w[(t + 1) & 15]

                    y = w[(t + 14) & 15]

                    xx = x * _COPY32

                    yy = y * _COPY32

                    w[t] = (w[t] + w[(t + 9) & 15] + (((xx >> 7) ^ (xx >> 18) ^ (x >> 3)) & m) + (((yy >> 17) ^ (yy >> 19) ^ (y >> 10)) & m)) & m

            for kt, x in zip(K256[16 * group : 16 * group + 16], w):
                ee = e * _COPY32

                aa = a * _COPY32

                t1 = h + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & m) + (g ^ (e & (f ^ g))) + kt * ones + x

                t2 = (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & m) + ((a & b) | (c & (a | b)))

                h, g, f, e, d, c, b, a = g, f, e, (d + t1) & m, c, b, a, (t1 + t2) & m

        return [(s + v) & m for s, v in zip(state, (a, b, c, d, e, f, g, h))]


class Sha512Lanes:
    """n SHA-512 compressions, as Sha256Lanes with 64-bit words in 128-bit fields."""

    __slots__ = ("ones", "mask")

    def __init__(self, n):
        self.ones = _ones(n, 128)

        self.mask = self.ones * 0xFFFFFFFFFFFFFFFF

    def compress(self, state, words):
        m, ones = self.mask, self.ones

        w = [*words]

        a, b, c, d, e, f, g, h = state

        for group in range(5):
            if group:
                for t in range(16):
                    x = w[(t + 1) & 15]

                    y = w[(t + 14) & 15]

                    xx = x * _COPY64

                    yy = y * _COPY64

                    w[t] = (w[t] + w[(t + 9) & 15] + (((xx >> 1) ^ (xx >> 8) ^ (x >> 7)) & m) + (((yy >> 19) ^ (yy >> 61) ^ (y >> 6)) & m)) & m

            for kt, x in zip(K512[16 * group : 16 * group + 16], w):
                ee = e * _COPY64

                aa = a * _COPY64

                t1 = h + (((ee >> 14) ^ (ee >> 18) ^ (ee >> 41)) & m) + (g ^ (e & (f ^ g))) + kt * ones + x

                t2 = (((aa >> 28) ^ (aa >> 34) ^ (aa >> 39)) & m) + ((a & b) | (c & (a | b)))

                h, g, f, e, d, c, b, a = g, f, e, (d + t1) & m, c, b, a, (t1 + t2) & m

        return [(s + v) & m for s, v in zip(state, (a, b, c, d, e, f, g, h))]


class KeccakLanes:
    """n Keccak-f[1600] permutations: a state is a list of the 25 packed lanes, permuted in place,
    by the steps of _keccak.permute."""

    __slots__ = ("ones", "mask", "rotations")

    def __init__(self, n):
        ones = self.ones = _ones(n, 64)

        self.mask = ones * 0xFFFFFFFFFFFFFFFF

        self.rotations = tuple(mask for r in [1, 2, 3, 6, 8, 10, 14, 15, 18, 20, 21, 25, 27, 28, 36, 39, 41, 43, 44, 45, 55, 56, 61, 62] for mask in (self.mask ^ (ones * ((1 << r) - 1)), ones * ((1 << r) - 1)))

    def permute(self, state):
        (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) = state

        m, ones = self.mask, self.ones

        h1, l1, h2, l2, h3, l3, h6, l6, h8, l8, h10, l10, h14, l14, h15, l15, h18, l18, h20, l20, h21, l21, h25, l25, h27, l27, h28, l28, h36, l36, h39, l39, h41, l41, h43, l43, h44, l44, h45, l45, h55, l55, h56, l56, h61, l61, h62, l62 = self.rotations

        a1 ^= m

        a2 ^= m

        a8 ^= m

        a12 ^= m

        a17 ^= m

        a20 ^= m

        for constant in ROUND_CONSTANTS:
            c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20

            c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21

            c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22

            c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23

            c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24

            d0 = c4 ^ ((((c1 << 1) & h1) | ((c1 >> 63) & l1)))

            d1 = c0 ^ ((((c2 << 1) & h1) | ((c2 >> 63) & l1)))

            d2 = c1 ^ ((((c3 << 1) & h1) | ((c3 >> 63) & l1)))

            d3 = c2 ^ ((((c4 << 1) & h1) | ((c4 >> 63) & l1)))

            d4 = c3 ^ ((((c0 << 1) & h1) | ((c0 >> 63) & l1)))

            a0 ^= d0

            a1 ^= d1

            a2 ^= d2

            a3 ^= d3

            a4 ^= d4

            a5 ^= d0

            a6 ^= d1

            a7 ^= d2

            a8 ^= d3

            a9 ^= d4

            a10 ^= d0

            a11 ^= d1

            a12 ^= d2

            a13 ^= d3

            a14 ^= d4

            a15 ^= d0

            a16 ^= d1

            a17 ^= d2

            a18 ^= d3

            a19 ^= d4

            a20 ^= d0

            a21 ^= d1

            a22 ^= d2

            a23 ^= d3

            a24 ^= d4

            b0 = a0

            b1 = (((a6 << 44) & h44) | ((a6 >> 20) & l44))

            b2 = (((a12 << 43) & h43) | ((a12 >> 21) & l43))

            b3 = (((a18 << 21) & h21) | ((a18 >> 43) & l21))

            b4 = (((a24 << 14) & h14) | ((a24 >> 50) & l14))

            b5 = (((a3 << 28) & h28) | ((a3 >> 36) & l28))

            b6 = (((a9 << 20) & h20) | ((a9 >> 44) & l20))

            b7 = (((a10 << 3) & h3) | ((a10 >> 61) & l3))

            b8 = (((a16 << 45) & h45) | ((a16 >> 19) & l45))

            b9 = (((a22 << 61) & h61) | ((a22 >> 3) & l61))

            b10 = (((a1 << 1) & h1) | ((a1 >> 63) & l1))

            b11 = (((a7 << 6) & h6) | ((a7 >> 58) & l6))

            b12 = (((a13 << 25) & h25) | ((a13 >> 39) & l25))

            b13 = (((a19 << 8) & h8) | ((a19 >> 56) & l8))

            b14 = (((a20 << 18) & h18) | ((a20 >> 46) & l18))

            b15 = (((a4 << 27) & h27) | ((a4 >> 37) & l27))

            b16 = (((a5 << 36) & h36) | ((a5 >> 28) & l36))

            b17 = (((a11 << 10) & h10) | ((a11 >> 54) & l10))

            b18 = (((a17 << 15) & h15) | ((a17 >> 49) & l15))

            b19 = (((a23 << 56) & h56) | ((a23 >> 8) & l56))

            b20 = (((a2 << 62) & h62) | ((a2 >> 2) & l62))

            b21 = (((a8 << 55) & h55) | ((a8 >> 9) & l55))

            b22 = (((a14 << 39) & h39) | ((a14 >> 25) & l39))

            b23 = (((a15 << 41) & h41) | ((a15 >> 23) & l41))

            b24 = (((a21 << 2) & h2) | ((a21 >> 62) & l2))

            a0 = b0 ^ (b1 | b2) ^ constant * ones

            a1 = b1 ^ ((b2 ^ m) | b3)

            a2 = b2 ^ (b3 & b4)

            a3 = b3 ^ (b4 | b0)

            a4 = b4 ^ (b0 & b1)

            a5 = b5 ^ (b6 | b7)

            a6 = b6 ^ (b7 & b8)

            a7 = b7 ^ (b8 | (b9 ^ m))

            a8 = b8 ^ (b9 | b5)

            a9 = b9 ^ (b5 & b6)

            x = b13 ^ m

            a10 = b10 ^ (b11 | b12)

            a11 = b11 ^ (b12 & b13)

            a12 = b12 ^ (x & b14)

            a13 = x ^ (b14 | b10)

            a14 = b14 ^ (b10 & b11)

            x = b18 ^ m

            a15 = b15 ^ (b16 & b17)

            a16 = b16 ^ (b17 | b18)

            a17 = b17 ^ (x | b19)

            a18 = x ^ (b19 & b15)

            a19 = b19 ^ (b15 | b16)

            x = b21 ^ m

            a20 = b20 ^ (x & b22)

            a21 = x ^ (b22 | b23)

            a22 = b22 ^ (b23 & b24)

            a23 = b23 ^ (b24 | b20)

            a24 = b24 ^ (b20 & b21)

        state[:] = (a0, a1 ^ m, a2 ^ m, a3, a4, a5, a6, a7, a8 ^ m, a9, a10, a11, a12 ^ m, a13, a14, a15, a16, a17 ^ m, a18, a19, a20 ^ m, a21, a22, a23, a24)


# The most lanes of one computation: past about 48 SHA-256 or Keccak lanes and 24 SHA-512 lanes
# the cost per lane stops falling (measured), while the memory of a computation keeps growing.
MOST = 64

_MOST_512 = 32


# The first lane and the lane count of each computation for n >= 1 lanes, at most `most` each and
# as even as possible.
def chunks(n, most=MOST):
    size = -(-n // -(-n // most))

    return [(first, min(size, n - first)) for first in range(0, n, size)]


# The 16 packed words of the blocks of `count` lanes, lane i's block at data[start + stride * i:]:
# big-endian word j of `width` bytes goes to field i of packed word j (2 * width bytes, little-
# endian), one strided copy per byte.
def _load(data, start, stride, count, width):
    field, end = 2 * width, start + stride * count

    packed = bytearray(field * count)

    words = []

    for j in range(16):
        at = start + width * (j + 1) - 1

        for b in range(width):
            packed[b::field] = data[at - b : end : stride]

        words.append(int.from_bytes(packed, "little"))

    wipe(packed)

    return words


# The n results of `size` bytes in `out`, as bytes objects, `out` zeroed.
def _split(out, size, n):
    with memoryview(out) as view:
        results = [view[size * i : size * (i + 1)].tobytes() for i in range(n)]

    wipe(out)

    return results


# The digests in the 8 packed words `state` (fields of 2 * width bytes) written to out[offset:],
# 8 * width bytes a lane.
def _store(state, count, width, out, offset):
    field, size = 2 * width, 8 * width

    end = offset + size * count

    for k, word in enumerate(state):
        raw = word.to_bytes(field * count, "little")

        for b in range(width):
            out[offset + width * k + b : end : size] = raw[width - 1 - b :: field]


# SHA-256 (`width` 4) or SHA-512 (8) of `count` lanes from the common chaining value `state`, lane
# i's blocks at data[start + stride * i:], `blocks` of them, its digest to out[offset + 8 * width
# * i:].
def _sha2(state, data, start, stride, count, blocks, width, out, offset):
    lanes = (Sha256Lanes if width == 4 else Sha512Lanes)(count)

    words = [lanes.ones * s for s in state]

    for t in range(blocks):
        words = lanes.compress(words, _load(data, start + 16 * width * t, stride, count, width))

    _store(words, count, width, out, offset)


# The digests after one more block of each of the n blocks of `data` (joined, each padded already)
# from the common chaining value `state`: the 32 bytes of each, joined in the order of the blocks.
def sha256_join(state, data, n):
    out = bytearray(32 * n)

    for first, count in chunks(n):
        _sha2(state, data, 64 * first, 64, count, 1, 4, out, 32 * first)

    return out


# As sha256_join, with SHA-512 and its 128-byte blocks and 64-byte digests.
def sha512_join(state, data, n):
    out = bytearray(64 * n)

    for first, count in chunks(n, _MOST_512):
        _sha2(state, data, 128 * first, 128, count, 1, 8, out, 64 * first)

    return out


# SHA-256 or SHA-512 (`width` 4 or 8) of each of `messages`, which share one length, continuing the
# chaining value `state` after `done` bytes (whole blocks) common to them all: the digests, as a
# list.
def _sha2_many(messages, state, done, width):
    n, length, block, size = len(messages), len(messages[0]), 16 * width, 8 * width

    tail = b"\x80" + bytes(-(length + 1 + 2 * width) % block) + (8 * (done + length)).to_bytes(2 * width, "big")

    data = b"".join([message + tail for message in messages])

    stride = length + len(tail)

    out = bytearray(size * n)

    for first, count in chunks(n, MOST if width == 4 else _MOST_512):
        _sha2(state, data, stride * first, stride, count, stride // block, width, out, size * first)

    return _split(out, size, n)


def sha256_many(messages, state=IV_256, done=0):
    return _sha2_many(messages, state, done, 4)


def sha512_many(messages, state=IV_512, done=0):
    return _sha2_many(messages, state, done, 8)


# Keccak of `count` lanes, lane i's padded input of `blocks` blocks of `rate` bytes at
# data[start + stride * i:], and `size` bytes squeezed from each to out[offset:]. A lane's bytes
# are the same in a block and in a packed word's field, so 8-byte views move them whatever the
# machine's byte order.
def _keccak(data, start, stride, count, blocks, rate, size, out, offset):
    lanes = KeccakLanes(count)

    words, step = rate // 8, stride // 8

    view = memoryview(data).cast("Q")

    state = [0] * 25

    for t in range(blocks):
        base = (start + rate * t) // 8

        for j in range(words):
            state[j] ^= int.from_bytes(view[base + j : base + j + step * count : step].tobytes(), "little")

        lanes.permute(state)

    view.release()

    whole = -(-size // 8)

    squeezed = bytearray(8 * whole * count)

    target = memoryview(squeezed).cast("Q")

    done = 0

    while True:
        for j in range(min(words, whole - done)):
            target[done + j :: whole] = memoryview(state[j].to_bytes(8 * count, "little")).cast("Q")

        done += words

        if done >= whole:
            break

        lanes.permute(state)

    target.release()

    if size == 8 * whole:
        out[offset : offset + size * count] = squeezed
    else:
        with memoryview(squeezed) as source:
            for i in range(count):
                out[offset + size * i : offset + size * (i + 1)] = source[8 * whole * i : 8 * whole * i + size]

    wipe(squeezed)


# Keccak-f[1600] of each of the n padded blocks of `rate` bytes in `data` (joined) absorbed into a
# zero state, and `size` bytes squeezed from each, joined.
def keccak_join(data, n, rate, size):
    out = bytearray(size * n)

    for first, count in chunks(n):
        _keccak(data, rate * first, rate, count, 1, rate, size, out, size * first)

    return out


# SHAKE (`rate` 168 or 136) of each of `messages`, which share one length, to `size` bytes each, as
# a list.
def shake_many(rate, messages, size):
    n, length = len(messages), len(messages[0])

    tail = shake_tail(rate, length % rate)

    data = b"".join([message + tail for message in messages])

    stride = length + len(tail)

    out = bytearray(size * n)

    for first, count in chunks(n):
        _keccak(data, stride * first, stride, count, stride // rate, rate, size, out, size * first)

    return _split(out, size, n)
