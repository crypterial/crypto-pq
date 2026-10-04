"""Many independent hash computations at once, one per lane of a Python integer.

A lane integer holds one fixed-width field per computation: lane i occupies bits [i * width,
(i + 1) * width). One big-integer operation then acts on every lane in a single pass of C code,
so a batch of thousands of compressions costs a few thousand Python operations instead of
millions. The hash-based signatures batch their independent hashes this way: the WOTS chains,
the FORS leaves and the nodes of one Merkle level.
"""

import struct
from functools import lru_cache

from ._keccak import ROUND_CONSTANTS, permute
from ._sha2 import K256, K512

M32 = 0xFFFFFFFF

M64 = 0xFFFFFFFFFFFFFFFF


@lru_cache(maxsize=32)
def ones(count, width):
    return int.from_bytes((b"\x01" + bytes(width // 8 - 1)) * count, "little")


def replicate(value, count, width):
    return value * ones(count, width)


def pack(values, width):
    if width == 128:
        flat = [0] * (2 * len(values))

        flat[0::2] = values

        values = flat

    return int.from_bytes(struct.pack(f"<{len(values)}Q", *values), "little")


def unpack(lanes, count, width):
    flat = struct.unpack(f"<{count * width // 64}Q", lanes.to_bytes(count * width // 8, "little"))

    return list(flat[0::2] if width == 128 else flat)


def lane(lanes, index, width, mask):
    return (lanes >> (index * width)) & mask


def select(lanes, start, count, width):
    return (lanes >> (start * width)) & ((1 << (count * width)) - 1)


def concatenate(parts, counts, width):
    return int.from_bytes(b"".join(part.to_bytes(count * width // 8, "little") for part, count in zip(parts, counts)), "little")


# A 64-bit field becomes the low half of a 128-bit field. The 8-byte groups only move, so the
# platform byte order of the memoryview does not matter.
def widen(lanes, count):
    out = bytearray(16 * count)

    memoryview(out).cast("Q")[0::2] = memoryview(lanes.to_bytes(8 * count, "little")).cast("Q")

    return int.from_bytes(out, "little")


# Big-endian words of equal-length byte strings, one string per lane, and back.
def words(chunks, size, width):
    k = len(chunks[0]) // size

    flat = struct.unpack(f">{len(chunks) * k}{'I' if size == 4 else 'Q'}", b"".join(chunks))

    return [pack(flat[j::k], width) for j in range(k)]


def chunks(lane_words, count, size, width):
    k = len(lane_words)

    flat = [0] * (count * k)

    for j, word in enumerate(lane_words):
        flat[j::k] = unpack(word, count, width)

    data = struct.pack(f">{count * k}{'I' if size == 4 else 'Q'}", *flat)

    step = size * k

    return [data[i * step : (i + 1) * step] for i in range(count)]


# Little-endian 64-bit words (Keccak lanes) of equal-length byte strings, and back.
def lanes64(chunks):
    k = len(chunks[0]) // 8

    flat = struct.unpack(f"<{len(chunks) * k}Q", b"".join(chunks))

    return [pack(flat[j::k], 64) for j in range(k)]


def chunks64(lane_words, count):
    k = len(lane_words)

    flat = [0] * (count * k)

    for j, word in enumerate(lane_words):
        flat[j::k] = unpack(word, count, 64)

    data = struct.pack(f"<{count * k}Q", *flat)

    return [data[i * 8 * k : (i + 1) * 8 * k] for i in range(count)]


def mask(flags, width):
    return pack([M64 if flag else 0 for flag in flags], width)


# Hash chains of different lengths in one batch: step(value, j) applies the hash with step index
# j to every lane. run_to returns each lane after ends[i] steps from index 0; run_from applies
# the steps starts[i] .. last - 1 to lane i. Every lane takes every step and keeps only the
# results it needs, which costs nothing extra in a batch.
def run_to(step, value, ends):
    result = [word & mask([end == 0 for end in ends], 64) for word in value]

    for j in range(max(ends)):
        value = step(value, j)

        keep = mask([end == j + 1 for end in ends], 64)

        result = [r | (word & keep) for r, word in zip(result, value)]

    return result


def run_from(step, value, starts, last):
    for j in range(min(starts), last):
        active = mask([start <= j for start in starts], 64)

        out = step(value, j)

        value = [x ^ ((x ^ y) & active) for x, y in zip(value, out)]

    return value


# SHA-2 message words of whole values that start `offset` bytes into a word, behind `top`, which
# already holds the bytes in front of them. The byte 0x80 that starts the padding follows the
# last value byte. Words are `size` bytes in fields twice as wide.
def shifted(top, values, size, offset, count):
    bits = 8 * size

    shift = 8 * offset

    one = ones(count, 2 * bits)

    full = one * ((1 << bits) - 1)

    low = one * ((1 << (bits - shift)) - 1)

    out = [top | ((values[0] >> shift) & low)]

    for previous, value in zip(values, values[1:]):
        out.append(((previous << (bits - shift)) | (value >> shift)) & full)

    out.append(((values[-1] << (bits - shift)) & full) | (one * (0x80 << (bits - shift - 8))))

    return out


# The same for little-endian Keccak lanes, where the SHAKE padding byte 0x1F follows the values.
def shifted_le(top, values, offset, count):
    shift = 8 * offset

    one = ones(count, 64)

    low = one * ((1 << shift) - 1)

    high = one * (M64 ^ ((1 << shift) - 1))

    out = [top | ((values[0] << shift) & high)]

    for previous, value in zip(values, values[1:]):
        out.append(((previous >> (64 - shift)) & low) | ((value << shift) & high))

    out.append(((values[-1] >> (64 - shift)) & low) | (one * (0x1F << shift)))

    return out


class Sha256:
    """SHA-256 compressions of `count` states at once.

    A 32-bit word sits in the low half of a 64-bit field. The high half takes the carries of a
    sum of a few words, and, just before a rotation, a second copy of the word: a right rotation
    of x is then one shift of x | x << 32 and one mask, instead of two shifts and two masks.
    """

    __slots__ = ("mask", "k")

    def __init__(self, count):
        one = ones(count, 64)

        self.mask = one * M32

        self.k = [one * k for k in K256]

    # `rounds` is the state after the first `start` rounds, when those rounds are the same in every
    # lane: then they ran once, on plain integers (see sha256).
    def compress(self, state, block, start=0, rounds=None):
        mask = self.mask

        w = list(block)

        for t in range(16, 64):
            x = w[t - 15]

            y = w[t - 2]

            xx = x | (x << 32)

            yy = y | (y << 32)

            s0 = ((xx >> 7) ^ (xx >> 18) ^ (x >> 3)) & mask

            s1 = ((yy >> 17) ^ (yy >> 19) ^ (y >> 10)) & mask

            w.append((w[t - 16] + w[t - 7] + s0 + s1) & mask)

        a, b, c, d, e, f, g, h = state if rounds is None else rounds

        bc = b ^ c

        for t in range(start, 64):
            k = self.k[t]

            x = w[t]

            ee = e | (e << 32)

            t1 = h + (((ee >> 6) ^ (ee >> 11) ^ (ee >> 25)) & mask) + (g ^ (e & (f ^ g))) + k + x

            aa = a | (a << 32)

            ab = a ^ b

            t2 = (((aa >> 2) ^ (aa >> 13) ^ (aa >> 22)) & mask) + (b ^ (ab & bc))

            bc = ab

            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & mask, c, b, a, (t1 + t2) & mask

        return [(s + v) & mask for s, v in zip(state, (a, b, c, d, e, f, g, h))]


class Sha512:
    """SHA-512 compressions of `count` states at once, with 64-bit words in 128-bit fields, for
    the same reasons as Sha256."""

    __slots__ = ("mask", "k")

    def __init__(self, count):
        one = ones(count, 128)

        self.mask = one * M64

        self.k = [one * k for k in K512]

    def compress(self, state, block):
        mask = self.mask

        w = list(block)

        for t in range(16, 80):
            x = w[t - 15]

            y = w[t - 2]

            xx = x | (x << 64)

            yy = y | (y << 64)

            s0 = ((xx >> 1) ^ (xx >> 8) ^ (x >> 7)) & mask

            s1 = ((yy >> 19) ^ (yy >> 61) ^ (y >> 6)) & mask

            w.append((w[t - 16] + w[t - 7] + s0 + s1) & mask)

        a, b, c, d, e, f, g, h = state

        bc = b ^ c

        for k, x in zip(self.k, w):
            ee = e | (e << 64)

            t1 = h + (((ee >> 14) ^ (ee >> 18) ^ (ee >> 41)) & mask) + (g ^ (e & (f ^ g))) + k + x

            aa = a | (a << 64)

            ab = a ^ b

            t2 = (((aa >> 28) ^ (aa >> 34) ^ (aa >> 39)) & mask) + (b ^ (ab & bc))

            bc = ab

            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & mask, c, b, a, (t1 + t2) & mask

        return [(s + v) & mask for s, v in zip(state, (a, b, c, d, e, f, g, h))]


# The rotations of theta and rho, in the order the unrolled code below unpacks their masks.
_ROTATIONS = (1, 44, 43, 21, 14, 28, 20, 3, 45, 61, 6, 25, 8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41, 2)


class Keccak:
    """Keccak-f[1600] on `count` states at once, one 64-bit field per state in each of the 25
    lane integers.

    The fields have no spare bits, so a rotation by r keeps two masked parts: the bits that stay
    in the field after x << r, and the r bits that x >> (64 - r) brings back to its bottom. The
    lanes are complemented as in the scalar permutation (see _keccak), with XOR by all ones as
    the NOT, so that no integer becomes negative.
    """

    __slots__ = ("full", "high", "low", "rc")

    def __init__(self, count):
        one = ones(count, 64)

        self.full = one * M64

        self.low = tuple(one * ((1 << r) - 1) for r in _ROTATIONS)

        self.high = tuple(one * (M64 ^ ((1 << r) - 1)) for r in _ROTATIONS)

        self.rc = [one * c for c in ROUND_CONSTANTS]

    def permute(self, state):
        (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) = state

        (h1, h44, h43, h21, h14, h28, h20, h3, h45, h61, h6, h25, h8, h18, h27, h36, h10, h15, h56, h62, h55, h39, h41, h2) = self.high

        (l1, l44, l43, l21, l14, l28, l20, l3, l45, l61, l6, l25, l8, l18, l27, l36, l10, l15, l56, l62, l55, l39, l41, l2) = self.low

        full = self.full

        a1 ^= full

        a2 ^= full

        a8 ^= full

        a12 ^= full

        a17 ^= full

        a20 ^= full

        for rc in self.rc:
            c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20

            c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21

            c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22

            c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23

            c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24

            d0 = c4 ^ ((c1 << 1) & h1) ^ ((c1 >> 63) & l1)

            d1 = c0 ^ ((c2 << 1) & h1) ^ ((c2 >> 63) & l1)

            d2 = c1 ^ ((c3 << 1) & h1) ^ ((c3 >> 63) & l1)

            d3 = c2 ^ ((c4 << 1) & h1) ^ ((c4 >> 63) & l1)

            d4 = c3 ^ ((c0 << 1) & h1) ^ ((c0 >> 63) & l1)

            b0 = a0 ^ d0

            x = a6 ^ d1

            b1 = ((x << 44) & h44) | ((x >> 20) & l44)

            x = a12 ^ d2

            b2 = ((x << 43) & h43) | ((x >> 21) & l43)

            x = a18 ^ d3

            b3 = ((x << 21) & h21) | ((x >> 43) & l21)

            x = a24 ^ d4

            b4 = ((x << 14) & h14) | ((x >> 50) & l14)

            x = a3 ^ d3

            b5 = ((x << 28) & h28) | ((x >> 36) & l28)

            x = a9 ^ d4

            b6 = ((x << 20) & h20) | ((x >> 44) & l20)

            x = a10 ^ d0

            b7 = ((x << 3) & h3) | ((x >> 61) & l3)

            x = a16 ^ d1

            b8 = ((x << 45) & h45) | ((x >> 19) & l45)

            x = a22 ^ d2

            b9 = ((x << 61) & h61) | ((x >> 3) & l61)

            x = a1 ^ d1

            b10 = ((x << 1) & h1) | ((x >> 63) & l1)

            x = a7 ^ d2

            b11 = ((x << 6) & h6) | ((x >> 58) & l6)

            x = a13 ^ d3

            b12 = ((x << 25) & h25) | ((x >> 39) & l25)

            x = a19 ^ d4

            b13 = ((x << 8) & h8) | ((x >> 56) & l8)

            x = a20 ^ d0

            b14 = ((x << 18) & h18) | ((x >> 46) & l18)

            x = a4 ^ d4

            b15 = ((x << 27) & h27) | ((x >> 37) & l27)

            x = a5 ^ d0

            b16 = ((x << 36) & h36) | ((x >> 28) & l36)

            x = a11 ^ d1

            b17 = ((x << 10) & h10) | ((x >> 54) & l10)

            x = a17 ^ d2

            b18 = ((x << 15) & h15) | ((x >> 49) & l15)

            x = a23 ^ d3

            b19 = ((x << 56) & h56) | ((x >> 8) & l56)

            x = a2 ^ d2

            b20 = ((x << 62) & h62) | ((x >> 2) & l62)

            x = a8 ^ d3

            b21 = ((x << 55) & h55) | ((x >> 9) & l55)

            x = a14 ^ d4

            b22 = ((x << 39) & h39) | ((x >> 25) & l39)

            x = a15 ^ d0

            b23 = ((x << 41) & h41) | ((x >> 23) & l41)

            x = a21 ^ d1

            b24 = ((x << 2) & h2) | ((x >> 62) & l2)

            a0 = b0 ^ (b1 | b2) ^ rc

            a1 = b1 ^ ((b2 ^ full) | b3)

            a2 = b2 ^ (b3 & b4)

            a3 = b3 ^ (b4 | b0)

            a4 = b4 ^ (b0 & b1)

            a5 = b5 ^ (b6 | b7)

            a6 = b6 ^ (b7 & b8)

            a7 = b7 ^ (b8 | (b9 ^ full))

            a8 = b8 ^ (b9 | b5)

            a9 = b9 ^ (b5 & b6)

            x = b13 ^ full

            a10 = b10 ^ (b11 | b12)

            a11 = b11 ^ (b12 & b13)

            a12 = b12 ^ (x & b14)

            a13 = x ^ (b14 | b10)

            a14 = b14 ^ (b10 & b11)

            x = b18 ^ full

            a15 = b15 ^ (b16 & b17)

            a16 = b16 ^ (b17 | b18)

            a17 = b17 ^ (x | b19)

            a18 = x ^ (b19 & b15)

            a19 = b19 ^ (b15 | b16)

            x = b21 ^ full

            a20 = b20 ^ (x & b22)

            a21 = x ^ (b22 | b23)

            a22 = b22 ^ (b23 & b24)

            a23 = b23 ^ (b24 | b20)

            a24 = b24 ^ (b20 & b21)

        return [a0, a1 ^ full, a2 ^ full, a3, a4, a5, a6, a7, a8 ^ full, a9, a10, a11, a12 ^ full, a13, a14, a15, a16, a17 ^ full, a18, a19, a20 ^ full, a21, a22, a23, a24]


# An engine holds its constants in every lane, megabytes for the largest batches, so each cache
# keeps only the four most recent engines: enough for a batch to reuse its engine at every step
# without holding on to many large ones.
@lru_cache(maxsize=4)
def sha256_engine(count):
    return Sha256(count)


@lru_cache(maxsize=4)
def sha512_engine(count):
    return Sha512(count)


@lru_cache(maxsize=4)
def keccak_engine(count):
    return Keccak(count)


# SHA-2 padding: zero words up to the last two words of a block, then the length in bits.
def _blocks(words, count, bits, width):
    words = list(words) + [0] * ((14 - len(words)) % 16)

    words += [0, replicate(bits, count, width)]

    return [words[i : i + 16] for i in range(0, len(words), 16)]


def _rounds256(state, words):
    a, b, c, d, e, f, g, h = state

    for k, x in zip(K256, words):
        t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + k + x

        t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))

        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32

    return [a, b, c, d, e, f, g, h]


# The final state of SHA-256 from a state shared by every lane (the IV or the state after a
# common first block), given the remaining message words up to the padding byte and the length
# of the whole message in bits. While the words of the first block are the same in every lane,
# so are the rounds that use them: those run once, and only the rest run on lanes.
def sha256(state, message, count, bits):
    engine = sha256_engine(count)

    one = ones(count, 64)

    blocks = _blocks(message, count, bits, 64)

    start = 0

    while start < 16 and blocks[0][start] == (blocks[0][start] & M32) * one:
        start += 1

    rounds = _rounds256(state, [word & M32 for word in blocks[0][:start]])

    lanes = [word * one for word in state]

    lanes = engine.compress(lanes, blocks[0], start, [word * one for word in rounds])

    for block in blocks[1:]:
        lanes = engine.compress(lanes, block)

    return lanes


def sha512(state, message, count, bits):
    engine = sha512_engine(count)

    state = [replicate(word, count, 128) for word in state]

    for block in _blocks(message, count, bits, 128):
        state = engine.compress(state, block)

    return state


# SHAKE256 of messages in Keccak lanes that already end with the padding byte 0x1F; returns the
# first `size` lanes of output.
def shake256(message, count, size):
    engine = keccak_engine(count)

    lanes = list(message) + [0] * (-len(message) % 17)

    lanes[-1] ^= replicate(0x80 << 56, count, 64)

    state = [0] * 25

    for start in range(0, len(lanes), 17):
        for i in range(17):
            state[i] ^= lanes[start + i]

        state = engine.permute(state)

    return state[:size]


# A message of at most rate - 1 bytes with its Keccak padding: the domain suffix (0x06 for SHA-3,
# 0x1F for SHAKE) right after it and 0x80 in the last byte of the rate; the rest of the 200-byte
# state stays zero.
def padded_block(message, rate, suffix):
    block = bytearray(200)

    block[: len(message)] = message

    block[len(message)] ^= suffix

    block[rate - 1] ^= 0x80

    return bytes(block)


# The padded blocks of a longer message, each as the 25 words that it adds to the state.
def padded_blocks(message, rate, suffix):
    data = bytearray(message)

    data.append(suffix)

    data += bytes(-len(data) % rate)

    data[-1] |= 0x80

    size = rate // 8

    words = struct.unpack(f"<{len(data) // 8}Q", data)

    return [list(words[i : i + size]) + [0] * (25 - size) for i in range(0, len(words), size)]


# The rest of a sponge on the scalar permutation.
def absorb(state, blocks):
    for block in blocks:
        for i, word in enumerate(block):
            state[i] ^= word

        permute(state)

    return state


class Squeeze:
    """SHAKE streams of short seeds, absorbed and squeezed together, one stream per lane. A rate is
    168 for SHAKE128 and 136 for SHAKE256; `rate` gives one for every stream or a list of them."""

    __slots__ = ("count", "rates", "engine", "state")

    def __init__(self, seeds, rate):
        self.count = len(seeds)

        self.rates = [rate] * self.count if isinstance(rate, int) else list(rate)

        self.engine = keccak_engine(self.count)

        self.state = lanes64([padded_block(seed, r, 0x1F) for seed, r in zip(seeds, self.rates)])

    def blocks(self, number):
        out = [b""] * self.count

        size = max(self.rates) // 8

        for _ in range(number):
            self.state = self.engine.permute(self.state)

            out = [a + b[:r] for a, b, r in zip(out, chunks64(self.state[:size], self.count), self.rates)]

        return out


class Beside:
    """One-block sponges in lanes 1 .., beside a longer sponge in lane 0 that pays for their
    permutations: before each permutation lane 0 absorbs its next block, while it has any, and
    after it every other lane squeezes `rate` bytes. `state` is lane 0's state so far and `blocks`
    its remaining blocks (see padded_blocks); `streams` are the padded blocks of the others."""

    __slots__ = ("count", "rates", "engine", "words", "pending", "lane")

    def __init__(self, state, blocks, streams, rates):
        self.count = 1 + len(streams)

        self.rates = rates

        self.engine = keccak_engine(self.count)

        self.words = [(word << 64) | lane for word, lane in zip(lanes64(streams), state)]

        self.pending = list(blocks)

        self.lane = state

    def blocks(self, number):
        out = [b""] * (self.count - 1)

        size = max(self.rates) // 8

        for _ in range(number):
            if self.pending:
                self.words = self.engine.permute([word ^ add for word, add in zip(self.words, self.pending.pop(0))])

                self.lane = [word & M64 for word in self.words]
            else:
                self.words = self.engine.permute(self.words)

            out = [a + b[:r] for a, b, r in zip(out, chunks64(self.words[:size], self.count)[1:], self.rates)]

        return out

    # Lane 0 after its last absorbed block, finished on the scalar permutation.
    def finish(self):
        return absorb(list(self.lane), self.pending)
