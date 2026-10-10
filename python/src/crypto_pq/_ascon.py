import struct

from ._errors import CryptoPQError, ErrorCode

_M64 = 0xFFFFFFFFFFFFFFFF

# Multiplying a word by 2^64 + 1 puts a copy of it above itself, so that a right rotation is one
# shift and a mask.
_COPY64 = (1 << 64) + 1

_WORD = struct.Struct("<Q")

ROUND_CONSTANTS = (0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B)

# The state after Ascon-p[12] of IV || 0^256 (SP 800-232, appendix A.3).
HASH256 = (0x9B1E5494E934D681, 0x4BC3A01E333751D2, 0xAE65396C6B34B81A, 0x3C7FD4A4D56A4DB3, 0x1A5C464906C5976D)

XOF128 = (0xDA82CE768D9447EB, 0xCC7CE6C75F1EF969, 0xE7508FD780085631, 0x0EE0EA53416B58CC, 0xE0547524DB6F0BDE)

CXOF128 = (0x675527C2A0E8DE03, 0x43D12D7DC0377BBC, 0xE9901DEC426E81B5, 0x2AB14907720780B6, 0x8F3F1D02D432BC46)

# SP 800-232, 5.3: the customization string of Ascon-CXOF128 has at most 2048 bits.
MAX_CUSTOMIZATION = 256


# Ascon-p[12]: the round constant, the S-box as the bitsliced Keccak chi between XOR layers, and
# the linear layer, which commutes with the complement of the S-box's third output.
def permute(x0, x1, x2, x3, x4):
    for constant in ROUND_CONSTANTS:
        x2 ^= constant ^ x1

        x0 ^= x4

        x4 ^= x3

        t0 = x0 ^ (x2 & ~x1)

        t1 = x1 ^ (x3 & ~x2)

        t2 = x2 ^ (x4 & ~x3)

        t3 = x3 ^ (x0 & ~x4)

        t4 = x4 ^ (x1 & ~x0)

        t1 ^= t0

        t0 ^= t4

        t3 ^= t2

        d = t0 * _COPY64

        x0 = t0 ^ ((d >> 19 ^ d >> 28) & _M64)

        d = t1 * _COPY64

        x1 = t1 ^ ((d >> 61 ^ d >> 39) & _M64)

        d = t2 * _COPY64

        x2 = t2 ^ ((d >> 1 ^ d >> 6) & _M64) ^ _M64

        d = t3 * _COPY64

        x3 = t3 ^ ((d >> 10 ^ d >> 17) & _M64)

        d = t4 * _COPY64

        x4 = t4 ^ ((d >> 7 ^ d >> 41) & _M64)

    return x0, x1, x2, x3, x4


class Ascon:
    """The Ascon sponge of SP 800-232 with a rate of 64 bits: message words load little-endian into
    the first word of the state, the last one padded with a 1 bit after the message. `size` is the
    output size of digest (Ascon-Hash256); read squeezes an XOF's output in pieces."""

    __slots__ = ("_state", "_buffer", "_size", "_output", "_position")

    def __init__(self, state, size=0):
        self._state = state

        self._buffer = bytearray()

        self._size = size

        self._output = b""

        self._position = -1

    def copy(self):
        other = Ascon(self._state, self._size)

        other._buffer[:] = self._buffer

        other._output = self._output

        other._position = self._position

        return other

    def update(self, data):
        if self._position >= 0:
            raise CryptoPQError(ErrorCode.UNSUPPORTED, "cannot update after read")

        buffer = self._buffer

        start = 0

        if buffer:
            start = min(8 - len(buffer), len(data))

            buffer += data[:start]

            if len(buffer) < 8:
                return

            self._absorb(buffer)

            buffer.clear()

        end = len(data) - (len(data) - start) % 8

        if end > start:
            self._absorb(data[start:end])

        buffer += data[end:]

    def _absorb(self, words):
        x0, x1, x2, x3, x4 = self._state

        for (word,) in _WORD.iter_unpack(words):
            x0, x1, x2, x3, x4 = permute(x0 ^ word, x1, x2, x3, x4)

        self._state = x0, x1, x2, x3, x4

    # The state after the last, padded block.
    def _padded(self):
        x0, x1, x2, x3, x4 = self._state

        buffer = self._buffer

        return permute(x0 ^ int.from_bytes(buffer, "little") ^ (1 << (8 * len(buffer))), x1, x2, x3, x4)

    def digest(self):
        state = self._padded()

        out = bytearray(state[0].to_bytes(8, "little"))

        while len(out) < self._size:
            state = permute(*state)

            out += state[0].to_bytes(8, "little")

        return bytes(out[: self._size])

    def read(self, length):
        if self._position < 0:
            self._state = self._padded()

            self._output = self._state[0].to_bytes(8, "little")

            self._position = 0

        out = bytearray()

        while len(out) < length:
            if self._position == 8:
                self._state = permute(*self._state)

                self._output = self._state[0].to_bytes(8, "little")

                self._position = 0

            take = min(length - len(out), 8 - self._position)

            out += self._output[self._position : self._position + take]

            self._position += take

        return bytes(out)


# Ascon-CXOF128 after its customization string: its bit length as one block, then the string
# itself, padded (an empty one too).
def customized(customization):
    x0, x1, x2, x3, x4 = CXOF128

    sponge = Ascon(permute(x0 ^ (8 * len(customization)), x1, x2, x3, x4))

    sponge.update(customization)

    return Ascon(sponge._padded())
