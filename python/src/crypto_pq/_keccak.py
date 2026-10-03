import struct

from ._blocks import Blocks
from ._errors import CryptoPQError, ErrorCode

_M64 = 0xFFFFFFFFFFFFFFFF

ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_STATE = struct.Struct("<25Q")

_LANES = {rate: struct.Struct(f"<{rate // 8}Q") for rate in (72, 104, 136, 144, 168)}


# Keccak-f[1600], unrolled. Lane x + 5y is a{x + 5y}; rho and pi move it to b{y + 5((2x + 3y) mod 5)}.
# Lanes 1, 2, 8, 12, 17 and 20 are kept complemented during the rounds (the lane complementing of
# the Keccak implementation overview, section 2.2): chi then needs one NOT per row instead of
# five, and theta, rho and pi carry the complements along unchanged.
def permute(state):
    (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) = state

    a1 ^= _M64

    a2 ^= _M64

    a8 ^= _M64

    a12 ^= _M64

    a17 ^= _M64

    a20 ^= _M64

    for constant in ROUND_CONSTANTS:
        c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20

        c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21

        c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22

        c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23

        c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24

        d0 = c4 ^ (((c1 << 1) | (c1 >> 63)) & _M64)

        d1 = c0 ^ (((c2 << 1) | (c2 >> 63)) & _M64)

        d2 = c1 ^ (((c3 << 1) | (c3 >> 63)) & _M64)

        d3 = c2 ^ (((c4 << 1) | (c4 >> 63)) & _M64)

        d4 = c3 ^ (((c0 << 1) | (c0 >> 63)) & _M64)

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

        b1 = ((a6 << 44) | (a6 >> 20)) & _M64

        b2 = ((a12 << 43) | (a12 >> 21)) & _M64

        b3 = ((a18 << 21) | (a18 >> 43)) & _M64

        b4 = ((a24 << 14) | (a24 >> 50)) & _M64

        b5 = ((a3 << 28) | (a3 >> 36)) & _M64

        b6 = ((a9 << 20) | (a9 >> 44)) & _M64

        b7 = ((a10 << 3) | (a10 >> 61)) & _M64

        b8 = ((a16 << 45) | (a16 >> 19)) & _M64

        b9 = ((a22 << 61) | (a22 >> 3)) & _M64

        b10 = ((a1 << 1) | (a1 >> 63)) & _M64

        b11 = ((a7 << 6) | (a7 >> 58)) & _M64

        b12 = ((a13 << 25) | (a13 >> 39)) & _M64

        b13 = ((a19 << 8) | (a19 >> 56)) & _M64

        b14 = ((a20 << 18) | (a20 >> 46)) & _M64

        b15 = ((a4 << 27) | (a4 >> 37)) & _M64

        b16 = ((a5 << 36) | (a5 >> 28)) & _M64

        b17 = ((a11 << 10) | (a11 >> 54)) & _M64

        b18 = ((a17 << 15) | (a17 >> 49)) & _M64

        b19 = ((a23 << 56) | (a23 >> 8)) & _M64

        b20 = ((a2 << 62) | (a2 >> 2)) & _M64

        b21 = ((a8 << 55) | (a8 >> 9)) & _M64

        b22 = ((a14 << 39) | (a14 >> 25)) & _M64

        b23 = ((a15 << 41) | (a15 >> 23)) & _M64

        b24 = ((a21 << 2) | (a21 >> 62)) & _M64

        a0 = b0 ^ (b1 | b2) ^ constant

        a1 = b1 ^ ((b2 ^ _M64) | b3)

        a2 = b2 ^ (b3 & b4)

        a3 = b3 ^ (b4 | b0)

        a4 = b4 ^ (b0 & b1)

        a5 = b5 ^ (b6 | b7)

        a6 = b6 ^ (b7 & b8)

        a7 = b7 ^ (b8 | (b9 ^ _M64))

        a8 = b8 ^ (b9 | b5)

        a9 = b9 ^ (b5 & b6)

        x = b13 ^ _M64

        a10 = b10 ^ (b11 | b12)

        a11 = b11 ^ (b12 & b13)

        a12 = b12 ^ (x & b14)

        a13 = x ^ (b14 | b10)

        a14 = b14 ^ (b10 & b11)

        x = b18 ^ _M64

        a15 = b15 ^ (b16 & b17)

        a16 = b16 ^ (b17 | b18)

        a17 = b17 ^ (x | b19)

        a18 = x ^ (b19 & b15)

        a19 = b19 ^ (b15 | b16)

        x = b21 ^ _M64

        a20 = b20 ^ (x & b22)

        a21 = x ^ (b22 | b23)

        a22 = b22 ^ (b23 & b24)

        a23 = b23 ^ (b24 | b20)

        a24 = b24 ^ (b20 & b21)

    state[:] = (a0, a1 ^ _M64, a2 ^ _M64, a3, a4, a5, a6, a7, a8 ^ _M64, a9, a10, a11, a12 ^ _M64, a13, a14, a15, a16, a17 ^ _M64, a18, a19, a20 ^ _M64, a21, a22, a23, a24)


class Keccak(Blocks):
    __slots__ = ("_state", "_suffix", "_size", "_lanes", "_output", "_position")

    def __init__(self, rate, suffix, size):
        super().__init__(rate)

        self._state = [0] * 25

        self._suffix = suffix

        self._size = size

        self._lanes = _LANES[rate]

        self._output = b""

        self._position = -1

    def update(self, data):
        if self._position >= 0:
            raise CryptoPQError(ErrorCode.UNSUPPORTED, "cannot update after read")

        super().update(data)

    def _process(self, data, offset):
        self._absorb(self._state, data, offset)

    def _absorb(self, state, data, offset):
        for i, lane in enumerate(self._lanes.unpack_from(data, offset)):
            state[i] ^= lane

        permute(state)

    def _finish(self, state):
        last = bytearray(self._block)

        last[: len(self._buffer)] = self._buffer

        last[len(self._buffer)] ^= self._suffix

        last[-1] ^= 0x80

        self._absorb(state, last, 0)

    def digest(self):
        state = list(self._state)

        self._finish(state)

        return _STATE.pack(*state)[: self._size]

    def read(self, length):
        rate = self._block

        if self._position < 0:
            self._finish(self._state)

            self._output = _STATE.pack(*self._state)[:rate]

            self._position = 0

        out = bytearray()

        while len(out) < length:
            if self._position == rate:
                permute(self._state)

                self._output = _STATE.pack(*self._state)[:rate]

                self._position = 0

            take = min(length - len(out), rate - self._position)

            out += self._output[self._position : self._position + take]

            self._position += take

        return bytes(out)
