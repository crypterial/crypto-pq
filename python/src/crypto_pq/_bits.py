"""Bit packing of 256 coefficients of `bits` bits each, coefficient i in bits [bits * i,
bits * (i + 1)) of a little-endian byte string, as ByteEncode (FIPS 203) and SimpleBitPack
(FIPS 204) lay them out.

Both directions work on every coefficient at once. The coefficients start in fields of 8, 16 or
32 bits of one integer, and eight rounds each merge every two neighbouring fields into one field
twice as wide, moving the upper value down against the lower one; unpacking runs the rounds
backwards.
"""

import struct
from functools import lru_cache

_FORMATS = {8: "B", 16: "H", 32: "I"}


def _field(bits):
    return 8 if bits <= 8 else 16 if bits <= 16 else 32


@lru_cache(maxsize=None)
def _rounds(bits, field):
    rounds = []

    for step in range(8 if bits < field else 0):
        width, size = field << step, bits << step

        unit = sum(1 << (2 * width * i) for i in range(256 >> (step + 1)))

        rounds.append((width - size, unit * ((1 << size) - 1), unit * (((1 << size) - 1) << size)))

    return rounds


# The encoding of an integer that holds the 256 values in fields of `field` bits.
def merge(x, bits, field):
    for shift, keep, move in _rounds(bits, field):
        x = (x & keep) | ((x >> shift) & move)

    return x.to_bytes(32 * bits, "little")


def pack(values, bits):
    field = _field(bits)

    return merge(int.from_bytes(struct.pack(f"<256{_FORMATS[field]}", *values), "little"), bits, field)


def unpack(data, bits):
    field = _field(bits)

    x = int.from_bytes(data, "little")

    for shift, keep, move in reversed(_rounds(bits, field)):
        x = (x & keep) | ((x & move) << shift)

    return struct.unpack(f"<256{_FORMATS[field]}", x.to_bytes(32 * field, "little"))
