from ._bytes import equal
from ._keccak import Keccak


def left_encode(value):
    size = max(1, (value.bit_length() + 7) // 8)

    return bytes([size]) + value.to_bytes(size, "big")


def right_encode(value):
    size = max(1, (value.bit_length() + 7) // 8)

    return value.to_bytes(size, "big") + bytes([size])


def encode_string(data):
    return left_encode(8 * len(data)) + data


def bytepad(data, rate):
    data = left_encode(rate) + data

    return data + bytes(-len(data) % rate)


# cSHAKE with the block of its function name N and customization S absorbed (SP 800-185, 3.3):
# copies of it go on with the data. With N = S = "" cSHAKE is SHAKE.
def cshake(rate, function_name, customization):
    if not function_name and not customization:
        return Keccak(rate, 0x1F, 0)

    sponge = Keccak(rate, 0x04, 0)

    sponge.update(bytepad(encode_string(function_name) + encode_string(customization), rate))

    return sponge


class Kmac:
    """KMAC under one key (SP 800-185, 4.3): `prefix` is cSHAKE with N = "KMAC" and the
    customization, which absorbs bytepad(encode_string(K)), then the data, then right_encode(L),
    L being 0 for KMACXOF. The key block is zeroed afterwards; Python cannot promise that no other
    copy remains."""

    __slots__ = ("_sponge", "_length", "_suffix")

    def __init__(self, prefix, length, xof, key):
        rate = prefix._block

        block = bytearray(left_encode(rate) + left_encode(8 * len(key)))

        block += key

        block += bytes(-len(block) % rate)

        sponge = prefix.copy()

        sponge.update(block)

        block[:] = bytes(len(block))

        self._sponge = sponge

        self._length = length

        self._suffix = right_encode(0 if xof else 8 * length)

    def update(self, data):
        self._sponge.update(data)

    def digest(self):
        sponge = self._sponge.copy()

        sponge.update(self._suffix)

        return sponge.read(self._length)

    def verify(self, tag):
        return equal(self.digest(), tag)
