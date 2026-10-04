"""Number-theoretic transforms of several polynomials at once.

The integer for coefficient j holds coefficient j of polynomial p in its 64-bit field p, so each
butterfly, a few big-integer operations, acts on every polynomial at the same position, in the
order of FIPS 203 and FIPS 204. A product with a zeta is reduced by Shoup's method: with
z' = floor(z * 2^32 / q), b * z - floor(b * z' / 2^32) * q lies in [0, 2q) for any b below 2^32.
The bounds below keep every field below 2^64, so no operation carries into the next field.
"""

import struct
from functools import lru_cache


@lru_cache(maxsize=32)
def _ones(count):
    return int.from_bytes((b"\x01" + bytes(7)) * count, "little")


class Ntt:
    __slots__ = ("q", "zetas", "shoup", "last", "scale")

    # zetas[1 ..] in the order the forward transform uses them, down to blocks of `last`
    # coefficients per half, and the inverse of the number of points for the inverse transform.
    def __init__(self, q, zetas, last, scale):
        self.q = q

        self.zetas = zetas

        self.shoup = [(z << 32) // q for z in zetas]

        self.last = last

        self.scale = scale

    def _pack(self, polys):
        q = self.q

        count = len(polys)

        flat = [0] * (256 * count)

        for index, poly in enumerate(polys):
            flat[index::count] = [x % q for x in poly]

        data = struct.pack(f"<{256 * count}Q", *flat)

        step = 8 * count

        return [int.from_bytes(data[i : i + step], "little") for i in range(0, 256 * step, step)]

    @staticmethod
    def _flat(lanes, count):
        return struct.unpack(f"<{256 * count}Q", b"".join(x.to_bytes(8 * count, "little") for x in lanes))

    # Every field grows by less than 2q per layer from below q, so it stays below 17q < 2^32; the
    # results keep those unreduced values.
    def forward(self, polys):
        q, zetas, shoup = self.q, self.zetas, self.shoup

        count = len(polys)

        w = self._pack(polys)

        one = _ones(count)

        low = one * 0xFFFFFFFF

        bias = one * (2 * q)

        k = 0

        length = 128

        while length >= self.last:
            for start in range(0, 256, 2 * length):
                k += 1

                z, zs = zetas[k], shoup[k]

                for j in range(start, start + length):
                    b = w[j + length]

                    t = b * z - (((b * zs) >> 32) & low) * q

                    a = w[j]

                    w[j + length] = a + bias - t

                    w[j] = a + t

            length //= 2

        flat = self._flat(w, count)

        return [flat[index::count] for index in range(count)]

    # Before the layer with blocks of 2^s * last coefficients per half, every field is below
    # 2^s * q: that bias keeps hi - lo positive, and the Shoup input stays below 2^8 * q < 2^31.
    # Polynomials in `extra` are added to the results before their reduction.
    def inverse(self, polys, extra=None):
        q, zetas, shoup, scale = self.q, self.zetas, self.shoup, self.scale

        count = len(polys)

        w = self._pack(polys)

        one = _ones(count)

        low = one * 0xFFFFFFFF

        k = 256 // self.last

        length = self.last

        bound = q

        while length <= 128:
            bias = one * bound

            for start in range(0, 256, 2 * length):
                k -= 1

                z, zs = zetas[k], shoup[k]

                for j in range(start, start + length):
                    a = w[j]

                    b = w[j + length]

                    w[j] = a + b

                    d = b + bias - a

                    w[j + length] = d * z - (((d * zs) >> 32) & low) * q

            length *= 2

            bound *= 2

        flat = self._flat(w, count)

        if extra is None:
            return [[x * scale % q for x in flat[index::count]] for index in range(count)]

        return [[(x * scale + e) % q for x, e in zip(flat[index::count], extra[index])] for index in range(count)]
