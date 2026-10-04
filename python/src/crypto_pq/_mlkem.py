import struct
from typing import NamedTuple

from . import _bits, _lanes
from ._bytes import equal
from ._ntt import Ntt
from ._primitives import sha3_256, sha3_512

Q = 3329


def _bit_reverse7(value):
    return int(f"{value:07b}"[::-1], 2)


ZETAS = [pow(17, _bit_reverse7(i), Q) for i in range(128)]

GAMMAS = [pow(17, 2 * _bit_reverse7(i) + 1, Q) for i in range(128)]


class Parameters(NamedTuple):
    name: str

    k: int

    eta1: int

    eta2: int

    du: int

    dv: int

    @property
    def encapsulation_key_size(self):
        return 384 * self.k + 32

    @property
    def decapsulation_key_size(self):
        return 768 * self.k + 96

    @property
    def ciphertext_size(self):
        return 32 * (self.du * self.k + self.dv)


ML_KEM_512 = Parameters("ML-KEM-512", 2, 3, 2, 10, 4)

ML_KEM_768 = Parameters("ML-KEM-768", 3, 2, 2, 10, 4)

ML_KEM_1024 = Parameters("ML-KEM-1024", 4, 2, 2, 11, 5)

_NTT = Ntt(Q, ZETAS, 2, 3303)


# The sum of the products of the 128 degree-1 pieces (FIPS 203, Algorithms 11 and 12), with the
# even and the odd coefficients of every piece in separate lists, unreduced: the caller reduces
# the sum once.
def dot(row, vector):
    even = [0] * 128

    odd = [0] * 128

    for f, g in zip(row, vector):
        a0, a1, b0, b1 = f[0::2], f[1::2], g[0::2], g[1::2]

        even = [e + x0 * y0 + x1 * y1 * gamma for e, x0, x1, y0, y1, gamma in zip(even, a0, a1, b0, b1, GAMMAS)]

        odd = [o + x0 * y1 + x1 * y0 for o, x0, x1, y0, y1 in zip(odd, a0, a1, b0, b1)]

    h = [0] * 256

    h[0::2] = even

    h[1::2] = odd

    return h


def byte_encode(f, d):
    return _bits.pack(f, d)


def byte_decode(data, d):
    f = _bits.unpack(data, d)

    return [x % Q for x in f] if d == 12 else f


# round(2^d * x / q) of each coefficient x = a - b + e, after its reduction: q is odd, so adding
# floor(q / 2) before the floor division never meets a tie.
def compress(f, g, h, d):
    mask = (1 << d) - 1

    return [((((a - b + e) % Q << d) + 1664) // Q) & mask for a, b, e in zip(f, g, h)]


def decompress(f, d):
    half = 1 << (d - 1)

    return [(y * Q + half) >> d for y in f]


# FIPS 203, Algorithm 7: two 12-bit candidates from every 3 bytes, in stream order. Each group
# of 3 bytes is spread into a 32-bit field, d1 stays in its low half and d2 moves to the high one.
def candidates(data):
    groups = len(data) // 3

    spread = bytearray(4 * groups)

    spread[0::4] = data[0::3]

    spread[1::4] = data[1::3]

    spread[2::4] = data[2::3]

    one = _lanes.ones(groups, 32)

    x = int.from_bytes(spread, "little")

    x = (x & (one * 0xFFF)) | ((x << 4) & (one * 0x0FFF0000))

    return struct.unpack(f"<{2 * groups}H", x.to_bytes(4 * groups, "little"))


def sample_ntt(data):
    return [c for c in candidates(data) if c < Q][:256]


def _matrix_seeds(rho, k):
    return [rho + bytes([j, i]) for i in range(k) for j in range(k)]


# SampleNTT for the whole matrix from streams that run in lanes, with any further streams of the
# same batch after the k * k of the matrix: three blocks nearly always give 256 coefficients, and
# another block follows for every stream whenever one of the matrix falls short.
def _sample_matrix(stream, k):
    data = stream.blocks(3)

    polys = [sample_ntt(d) for d in data[: k * k]]

    while any(len(a) < 256 for a in polys):
        data = [d + more for d, more in zip(data, stream.blocks(1))]

        polys = [sample_ntt(d) for d in data[: k * k]]

    return [polys[i * k : (i + 1) * k] for i in range(k)], data[k * k :]


def _cbd_masks(eta):
    width = 2 * eta

    groups = sum(1 << (eta * i) for i in range(512))

    low = sum(((1 << eta) - 1) << (width * i) for i in range(256))

    return groups, low, eta * (low // ((1 << eta) - 1))


_CBD = {eta: _cbd_masks(eta) for eta in (2, 3)}


# FIPS 203, Algorithm 8, on every coefficient at once, as the values x - y + eta in [0, 2 eta]:
# after the bits of each eta-bit group are added in place, a field of 2 * eta bits holds x and y
# side by side, and x + eta - y never borrows from the next field.
def sample_cbd(data, eta):
    groups, low, bias = _CBD[eta]

    bits = int.from_bytes(data, "little")

    sums = sum((bits >> i) & groups for i in range(eta))

    values = (sums & low) + bias - ((sums >> eta) & low)

    return _bits.unpack(values.to_bytes(64 * eta, "little"), 2 * eta)


def _noise_etas(params):
    return [params.eta1] * params.k + [params.eta2] * (params.k + 1)


# The PRF outputs for nonces 0, 1, ... with the given eta each, as one batch of SHAKE256 streams.
def prfs(seed, etas):
    data = _lanes.Squeeze([seed + bytes([n]) for n in range(len(etas))], 136).blocks(-(-64 * max(etas) // 136))

    return [d[: 64 * eta] for d, eta in zip(data, etas)]


# K-PKE.KeyGen; the PRF streams of s and e share the lanes of the matrix.
def pke_keygen(d, params):
    k, eta = params.k, params.eta1

    g = sha3_512(d + bytes([k]))

    rho, sigma = g[:32], g[32:]

    seeds = [sigma + bytes([n]) for n in range(2 * k)]

    stream = _lanes.Squeeze(_matrix_seeds(rho, k) + seeds, [168] * (k * k) + [136] * (2 * k))

    a, noise = _sample_matrix(stream, k)

    noise = _NTT.forward([[x - eta for x in sample_cbd(data[: 64 * eta], eta)] for data in noise])

    s, e = [[x % Q for x in poly] for poly in noise[:k]], noise[k:]

    t = [[(x + y) % Q for x, y in zip(dot(a[i], s), e[i])] for i in range(k)]

    ek = b"".join(byte_encode(x, 12) for x in t) + rho

    dk = b"".join(byte_encode(x, 12) for x in s)

    return ek, dk


# Encryption and decryption multiply in the normal domain by Kronecker substitution: a polynomial
# evaluated at 2^w is an integer whose base-2^w digits are its coefficients, so one integer product
# gives the product polynomial, and X^256 = -1 folds its upper 256 digits back. The secret operand
# (y, or s) carries 2^(w - 1) in every digit, which keeps its size independent of its coefficients;
# a public correction removes the public operand times that bias and adds 2^(w - 1) to every digit
# of the result, so that digits of either sign stay apart. Products with y use w = 24: their
# coefficients stay below k * 256 * (q - 1) * eta1 < 2^23. y comes as the values of sample_cbd,
# y + eta1, and the lower half of the result carries eta2 less, so that adding the values of e1 and
# e2 gives u and v directly. Products with s use w = 32 with both operands centred, in groups of at
# most three: 3 * 256 * 1664^2 < 2^31.
def _ones(count, size):
    return int.from_bytes((b"\x01" + bytes(size - 1)) * count, "little")


_HALF_24 = 1 << 23

_TEMPLATE_24 = b"\x00\x00\x80" * 256

_HALF_32 = 1 << 31

_OPERAND_32 = _HALF_32 * _ones(256, 4)

_BIAS_32 = _HALF_32 * _ones(512, 4)


def _evaluate24(values):
    data = struct.pack(f"<{len(values)}I", *values)

    packed = bytearray(3 * len(values))

    packed[0::3] = data[0::4]

    packed[1::3] = data[1::4]

    packed[2::3] = data[2::4]

    return int.from_bytes(packed, "little")


def _digits24(value):
    data = value.to_bytes(1536, "little")

    spread = bytearray(2048)

    spread[0::4] = data[0::3]

    spread[1::4] = data[1::3]

    spread[2::4] = data[2::3]

    return struct.unpack("<512I", spread)


# The evaluation of y + 2^23 + eta1 at 2^24, from the values of sample_cbd.
def _noise_operand(values):
    data = bytearray(_TEMPLATE_24)

    data[0::3] = values

    return int.from_bytes(data, "little")


def _evaluate32(values):
    return int.from_bytes(struct.pack("<256I", *values), "little")


# The two halves of the digits of sum(public * secret) - correction, whose difference is the
# product modulo X^256 + 1.
def _product24(publics, secrets, correction):
    digits = _digits24(sum(a * b for a, b in zip(publics, secrets)) - correction)

    return digits[:256], digits[256:]


# The matrix columns and t of K-PKE in the normal domain, evaluated at 2^24, with the corrections
# of their products.
def _encryption_state(a, t, params):
    k = params.k

    normal = _NTT.inverse([a[j][i] for i in range(k) for j in range(k)] + t)

    rows = [[_evaluate24(normal[i * k + j]) for j in range(k)] for i in range(k)] + [[_evaluate24(poly) for poly in normal[k * k :]]]

    operand = (_HALF_24 + params.eta1) * _ones(256, 3)

    bias = (_HALF_24 - params.eta2) * _ones(256, 3) + (_HALF_24 * _ones(256, 3) << 6144)

    return rows, [sum(row) * operand - bias for row in rows]


# K-PKE.Encrypt from the PRF outputs: u = A^T y + e1 and v = t^T y + e2 + Decompress_1(m).
def _encrypt(state, m, noise, params):
    k, du, dv = params.k, params.du, params.dv

    rows, corrections = state

    y = [_noise_operand(sample_cbd(data, params.eta1)) for data in noise[:k]]

    c = []

    for i in range(k):
        lo, hi = _product24(rows[i], y, corrections[i])

        c.append(byte_encode(compress(lo, hi, sample_cbd(noise[k + i], params.eta2), du), du))

    lo, hi = _product24(rows[k], y, corrections[k])

    e2 = [e + 1665 * bit for e, bit in zip(sample_cbd(noise[2 * k], params.eta2), byte_decode(m, 1))]

    return b"".join(c) + byte_encode(compress(lo, hi, e2, dv), dv)


# K-PKE.Decrypt: w = v - s^T u, with the evaluations of s from the decapsulation key.
def _decrypt(secret, c, params):
    k, du, dv = params.k, params.du, params.dv

    u = []

    for i in range(k):
        f = decompress(byte_decode(c[32 * du * i : 32 * du * (i + 1)], du), du)

        u.append(_evaluate32([(x - Q if x > 1664 else x) + _HALF_32 for x in f]) - _OPERAND_32)

    w = decompress(byte_decode(c[32 * du * k :], dv), dv)

    for start in range(0, k, 3):
        group = range(start, min(start + 3, k))

        product = sum(u[j] * secret[j] for j in group) - sum(u[j] for j in group) * _OPERAND_32 + _BIAS_32

        digits = struct.unpack("<512I", product.to_bytes(2048, "little"))

        lo, hi = digits[:256], digits[256:]

        if start + 3 < k:
            w = [x - a + b for x, a, b in zip(w, lo, hi)]

    return byte_encode(compress(w, lo, hi, 1), 1)


class EncapsulationKey:
    """An encapsulation key with H(ek) and its encryption state, both computed on first use and
    kept: each goes once from None to its value, so threads that race there compute equal values."""

    __slots__ = ("ek", "params", "_hash", "_state")

    def __init__(self, ek, params, h=None):
        self.ek = ek

        self.params = params

        self._hash = h

        self._state = None

    def hash(self):
        if self._hash is None:
            self._hash = sha3_256(self.ek)

        return self._hash

    # A key that still needs H(ek) hashes it in lane 0 beside the matrix streams.
    def state(self):
        if self._state is None:
            k = self.params.k

            ek = self.ek

            seeds = _matrix_seeds(ek[384 * k :], k)

            if self._hash is None:
                stream = _lanes.Beside([0] * 25, _lanes.padded_blocks(ek, 136, 0x06), [_lanes.padded_block(seed, 168, 0x1F) for seed in seeds], [168] * (k * k))

                a, _ = _sample_matrix(stream, k)

                self._hash = struct.pack("<4Q", *stream.finish()[:4])
            else:
                a, _ = _sample_matrix(_lanes.Squeeze(seeds, 168), k)

            self._state = _encryption_state(a, [byte_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(k)], self.params)

        return self._state


class DecapsulationKey:
    """A decapsulation key with its public part, and with s in the normal domain, centred and
    evaluated for the products of _decrypt on first use."""

    __slots__ = ("dk", "params", "public", "z", "_secret")

    def __init__(self, dk, params, public):
        self.dk = dk

        self.params = params

        self.public = public

        self.z = dk[768 * params.k + 64 :]

        self._secret = None

    def secret(self):
        if self._secret is None:
            k = self.params.k

            s = _NTT.inverse([byte_decode(self.dk[384 * i : 384 * (i + 1)], 12) for i in range(k)])

            self._secret = [_evaluate32([x - (((1664 - x) >> 31) & Q) + _HALF_32 for x in poly]) for poly in s]

        return self._secret


def public_state(ek, params):
    return EncapsulationKey(ek, params)


def private_state(dk, params):
    k = params.k

    return DecapsulationKey(dk, params, EncapsulationKey(dk[384 * k : 768 * k + 32], params, dk[768 * k + 32 : 768 * k + 64]))


def keygen_internal(d, z, params):
    ek, dk = pke_keygen(d, params)

    return ek, dk + ek + sha3_256(ek) + z


def encaps_internal(key, m, params):
    state = key.state()

    g = sha3_512(m + key.hash())

    return g[:32], _encrypt(state, m, prfs(g[32:], _noise_etas(params)), params)


# Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c). J takes one
# permutation per block of z || c; G(m || h), and then the PRF streams from r, ride in the lanes of
# its first permutations.
def decaps_internal(key, c, params):
    m = _decrypt(key.secret(), c, params)

    blocks = _lanes.padded_blocks(key.z + c, 136, 0x1F)

    stream = _lanes.Beside([0] * 25, blocks, [_lanes.padded_block(m + key.public.hash(), 72, 0x06)], [72])

    g = stream.blocks(1)[0]

    etas = _noise_etas(params)

    stream = _lanes.Beside(stream.lane, stream.pending, [_lanes.padded_block(g[32:64] + bytes([n]), 136, 0x1F) for n in range(len(etas))], [136] * len(etas))

    noise = [d[: 64 * eta] for d, eta in zip(stream.blocks(-(-64 * max(etas) // 136)), etas)]

    rejected = struct.pack("<4Q", *stream.finish()[:4])

    return g[:32] if equal(c, _encrypt(key.public.state(), m, noise, params)) else rejected


# FIPS 203, 7.2: every coefficient of the encoded vector must already be reduced modulo q.
def check_encapsulation_key(ek, params):
    if len(ek) != params.encapsulation_key_size:
        return False

    for i in range(params.k):
        chunk = ek[384 * i : 384 * (i + 1)]

        if byte_encode(byte_decode(chunk, 12), 12) != chunk:
            return False

    return True


def check_decapsulation_key(dk, params):
    k = params.k

    if len(dk) != params.decapsulation_key_size:
        return False

    ek = dk[384 * k : 768 * k + 32]

    return check_encapsulation_key(ek, params) and sha3_256(ek) == dk[768 * k + 32 : 768 * k + 64]


def public_key_of(dk, params):
    k = params.k

    return dk[384 * k : 768 * k + 32]
