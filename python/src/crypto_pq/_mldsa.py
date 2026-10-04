import struct
from typing import NamedTuple

from . import _bits, _lanes
from ._ntt import Ntt
from ._primitives import shake256

Q = 8380417

D = 13


def _bit_reverse8(value):
    return int(f"{value:08b}"[::-1], 2)


ZETAS = [pow(1753, _bit_reverse8(k), Q) for k in range(256)]


class Parameters(NamedTuple):
    name: str

    k: int

    l: int

    eta: int

    tau: int

    lam: int

    gamma1: int

    gamma2: int

    omega: int

    @property
    def beta(self):
        return self.tau * self.eta

    @property
    def public_key_size(self):
        return 32 + 320 * self.k

    @property
    def private_key_size(self):
        return 128 + 32 * ((self.k + self.l) * (2 * self.eta).bit_length() + D * self.k)

    @property
    def signature_size(self):
        return self.lam // 4 + 32 * self.l * (1 + (self.gamma1 - 1).bit_length()) + self.omega + self.k


ML_DSA_44 = Parameters("ML-DSA-44", 4, 4, 2, 39, 128, 1 << 17, (Q - 1) // 88, 80)

ML_DSA_65 = Parameters("ML-DSA-65", 6, 5, 4, 49, 192, 1 << 19, (Q - 1) // 32, 55)

ML_DSA_87 = Parameters("ML-DSA-87", 8, 7, 2, 60, 256, 1 << 19, (Q - 1) // 32, 75)


_NTT = Ntt(Q, ZETAS, 1, 8347681)


# The sum of the products of matching coefficients, three products per pass, unreduced: the
# inverse transform reduces it.
def dot(row, vector):
    terms = list(zip(row, vector))

    total = [0] * 256

    for start in range(0, len(terms), 3):
        if start + 3 <= len(terms):
            (f0, g0), (f1, g1), (f2, g2) = terms[start : start + 3]

            total = [t + a * b + c * d + e * h for t, a, b, c, d, e, h in zip(total, f0, g0, f1, g1, f2, g2)]
        else:
            for f, g in terms[start:]:
                total = [t + a * b for t, a, b in zip(total, f, g)]

    return total


# The norm of a vector whose coefficients are already centred, as signed integers.
def infinity_norm(vector):
    return max(max(map(abs, poly)) for poly in vector)


# FIPS 204, Algorithm 37, on whole polynomials of coefficients in [0, q), without branches: the
# formulas of the reference implementation, equal to the specification for every input.
def high_bits(poly, gamma2):
    if gamma2 == (Q - 1) // 32:
        return [((((r + 127) >> 7) * 1025 + (1 << 21)) >> 22) & 15 for r in poly]

    high = [(((r + 127) >> 7) * 11275 + (1 << 23)) >> 24 for r in poly]

    return [r1 ^ (((43 - r1) >> 31) & r1) for r1 in high]


# FIPS 204, Algorithm 36: r1 = HighBits(r) and the centred r0 = r - r1 * 2 * gamma2.
def decompose(poly, gamma2):
    two = 2 * gamma2

    r1 = high_bits(poly, gamma2)

    low = [r - a * two for r, a in zip(poly, r1)]

    return r1, [r0 - ((((Q - 1) // 2 - r0) >> 31) & Q) for r0 in low]


# FIPS 204, Algorithm 39, for every coefficient: whether adding c changes the high bits r1 of r.
def make_hint(c, r, r1, gamma2):
    moved = high_bits([(x + y) % Q for x, y in zip(r, c)], gamma2)

    return [int(a != b) for a, b in zip(moved, r1)]


# FIPS 204, Algorithm 40, with the hint as the positions of its ones.
def use_hint(positions, poly, gamma2):
    m = (Q - 1) // (2 * gamma2)

    r1, r0 = decompose(poly, gamma2)

    for j in positions:
        r1[j] = (r1[j] + 1) % m if r0[j] > 0 else (r1[j] - 1) % m

    return r1


def bit_pack(w, a, b):
    return _bits.pack([b - x for x in w], (a + b).bit_length())


def bit_unpack(data, a, b):
    return [b - x for x in _bits.unpack(data, (a + b).bit_length())]


def hint_bit_pack(h, p):
    out = bytearray(p.omega + p.k)

    index = 0

    for i, poly in enumerate(h):
        for j, bit in enumerate(poly):
            if bit:
                out[index] = j

                index += 1

        out[p.omega + i] = index

    return bytes(out)


# FIPS 204, Algorithm 21, giving the positions of the ones of each polynomial: the encoding must
# be canonical (strictly increasing indices, zero padding), otherwise the signature is rejected.
def hint_bit_unpack(data, p):
    h = [[] for _ in range(p.k)]

    index = 0

    for i in range(p.k):
        end = data[p.omega + i]

        if end < index or end > p.omega:
            return None

        first = index

        while index < end:
            if index > first and data[index - 1] >= data[index]:
                return None

            h[i].append(data[index])

            index += 1

    if any(data[index : p.omega]):
        return None

    return h


def eta_bits(p):
    return (2 * p.eta).bit_length()


def gamma1_bits(p):
    return 1 + (p.gamma1 - 1).bit_length()


def pk_decode(pk, p):
    return pk[:32], [_bits.unpack(pk[32 + 320 * i : 32 + 320 * (i + 1)], 10) for i in range(p.k)]


def sk_decode(sk, p):
    size = 32 * eta_bits(p)

    offset = 128

    s = []

    for _ in range(p.l + p.k):
        s.append(bit_unpack(sk[offset : offset + size], p.eta, p.eta))

        offset += size

    t0 = []

    for _ in range(p.k):
        t0.append(bit_unpack(sk[offset : offset + 32 * D], (1 << (D - 1)) - 1, 1 << (D - 1)))

        offset += 32 * D

    return sk[:32], sk[32:64], sk[64:128], s[: p.l], s[p.l :], t0


def sig_encode(c_tilde, z, h, p):
    bits = gamma1_bits(p)

    return c_tilde + b"".join(_bits.pack([p.gamma1 - x for x in poly], bits) for poly in z) + hint_bit_pack(h, p)


def sig_decode(sig, p):
    bits = gamma1_bits(p)

    offset = p.lam // 4

    z = []

    for _ in range(p.l):
        z.append(bit_unpack(sig[offset : offset + 32 * bits], p.gamma1 - 1, p.gamma1))

        offset += 32 * bits

    h = hint_bit_unpack(sig[offset:], p)

    return (sig[: p.lam // 4], z, h) if h is not None else None


def w1_encode(w1, p):
    bits = ((Q - 1) // (2 * p.gamma2) - 1).bit_length()

    return b"".join(_bits.pack(poly, bits) for poly in w1)


# FIPS 204, Algorithm 30, on a SHAKE128 output: the accepted 23-bit candidates of its 3-byte
# groups, each spread into a 32-bit field.
def rej_ntt_poly(data):
    groups = len(data) // 3

    spread = bytearray(4 * groups)

    spread[0::4] = data[0::3]

    spread[1::4] = data[1::3]

    spread[2::4] = data[2::3]

    x = int.from_bytes(spread, "little") & (_lanes.ones(groups, 32) * 0x7FFFFF)

    return [z for z in struct.unpack(f"<{groups}I", x.to_bytes(4 * groups, "little")) if z < Q][:256]


# FIPS 204, Algorithm 31, on a SHAKE256 output: the low and the high half of every byte, in turn.
def rej_bounded_poly(data, eta):
    x = int.from_bytes(data, "little")

    low = _lanes.ones(len(data), 8) * 0x0F

    halves = bytearray(2 * len(data))

    halves[0::2] = (x & low).to_bytes(len(data), "little")

    halves[1::2] = ((x >> 4) & low).to_bytes(len(data), "little")

    if eta == 2:
        return [2 - half % 5 for half in halves if half < 15][:256]

    return [4 - half for half in halves if half < 9][:256]


# The samplers of a key run their streams in lanes: a first number of blocks that nearly always
# suffices, then another block for every stream whenever one of them falls short.
def _sample(seeds, rates, blocks, parsers):
    stream = _lanes.Squeeze(seeds, rates)

    data = stream.blocks(blocks)

    polys = [parse(d) for parse, d in zip(parsers, data)]

    while any(len(poly) < 256 for poly in polys):
        data = [d + more for d, more in zip(data, stream.blocks(1))]

        polys = [parse(d) for parse, d in zip(parsers, data)]

    return polys


def _matrix_seeds(rho, p):
    return [rho + bytes([s, r]) for r in range(p.k) for s in range(p.l)]


def expand_a(rho, p):
    polys = _sample(_matrix_seeds(rho, p), 168, 5, [rej_ntt_poly] * (p.k * p.l))

    return [polys[r * p.l : (r + 1) * p.l] for r in range(p.k)]


# ExpandA and ExpandS. The SHAKE256 streams of s1 and s2, whose first two blocks nearly always
# suffice, ride in the five blocks of the matrix streams while that batch has at most 32 lanes;
# beyond, each extra lane costs more than a batch of their own (measured), as for ML-DSA-87.
def expand_a_and_s(rho, rho_prime, p):
    count, extra = p.k * p.l, p.l + p.k

    seeds = [rho_prime + r.to_bytes(2, "little") for r in range(extra)]

    def bounded(data):
        poly = rej_bounded_poly(data[:272], p.eta)

        return poly if len(poly) == 256 else rej_bounded_poly(data, p.eta)

    if count <= 32:
        polys = _sample(_matrix_seeds(rho, p) + seeds, [168] * count + [136] * extra, 5, [rej_ntt_poly] * count + [bounded] * extra)

        a, s = [polys[r * p.l : (r + 1) * p.l] for r in range(p.k)], polys[count:]
    else:
        a, s = expand_a(rho, p), _sample(seeds, 136, 2, [bounded] * extra)

    return a, s[: p.l], s[p.l :]


# ExpandMask for `count` signing attempts from kappa on, in one batch of SHAKE256 streams.
def expand_masks(rho, kappa, count, p):
    size = 32 * gamma1_bits(p)

    seeds = [rho + (kappa + r).to_bytes(2, "little") for r in range(count * p.l)]

    return [bit_unpack(d[:size], p.gamma1 - 1, p.gamma1) for d in _lanes.Squeeze(seeds, 136).blocks(-(-size // 136))]


# FIPS 204, Algorithm 29, on the first bytes of a SHAKE256 stream; None if they run out.
def sample_in_ball(data, tau):
    signs = int.from_bytes(data[:8], "little")

    position = 8

    c = [0] * 256

    for i in range(256 - tau, 256):
        while True:
            if position == len(data):
                return None

            j = data[position]

            position += 1

            if j <= i:
                break

        c[i] = c[j]

        c[j] = 1 - 2 * (signs & 1)

        signs >>= 1

    return c


# SampleInBall in every lane of a stream, which squeezes more blocks while any lane runs out.
def _challenges(stream, tau):
    data = stream.blocks(1)

    c = [sample_in_ball(d, tau) for d in data]

    while None in c:
        data = [d + more for d, more in zip(data, stream.blocks(1))]

        c = [sample_in_ball(d, tau) for d in data]

    return c


_BIAS = {bits: (1 << (bits - 1)) * _lanes.ones(512, bits) for bits in (16, 32)}

_OPERAND_BIAS = {bits: _BIAS[bits] & ((1 << (256 * bits)) - 1) for bits in (16, 32)}


# f + 2^(bits - 1) per digit at 2^bits: every digit is positive, so the integer's length does not
# depend on the coefficients.
def _biased(f, bits):
    data = struct.pack(f"<{len(f)}{'H' if bits == 16 else 'I'}", *[x + (1 << (bits - 1)) for x in f])

    return int.from_bytes(data, "little")


def _evaluate(f, bits):
    return _biased(f, bits) - _OPERAND_BIAS[bits]


class Challenge:
    """The challenge c of a signature, whose products with polynomials of small coefficients come
    from one integer multiplication (Kronecker substitution) instead of NTTs.

    c and f are evaluated at 2^bits, where every coefficient of the integer product c * f has
    magnitude below 2^(bits - 1); a bias of 2^(bits - 1) per digit keeps the digits of the
    product apart, and X^256 = -1 folds the upper 256 of them back. The result is the product in
    Z[X] / (X^256 + 1), as signed coefficients of that magnitude, which equal the product that
    the NTT gives modulo q.
    """

    __slots__ = ("values", "corrections")

    def __init__(self, c):
        self.values = {bits: _evaluate(c, bits) for bits in (16, 32)}

        self.corrections = {bits: self.values[bits] * _OPERAND_BIAS[bits] - _BIAS[bits] for bits in (16, 32)}

    # f, often secret, comes as _biased(f, bits), which keeps the size of the multiplication
    # independent of its coefficients; the public correction then removes c times that bias.
    def times(self, f, bits):
        product = self.values[bits] * f - self.corrections[bits]

        digits = struct.unpack(f"<512{'H' if bits == 16 else 'I'}", product.to_bytes(64 * bits, "little"))

        return [x - y for x, y in zip(digits[:256], digits[256:])]


_ROW = struct.Struct("<256I")


class VerificationKey:
    """A public key with tr, the matrix A-hat and the evaluations of t1 for its products with c,
    each computed on first use and kept. Each goes once from None to its value, so threads that
    race there compute equal values. The matrix is kept as 1 KiB per polynomial."""

    __slots__ = ("pk", "params", "_tr", "_matrix", "_t1")

    def __init__(self, pk, params, tr=None):
        self.pk = pk

        self.params = params

        self._tr = tr

        self._matrix = None

        self._t1 = None

    def tr(self):
        if self._tr is None:
            self._tr = shake256(self.pk, 64)

        return self._tr

    def matrix(self):
        if self._matrix is None:
            self._matrix = b"".join(_ROW.pack(*poly) for row in expand_a(self.pk[:32], self.params) for poly in row)

        l, data = self.params.l, self._matrix

        return [[_ROW.unpack_from(data, 1024 * (i * l + j)) for j in range(l)] for i in range(self.params.k)]

    def t1(self):
        if self._t1 is None:
            self._t1 = [_biased(t, 32) for t in pk_decode(self.pk, self.params)[1]]

        return self._t1


class SigningKey:
    """A private key with its public part, and with K and the evaluations of s1, s2 and t0 for their
    products with c, decoded on first use and kept."""

    __slots__ = ("sk", "params", "public", "_secrets")

    def __init__(self, sk, params, public):
        self.sk = sk

        self.params = params

        self.public = public

        self._secrets = None

    def secrets(self):
        if self._secrets is None:
            _, key, _, s1, s2, t0 = sk_decode(self.sk, self.params)

            self._secrets = key, [_biased(s, 16) for s in s1], [_biased(s, 16) for s in s2], [_biased(t, 32) for t in t0]

        return self._secrets


def public_state(pk, params):
    return VerificationKey(pk, params)


def private_state(sk, pk, params):
    return SigningKey(sk, params, VerificationKey(pk, params, sk[64:128]))


_ONES32 = _lanes.ones(256, 32)

_LOW13 = 0x1FFF * _ONES32

_LOW10 = 0x3FF * _ONES32

_ABOVE_HALF = ((1 << 31) - 4097) * _ONES32

_T0_OFFSET = 4096 * _ONES32


# t = A s1 + s2, split by Power2Round (FIPS 204, Algorithm 35) and encoded as in pkEncode and
# skEncode, on every coefficient at once in 32-bit fields: with r0' = r mod 2^13 and a carry of
# one where r0' > 2^12, t1 = (r >> 13) + carry, and the encoding of t0 = r0' - 2^13 * carry is
# 2^12 - t0. Returns the encodings of t1 and t0.
def public_t(a, s1, s2, p):
    s1_hat = _NTT.forward(s1)

    t1, t0 = [], []

    for poly in _NTT.inverse([dot(a[i], s1_hat) for i in range(p.k)], s2):
        r = int.from_bytes(struct.pack("<256I", *poly), "little")

        low = r & _LOW13

        carry = ((low + _ABOVE_HALF) >> 31) & _ONES32

        t1.append(_bits.merge(((r >> D) & _LOW10) + carry, 10, 32))

        t0.append(_bits.merge(_T0_OFFSET + (carry << D) - low, D, 32))

    return b"".join(t1), b"".join(t0)


def keygen_internal(xi, p):
    expanded = shake256(xi + bytes([p.k, p.l]), 128)

    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:]

    a, s1, s2 = expand_a_and_s(rho, rho_prime, p)

    t1, t0 = public_t(a, s1, s2, p)

    pk = rho + t1

    return pk, rho + key + shake256(pk, 64) + b"".join(bit_pack(s, p.eta, p.eta) for s in s1 + s2) + t0


# An expanded private key carries everything needed to rebuild the public key, so a key whose
# parts disagree is rejected instead of producing signatures that never verify.
def check_private_key(sk, p):
    rho, _, tr, s1, s2, _ = sk_decode(sk, p)

    if any(abs(x) > p.eta for poly in s1 + s2 for x in poly):
        return None

    t1, t0 = public_t(expand_a(rho, p), s1, s2, p)

    if t0 != sk[128 + 32 * eta_bits(p) * (p.l + p.k) :]:
        return None

    pk = rho + t1

    return pk if shake256(pk, 64) == tr else None


# Signing attempts run in groups: their ExpandMask streams, transforms, c-tilde hashes and
# SampleInBall streams share lanes, and the attempts are then checked in the order of kappa, so the
# first one accepted is the one of FIPS 204.
GROUP = 3


def _padded8(data):
    return data + bytes(-len(data) % 8)


def _attempts(a, rho_prime, kappa, mu, p):
    k, l = p.k, p.l

    y = expand_masks(rho_prime, kappa, GROUP, p)

    y_hat = _NTT.forward(y)

    w = _NTT.inverse([dot(a[i], y_hat[n * l : (n + 1) * l]) for n in range(GROUP) for i in range(k)])

    w = [w[n * k : (n + 1) * k] for n in range(GROUP)]

    w1 = [w1_encode([high_bits(poly, p.gamma2) for poly in attempt], p) for attempt in w]

    messages = _lanes.lanes64([_padded8(mu + data + b"\x1f") for data in w1])

    c_tilde = _lanes.chunks64(_lanes.shake256(messages, GROUP, p.lam // 32), GROUP)

    c = _challenges(_lanes.Squeeze(c_tilde, 136), p.tau)

    return [(y[n * l : (n + 1) * l], w[n], c_tilde[n], Challenge(c[n])) for n in range(GROUP)]


def sign_internal(key, message, rnd, p):
    a = key.public.matrix()

    secret, s1, s2, t0 = key.secrets()

    mu = shake256(key.public.tr() + message, 64)

    rho_prime = shake256(secret + rnd + mu, 64)

    kappa = 0

    while True:
        for y, w, c_tilde, c in _attempts(a, rho_prime, kappa, mu, p):
            z = [[x + e for x, e in zip(y[i], c.times(s1[i], 16))] for i in range(p.l)]

            difference = [[(x - e) % Q for x, e in zip(w[i], c.times(s2[i], 16))] for i in range(p.k)]

            r1, r0 = zip(*[decompose(poly, p.gamma2) for poly in difference])

            if infinity_norm(z) >= p.gamma1 - p.beta or infinity_norm(r0) >= p.gamma2 - p.beta:
                continue

            ct0 = [c.times(t, 32) for t in t0]

            h = [make_hint(ct0[i], difference[i], r1[i], p.gamma2) for i in range(p.k)]

            if infinity_norm(ct0) >= p.gamma2 or sum(map(sum, h)) > p.omega:
                continue

            return sig_encode(c_tilde, z, h, p)

        kappa += GROUP * p.l


# mu needs tr || M', usually one block; SampleInBall of c-tilde rides in the lanes of its first
# permutation.
def verify_internal(key, message, sig, p):
    if len(sig) != p.signature_size:
        return False

    decoded = sig_decode(sig, p)

    if decoded is None:
        return False

    c_tilde, z, h = decoded

    if infinity_norm(z) >= p.gamma1 - p.beta:
        return False

    stream = _lanes.Beside([0] * 25, _lanes.padded_blocks(key.tr() + message, 136, 0x1F), [_lanes.padded_block(c_tilde, 136, 0x1F)], [136])

    c = Challenge(_challenges(stream, p.tau)[0])

    mu = struct.pack("<8Q", *stream.finish()[:8])

    a = key.matrix()

    t1 = key.t1()

    z_hat = _NTT.forward(z)

    w = _NTT.inverse([dot(a[i], z_hat) for i in range(p.k)], [[-(y << D) for y in c.times(t1[i], 32)] for i in range(p.k)])

    w1 = [use_hint(h[i], w[i], p.gamma2) for i in range(p.k)]

    return shake256(mu + w1_encode(w1, p), p.lam // 4) == c_tilde
