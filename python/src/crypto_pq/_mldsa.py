import struct
from typing import NamedTuple

from . import _lanes
from ._primitives import shake256, shake256_stream

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


# The butterflies reduce only the product: the sums stay within 9q, which Python integers hold
# exactly, and the last line reduces every coefficient once.
def ntt(w):
    w = [x % Q for x in w]

    m = 0

    length = 128

    while length >= 1:
        for start in range(0, 256, 2 * length):
            m += 1

            zeta = ZETAS[m]

            for j in range(start, start + length):
                t = zeta * w[j + length] % Q

                x = w[j]

                w[j + length] = x - t

                w[j] = x + t

        length //= 2

    return [x % Q for x in w]


def inverse_ntt(w):
    w = list(w)

    m = 256

    length = 1

    while length < 256:
        for start in range(0, 256, 2 * length):
            m -= 1

            zeta = Q - ZETAS[m]

            for j in range(start, start + length):
                t = w[j]

                u = w[j + length]

                w[j] = (t + u) % Q

                w[j + length] = zeta * (t - u) % Q

        length *= 2

    return [x * 8347681 % Q for x in w]


def dot(row, vector):
    total = [a * b for a, b in zip(row[0], vector[0])]

    for f, g in zip(row[1:], vector[1:]):
        total = [t + a * b for t, a, b in zip(total, f, g)]

    return [t % Q for t in total]


def centered(x):
    x %= Q

    return x - Q if x > (Q - 1) // 2 else x


def infinity_norm(vector):
    values = [x % Q for poly in vector for x in poly]

    return max(Q - x if x > (Q - 1) // 2 else x for x in values)


# FIPS 204, Algorithms 35 to 37, on whole polynomials of coefficients in [0, q), without branches:
# the formulas of the reference implementation, equal to the specification for every input.
def power2round(poly):
    low = [(r & 0x1FFF) - (((4096 - (r & 0x1FFF)) >> 31) & 8192) for r in poly]

    return [(r - r0) >> D for r, r0 in zip(poly, low)], low


def high_bits(poly, gamma2):
    if gamma2 == (Q - 1) // 32:
        return [((((r + 127) >> 7) * 1025 + (1 << 21)) >> 22) & 15 for r in poly]

    high = [(((r + 127) >> 7) * 11275 + (1 << 23)) >> 24 for r in poly]

    return [r1 ^ (((43 - r1) >> 31) & r1) for r1 in high]


def low_bits(poly, gamma2):
    two = 2 * gamma2

    low = [r - r1 * two for r, r1 in zip(poly, high_bits(poly, gamma2))]

    return [r0 - ((((Q - 1) // 2 - r0) >> 31) & Q) for r0 in low]


# FIPS 204, Algorithm 39, for every coefficient: whether adding c changes the high bits of r.
def make_hint(c, r, gamma2):
    moved = high_bits([(x + y) % Q for x, y in zip(r, c)], gamma2)

    return [int(a != b) for a, b in zip(moved, high_bits(r, gamma2))]


def use_hint(h, poly, gamma2):
    m = (Q - 1) // (2 * gamma2)

    out = []

    for bit, r1, r0 in zip(h, high_bits(poly, gamma2), low_bits(poly, gamma2)):
        if bit:
            r1 = (r1 + 1) % m if r0 > 0 else (r1 - 1) % m

        out.append(r1)

    return out


def pack(values, bits):
    value = 0

    for i, x in enumerate(values):
        value |= x << (bits * i)

    return value.to_bytes(32 * bits, "little")


def unpack(data, bits):
    value = int.from_bytes(data, "little")

    mask = (1 << bits) - 1

    return [(value >> (bits * i)) & mask for i in range(256)]


def bit_pack(w, a, b):
    return pack([b - x for x in w], (a + b).bit_length())


def bit_unpack(data, a, b):
    return [b - x for x in unpack(data, (a + b).bit_length())]


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


# FIPS 204, Algorithm 21: the encoding must be canonical (strictly increasing indices, zero
# padding), otherwise the signature is rejected.
def hint_bit_unpack(data, p):
    h = [[0] * 256 for _ in range(p.k)]

    index = 0

    for i in range(p.k):
        end = data[p.omega + i]

        if end < index or end > p.omega:
            return None

        first = index

        while index < end:
            if index > first and data[index - 1] >= data[index]:
                return None

            h[i][data[index]] = 1

            index += 1

    if any(data[index : p.omega]):
        return None

    return h


def eta_bits(p):
    return (2 * p.eta).bit_length()


def gamma1_bits(p):
    return 1 + (p.gamma1 - 1).bit_length()


def pk_encode(rho, t1):
    return rho + b"".join(pack(t, 10) for t in t1)


def pk_decode(pk, p):
    return pk[:32], [unpack(pk[32 + 320 * i : 32 + 320 * (i + 1)], 10) for i in range(p.k)]


def sk_encode(rho, key, tr, s1, s2, t0, p):
    out = rho + key + tr

    out += b"".join(bit_pack(s, p.eta, p.eta) for s in s1 + s2)

    out += b"".join(bit_pack(t, (1 << (D - 1)) - 1, 1 << (D - 1)) for t in t0)

    return out


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

    return c_tilde + b"".join(pack([p.gamma1 - centered(x) for x in poly], bits) for poly in z) + hint_bit_pack(h, p)


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

    return b"".join(pack(poly, bits) for poly in w1)


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
def _sample(seeds, rate, blocks, parse):
    stream = _lanes.Squeeze(seeds, rate)

    data = stream.blocks(blocks)

    polys = [parse(d) for d in data]

    while any(len(poly) < 256 for poly in polys):
        data = [d + more for d, more in zip(data, stream.blocks(1))]

        polys = [parse(d) for d in data]

    return polys


def expand_a(rho, p):
    polys = _sample([rho + bytes([s, r]) for r in range(p.k) for s in range(p.l)], 168, 5, rej_ntt_poly)

    return [polys[r * p.l : (r + 1) * p.l] for r in range(p.k)]


def expand_s(rho, p):
    s = _sample([rho + r.to_bytes(2, "little") for r in range(p.l + p.k)], 136, 2, lambda data: rej_bounded_poly(data, p.eta))

    return s[: p.l], s[p.l :]


def expand_mask(rho, kappa, p):
    size = 32 * gamma1_bits(p)

    data = _lanes.Squeeze([rho + (kappa + r).to_bytes(2, "little") for r in range(p.l)], 136).blocks(-(-size // 136))

    return [bit_unpack(d[:size], p.gamma1 - 1, p.gamma1) for d in data]


def sample_in_ball(seed, tau):
    stream = shake256_stream(seed)

    data = stream.read(136)

    signs = int.from_bytes(data[:8], "little")

    position = 8

    c = [0] * 256

    for i in range(256 - tau, 256):
        while True:
            if position == len(data):
                data += stream.read(136)

            j = data[position]

            position += 1

            if j <= i:
                break

        c[i] = c[j]

        c[j] = 1 - 2 * (signs & 1)

        signs >>= 1

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
    Z_q[X] / (X^256 + 1) that the NTT gives, reduced to [0, q).
    """

    __slots__ = ("values", "corrections")

    def __init__(self, c):
        self.values = {bits: _evaluate(c, bits) for bits in (16, 32)}

        self.corrections = {bits: self.values[bits] * _OPERAND_BIAS[bits] - _BIAS[bits] for bits in (16, 32)}

    # f, often secret, is multiplied with its bias, which keeps the size of the multiplication
    # independent of its coefficients; the public correction then removes c times that bias.
    def times(self, f, bits):
        product = self.values[bits] * _biased(f, bits) - self.corrections[bits]

        digits = struct.unpack(f"<512{'H' if bits == 16 else 'I'}", product.to_bytes(64 * bits, "little"))

        return [(x - y) % Q for x, y in zip(digits[:256], digits[256:])]


def public_t(a, s1, s2, p):
    s1_hat = [ntt(s) for s in s1]

    return [[(x + e) % Q for x, e in zip(inverse_ntt(dot(a[i], s1_hat)), s2[i])] for i in range(p.k)]


def keygen_internal(xi, p):
    expanded = shake256(xi + bytes([p.k, p.l]), 128)

    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:]

    s1, s2 = expand_s(rho_prime, p)

    t = public_t(expand_a(rho, p), s1, s2, p)

    t1, t0 = zip(*[power2round(poly) for poly in t])

    pk = pk_encode(rho, t1)

    return pk, sk_encode(rho, key, shake256(pk, 64), s1, s2, t0, p)


# An expanded private key carries everything needed to rebuild the public key, so a key whose
# parts disagree is rejected instead of producing signatures that never verify.
def check_private_key(sk, p):
    rho, key, tr, s1, s2, t0 = sk_decode(sk, p)

    if any(abs(x) > p.eta for poly in s1 + s2 for x in poly):
        return None

    t1, t0_check = zip(*[power2round(poly) for poly in public_t(expand_a(rho, p), s1, s2, p)])

    if list(t0_check) != t0:
        return None

    pk = pk_encode(rho, t1)

    return pk if shake256(pk, 64) == tr else None


def sign_internal(sk, message, rnd, p):
    rho, key, tr, s1, s2, t0 = sk_decode(sk, p)

    a = expand_a(rho, p)

    mu = shake256(tr + message, 64)

    rho_prime = shake256(key + rnd + mu, 64)

    kappa = 0

    while True:
        y = expand_mask(rho_prime, kappa, p)

        kappa += p.l

        y_hat = [ntt(v) for v in y]

        w = [inverse_ntt(dot(a[i], y_hat)) for i in range(p.k)]

        c_tilde = shake256(mu + w1_encode([high_bits(poly, p.gamma2) for poly in w], p), p.lam // 4)

        c = Challenge(sample_in_ball(c_tilde, p.tau))

        z = [[(x + e) % Q for x, e in zip(y[i], c.times(s1[i], 16))] for i in range(p.l)]

        difference = [[(x - e) % Q for x, e in zip(w[i], c.times(s2[i], 16))] for i in range(p.k)]

        r0 = [low_bits(poly, p.gamma2) for poly in difference]

        if infinity_norm(z) >= p.gamma1 - p.beta or max(abs(x) for poly in r0 for x in poly) >= p.gamma2 - p.beta:
            continue

        ct0 = [c.times(t, 32) for t in t0]

        h = [make_hint(ct0[i], difference[i], p.gamma2) for i in range(p.k)]

        if infinity_norm(ct0) >= p.gamma2 or sum(map(sum, h)) > p.omega:
            continue

        return sig_encode(c_tilde, z, h, p)


def verify_internal(pk, message, sig, p):
    if len(pk) != p.public_key_size or len(sig) != p.signature_size:
        return False

    rho, t1 = pk_decode(pk, p)

    decoded = sig_decode(sig, p)

    if decoded is None:
        return False

    c_tilde, z, h = decoded

    if infinity_norm(z) >= p.gamma1 - p.beta:
        return False

    a = expand_a(rho, p)

    mu = shake256(shake256(pk, 64) + message, 64)

    c = Challenge(sample_in_ball(c_tilde, p.tau))

    z_hat = [ntt(v) for v in z]

    az = [inverse_ntt(dot(a[i], z_hat)) for i in range(p.k)]

    w = [[(x - (y << D)) % Q for x, y in zip(az[i], c.times(t1[i], 32))] for i in range(p.k)]

    w1 = [use_hint(h[i], w[i], p.gamma2) for i in range(p.k)]

    return shake256(mu + w1_encode(w1, p), p.lam // 4) == c_tilde
