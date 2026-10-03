import struct
from typing import NamedTuple

from . import _lanes
from ._bytes import equal
from ._primitives import sha3_256, sha3_512, shake256

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


# In both transforms the butterflies reduce only the products: the sums stay below 2^7 q in
# magnitude, which Python integers hold exactly, and the last line reduces every coefficient once.
def ntt(f):
    f = list(f)

    i = 1

    length = 128

    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]

            i += 1

            for j in range(start, start + length):
                t = zeta * f[j + length] % Q

                x = f[j]

                f[j + length] = x - t

                f[j] = x + t

        length //= 2

    return [x % Q for x in f]


def inverse_ntt(f):
    f = list(f)

    i = 127

    length = 2

    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]

            i -= 1

            for j in range(start, start + length):
                t = f[j]

                u = f[j + length]

                f[j] = t + u

                f[j + length] = zeta * (u - t) % Q

        length *= 2

    return [x * 3303 % Q for x in f]


def add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def subtract(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


# The sum of the products of the 128 degree-1 pieces (FIPS 203, Algorithms 11 and 12), with the
# even and the odd coefficients of every piece in separate lists and one reduction at the end.
def dot(row, vector):
    even = [0] * 128

    odd = [0] * 128

    for f, g in zip(row, vector):
        a0, a1, b0, b1 = f[0::2], f[1::2], g[0::2], g[1::2]

        even = [e + x0 * y0 + x1 * y1 * gamma for e, x0, x1, y0, y1, gamma in zip(even, a0, a1, b0, b1, GAMMAS)]

        odd = [o + x0 * y1 + x1 * y0 for o, x0, x1, y0, y1 in zip(odd, a0, a1, b0, b1)]

    h = [0] * 256

    h[0::2] = [e % Q for e in even]

    h[1::2] = [o % Q for o in odd]

    return h


def byte_encode(f, d):
    value = 0

    for i, coefficient in enumerate(f):
        value |= coefficient << (d * i)

    return value.to_bytes(32 * d, "little")


def byte_decode(data, d):
    value = int.from_bytes(data, "little")

    mask = (1 << d) - 1

    f = [(value >> (d * i)) & mask for i in range(256)]

    return [x % Q for x in f] if d == 12 else f


# round(2^d * x / q): q is odd, so adding floor(q / 2) before the floor division never meets a tie.
def compress(x, d):
    return (((x << d) + 1664) // Q) & ((1 << d) - 1)


def decompress(y, d):
    return (y * Q + (1 << (d - 1))) >> d


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


# SampleNTT for the whole matrix: the k * k SHAKE128 streams run in lanes, three blocks at first,
# which nearly always give 256 coefficients, and another block whenever one stream needs it.
def matrix(rho, k):
    stream = _lanes.Squeeze([rho + bytes([j, i]) for i in range(k) for j in range(k)], 168)

    data = stream.blocks(3)

    polys = [sample_ntt(d) for d in data]

    while any(len(a) < 256 for a in polys):
        data = [d + more for d, more in zip(data, stream.blocks(1))]

        polys = [sample_ntt(d) for d in data]

    return [polys[i * k : (i + 1) * k] for i in range(k)]


def _cbd_masks(eta):
    width = 2 * eta

    groups = sum(1 << (eta * i) for i in range(512))

    low = sum(((1 << eta) - 1) << (width * i) for i in range(256))

    return groups, low, eta * (low // ((1 << eta) - 1))


_CBD = {eta: _cbd_masks(eta) for eta in (2, 3)}


# FIPS 203, Algorithm 8, on every coefficient at once: after the bits of each eta-bit group are
# added in place, a field of 2 * eta bits holds x and y side by side, and x + eta - y never
# borrows from the next field.
def sample_cbd(data, eta):
    groups, low, bias = _CBD[eta]

    bits = int.from_bytes(data, "little")

    sums = sum((bits >> i) & groups for i in range(eta))

    values = (sums & low) + bias - ((sums >> eta) & low)

    width = 2 * eta

    mask = (1 << width) - 1

    return [(((values >> (width * i)) & mask) - eta) % Q for i in range(256)]


# The PRF outputs for nonces 0, 1, ... with the given eta each, as one batch of SHAKE256 streams.
def prfs(seed, etas):
    data = _lanes.Squeeze([seed + bytes([n]) for n in range(len(etas))], 136).blocks(-(-64 * max(etas) // 136))

    return [d[: 64 * eta] for d, eta in zip(data, etas)]


def pke_keygen(d, params):
    k = params.k

    g = sha3_512(d + bytes([k]))

    rho, sigma = g[:32], g[32:]

    a = matrix(rho, k)

    noise = [ntt(sample_cbd(data, params.eta1)) for data in prfs(sigma, [params.eta1] * (2 * k))]

    s, e = noise[:k], noise[k:]

    t = [add(dot(a[i], s), e[i]) for i in range(k)]

    ek = b"".join(byte_encode(x, 12) for x in t) + rho

    dk = b"".join(byte_encode(x, 12) for x in s)

    return ek, dk


def pke_encrypt(ek, m, r, params):
    k = params.k

    t = [byte_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(k)]

    a = matrix(ek[384 * k :], k)

    noise = prfs(r, [params.eta1] * k + [params.eta2] * (k + 1))

    y = [ntt(sample_cbd(data, params.eta1)) for data in noise[:k]]

    e1 = [sample_cbd(data, params.eta2) for data in noise[k : 2 * k]]

    e2 = sample_cbd(noise[2 * k], params.eta2)

    columns = [[a[j][i] for j in range(k)] for i in range(k)]

    u = [add(inverse_ntt(dot(columns[i], y)), e1[i]) for i in range(k)]

    mu = [decompress(bit, 1) for bit in byte_decode(m, 1)]

    v = add(add(inverse_ntt(dot(t, y)), e2), mu)

    c1 = b"".join(byte_encode([compress(x, params.du) for x in f], params.du) for f in u)

    c2 = byte_encode([compress(x, params.dv) for x in v], params.dv)

    return c1 + c2


def pke_decrypt(dk, c, params):
    k, du, dv = params.k, params.du, params.dv

    u = [[decompress(x, du) for x in byte_decode(c[32 * du * i : 32 * du * (i + 1)], du)] for i in range(k)]

    v = [decompress(x, dv) for x in byte_decode(c[32 * du * k :], dv)]

    s = [byte_decode(dk[384 * i : 384 * (i + 1)], 12) for i in range(k)]

    w = subtract(v, inverse_ntt(dot(s, [ntt(f) for f in u])))

    return byte_encode([compress(x, 1) for x in w], 1)


def keygen_internal(d, z, params):
    ek, dk = pke_keygen(d, params)

    return ek, dk + ek + sha3_256(ek) + z


def encaps_internal(ek, m, params):
    g = sha3_512(m + sha3_256(ek))

    shared_secret, r = g[:32], g[32:]

    return shared_secret, pke_encrypt(ek, m, r, params)


# Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c).
def decaps_internal(dk, c, params):
    k = params.k

    dk_pke, ek, h, z = dk[: 384 * k], dk[384 * k : 768 * k + 32], dk[768 * k + 32 : 768 * k + 64], dk[768 * k + 64 :]

    m = pke_decrypt(dk_pke, c, params)

    g = sha3_512(m + h)

    shared_secret, r = g[:32], g[32:]

    rejected = shake256(z + c, 32)

    return shared_secret if equal(c, pke_encrypt(ek, m, r, params)) else rejected


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
