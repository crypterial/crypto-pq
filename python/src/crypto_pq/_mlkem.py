from typing import NamedTuple

from ._bytes import equal
from ._primitives import sha3_256, sha3_512, shake128, shake256

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

                f[j + length] = (f[j] - t) % Q

                f[j] = (f[j] + t) % Q

        length //= 2

    return f


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

                f[j] = (t + f[j + length]) % Q

                f[j + length] = zeta * (f[j + length] - t) % Q

        length *= 2

    return [x * 3303 % Q for x in f]


def multiply_ntts(f, g):
    h = [0] * 256

    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]

        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q

        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q

    return h


def add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def subtract(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def dot(row, vector):
    total = [0] * 256

    for f, g in zip(row, vector):
        total = add(total, multiply_ntts(f, g))

    return total


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


def sample_ntt(seed):
    stream = shake128(seed)

    a = []

    while len(a) < 256:
        block = stream.read(168)

        for offset in range(0, 168, 3):
            d1 = block[offset] | ((block[offset + 1] & 0x0F) << 8)

            d2 = (block[offset + 1] >> 4) | (block[offset + 2] << 4)

            if d1 < Q and len(a) < 256:
                a.append(d1)

            if d2 < Q and len(a) < 256:
                a.append(d2)

    return a


def sample_cbd(data, eta):
    bits = int.from_bytes(data, "little")

    mask = (1 << eta) - 1

    f = []

    for i in range(256):
        x = ((bits >> (2 * i * eta)) & mask).bit_count()

        y = ((bits >> (2 * i * eta + eta)) & mask).bit_count()

        f.append((x - y) % Q)

    return f


def prf(eta, seed, nonce):
    return shake256(seed + bytes([nonce]), 64 * eta)


def matrix(rho, k):
    return [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]


def pke_keygen(d, params):
    k = params.k

    g = sha3_512(d + bytes([k]))

    rho, sigma = g[:32], g[32:]

    a = matrix(rho, k)

    s = [ntt(sample_cbd(prf(params.eta1, sigma, n), params.eta1)) for n in range(k)]

    e = [ntt(sample_cbd(prf(params.eta1, sigma, k + n), params.eta1)) for n in range(k)]

    t = [add(dot(a[i], s), e[i]) for i in range(k)]

    ek = b"".join(byte_encode(x, 12) for x in t) + rho

    dk = b"".join(byte_encode(x, 12) for x in s)

    return ek, dk


def pke_encrypt(ek, m, r, params):
    k = params.k

    t = [byte_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(k)]

    a = matrix(ek[384 * k :], k)

    y = [ntt(sample_cbd(prf(params.eta1, r, n), params.eta1)) for n in range(k)]

    e1 = [sample_cbd(prf(params.eta2, r, k + n), params.eta2) for n in range(k)]

    e2 = sample_cbd(prf(params.eta2, r, 2 * k), params.eta2)

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
