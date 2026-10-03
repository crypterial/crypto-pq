from typing import NamedTuple

from ._primitives import shake128, shake256, shake256_stream

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

                w[j + length] = (w[j] - t) % Q

                w[j] = (w[j] + t) % Q

        length //= 2

    return w


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

                w[j] = (t + w[j + length]) % Q

                w[j + length] = zeta * (t - w[j + length]) % Q

        length *= 2

    return [x * 8347681 % Q for x in w]


def pointwise(f, g):
    return [a * b % Q for a, b in zip(f, g)]


def dot(row, vector):
    total = [0] * 256

    for f, g in zip(row, vector):
        total = [(t + a * b) % Q for t, a, b in zip(total, f, g)]

    return total


def centered(x):
    x %= Q

    return x - Q if x > (Q - 1) // 2 else x


def infinity_norm(vector):
    return max(abs(centered(x)) for poly in vector for x in poly)


def power2round(r):
    r %= Q

    r0 = r & ((1 << D) - 1)

    if r0 > 1 << (D - 1):
        r0 -= 1 << D

    return (r - r0) >> D, r0


def decompose(r, gamma2):
    r %= Q

    r0 = r % (2 * gamma2)

    if r0 > gamma2:
        r0 -= 2 * gamma2

    if r - r0 == Q - 1:
        return 0, r0 - 1

    return (r - r0) // (2 * gamma2), r0


def high_bits(r, gamma2):
    return decompose(r, gamma2)[0]


def low_bits(r, gamma2):
    return decompose(r, gamma2)[1]


def make_hint(z, r, gamma2):
    return int(high_bits(r, gamma2) != high_bits(r + z, gamma2))


def use_hint(h, r, gamma2):
    m = (Q - 1) // (2 * gamma2)

    r1, r0 = decompose(r, gamma2)

    if h and r0 > 0:
        return (r1 + 1) % m

    if h:
        return (r1 - 1) % m

    return r1


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


def rej_ntt_poly(seed):
    stream = shake128(seed)

    a = []

    while len(a) < 256:
        block = stream.read(168)

        for offset in range(0, 168, 3):
            z = block[offset] | (block[offset + 1] << 8) | ((block[offset + 2] & 0x7F) << 16)

            if z < Q and len(a) < 256:
                a.append(z)

    return a


def rej_bounded_poly(seed, eta):
    stream = shake256_stream(seed)

    a = []

    while len(a) < 256:
        for byte in stream.read(136):
            for half in (byte & 0x0F, byte >> 4):
                if len(a) == 256:
                    break

                if eta == 2 and half < 15:
                    a.append(2 - half % 5)
                elif eta == 4 and half < 9:
                    a.append(4 - half)

    return a


def expand_a(rho, p):
    return [[rej_ntt_poly(rho + bytes([s, r])) for s in range(p.l)] for r in range(p.k)]


def expand_s(rho, p):
    s = [rej_bounded_poly(rho + r.to_bytes(2, "little"), p.eta) for r in range(p.l + p.k)]

    return s[: p.l], s[p.l :]


def expand_mask(rho, kappa, p):
    bits = gamma1_bits(p)

    return [bit_unpack(shake256(rho + (kappa + r).to_bytes(2, "little"), 32 * bits), p.gamma1 - 1, p.gamma1) for r in range(p.l)]


def sample_in_ball(seed, tau):
    stream = shake256_stream(seed)

    signs = int.from_bytes(stream.read(8), "little")

    c = [0] * 256

    for i in range(256 - tau, 256):
        j = stream.read(1)[0]

        while j > i:
            j = stream.read(1)[0]

        c[i] = c[j]

        c[j] = 1 - 2 * (signs & 1)

        signs >>= 1

    return c


def public_t(a, s1, s2, p):
    s1_hat = [ntt(s) for s in s1]

    return [[(x + e) % Q for x, e in zip(inverse_ntt(dot(a[i], s1_hat)), s2[i])] for i in range(p.k)]


def keygen_internal(xi, p):
    expanded = shake256(xi + bytes([p.k, p.l]), 128)

    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:]

    s1, s2 = expand_s(rho_prime, p)

    t = public_t(expand_a(rho, p), s1, s2, p)

    t1 = [[power2round(x)[0] for x in poly] for poly in t]

    t0 = [[power2round(x)[1] for x in poly] for poly in t]

    pk = pk_encode(rho, t1)

    return pk, sk_encode(rho, key, shake256(pk, 64), s1, s2, t0, p)


# An expanded private key carries everything needed to rebuild the public key, so a key whose
# parts disagree is rejected instead of producing signatures that never verify.
def check_private_key(sk, p):
    rho, key, tr, s1, s2, t0 = sk_decode(sk, p)

    if any(abs(x) > p.eta for poly in s1 + s2 for x in poly):
        return None

    t = public_t(expand_a(rho, p), s1, s2, p)

    if [[power2round(x)[1] for x in poly] for poly in t] != t0:
        return None

    pk = pk_encode(rho, [[power2round(x)[0] for x in poly] for poly in t])

    return pk if shake256(pk, 64) == tr else None


def public_key_of(sk, p):
    return check_private_key(sk, p)


def sign_internal(sk, message, rnd, p):
    rho, key, tr, s1, s2, t0 = sk_decode(sk, p)

    s1_hat = [ntt(s) for s in s1]

    s2_hat = [ntt(s) for s in s2]

    t0_hat = [ntt(t) for t in t0]

    a = expand_a(rho, p)

    mu = shake256(tr + message, 64)

    rho_prime = shake256(key + rnd + mu, 64)

    kappa = 0

    while True:
        y = expand_mask(rho_prime, kappa, p)

        kappa += p.l

        y_hat = [ntt(v) for v in y]

        w = [inverse_ntt(dot(a[i], y_hat)) for i in range(p.k)]

        w1 = [[high_bits(x, p.gamma2) for x in poly] for poly in w]

        c_tilde = shake256(mu + w1_encode(w1, p), p.lam // 4)

        c_hat = ntt(sample_in_ball(c_tilde, p.tau))

        cs1 = [inverse_ntt(pointwise(c_hat, s)) for s in s1_hat]

        cs2 = [inverse_ntt(pointwise(c_hat, s)) for s in s2_hat]

        z = [[(a1 + b1) % Q for a1, b1 in zip(y[r], cs1[r])] for r in range(p.l)]

        r0 = [[low_bits(x - e, p.gamma2) for x, e in zip(w[i], cs2[i])] for i in range(p.k)]

        if infinity_norm(z) >= p.gamma1 - p.beta or max(abs(x) for poly in r0 for x in poly) >= p.gamma2 - p.beta:
            continue

        ct0 = [inverse_ntt(pointwise(c_hat, t)) for t in t0_hat]

        h = [[make_hint(-c, x - e + c, p.gamma2) for c, x, e in zip(ct0[i], w[i], cs2[i])] for i in range(p.k)]

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

    c_hat = ntt(sample_in_ball(c_tilde, p.tau))

    z_hat = [ntt(v) for v in z]

    t1_hat = [ntt([x << D for x in t]) for t in t1]

    w = [inverse_ntt([(x - y) % Q for x, y in zip(dot(a[i], z_hat), pointwise(c_hat, t1_hat[i]))]) for i in range(p.k)]

    w1 = [[use_hint(b, x, p.gamma2) for b, x in zip(h[i], w[i])] for i in range(p.k)]

    return shake256(mu + w1_encode(w1, p), p.lam // 4) == c_tilde
