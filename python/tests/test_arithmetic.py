import random
import unittest

from crypto_pq import _bits, _mldsa, _mlkem
from crypto_pq._ntt import Ntt

KEM_Q, DSA_Q = 3329, 8380417


def bit_reverse(value, bits):
    return int(f"{value:0{bits}b}"[::-1], 2)


KEM_ZETAS = [pow(17, bit_reverse(i, 7), KEM_Q) for i in range(128)]

KEM_GAMMAS = [pow(17, 2 * bit_reverse(i, 7) + 1, KEM_Q) for i in range(128)]

DSA_ZETAS = [pow(1753, bit_reverse(i, 8), DSA_Q) for i in range(256)]

TRANSFORMS = ((KEM_Q, KEM_ZETAS, 2, pow(128, -1, KEM_Q)), (DSA_Q, DSA_ZETAS, 1, pow(256, -1, DSA_Q)))


# FIPS 203, Algorithms 9 and 10, and FIPS 204, Algorithms 41 and 42, as written there.
def reference_ntt(f, q, zetas, last):
    f = [x % q for x in f]

    k, length = 0, 128

    while length >= last:
        for start in range(0, 256, 2 * length):
            k += 1

            for j in range(start, start + length):
                t = zetas[k] * f[j + length] % q

                f[j + length] = (f[j] - t) % q

                f[j] = (f[j] + t) % q

        length //= 2

    return f


def reference_inverse(f, q, zetas, last, scale):
    f = list(f)

    k, length = 256 // last, last

    while length <= 128:
        for start in range(0, 256, 2 * length):
            k -= 1

            for j in range(start, start + length):
                t = f[j]

                f[j] = (t + f[j + length]) % q

                f[j + length] = zetas[k] * (f[j + length] - t) % q

        length *= 2

    return [x * scale % q for x in f]


def reference_pack(values, bits):
    return sum(x << (bits * i) for i, x in enumerate(values)).to_bytes(32 * bits, "little")


# FIPS 203, Algorithm 8, bit by bit.
def reference_cbd(data, eta):
    bits = [(data[i // 8] >> (i % 8)) & 1 for i in range(8 * len(data))]

    return [sum(bits[2 * eta * i : 2 * eta * i + eta]) - sum(bits[2 * eta * i + eta : 2 * eta * (i + 1)]) for i in range(256)]


def reference_multiply(f, g):
    out = []

    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]

        out += [(a0 * b0 + a1 * b1 * KEM_GAMMAS[i]) % KEM_Q, (a0 * b1 + a1 * b0) % KEM_Q]

    return out


def reference_compress(f, d):
    return [(((x % KEM_Q) << d) + KEM_Q // 2) // KEM_Q % (1 << d) for x in f]


# FIPS 203, Algorithm 14, from the NTT forms of A and t and from the PRF outputs.
def reference_encrypt(a, t, m, noise, params):
    k = params.k

    def inverse(f):
        return reference_inverse(f, KEM_Q, KEM_ZETAS, 2, pow(128, -1, KEM_Q))

    y = [reference_ntt(reference_cbd(noise[i], params.eta1), KEM_Q, KEM_ZETAS, 2) for i in range(k)]

    out = b""

    for i in range(k):
        total = [sum(x) for x in zip(*[reference_multiply(a[j][i], y[j]) for j in range(k)])]

        u = [x + e for x, e in zip(inverse(total), reference_cbd(noise[k + i], params.eta2))]

        out += reference_pack(reference_compress(u, params.du), params.du)

    total = [sum(x) for x in zip(*[reference_multiply(t[j], y[j]) for j in range(k)])]

    mu = [1665 * ((m[i // 8] >> (i % 8)) & 1) for i in range(256)]

    v = [x + e + bit for x, e, bit in zip(inverse(total), reference_cbd(noise[2 * k], params.eta2), mu)]

    return out + reference_pack(reference_compress(v, params.dv), params.dv)


# Noise bytes whose every coefficient is +eta (x = eta, y = 0) or -eta.
def extreme_noise(eta, sign):
    group = (1 << eta) - 1 if sign > 0 else ((1 << eta) - 1) << eta

    return sum(group << (2 * eta * i) for i in range(256)).to_bytes(64 * eta, "little")


def negacyclic(f, g):
    out = [0] * 256

    for i, a in enumerate(f):
        for j, b in enumerate(g):
            if i + j < 256:
                out[i + j] += a * b
            else:
                out[i + j - 256] -= a * b

    return out


class TransformTest(unittest.TestCase):
    def test_batches(self):
        rng = random.Random(20261004)

        for q, zetas, last, scale in TRANSFORMS:
            engine = Ntt(q, zetas, last, scale)

            for count in (1, 2, 5, 12):
                with self.subTest(q=q, count=count):
                    polys = [[rng.randrange(-q, 2 * q) for _ in range(256)] for _ in range(count)]

                    self.assertEqual([[x % q for x in f] for f in engine.forward(polys)], [reference_ntt(f, q, zetas, last) for f in polys])

                    reduced = [[x % q for x in f] for f in polys]

                    self.assertEqual(engine.inverse(reduced), [reference_inverse(f, q, zetas, last, scale) for f in reduced])

                    extra = [[rng.randrange(-q, q) for _ in range(256)] for _ in range(count)]

                    expected = [[(x + e) % q for x, e in zip(reference_inverse(f, q, zetas, last, scale), g)] for f, g in zip(reduced, extra)]

                    self.assertEqual(engine.inverse(reduced, extra), expected)

    # A Shoup remainder of q or more, next to a zero coefficient, needs the whole bias of 2q.
    # ML-DSA has such remainders; for ML-KEM's small q they stay below q.
    def test_shoup_corner(self):
        q, zetas, last, scale = TRANSFORMS[1]

        shoup = (zetas[1] << 32) // q

        b = next(b for b in range(q - 1, 0, -1) if b * zetas[1] - ((b * shoup) >> 32) * q >= q)

        f = [0] * 256

        f[128] = b

        self.assertEqual([[x % q for x in g] for g in Ntt(q, zetas, last, scale).forward([f] * 3)], [reference_ntt(f, q, zetas, last)] * 3)

    # Every field reaches its largest value when every coefficient is q - 1.
    def test_extremes(self):
        for q, zetas, last, scale in TRANSFORMS:
            engine = Ntt(q, zetas, last, scale)

            polys = [[q - 1] * 256] * 3

            self.assertEqual([[x % q for x in f] for f in engine.forward(polys)], [reference_ntt(polys[0], q, zetas, last)] * 3)

            self.assertEqual(engine.inverse(polys), [reference_inverse(polys[0], q, zetas, last, scale)] * 3)


class BitsTest(unittest.TestCase):
    def test_round_trip(self):
        rng = random.Random(7)

        for bits in (1, 3, 4, 5, 6, 8, 10, 11, 12, 13, 16, 18, 20, 32):
            with self.subTest(bits=bits):
                for values in ([rng.getrandbits(bits) for _ in range(256)], [(1 << bits) - 1] * 256, [0] * 256):
                    data = reference_pack(values, bits)

                    self.assertEqual(_bits.pack(values, bits), data)

                    self.assertEqual(list(_bits.unpack(data, bits)), values)


class KroneckerTest(unittest.TestCase):
    # A of all q - 1 in the normal domain with y of all +eta1 or -eta1 makes the largest
    # coefficients of the products, at the bound of their 24-bit digits.
    def test_encryption_bound(self):
        rng = random.Random(11)

        for params in (_mlkem.ML_KEM_512, _mlkem.ML_KEM_768, _mlkem.ML_KEM_1024):
            k = params.k

            top = reference_ntt([KEM_Q - 1] * 256, KEM_Q, KEM_ZETAS, 2)

            a = [[top] * k for _ in range(k)]

            state = _mlkem._encryption_state(a, [top] * k, params)

            for sign in (1, -1):
                with self.subTest(params=params.name, sign=sign):
                    noise = [extreme_noise(params.eta1, sign)] * k + [extreme_noise(params.eta2, -sign)] * (k + 1)

                    m = rng.randbytes(32)

                    self.assertEqual(_mlkem._encrypt(state, m, noise, params), reference_encrypt(a, [top] * k, m, noise, params))

            noise = [rng.randbytes(64 * eta) for eta in _mlkem._noise_etas(params)]

            a = [[[rng.randrange(KEM_Q) for _ in range(256)] for _ in range(k)] for _ in range(k)]

            t = [[rng.randrange(KEM_Q) for _ in range(256)] for _ in range(k)]

            m = rng.randbytes(32)

            self.assertEqual(_mlkem._encrypt(_mlkem._encryption_state(a, t, params), m, noise, params), reference_encrypt(a, t, m, noise, params))

    # An expanded decapsulation key may hold any s; s and u of centred magnitude 1664 reach the
    # bound of the 32-bit digits in a group of three.
    def test_decryption_bound(self):
        for params in (_mlkem.ML_KEM_768, _mlkem.ML_KEM_1024):
            k, du, dv = params.k, params.du, params.dv

            for value in (1664, KEM_Q - 1664):
                with self.subTest(params=params.name, value=value):
                    s = [[value] * 256] * k

                    s_hat = [reference_ntt(f, KEM_Q, KEM_ZETAS, 2) for f in s]

                    dk = b"".join(reference_pack(f, 12) for f in s_hat) + bytes(768 * k + 96 - 384 * k)

                    key = _mlkem.DecapsulationKey(dk, params, None)

                    compressed_v = [i % (1 << dv) for i in range(256)]

                    c = reference_pack([1 << (du - 1)] * 256, du) * k + reference_pack(compressed_v, dv)

                    u = [(KEM_Q + 1) // 2] * 256

                    v = [(y * KEM_Q + (1 << (dv - 1))) >> dv for y in compressed_v]

                    product = [sum(x) for x in zip(*[negacyclic([x - KEM_Q if x > 1664 else x for x in u], [x - KEM_Q if x > 1664 else x for x in f]) for f in s])]

                    w = [x - y for x, y in zip(v, product)]

                    self.assertEqual(_mlkem._decrypt(key.secret(), c, params), reference_pack(reference_compress(w, 1), 1))

    # Products of c with polynomials at the extremes of s1, s2, t0 and t1.
    def test_challenge(self):
        rng = random.Random(5)

        c = [0] * 256

        for i in rng.sample(range(256), 60):
            c[i] = rng.choice((1, -1))

        challenge = _mldsa.Challenge(c)

        for bits, bound in ((16, 4), (16, -4), (32, 4096), (32, -4095), (32, 1023)):
            with self.subTest(bits=bits, bound=bound):
                f = [bound] * 256

                self.assertEqual(challenge.times(_mldsa._biased(f, bits), bits), negacyclic(c, f))

                f = [rng.randrange(-abs(bound), abs(bound) + 1) for _ in range(256)]

                self.assertEqual(challenge.times(_mldsa._biased(f, bits), bits), negacyclic(c, f))


class SigningGroupTest(unittest.TestCase):
    # Signing attempts run in groups; any group size must pick the first attempt that FIPS 204
    # accepts, so the signatures match those of single attempts.
    def test_group_sizes(self):
        rng = random.Random(3)

        group = _mldsa.GROUP

        try:
            for params in (_mldsa.ML_DSA_44, _mldsa.ML_DSA_65, _mldsa.ML_DSA_87):
                pk, sk = _mldsa.keygen_internal(rng.randbytes(32), params)

                key = _mldsa.private_state(sk, pk, params)

                messages = [rng.randbytes(20) for _ in range(4)]

                signatures = {}

                for size in (1, 2, 3, 4):
                    _mldsa.GROUP = size

                    signatures[size] = [_mldsa.sign_internal(key, m, bytes(32), params) for m in messages]

                with self.subTest(params=params.name):
                    self.assertEqual(signatures[2], signatures[1])

                    self.assertEqual(signatures[3], signatures[1])

                    self.assertEqual(signatures[4], signatures[1])
        finally:
            _mldsa.GROUP = group


if __name__ == "__main__":
    unittest.main()
