from typing import NamedTuple

from ._hash import HMAC_SHA_256, HMAC_SHA_512
from ._primitives import sha256, sha512, shake256
from ._sha2 import IV_256, IV_512, Sha256, Sha512

WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)

W = 16

LG_W = 4


class Parameters(NamedTuple):
    name: str

    shake: bool

    n: int

    h: int

    d: int

    hp: int

    a: int

    k: int

    m: int

    @property
    def length(self):
        return 2 * self.n + 3

    @property
    def public_key_size(self):
        return 2 * self.n

    @property
    def private_key_size(self):
        return 4 * self.n

    @property
    def signature_size(self):
        return (1 + self.k * (1 + self.a) + self.h + self.d * self.length) * self.n


def _sets(family, shake):
    sizes = (
        ("128s", 16, 63, 7, 9, 12, 14, 30),
        ("128f", 16, 66, 22, 3, 6, 33, 34),
        ("192s", 24, 63, 7, 9, 14, 17, 39),
        ("192f", 24, 66, 22, 3, 8, 33, 42),
        ("256s", 32, 64, 8, 8, 14, 22, 47),
        ("256f", 32, 68, 17, 4, 9, 35, 49),
    )

    return [Parameters(f"SLH-DSA-{family}-{size}", shake, *rest) for size, *rest in sizes]


SHA2 = _sets("SHA2", False)

SHAKE = _sets("SHAKE", True)


def set_layer(adrs, value):
    adrs[0:4] = value.to_bytes(4, "big")


def set_tree(adrs, value):
    adrs[4:16] = value.to_bytes(12, "big")


def set_type(adrs, value):
    adrs[16:20] = value.to_bytes(4, "big")

    adrs[20:32] = bytes(12)


def set_key_pair(adrs, value):
    adrs[20:24] = value.to_bytes(4, "big")


def set_chain(adrs, value):
    adrs[24:28] = value.to_bytes(4, "big")


def set_hash(adrs, value):
    adrs[28:32] = value.to_bytes(4, "big")


def key_pair(adrs):
    return int.from_bytes(adrs[20:24], "big")


def tree_index(adrs):
    return int.from_bytes(adrs[28:32], "big")


set_tree_height = set_chain

set_tree_index = set_hash


# FIPS 205, section 11: F, H, T and PRF bound to one public seed. For SHA-2 the block holding
# PK.seed and its zero padding is hashed once and the state reused for every call.
class Hashes:
    def __init__(self, p, pk_seed, sk_seed):
        self.n = p.n

        self.pk_seed = pk_seed

        self.sk_seed = sk_seed

        self.shake = p.shake

        if not p.shake:
            self.small = Sha256(IV_256, 32)

            self.small.update(pk_seed + bytes(64 - p.n))

            if p.n == 16:
                self.large = self.small
            else:
                self.large = Sha512(IV_512, 64)

                self.large.update(pk_seed + bytes(128 - p.n))

    def _sha2(self, base, adrs, message):
        engine = base.copy()

        engine.update(bytes([adrs[3]]) + adrs[8:16] + bytes([adrs[19]]) + adrs[20:32] + message)

        return engine.digest()[: self.n]

    def f(self, adrs, message):
        if self.shake:
            return shake256(self.pk_seed + adrs + message, self.n)

        return self._sha2(self.small, adrs, message)

    def h(self, adrs, message):
        if self.shake:
            return shake256(self.pk_seed + adrs + message, self.n)

        return self._sha2(self.large, adrs, message)

    t = h

    def prf(self, adrs):
        if self.shake:
            return shake256(self.pk_seed + adrs + self.sk_seed, self.n)

        return self._sha2(self.small, adrs, self.sk_seed)


def mgf1(seed, length, hash_function):
    out = b""

    counter = 0

    while len(out) < length:
        out += hash_function(seed + counter.to_bytes(4, "big"))

        counter += 1

    return out[:length]


def h_msg(p, r, pk_seed, pk_root, message):
    if p.shake:
        return shake256(r + pk_seed + pk_root + message, p.m)

    hash_function = sha256 if p.n == 16 else sha512

    return mgf1(r + pk_seed + hash_function(r + pk_seed + pk_root + message), p.m, hash_function)


def prf_msg(p, sk_prf, opt_rand, message):
    if p.shake:
        return shake256(sk_prf + opt_rand + message, p.n)

    hmac = HMAC_SHA_256 if p.n == 16 else HMAC_SHA_512

    return hmac.digest(sk_prf, opt_rand + message)[: p.n]


def base_2b(data, b, out_length):
    out = []

    total = 0

    bits = 0

    offset = 0

    for _ in range(out_length):
        while bits < b:
            total = (total << 8) | data[offset]

            offset += 1

            bits += 8

        bits -= b

        out.append((total >> bits) & ((1 << b) - 1))

    return out


def chain(hashes, x, start, steps, adrs):
    for j in range(start, start + steps):
        set_hash(adrs, j)

        x = hashes.f(adrs, x)

    return x


def wots_digits(p, message):
    digits = base_2b(message, LG_W, 2 * p.n)

    checksum = sum(W - 1 - x for x in digits) << 4

    return digits + base_2b(checksum.to_bytes(2, "big"), LG_W, 3)


def wots_secret(hashes, adrs, i):
    sk_adrs = bytearray(adrs)

    set_type(sk_adrs, WOTS_PRF)

    set_key_pair(sk_adrs, key_pair(adrs))

    set_chain(sk_adrs, i)

    return hashes.prf(sk_adrs)


def wots_public(p, hashes, adrs, values):
    pk_adrs = bytearray(adrs)

    set_type(pk_adrs, WOTS_PK)

    set_key_pair(pk_adrs, key_pair(adrs))

    return hashes.t(pk_adrs, b"".join(values))


def wots_pk_gen(p, hashes, adrs):
    values = []

    for i in range(p.length):
        secret = wots_secret(hashes, adrs, i)

        set_chain(adrs, i)

        values.append(chain(hashes, secret, 0, W - 1, adrs))

    return wots_public(p, hashes, adrs, values)


def wots_sign(p, hashes, message, adrs):
    out = []

    for i, digit in enumerate(wots_digits(p, message)):
        secret = wots_secret(hashes, adrs, i)

        set_chain(adrs, i)

        out.append(chain(hashes, secret, 0, digit, adrs))

    return b"".join(out)


def wots_pk_from_sig(p, hashes, signature, message, adrs):
    values = []

    n = p.n

    for i, digit in enumerate(wots_digits(p, message)):
        set_chain(adrs, i)

        values.append(chain(hashes, signature[i * n : (i + 1) * n], digit, W - 1 - digit, adrs))

    return wots_public(p, hashes, adrs, values)


def xmss_node(p, hashes, i, z, adrs):
    if z == 0:
        set_type(adrs, WOTS_HASH)

        set_key_pair(adrs, i)

        return wots_pk_gen(p, hashes, adrs)

    left = xmss_node(p, hashes, 2 * i, z - 1, adrs)

    right = xmss_node(p, hashes, 2 * i + 1, z - 1, adrs)

    set_type(adrs, TREE)

    set_tree_height(adrs, z)

    set_tree_index(adrs, i)

    return hashes.h(adrs, left + right)


def xmss_sign(p, hashes, message, index, adrs):
    auth = [xmss_node(p, hashes, (index >> j) ^ 1, j, adrs) for j in range(p.hp)]

    set_type(adrs, WOTS_HASH)

    set_key_pair(adrs, index)

    return wots_sign(p, hashes, message, adrs) + b"".join(auth)


def xmss_pk_from_sig(p, hashes, index, signature, message, adrs):
    n = p.n

    set_type(adrs, WOTS_HASH)

    set_key_pair(adrs, index)

    node = wots_pk_from_sig(p, hashes, signature[: p.length * n], message, adrs)

    auth = signature[p.length * n :]

    set_type(adrs, TREE)

    set_tree_index(adrs, index)

    for k in range(p.hp):
        set_tree_height(adrs, k + 1)

        sibling = auth[k * n : (k + 1) * n]

        if (index >> k) & 1 == 0:
            set_tree_index(adrs, tree_index(adrs) // 2)

            node = hashes.h(adrs, node + sibling)
        else:
            set_tree_index(adrs, (tree_index(adrs) - 1) // 2)

            node = hashes.h(adrs, sibling + node)

    return node


def ht_sign(p, hashes, message, tree, leaf):
    adrs = bytearray(32)

    set_tree(adrs, tree)

    part = xmss_sign(p, hashes, message, leaf, adrs)

    out = [part]

    root = xmss_pk_from_sig(p, hashes, leaf, part, message, adrs)

    for j in range(1, p.d):
        leaf = tree % (1 << p.hp)

        tree >>= p.hp

        set_layer(adrs, j)

        set_tree(adrs, tree)

        part = xmss_sign(p, hashes, root, leaf, adrs)

        out.append(part)

        if j < p.d - 1:
            root = xmss_pk_from_sig(p, hashes, leaf, part, root, adrs)

    return b"".join(out)


def ht_verify(p, hashes, message, signature, tree, leaf, pk_root):
    size = (p.length + p.hp) * p.n

    adrs = bytearray(32)

    set_tree(adrs, tree)

    node = xmss_pk_from_sig(p, hashes, leaf, signature[:size], message, adrs)

    for j in range(1, p.d):
        leaf = tree % (1 << p.hp)

        tree >>= p.hp

        set_layer(adrs, j)

        set_tree(adrs, tree)

        node = xmss_pk_from_sig(p, hashes, leaf, signature[j * size : (j + 1) * size], node, adrs)

    return node == pk_root


def fors_secret(hashes, adrs, index):
    sk_adrs = bytearray(adrs)

    set_type(sk_adrs, FORS_PRF)

    set_key_pair(sk_adrs, key_pair(adrs))

    set_tree_index(sk_adrs, index)

    return hashes.prf(sk_adrs)


def fors_node(p, hashes, i, z, adrs):
    if z == 0:
        secret = fors_secret(hashes, adrs, i)

        set_tree_height(adrs, 0)

        set_tree_index(adrs, i)

        return hashes.f(adrs, secret)

    left = fors_node(p, hashes, 2 * i, z - 1, adrs)

    right = fors_node(p, hashes, 2 * i + 1, z - 1, adrs)

    set_tree_height(adrs, z)

    set_tree_index(adrs, i)

    return hashes.h(adrs, left + right)


def fors_sign(p, hashes, digest, adrs):
    out = []

    for i, index in enumerate(base_2b(digest, p.a, p.k)):
        out.append(fors_secret(hashes, adrs, (i << p.a) + index))

        for j in range(p.a):
            out.append(fors_node(p, hashes, (i << (p.a - j)) + ((index >> j) ^ 1), j, adrs))

    return b"".join(out)


def fors_pk_from_sig(p, hashes, signature, digest, adrs):
    n = p.n

    roots = []

    for i, index in enumerate(base_2b(digest, p.a, p.k)):
        offset = i * (p.a + 1) * n

        set_tree_height(adrs, 0)

        set_tree_index(adrs, (i << p.a) + index)

        node = hashes.f(adrs, signature[offset : offset + n])

        for j in range(p.a):
            sibling = signature[offset + (j + 1) * n : offset + (j + 2) * n]

            set_tree_height(adrs, j + 1)

            if (index >> j) & 1 == 0:
                set_tree_index(adrs, tree_index(adrs) // 2)

                node = hashes.h(adrs, node + sibling)
            else:
                set_tree_index(adrs, (tree_index(adrs) - 1) // 2)

                node = hashes.h(adrs, sibling + node)

        roots.append(node)

    pk_adrs = bytearray(adrs)

    set_type(pk_adrs, FORS_ROOTS)

    set_key_pair(pk_adrs, key_pair(adrs))

    return hashes.t(pk_adrs, b"".join(roots))


def root(p, sk_seed, pk_seed):
    adrs = bytearray(32)

    set_layer(adrs, p.d - 1)

    return xmss_node(p, Hashes(p, pk_seed, sk_seed), 0, p.hp, adrs)


def keygen_internal(sk_seed, sk_prf, pk_seed, p):
    pk_root = root(p, sk_seed, pk_seed)

    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


def split_digest(p, digest):
    md_size = (p.k * p.a + 7) // 8

    tree_bits = p.h - p.h // p.d

    tree_size = (tree_bits + 7) // 8

    leaf_bits = p.h // p.d

    leaf_size = (leaf_bits + 7) // 8

    tree = int.from_bytes(digest[md_size : md_size + tree_size], "big") % (1 << tree_bits)

    leaf = int.from_bytes(digest[md_size + tree_size : md_size + tree_size + leaf_size], "big") % (1 << leaf_bits)

    return digest[:md_size], tree, leaf


def sign_internal(message, sk, addrnd, p):
    n = p.n

    sk_seed, sk_prf, pk_seed, pk_root = sk[:n], sk[n : 2 * n], sk[2 * n : 3 * n], sk[3 * n :]

    hashes = Hashes(p, pk_seed, sk_seed)

    r = prf_msg(p, sk_prf, addrnd, message)

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    adrs = bytearray(32)

    set_tree(adrs, tree)

    set_type(adrs, FORS_TREE)

    set_key_pair(adrs, leaf)

    fors = fors_sign(p, hashes, md, adrs)

    pk_fors = fors_pk_from_sig(p, hashes, fors, md, adrs)

    return r + fors + ht_sign(p, hashes, pk_fors, tree, leaf)


def verify_internal(message, signature, pk, p):
    n = p.n

    if len(signature) != p.signature_size or len(pk) != p.public_key_size:
        return False

    pk_seed, pk_root = pk[:n], pk[n:]

    hashes = Hashes(p, pk_seed, None)

    r = signature[:n]

    fors_end = (1 + p.k * (1 + p.a)) * n

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    adrs = bytearray(32)

    set_tree(adrs, tree)

    set_type(adrs, FORS_TREE)

    set_key_pair(adrs, leaf)

    pk_fors = fors_pk_from_sig(p, hashes, signature[n:fors_end], md, adrs)

    return ht_verify(p, hashes, pk_fors, signature[fors_end:], tree, leaf, pk_root)
