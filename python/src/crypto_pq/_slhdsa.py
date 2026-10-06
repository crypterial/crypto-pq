import struct
from typing import NamedTuple

from . import _primitives
from ._hash import HMAC_SHA_256, HMAC_SHA_512

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

_WORD = struct.Struct(">I").pack

# The 32-bit words below 1024: chain and hash addresses, key pairs and the nodes of an XMSS tree.
_WORDS = [_WORD(i) for i in range(1024)]

_ZERO = bytes(4)


def mgf1(seed, length, hash_function):
    out = b""

    counter = 0

    while len(out) < length:
        out += hash_function(seed + counter.to_bytes(4, "big")).digest()

        counter += 1

    return out[:length]


def h_msg(p, r, pk_seed, pk_root, message):
    if p.shake:
        return _primitives.shake_256(r + pk_seed + pk_root + message).digest(p.m)

    hash_function = _primitives.sha256 if p.n == 16 else _primitives.sha512

    return mgf1(r + pk_seed + hash_function(r + pk_seed + pk_root + message).digest(), p.m, hash_function)


def prf_msg(p, sk_prf, opt_rand, message):
    if p.shake:
        return _primitives.shake_256(sk_prf + opt_rand + message).digest(p.n)

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


def wots_digits(p, message):
    digits = base_2b(message, LG_W, 2 * p.n)

    checksum = sum(W - 1 - x for x in digits) << 4

    return digits + base_2b(checksum.to_bytes(2, "big"), LG_W, 3)


def split_digest(p, digest):
    md_size = (p.k * p.a + 7) // 8

    tree_bits = p.h - p.h // p.d

    tree_size = (tree_bits + 7) // 8

    leaf_bits = p.h // p.d

    leaf_size = (leaf_bits + 7) // 8

    tree = int.from_bytes(digest[md_size : md_size + tree_size], "big") % (1 << tree_bits)

    leaf = int.from_bytes(digest[md_size + tree_size : md_size + tree_size + leaf_size], "big") % (1 << leaf_bits)

    return digest[:md_size], tree, leaf


class _Sha2Hashes:
    """F, H, T and PRF of the SHA-2 sets for one key (FIPS 205, 11.2): each hash continues the state
    after the block of PK.seed and zeros. F and PRF use SHA-256; H and T use SHA-512 when n > 16.

    An address is its head (one byte of the layer, the low eight bytes of the tree and one byte of
    the type: the compressed form ADRSc) and three 32-bit words.
    """

    __slots__ = ("n", "sk_seed", "small", "large")

    def __init__(self, p, pk_seed, sk_seed):
        n = p.n

        self.n = n

        self.sk_seed = sk_seed

        self.small = _primitives.sha256(pk_seed + bytes(64 - n)).copy

        self.large = _primitives.sha512(pk_seed + bytes(128 - n)).copy if n > 16 else self.small

    @staticmethod
    def head(layer, tree, kind):
        return bytes([layer]) + tree.to_bytes(8, "big") + bytes([kind])

    def f(self, adrs, value):
        h = self.small()

        h.update(adrs + value)

        return h.digest()[: self.n]

    def prf(self, adrs):
        h = self.small()

        h.update(adrs + self.sk_seed)

        return h.digest()[: self.n]

    def h(self, adrs, value):
        h = self.large()

        h.update(adrs + value)

        return h.digest()[: self.n]

    t = h

    # F with hash addresses first .. last - 1 in turn, after `prefix`: the head, the key pair and
    # the chain address.
    def chain(self, prefix, value, first, last):
        copy, n, words = self.small, self.n, _WORDS

        for j in range(first, last):
            h = copy()

            h.update(prefix + words[j] + value)

            value = h.digest()[:n]

        return value

    # The parents of `nodes`, numbered from `first`, after `prefix`: the head, the first word and
    # their height.
    def parents(self, prefix, first, nodes):
        copy, n = self.large, self.n

        out = []

        for i in range(0, len(nodes), 2):
            h = copy()

            h.update(prefix + _WORD(first + (i >> 1)) + nodes[i] + nodes[i + 1])

            out.append(h.digest()[:n])

        return out


class _Sha2WholeHashes(_Sha2Hashes):
    """The same hashes, each from a new state of its whole input, where states copy and update
    slowly (see _primitives.copies_cheaply)."""

    __slots__ = ("small_block", "large_block", "sha256", "large_hash")

    def __init__(self, p, pk_seed, sk_seed):
        n = p.n

        self.n = n

        self.sk_seed = sk_seed

        self.sha256 = _primitives.sha256

        self.large_hash = _primitives.sha512 if n > 16 else self.sha256

        self.small_block = pk_seed + bytes(64 - n)

        self.large_block = pk_seed + bytes(128 - n) if n > 16 else self.small_block

    def f(self, adrs, value):
        return self.sha256(self.small_block + adrs + value).digest()[: self.n]

    def prf(self, adrs):
        return self.sha256(self.small_block + adrs + self.sk_seed).digest()[: self.n]

    def h(self, adrs, value):
        return self.large_hash(self.large_block + adrs + value).digest()[: self.n]

    t = h

    def chain(self, prefix, value, first, last):
        sha256, n, words = self.sha256, self.n, _WORDS

        prefix = self.small_block + prefix

        for j in range(first, last):
            value = sha256(prefix + words[j] + value).digest()[:n]

        return value

    def parents(self, prefix, first, nodes):
        large_hash, n = self.large_hash, self.n

        prefix = self.large_block + prefix

        return [large_hash(prefix + _WORD(first + (i >> 1)) + nodes[i] + nodes[i + 1]).digest()[:n] for i in range(0, len(nodes), 2)]


class _ShakeHashes:
    """F, H, T and PRF of the SHAKE sets for one key (FIPS 205, 11.1), with the same interface; an
    address head is the layer, the 12-byte tree and the type."""

    __slots__ = ("n", "pk_seed", "sk_seed", "shake")

    def __init__(self, p, pk_seed, sk_seed):
        self.n = p.n

        self.pk_seed = pk_seed

        self.sk_seed = sk_seed

        self.shake = _primitives.shake_256

    @staticmethod
    def head(layer, tree, kind):
        return layer.to_bytes(4, "big") + tree.to_bytes(12, "big") + kind.to_bytes(4, "big")

    def f(self, adrs, value):
        return self.shake(self.pk_seed + adrs + value).digest(self.n)

    h = t = f

    def prf(self, adrs):
        return self.shake(self.pk_seed + adrs + self.sk_seed).digest(self.n)

    def chain(self, prefix, value, first, last):
        shake_256, n, words = self.shake, self.n, _WORDS

        prefix = self.pk_seed + prefix

        for j in range(first, last):
            value = shake_256(prefix + words[j] + value).digest(n)

        return value

    def parents(self, prefix, first, nodes):
        shake_256, n = self.shake, self.n

        prefix = self.pk_seed + prefix

        return [shake_256(prefix + _WORD(first + (i >> 1)) + nodes[i] + nodes[i + 1]).digest(n) for i in range(0, len(nodes), 2)]


def _hashes(p, pk_seed, sk_seed):
    if p.shake:
        return _ShakeHashes(p, pk_seed, sk_seed)

    return (_Sha2Hashes if _primitives.copies_cheaply(_primitives.sha256) else _Sha2WholeHashes)(p, pk_seed, sk_seed)


# FIPS 205, Algorithm 6: the WOTS+ public key of `keypair` under the heads of its PRF, chain and
# public key addresses. With `digits`, also the WOTS+ signature (Algorithm 7) of the message they
# encode, whose values the chains pass through on their way.
def wots_pk(hashes, p, heads, keypair, digits=None):
    prf_head, hash_head, pk_head = heads

    word = _WORDS[keypair]

    prf_prefix, hash_prefix = prf_head + word, hash_head + word

    ends, signature = [], []

    for i in range(p.length):
        chain = _WORDS[i]

        value = hashes.prf(prf_prefix + chain + _ZERO)

        prefix = hash_prefix + chain

        if digits is not None:
            value = hashes.chain(prefix, value, 0, digits[i])

            signature.append(value)

            ends.append(hashes.chain(prefix, value, digits[i], W - 1))
        else:
            ends.append(hashes.chain(prefix, value, 0, W - 1))

    return hashes.t(pk_head + word + bytes(8), b"".join(ends)), b"".join(signature)


# Every level of the XMSS tree `tree` of `layer`, from its leaves to its root, and the WOTS+
# signature of `message` with leaf `leaf` when a message is given (FIPS 205, Algorithms 9 and 10).
def xmss_levels(hashes, p, layer, tree, message=None, leaf=0):
    heads = hashes.head(layer, tree, WOTS_PRF), hashes.head(layer, tree, WOTS_HASH), hashes.head(layer, tree, WOTS_PK)

    digits = wots_digits(p, message) if message is not None else None

    leaves, signature = [], b""

    for keypair in range(1 << p.hp):
        if keypair == leaf and digits is not None:
            node, signature = wots_pk(hashes, p, heads, keypair, digits)
        else:
            node = wots_pk(hashes, p, heads, keypair)[0]

        leaves.append(node)

    levels = [leaves]

    head = hashes.head(layer, tree, TREE) + _ZERO

    for z in range(1, p.hp + 1):
        levels.append(hashes.parents(head + _WORDS[z], 0, levels[-1]))

    return levels, signature


def root(p, sk_seed, pk_seed):
    return xmss_levels(_hashes(p, pk_seed, sk_seed), p, p.d - 1, 0)[0][-1][0]


def keygen_internal(sk_seed, sk_prf, pk_seed, p):
    pk_root = root(p, sk_seed, pk_seed)

    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


# FIPS 205, Algorithm 12: each layer signs the root of the one below with the leaf that the tree
# address gives, and its tree's levels give the authentication path and its own root.
def ht_sign(hashes, p, message, tree, leaf):
    out = []

    for layer in range(p.d):
        levels, signature = xmss_levels(hashes, p, layer, tree, message, leaf)

        out.append(signature)

        out += [levels[z][(leaf >> z) ^ 1] for z in range(p.hp)]

        message = levels[-1][0]

        leaf = tree & ((1 << p.hp) - 1)

        tree >>= p.hp

    return b"".join(out)


# FIPS 205, Algorithms 14 to 16: every FORS tree in turn, with the secret value of its leaf, the
# authentication path and its root; returns the signature and the FORS public key.
def fors_sign(hashes, p, md, tree, leaf):
    indices = base_2b(md, p.a, p.k)

    word = _WORDS[leaf]

    prf_head = hashes.head(0, tree, FORS_PRF) + word + _ZERO

    tree_head = hashes.head(0, tree, FORS_TREE) + word

    leaf_head = tree_head + _ZERO

    prf, f = hashes.prf, hashes.f

    out, roots = [], []

    for i in range(p.k):
        first = i << p.a

        level = [f(leaf_head + address, prf(prf_head + address)) for address in map(_WORD, range(first, first + (1 << p.a)))]

        index = indices[i]

        out.append(prf(prf_head + _WORD(first + index)))

        for z in range(p.a):
            out.append(level[(index >> z) ^ 1])

            level = hashes.parents(tree_head + _WORDS[z + 1], first >> (z + 1), level)

        roots.append(level[0])

    return b"".join(out), hashes.t(hashes.head(0, tree, FORS_ROOTS) + word + bytes(8), b"".join(roots))


def sign_internal(message, sk, addrnd, p):
    n = p.n

    sk_seed, sk_prf, pk_seed, pk_root = sk[:n], sk[n : 2 * n], sk[2 * n : 3 * n], sk[3 * n :]

    hashes = _hashes(p, pk_seed, sk_seed)

    r = prf_msg(p, sk_prf, addrnd, message)

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    fors, pk_fors = fors_sign(hashes, p, md, tree, leaf)

    return r + fors + ht_sign(hashes, p, pk_fors, tree, leaf)


# Climbs from `node`, at `index` on the lowest level, along the authentication path `auth`, under
# `prefix`: an address head and its first word.
def climb(hashes, p, node, index, auth, prefix, height):
    n = p.n

    for z in range(height):
        sibling = auth[z * n : (z + 1) * n]

        pair = sibling + node if index & 1 else node + sibling

        index >>= 1

        node = hashes.h(prefix + _WORDS[z + 1] + _WORD(index), pair)

    return node


# FIPS 205, Algorithm 17.
def fors_pk_from_sig(hashes, p, signature, md, tree, leaf):
    n = p.n

    indices = base_2b(md, p.a, p.k)

    word = _WORDS[leaf]

    tree_head = hashes.head(0, tree, FORS_TREE) + word

    size = (p.a + 1) * n

    roots = []

    for i in range(p.k):
        part = signature[i * size : (i + 1) * size]

        index = (i << p.a) + indices[i]

        node = hashes.f(tree_head + _ZERO + _WORD(index), part[:n])

        roots.append(climb(hashes, p, node, index, part[n:], tree_head, p.a))

    return hashes.t(hashes.head(0, tree, FORS_ROOTS) + word + bytes(8), b"".join(roots))


# FIPS 205, Algorithms 8 and 11.
def xmss_pk_from_sig(hashes, p, leaf, signature, message, layer, tree):
    n = p.n

    digits = wots_digits(p, message)

    word = _WORDS[leaf]

    hash_prefix = hashes.head(layer, tree, WOTS_HASH) + word

    ends = [hashes.chain(hash_prefix + _WORDS[i], signature[i * n : (i + 1) * n], digits[i], W - 1) for i in range(p.length)]

    node = hashes.t(hashes.head(layer, tree, WOTS_PK) + word + bytes(8), b"".join(ends))

    return climb(hashes, p, node, leaf, signature[p.length * n :], hashes.head(layer, tree, TREE) + _ZERO, p.hp)


def ht_verify(hashes, p, message, signature, tree, leaf, pk_root):
    size = (p.length + p.hp) * p.n

    node = message

    for layer in range(p.d):
        node = xmss_pk_from_sig(hashes, p, leaf, signature[layer * size : (layer + 1) * size], node, layer, tree)

        leaf = tree & ((1 << p.hp) - 1)

        tree >>= p.hp

    return node == pk_root


def verify_internal(message, signature, pk, p):
    n = p.n

    if len(signature) != p.signature_size or len(pk) != p.public_key_size:
        return False

    pk_seed, pk_root = pk[:n], pk[n:]

    hashes = _hashes(p, pk_seed, None)

    r = signature[:n]

    fors_end = (1 + p.k * (1 + p.a)) * n

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    pk_fors = fors_pk_from_sig(hashes, p, signature[n:fors_end], md, tree, leaf)

    return ht_verify(hashes, p, pk_fors, signature[fors_end:], tree, leaf, pk_root)
