from typing import NamedTuple

from ._merkle import MerkleTree
from ._primitives import sha256, shake256

W = 16

OTS, LTREE, HASH_TREE = 0, 1, 2

F, H, H_MSG, PRF, PRF_KEYGEN = range(5)


class Parameters(NamedTuple):
    name: str

    oid: int

    multi: bool

    shake: bool

    n: int

    h: int

    d: int

    @property
    def padding(self):
        return 32 if self.n == 32 else 4

    @property
    def tree_height(self):
        return self.h // self.d

    @property
    def length(self):
        return 2 * self.n + 3

    @property
    def index_size(self):
        return (self.h + 7) // 8 if self.multi else 4

    @property
    def public_key_size(self):
        return 4 + 2 * self.n

    @property
    def signature_size(self):
        return self.index_size + self.n + (self.d * self.length + self.h) * self.n


def _families():
    return (("SHA2", False, 32, "256"), ("SHA2", False, 24, "192"), ("SHAKE256", True, 32, "256"), ("SHAKE256", True, 24, "192"))


# The SP 800-208 parameter sets with their RFC 8391 and NIST code points.
XMSS_SETS = {}

XMSS_MT_SETS = {}

for _family, _base_xmss, _base_mt in zip(_families(), (0x01, 0x0D, 0x10, 0x13), (0x01, 0x21, 0x29, 0x31)):
    _name, _shake, _n, _bits = _family

    for _j, _h in enumerate((10, 16, 20)):
        _p = Parameters(f"XMSS-{_name}_{_h}_{_bits}", _base_xmss + _j, False, _shake, _n, _h, 1)

        XMSS_SETS[_p.name] = _p

    for _j, (_h, _d) in enumerate(((20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6), (60, 12))):
        _p = Parameters(f"XMSSMT-{_name}_{_h}/{_d}_{_bits}", _base_mt + _j, True, _shake, _n, _h, _d)

        XMSS_MT_SETS[_p.name] = _p


def by_oid(sets, oid):
    return next((p for p in sets.values() if p.oid == oid), None)


def hash_function(p, prefix, key, message):
    data = prefix.to_bytes(p.padding, "big") + key + message

    return shake256(data, p.n) if p.shake else sha256(data)[: p.n]


def address(layer, tree, kind):
    adrs = bytearray(32)

    adrs[0:4] = layer.to_bytes(4, "big")

    adrs[4:12] = tree.to_bytes(8, "big")

    adrs[12:16] = kind.to_bytes(4, "big")

    return adrs


def set_word(adrs, word, value):
    adrs[4 * word : 4 * word + 4] = value.to_bytes(4, "big")


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def prf(p, key, adrs):
    return hash_function(p, PRF, key, bytes(adrs))


def chain(p, x, start, steps, pub_seed, adrs):
    for k in range(start, start + steps):
        set_word(adrs, 6, k)

        set_word(adrs, 7, 0)

        key = prf(p, pub_seed, adrs)

        set_word(adrs, 7, 1)

        mask = prf(p, pub_seed, adrs)

        x = hash_function(p, F, key, xor(x, mask))

    return x


def wots_digits(p, message):
    digits = []

    for byte in message:
        digits += [byte >> 4, byte & 0x0F]

    checksum = sum(W - 1 - x for x in digits) << 4

    return digits + [(checksum >> shift) & 0x0F for shift in (12, 8, 4)]


# SP 800-208: secret chain values come from PRF_keygen(SK_SEED, PUB_SEED || ADRS) with the hash
# and key-and-mask words cleared.
def wots_secret(p, sk_seed, pub_seed, adrs, i):
    set_word(adrs, 5, i)

    set_word(adrs, 6, 0)

    set_word(adrs, 7, 0)

    return hash_function(p, PRF_KEYGEN, sk_seed, pub_seed + bytes(adrs))


def wots_public(p, sk_seed, pub_seed, adrs):
    secrets = [wots_secret(p, sk_seed, pub_seed, adrs, i) for i in range(p.length)]

    out = []

    for i, secret in enumerate(secrets):
        set_word(adrs, 5, i)

        out.append(chain(p, secret, 0, W - 1, pub_seed, adrs))

    return out


def wots_sign(p, message, sk_seed, pub_seed, adrs):
    secrets = [wots_secret(p, sk_seed, pub_seed, adrs, i) for i in range(p.length)]

    out = []

    for i, (secret, digit) in enumerate(zip(secrets, wots_digits(p, message))):
        set_word(adrs, 5, i)

        out.append(chain(p, secret, 0, digit, pub_seed, adrs))

    return b"".join(out)


def wots_public_from_signature(p, signature, message, pub_seed, adrs):
    n = p.n

    out = []

    for i, digit in enumerate(wots_digits(p, message)):
        set_word(adrs, 5, i)

        out.append(chain(p, signature[i * n : (i + 1) * n], digit, W - 1 - digit, pub_seed, adrs))

    return out


def rand_hash(p, left, right, pub_seed, adrs):
    set_word(adrs, 7, 0)

    key = prf(p, pub_seed, adrs)

    set_word(adrs, 7, 1)

    mask0 = prf(p, pub_seed, adrs)

    set_word(adrs, 7, 2)

    mask1 = prf(p, pub_seed, adrs)

    return hash_function(p, H, key, xor(left, mask0) + xor(right, mask1))


def ltree(p, values, pub_seed, adrs):
    values = list(values)

    set_word(adrs, 5, 0)

    while len(values) > 1:
        paired = []

        for i in range(len(values) // 2):
            set_word(adrs, 6, i)

            paired.append(rand_hash(p, values[2 * i], values[2 * i + 1], pub_seed, adrs))

        if len(values) % 2:
            paired.append(values[-1])

        values = paired

        set_word(adrs, 5, int.from_bytes(adrs[20:24], "big") + 1)

    return values[0]


def leaf(p, sk_seed, pub_seed, layer, tree, index):
    ots = address(layer, tree, OTS)

    set_word(ots, 4, index)

    values = wots_public(p, sk_seed, pub_seed, ots)

    lt = address(layer, tree, LTREE)

    set_word(lt, 4, index)

    return ltree(p, values, pub_seed, lt)


def subtree(p, sk_seed, pub_seed, layer, tree):
    def make_leaf(index):
        return leaf(p, sk_seed, pub_seed, layer, tree, index)

    def combine(z, j, left, right):
        adrs = address(layer, tree, HASH_TREE)

        set_word(adrs, 5, z)

        set_word(adrs, 6, j)

        return rand_hash(p, left, right, pub_seed, adrs)

    return MerkleTree(p.tree_height, make_leaf, combine)


def compute_root(p, node, index, auth, pub_seed, layer, tree):
    adrs = address(layer, tree, HASH_TREE)

    n = p.n

    for k in range(p.tree_height):
        set_word(adrs, 5, k)

        set_word(adrs, 6, index >> (k + 1))

        sibling = auth[k * n : (k + 1) * n]

        if (index >> k) & 1:
            node = rand_hash(p, sibling, node, pub_seed, adrs)
        else:
            node = rand_hash(p, node, sibling, pub_seed, adrs)

    return node


def message_digest(p, r, root, index, message):
    return hash_function(p, H_MSG, r + root + index.to_bytes(p.n, "big"), message)


def verify(p, public_key, message, signature):
    n = p.n

    if len(public_key) != p.public_key_size or len(signature) != p.signature_size:
        return False

    if int.from_bytes(public_key[:4], "big") != p.oid:
        return False

    root, pub_seed = public_key[4 : 4 + n], public_key[4 + n :]

    index = int.from_bytes(signature[: p.index_size], "big")

    if index >> p.h:
        return False

    r = signature[p.index_size : p.index_size + n]

    node = message_digest(p, r, root, index, message)

    offset = p.index_size + n

    for layer in range(p.d):
        leaf_index = index & ((1 << p.tree_height) - 1)

        index >>= p.tree_height

        ots = address(layer, index, OTS)

        set_word(ots, 4, leaf_index)

        values = wots_public_from_signature(p, signature[offset : offset + p.length * n], node, pub_seed, ots)

        offset += p.length * n

        lt = address(layer, index, LTREE)

        set_word(lt, 4, leaf_index)

        node = compute_root(p, ltree(p, values, pub_seed, lt), leaf_index, signature[offset : offset + p.tree_height * n], pub_seed, layer, index)

        offset += p.tree_height * n

    return node == root


class Xmss:
    """The signing side of an XMSS or XMSS^MT key, with one cached tree per layer."""

    def __init__(self, p, sk_seed, sk_prf, pub_seed):
        self.p = p

        self.sk_seed = sk_seed

        self.sk_prf = sk_prf

        self.pub_seed = pub_seed

        self.trees = {}

        self.root = self._tree(p.d - 1, 0).root

    @property
    def public_key(self):
        return self.p.oid.to_bytes(4, "big") + self.root + self.pub_seed

    @property
    def capacity(self):
        return 1 << self.p.h

    def _tree(self, layer, tree):
        cached = self.trees.get(layer)

        if cached is None or cached[0] != tree:
            cached = (tree, subtree(self.p, self.sk_seed, self.pub_seed, layer, tree))

            self.trees[layer] = cached

        return cached[1]

    def sign(self, index, message):
        p = self.p

        r = hash_function(p, PRF, self.sk_prf, index.to_bytes(32, "big"))

        node = message_digest(p, r, self.root, index, message)

        out = [index.to_bytes(p.index_size, "big"), r]

        for layer in range(p.d):
            leaf_index = index & ((1 << p.tree_height) - 1)

            index >>= p.tree_height

            ots = address(layer, index, OTS)

            set_word(ots, 4, leaf_index)

            out.append(wots_sign(p, node, self.sk_seed, self.pub_seed, ots))

            tree = self._tree(layer, index)

            out += tree.auth_path(leaf_index)

            node = tree.root

        return b"".join(out)
