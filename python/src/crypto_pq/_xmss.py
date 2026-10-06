import struct
from typing import NamedTuple

from . import _primitives
from ._merkle import MerkleTree

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

    return _primitives.shake_256(data).digest(p.n) if p.shake else _primitives.sha256(data).digest()[: p.n]


# An address: layer, tree, type, then the words 4 to 7 (OTS, L-tree or padding; chain or tree
# height; hash or tree index; key and mask).
_ADDRESS = struct.Struct(">IQIIIII")


def address(layer, tree, kind, word4=0, word5=0, word6=0, word7=0):
    return _ADDRESS.pack(layer, tree, kind, word4, word5, word6, word7)


def xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def rand_hash(p, left, right, pub_seed, layer, tree, kind, word4, word5, word6):
    key, mask0, mask1 = (hash_function(p, PRF, pub_seed, address(layer, tree, kind, word4, word5, word6, i)) for i in range(3))

    return hash_function(p, H, key, xor(left, mask0) + xor(right, mask1))


def wots_digits(p, message):
    digits = []

    for byte in message:
        digits += [byte >> 4, byte & 0x0F]

    checksum = sum(W - 1 - x for x in digits) << 4

    return digits + [(checksum >> shift) & 0x0F for shift in (12, 8, 4)]


_WORD = struct.Struct(">I").pack

_KEY_AND_MASK = [_WORD(i) for i in range(3)]


class _Hashes:
    """The keyed hashes of one XMSS key. PRF and PRF_keygen have fixed prefixes (toByte(3) ||
    PUB_SEED, and toByte(4) || SK_SEED || PUB_SEED), which fill at least one SHA-256 block when n
    = 32: where states copy cheaply, they continue copies of the states after them. F and H hash
    their whole input."""

    __slots__ = ("p", "_hash", "_prf", "_keygen", "_prf_state", "_keygen_state", "_f", "_h")

    def __init__(self, p, pub_seed, sk_seed=None):
        constructor = _primitives.shake_256 if p.shake else _primitives.sha256

        self.p = p

        self._hash = constructor

        self._prf = PRF.to_bytes(p.padding, "big") + pub_seed

        self._keygen = None if sk_seed is None else PRF_KEYGEN.to_bytes(p.padding, "big") + sk_seed + pub_seed

        copies = _primitives.copies_cheaply(constructor)

        self._prf_state = constructor(self._prf).copy if copies else None

        self._keygen_state = constructor(self._keygen).copy if copies and sk_seed is not None else None

        self._f = F.to_bytes(p.padding, "big")

        self._h = H.to_bytes(p.padding, "big")

    def _digest(self, h):
        return h.digest(self.p.n) if self.p.shake else h.digest()[: self.p.n]

    def _keyed(self, state, prefix, adrs):
        if state is None:
            return self._digest(self._hash(prefix + adrs))

        h = state()

        h.update(adrs)

        return self._digest(h)

    def prf(self, adrs):
        return self._keyed(self._prf_state, self._prf, adrs)

    def prf_keygen(self, adrs):
        return self._keyed(self._keygen_state, self._keygen, adrs)

    def f(self, key, message):
        return self._digest(self._hash(self._f + key + message))

    # RAND_HASH of RFC 8391, for an address `prefix` that lacks only its key-and-mask word.
    def rand_hash(self, prefix, left, right):
        key, mask0, mask1 = (self.prf(prefix + word) for word in _KEY_AND_MASK)

        return self._digest(self._hash(self._h + key + xor(left, mask0) + xor(right, mask1)))

    # The steps first .. last - 1 of the chain whose address, up to its hash word, is `prefix`.
    def chain(self, prefix, value, first, last):
        for k in range(first, last):
            adrs = prefix + _WORD(k)

            key = self.prf(adrs + _KEY_AND_MASK[0])

            value = self.f(key, xor(value, self.prf(adrs + _KEY_AND_MASK[1])))

        return value

    # The WOTS+ secret values of one leaf, at the address of its chains up to the chain word.
    def secrets(self, prefix):
        return [self.prf_keygen(prefix + _WORD(i) + bytes(8)) for i in range(self.p.length)]

    # RFC 8391, Algorithm 4: the L-tree of a WOTS+ public key.
    def ltree(self, layer, tree, leaf, values):
        height = 0

        while len(values) > 1:
            pairs = len(values) // 2

            parents = [self.rand_hash(address(layer, tree, LTREE, leaf, height, i)[:-4], values[2 * i], values[2 * i + 1]) for i in range(pairs)]

            values = parents + values[2 * pairs :]

            height += 1

        return values[0]


def _chain_prefix(layer, tree, leaf):
    return address(layer, tree, OTS, leaf)[:20]


# The leaves first .. first + count - 1 of one XMSS tree: the L-trees of their WOTS+ public keys.
def leaves(p, sk_seed, pub_seed, layer, tree, first, count):
    hashes = _Hashes(p, pub_seed, sk_seed)

    out = []

    for leaf in range(first, first + count):
        prefix = _chain_prefix(layer, tree, leaf)

        values = [hashes.chain(prefix + _WORD(i), x, 0, W - 1) for i, x in enumerate(hashes.secrets(prefix))]

        out.append(hashes.ltree(layer, tree, leaf, values))

    return out


def combine(p, pub_seed, layer, tree, z, first, lefts, rights):
    hashes = _Hashes(p, pub_seed)

    return [hashes.rand_hash(address(layer, tree, HASH_TREE, 0, z, first + i)[:-4], left, right) for i, (left, right) in enumerate(zip(lefts, rights))]


def subtree(p, sk_seed, pub_seed, layer, tree, levels=None):
    def tree_leaves(first, count):
        return leaves(p, sk_seed, pub_seed, layer, tree, first, count)

    def tree_combine(z, first, lefts, rights):
        return combine(p, pub_seed, layer, tree, z, first, lefts, rights)

    return MerkleTree(p.tree_height, tree_leaves, tree_combine, levels)


def wots_sign(p, message, sk_seed, pub_seed, layer, tree, leaf):
    hashes = _Hashes(p, pub_seed, sk_seed)

    prefix = _chain_prefix(layer, tree, leaf)

    return b"".join(hashes.chain(prefix + _WORD(i), x, 0, a) for i, (x, a) in enumerate(zip(hashes.secrets(prefix), wots_digits(p, message))))


def leaf_from_signature(p, signature, message, pub_seed, layer, tree, leaf):
    n = p.n

    hashes = _Hashes(p, pub_seed)

    prefix = _chain_prefix(layer, tree, leaf)

    values = [hashes.chain(prefix + _WORD(i), signature[i * n : (i + 1) * n], a, W - 1) for i, a in enumerate(wots_digits(p, message))]

    return hashes.ltree(layer, tree, leaf, values)


def compute_root(p, node, index, auth, pub_seed, layer, tree):
    n = p.n

    for k in range(p.tree_height):
        sibling = auth[k * n : (k + 1) * n]

        if (index >> k) & 1:
            node = rand_hash(p, sibling, node, pub_seed, layer, tree, HASH_TREE, 0, k, index >> (k + 1))
        else:
            node = rand_hash(p, node, sibling, pub_seed, layer, tree, HASH_TREE, 0, k, index >> (k + 1))

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

        leaf = leaf_from_signature(p, signature[offset : offset + p.length * n], node, pub_seed, layer, index, leaf_index)

        offset += p.length * n

        node = compute_root(p, leaf, leaf_index, signature[offset : offset + p.tree_height * n], pub_seed, layer, index)

        offset += p.tree_height * n

    return node == root


class Xmss:
    """The signing side of an XMSS or XMSS^MT key, with one cached tree per layer.

    Above layer 0 a layer's part of the signature, the WOTS+ signature of the root below and its
    authentication path, depends only on index >> (layer * h / d). It is kept until that value
    changes, as HSS keeps its signed child keys, so most signatures sign layer 0 only.

    `cached` maps layers to (tree number, levels) for the trees of a verified tree cache that the
    next index signs with; they replace the build, checked against their own nodes."""

    def __init__(self, p, sk_seed, sk_prf, pub_seed, cached=None):
        self.p = p

        self.sk_seed = sk_seed

        self.sk_prf = sk_prf

        self.pub_seed = pub_seed

        self.trees = {layer: (tree, subtree(p, sk_seed, pub_seed, layer, tree, levels)) for layer, (tree, levels) in (cached or {}).items()}

        self.signed = {}

        self.root = self._tree(p.d - 1, 0).root

    @property
    def public_key(self):
        return self.p.oid.to_bytes(4, "big") + self.root + self.pub_seed

    @property
    def capacity(self):
        return 1 << self.p.h

    # Every tree the key holds, top first, as (layer, tree number, Merkle tree).
    def cached(self):
        return [(layer, *self.trees[layer]) for layer in sorted(self.trees, reverse=True)]

    def _tree(self, layer, tree):
        cached = self.trees.get(layer)

        if cached is None or cached[0] != tree:
            cached = (tree, subtree(self.p, self.sk_seed, self.pub_seed, layer, tree))

            self.trees[layer] = cached

        return cached[1]

    # The part of layer `layer` signs the root of tree `prefix` of the layer below with leaf
    # prefix mod 2^(h/d) of tree prefix >> (h/d).
    def _layer(self, layer, prefix):
        cached = self.signed.get(layer)

        if cached is None or cached[0] != prefix:
            p = self.p

            leaf, tree = prefix & ((1 << p.tree_height) - 1), prefix >> p.tree_height

            node = self._tree(layer - 1, prefix).root

            part = wots_sign(p, node, self.sk_seed, self.pub_seed, layer, tree, leaf) + b"".join(self._tree(layer, tree).auth_path(leaf))

            cached = (prefix, part)

            self.signed[layer] = cached

        return cached[1]

    def sign(self, index, message):
        p = self.p

        r = hash_function(p, PRF, self.sk_prf, index.to_bytes(32, "big"))

        node = message_digest(p, r, self.root, index, message)

        leaf, tree = index & ((1 << p.tree_height) - 1), index >> p.tree_height

        out = [index.to_bytes(p.index_size, "big"), r, wots_sign(p, node, self.sk_seed, self.pub_seed, 0, tree, leaf)]

        out += self._tree(0, tree).auth_path(leaf)

        out += [self._layer(layer, index >> (layer * p.tree_height)) for layer in range(1, p.d)]

        return b"".join(out)
