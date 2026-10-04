import struct
from itertools import starmap
from typing import NamedTuple

from . import _lanes
from ._merkle import MerkleTree
from ._primitives import sha256, shake256
from ._sha2 import IV_256, Sha256

W = 16

OTS, LTREE, HASH_TREE = 0, 1, 2

F, H, H_MSG, PRF, PRF_KEYGEN = range(5)

# Lanes per batch (see _slhdsa).
CHUNK = 8192


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


# An address: layer, tree, type, then the words 4 to 7 (OTS, L-tree or padding; chain or tree
# height; hash or tree index; key and mask).
_ADDRESS = struct.Struct(">IQIIIII")


def address(layer, tree, kind, word4=0, word5=0, word6=0, word7=0):
    return _ADDRESS.pack(layer, tree, kind, word4, word5, word6, word7)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def rand_hash(p, left, right, pub_seed, layer, tree, kind, word4, word5, word6):
    key, mask0, mask1 = (hash_function(p, PRF, pub_seed, address(layer, tree, kind, word4, word5, word6, i)) for i in range(3))

    return hash_function(p, H, key, xor(left, mask0) + xor(right, mask1))


def wots_digits(p, message):
    digits = []

    for byte in message:
        digits += [byte >> 4, byte & 0x0F]

    checksum = sum(W - 1 - x for x in digits) << 4

    return digits + [(checksum >> shift) & 0x0F for shift in (12, 8, 4)]


def _swap32(value):
    return int.from_bytes(value.to_bytes(4, "big"), "little")


class Lanes:
    """The hashes of one XMSS key on many inputs at once (see _lanes).

    Every hash is H(toByte(prefix, padding) || KEY || M). With SHA-256 and n = 32 the first block
    is the prefix and the key, so the keyed PRFs start from the state after that block; with n =
    24 the 4-byte prefix keeps every value word-aligned. SHAKE256 values are Keccak lanes; with n =
    24 the key and message start 4 bytes into a lane. A value is n/4 SHA-256 words in 64-bit
    fields, or n/8 Keccak lanes.
    """

    def __init__(self, p, pub_seed, sk_seed, count):
        self.p = p

        self.count = count

        self.pub_seed = self.constant(pub_seed)

        self.sk_seed = self.constant(sk_seed) if sk_seed is not None else None

        self.keyed = {}

        if not p.shake and p.padding == 32:
            for prefix, key in ((PRF, pub_seed), (PRF_KEYGEN, sk_seed)):
                if key is not None:
                    engine = Sha256(IV_256, 32)

                    engine.update(prefix.to_bytes(32, "big") + key)

                    self.keyed[prefix] = list(engine._state)

    def constant(self, data):
        if self.p.shake:
            words = struct.unpack(f"<{len(data) // 8}Q", data)
        else:
            words = struct.unpack(f">{len(data) // 4}I", data)

        return [_lanes.replicate(word, self.count, 64) for word in words]

    def from_bytes(self, values):
        return _lanes.lanes64(values) if self.p.shake else _lanes.words(values, 4, 64)

    def to_bytes(self, value):
        return _lanes.chunks64(value, self.count) if self.p.shake else _lanes.chunks(value, self.count, 4, 64)

    # The address words of every lane from fields that are one value for all lanes, or lists.
    def address(self, layer, tree, kind, word4=0, word5=0, word6=0, word7=0):
        fields = (layer, tree, kind, word4, word5, word6, word7)

        layout = "<4Q" if self.p.shake else ">8I"

        if not any(isinstance(field, list) for field in fields):
            return [_lanes.replicate(word, self.count, 64) for word in struct.unpack(layout, _ADDRESS.pack(*fields))]

        columns = [field if isinstance(field, list) else [field] * self.count for field in fields]

        data = b"".join(starmap(_ADDRESS.pack, zip(*columns)))

        return [_lanes.pack(column, 64) for column in zip(*struct.iter_unpack(layout, data))]

    # The address with words 6 and 7 set for every lane, for an address made with both zero.
    def last_words(self, adrs, word6, word7):
        if self.p.shake:
            return adrs[:3] + [_lanes.replicate(_swap32(word6) | (_swap32(word7) << 32), self.count, 64)]

        return adrs[:6] + [_lanes.replicate(word6, self.count, 64), _lanes.replicate(word7, self.count, 64)]

    def hash(self, prefix, key, message):
        p, count = self.p, self.count

        if p.shake:
            if p.padding == 32:
                lanes = [0, 0, 0, _lanes.replicate(prefix << 56, count, 64)] + key + message + [_lanes.replicate(0x1F, count, 64)]
            else:
                lanes = _lanes.shifted_le(_lanes.replicate(_swap32(prefix), count, 64), key + message, 4, count)

            return _lanes.shake256(lanes, count, p.n // 8)

        end = [_lanes.replicate(0x80000000, count, 64)]

        if prefix in self.keyed:
            return _lanes.sha256(self.keyed[prefix], message + end, count, 8 * (64 + 4 * len(message)))[: p.n // 4]

        head = [0] * (p.padding // 4 - 1) + [_lanes.replicate(prefix, count, 64)]

        words = head + key + message + end

        return _lanes.sha256(IV_256, words, count, 32 * (len(words) - 1))[: p.n // 4]

    def prf(self, adrs):
        return self.hash(PRF, self.pub_seed, adrs)

    def prf_keygen(self, adrs):
        return self.hash(PRF_KEYGEN, self.sk_seed, self.pub_seed + adrs)

    # One step of the chains of the given address (made with hash and key-and-mask words zero):
    # the key and the bitmask come from PRF(PUB_SEED, ADRS) with key-and-mask 0 and 1.
    def chain_step(self, adrs):
        def step(value, k):
            key = self.prf(self.last_words(adrs, k, 0))

            mask = self.prf(self.last_words(adrs, k, 1))

            return self.hash(F, key, [x ^ y for x, y in zip(value, mask)])

        return step

    # RAND_HASH of RFC 8391 for an address made with key-and-mask word zero.
    def rand_hash(self, adrs, left, right):
        key, mask0, mask1 = (self.prf(adrs[:-1] + [adrs[-1] | self._mask_word(i)]) for i in range(3))

        return self.hash(H, key, [x ^ y for x, y in zip(left, mask0)] + [x ^ y for x, y in zip(right, mask1)])

    def _mask_word(self, value):
        return _lanes.replicate(_swap32(value) << 32 if self.p.shake else value, self.count, 64)


# The L-trees of several leaves at once: values[i] holds WOTS public key value i of every leaf.
# Each level hashes the pairs of every leaf in one batch, pair i of leaf c in lane i * count + c.
def ltrees(p, pub_seed, layer, tree, leaves, values):
    count = len(leaves)

    height = 0

    while len(values) > 1:
        pairs = len(values) // 2

        lanes = Lanes(p, pub_seed, None, pairs * count)

        words = range(len(values[0]))

        left = [_lanes.concatenate([values[2 * i][j] for i in range(pairs)], [count] * pairs, 64) for j in words]

        right = [_lanes.concatenate([values[2 * i + 1][j] for i in range(pairs)], [count] * pairs, 64) for j in words]

        adrs = lanes.address(layer, tree, LTREE, leaves * pairs, height, [i for i in range(pairs) for _ in range(count)])

        out = lanes.rand_hash(adrs, left, right)

        values = [[_lanes.select(word, i * count, count, 64) for word in out] for i in range(pairs)] + values[2 * pairs :]

        height += 1

    return values[0]


# The leaves first .. first + count - 1 of one XMSS tree: lane i * size + c of a batch is chain i
# of leaf c, so that the values of one chain form a slice for the L-trees.
def leaves(p, sk_seed, pub_seed, layer, tree, first, count):
    per_batch = max(1, CHUNK // p.length)

    out = []

    for start in range(first, first + count, per_batch):
        size = min(per_batch, first + count - start)

        lanes = Lanes(p, pub_seed, sk_seed, size * p.length)

        indices = list(range(start, start + size))

        chains = [i for i in range(p.length) for _ in range(size)]

        adrs = lanes.address(layer, tree, OTS, indices * p.length, chains)

        step = lanes.chain_step(adrs)

        value = lanes.prf_keygen(adrs)

        for k in range(W - 1):
            value = step(value, k)

        values = [[_lanes.select(word, i * size, size, 64) for word in value] for i in range(p.length)]

        out += Lanes(p, pub_seed, None, size).to_bytes(ltrees(p, pub_seed, layer, tree, indices, values))

    return out


def combine(p, pub_seed, layer, tree, z, first, lefts, rights):
    out = []

    for start in range(0, len(lefts), CHUNK):
        size = min(CHUNK, len(lefts) - start)

        lanes = Lanes(p, pub_seed, None, size)

        adrs = lanes.address(layer, tree, HASH_TREE, 0, z, list(range(first + start, first + start + size)))

        out += lanes.to_bytes(lanes.rand_hash(adrs, lanes.from_bytes(lefts[start : start + size]), lanes.from_bytes(rights[start : start + size])))

    return out


def subtree(p, sk_seed, pub_seed, layer, tree):
    def tree_leaves(first, count):
        return leaves(p, sk_seed, pub_seed, layer, tree, first, count)

    def tree_combine(z, first, lefts, rights):
        return combine(p, pub_seed, layer, tree, z, first, lefts, rights)

    return MerkleTree(p.tree_height, tree_leaves, tree_combine)


def wots_sign(p, message, sk_seed, pub_seed, layer, tree, leaf):
    lanes = Lanes(p, pub_seed, sk_seed, p.length)

    adrs = lanes.address(layer, tree, OTS, leaf, list(range(p.length)))

    value = _lanes.run_to(lanes.chain_step(adrs), lanes.prf_keygen(adrs), wots_digits(p, message))

    return b"".join(lanes.to_bytes(value))


def leaf_from_signature(p, signature, message, pub_seed, layer, tree, leaf):
    n = p.n

    lanes = Lanes(p, pub_seed, None, p.length)

    adrs = lanes.address(layer, tree, OTS, leaf, list(range(p.length)))

    value = lanes.from_bytes([signature[i * n : (i + 1) * n] for i in range(p.length)])

    value = _lanes.run_from(lanes.chain_step(adrs), value, wots_digits(p, message), W - 1)

    values = [[_lanes.select(word, i, 1, 64) for word in value] for i in range(p.length)]

    return Lanes(p, pub_seed, None, 1).to_bytes(ltrees(p, pub_seed, layer, tree, [leaf], values))[0]


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
    changes, as HSS keeps its signed child keys, so most signatures sign layer 0 only."""

    def __init__(self, p, sk_seed, sk_prf, pub_seed):
        self.p = p

        self.sk_seed = sk_seed

        self.sk_prf = sk_prf

        self.pub_seed = pub_seed

        self.trees = {}

        self.signed = {}

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
