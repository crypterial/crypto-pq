import struct
from typing import NamedTuple

from . import _lanes, _primitives, _sha2
from ._bytes import Output
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

# The chain addresses of every WOTS+ key, and the zero hash and key-and-mask words of a secret.
_CHAINS = [_WORD(i) for i in range(67)]

_SECRET = bytes(8)


class _Hashes:
    """The keyed hashes of one XMSS key, many at a time (see _lanes): PRF and PRF_keygen have fixed
    prefixes (toByte(3) || PUB_SEED, and toByte(4) || SK_SEED || PUB_SEED), and the SHA-2 hashes
    continue the chaining value after their whole blocks."""

    __slots__ = ("p", "_prf", "_keygen", "_f", "_h")

    def __init__(self, p, pub_seed, sk_seed=None):
        self.p = p

        self._prf = self._start(PRF.to_bytes(p.padding, "big") + pub_seed)

        self._keygen = None if sk_seed is None else self._start(PRF_KEYGEN.to_bytes(p.padding, "big") + sk_seed + pub_seed)

        self._f = self._start(F.to_bytes(p.padding, "big"))

        self._h = self._start(H.to_bytes(p.padding, "big"))

    # A prefix as SHAKE takes it, or SHA-256's chaining value after its whole blocks, their length
    # and the rest of the prefix.
    def _start(self, prefix):
        if self.p.shake:
            return prefix

        whole = len(prefix) - len(prefix) % 64

        state = _sha2.IV_256

        for offset in range(0, whole, 64):
            state = _sha2.chain256(state, prefix[offset : offset + 64])

        return state, whole, prefix[whole:]

    # The hashes of the prefix `start` followed by each of `messages`, which share one length.
    def _many(self, start, messages):
        n = self.p.n

        if self.p.shake:
            return _lanes.shake_many(136, [start + message for message in messages], n)

        state, done, rest = start

        return [digest[:n] for digest in _lanes.sha256_many([rest + message for message in messages], state, done)]

    def prf_many(self, addresses):
        return self._many(self._prf, addresses)

    def keygen_many(self, addresses):
        return self._many(self._keygen, addresses)

    # RAND_HASH of RFC 8391 for many nodes, each under an address prefix that lacks only its
    # key-and-mask word.
    def rand_hash_many(self, prefixes, lefts, rights):
        m = len(prefixes)

        prf = self.prf_many([prefix + word for word in _KEY_AND_MASK for prefix in prefixes])

        return self._many(self._h, [key + xor(left, mask0) + xor(right, mask1) for key, left, right, mask0, mask1 in zip(prf[:m], lefts, rights, prf[m : 2 * m], prf[2 * m :])])

    # The chains under `prefixes` (addresses up to the hash word), stepped together: chain i runs
    # from values[i] at step firsts[i] to lasts[i].
    def chains(self, prefixes, values, firsts, lasts):
        values = [*values]

        for j in range(min(firsts), max(lasts)):
            active = [i for i in range(len(values)) if firsts[i] <= j < lasts[i]]

            if not active:
                continue

            step = _WORD(j)

            prf = self.prf_many([prefixes[i] + step + word for word in _KEY_AND_MASK[:2] for i in active])

            m = len(active)

            for i, value in zip(active, self._many(self._f, [key + xor(values[i], mask) for i, key, mask in zip(active, prf[:m], prf[m:])])):
                values[i] = value

        return values

    # The secret values of the chains of one leaf, whose addresses `prefixes` reach their chain words.
    def secrets(self, prefixes):
        return self.keygen_many([prefix + _SECRET for prefix in prefixes])

    # RFC 8391, Algorithm 4: the L-tree of a WOTS+ public key, each level in place of the one below.
    def ltree(self, layer, tree, leaf, values):
        height = 0

        while len(values) > 1:
            pairs = len(values) // 2

            values[:pairs] = self.rand_hash_many([address(layer, tree, LTREE, leaf, height, i)[:-4] for i in range(pairs)], values[0 : 2 * pairs : 2], values[1 : 2 * pairs : 2])

            values[pairs:] = values[2 * pairs :]

            height += 1

        return values[0]


# The addresses of the chains of one leaf up to their hash words.
def _prefixes(p, layer, tree, leaf):
    head = address(layer, tree, OTS, leaf)[:20]

    return [head + chain for chain in _CHAINS[: p.length]]


# The leaves first .. first + count - 1 of one XMSS tree: the L-trees of their WOTS+ public keys.
def leaves(p, sk_seed, pub_seed, layer, tree, first, count):
    hashes = _Hashes(p, pub_seed, sk_seed)

    out = []

    for leaf in range(first, first + count):
        prefixes = _prefixes(p, layer, tree, leaf)

        out.append(hashes.ltree(layer, tree, leaf, hashes.chains(prefixes, hashes.secrets(prefixes), [0] * p.length, [W - 1] * p.length)))

    return out


def combine(p, pub_seed, layer, tree, z, first, lefts, rights):
    hashes = _Hashes(p, pub_seed)

    return hashes.rand_hash_many([address(layer, tree, HASH_TREE, 0, z, first + i)[:-4] for i in range(len(lefts))], lefts, rights)


def subtree(p, sk_seed, pub_seed, layer, tree, levels=None):
    def tree_leaves(first, count):
        return leaves(p, sk_seed, pub_seed, layer, tree, first, count)

    def tree_combine(z, first, lefts, rights):
        return combine(p, pub_seed, layer, tree, z, first, lefts, rights)

    return MerkleTree(p.tree_height, tree_leaves, tree_combine, levels)


# The WOTS+ signature of `message`, written to out[offset:].
def wots_sign(p, message, sk_seed, pub_seed, layer, tree, leaf, out, offset):
    n = p.n

    hashes = _Hashes(p, pub_seed, sk_seed)

    prefixes = _prefixes(p, layer, tree, leaf)

    for i, value in enumerate(hashes.chains(prefixes, hashes.secrets(prefixes), [0] * p.length, wots_digits(p, message))):
        out[offset + i * n : offset + (i + 1) * n] = value


# The leaf that the WOTS+ signature at signature[offset:] gives.
def leaf_from_signature(p, signature, offset, message, pub_seed, layer, tree, leaf):
    n = p.n

    hashes = _Hashes(p, pub_seed)

    starts = [signature[offset + i * n : offset + (i + 1) * n] for i in range(p.length)]

    return hashes.ltree(layer, tree, leaf, hashes.chains(_prefixes(p, layer, tree, leaf), starts, wots_digits(p, message), [W - 1] * p.length))


# The root from `node` along the authentication path at signature[offset:].
def compute_root(p, node, index, signature, offset, pub_seed, layer, tree):
    n = p.n

    for k in range(p.tree_height):
        sibling = signature[offset + k * n : offset + (k + 1) * n]

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

        leaf = leaf_from_signature(p, signature, offset, node, pub_seed, layer, index, leaf_index)

        offset += p.length * n

        node = compute_root(p, leaf, leaf_index, signature, offset, pub_seed, layer, index)

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

            part = Output((p.length + p.tree_height) * p.n)

            wots_sign(p, node, self.sk_seed, self.pub_seed, layer, tree, leaf, part.view, 0)

            _write(part.view, p.length * p.n, self._tree(layer, tree).auth_path(leaf))

            cached = (prefix, part.finish())

            self.signed[layer] = cached

        return cached[1]

    def sign(self, index, message):
        p = self.p

        r = hash_function(p, PRF, self.sk_prf, index.to_bytes(32, "big"))

        node = message_digest(p, r, self.root, index, message)

        leaf, tree = index & ((1 << p.tree_height) - 1), index >> p.tree_height

        # The trees and the upper layers' parts are built, when they change, before the
        # signature's buffer exists.
        bottom = self._tree(0, tree)

        layers = [self._layer(layer, index >> (layer * p.tree_height)) for layer in range(1, p.d)]

        signature = Output(p.signature_size)

        out, offset = signature.view, p.index_size + p.n

        out[:offset] = index.to_bytes(p.index_size, "big") + r

        wots_sign(p, node, self.sk_seed, self.pub_seed, 0, tree, leaf, out, offset)

        _write(out, _write(out, offset + p.length * p.n, bottom.auth_path(leaf)), layers)

        return signature.finish()


# Writes `parts` in turn to out[offset:]; returns the offset after them.
def _write(out, offset, parts):
    for part in parts:
        out[offset : offset + len(part)] = part

        offset += len(part)

    return offset
