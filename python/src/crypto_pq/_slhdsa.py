import struct
from functools import lru_cache
from itertools import starmap
from typing import NamedTuple

from . import _lanes
from ._hash import HMAC_SHA_256, HMAC_SHA_512
from ._lanes import M64
from ._primitives import sha256, sha512, shake256
from ._sha2 import IV_256, IV_512, Sha256, Sha512

WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)

W = 16

LG_W = 4

# Lanes per batch: enough to make the interpreter's share of each big-integer operation small,
# few enough for the operands to stay in the processor cache.
CHUNK = 8192


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

# An address: layer, tree, type and the three words after it (key pair, chain or tree height,
# hash or tree index). The tree address of SLH-DSA fits in its low 8 bytes.
_ADDRESS = struct.Struct(">I4xQIIII")

_COMPRESSED = struct.Struct(">BQBIII")


def address(layer, tree, kind, word5=0, word6=0, word7=0):
    return _ADDRESS.pack(layer, tree, kind, word5, word6, word7)


def _records(record, count, fields):
    columns = [field if isinstance(field, list) else [field] * count for field in fields]

    return b"".join(starmap(record.pack, zip(*columns)))


# The words of one address per lane, from fields that are either one value for every lane or a
# list with one value per lane.
def _address_words(record, layout, widths, count, fields):
    if not any(isinstance(field, list) for field in fields):
        words = struct.unpack(layout, record.pack(*fields))

        return [_lanes.replicate(word, count, width) for word, width in zip(words, widths)]

    columns = zip(*struct.iter_unpack(layout, _records(record, count, fields)))

    return [_lanes.pack(column, width) for column, width in zip(columns, widths)]


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


class _Sha2Lanes:
    """F, H, T and PRF of the SHA-2 sets on many inputs at once (see _lanes).

    The messages follow the block of PK.seed and zeros, whose compression is done once, and start
    with the 22-byte compressed address, so the values after it start 2 bytes into a word. A value
    from F or PRF is a list of 32-bit SHA-256 words in 64-bit fields; with n > 16, H and T use
    SHA-512 and their values are 64-bit words in 128-bit fields.
    """

    def __init__(self, p, pk_seed, sk_seed):
        n = p.n

        self.n = n

        self.wide = n > 16

        self.width = 128 if self.wide else 64

        small = Sha256(IV_256, 32)

        small.update(pk_seed + bytes(64 - n))

        self.small = list(small._state)

        if self.wide:
            large = Sha512(IV_512, 64)

            large.update(pk_seed + bytes(128 - n))

            self.large = list(large._state)

        self.sk_seed = list(struct.unpack(f">{n // 4}I", sk_seed)) if sk_seed is not None else None

    # The compressed address keeps byte 3 of the layer, the low 8 bytes of the tree and byte 3 of
    # the type: 22 bytes, five 32-bit words and the top half of a sixth. The SHA-512 form is two
    # 64-bit words and the top six bytes of a third.
    def address(self, count, layer, tree, kind, word5=0, word6=0, word7=0, wide=False):
        fields = (layer, tree, kind, word5, word6, word7)

        if wide and self.wide:
            v0, v1, v2, v3 = _address_words(_COMPRESSED, ">QQIH", (128,) * 4, count, fields)

            return [v0, v1, (v2 << 32) | (v3 << 16)]

        words = _address_words(_COMPRESSED, ">IIIIIH", (64,) * 6, count, fields)

        words[5] <<= 16

        return words

    def to_bytes(self, value, count, wide=False):
        if wide and self.wide:
            return _lanes.chunks(value, count, 8, 128)

        return _lanes.chunks(value, count, 4, 64)

    def from_bytes(self, values, wide=False):
        if wide and self.wide:
            return _lanes.words(values, 8, 128)

        return _lanes.words(values, 4, 64)

    # An F output becomes an input of H: SHA-512 takes the 32-bit words two at a time.
    def widen(self, value, count):
        if not self.wide:
            return value

        return [_lanes.widen((value[i] << 32) | value[i + 1], count) for i in range(0, len(value), 2)]

    def _small(self, count, words, length):
        return _lanes.sha256(self.small, words, count, 8 * (64 + length))[: self.n // 4]

    def _large(self, count, words, length):
        return _lanes.sha512(self.large, words, count, 8 * (128 + length))[: self.n // 8]

    def f(self, adrs, value, count):
        return self._small(count, adrs[:5] + _lanes.shifted(adrs[5], value, 4, 2, count), 22 + self.n)

    def prf(self, adrs, count):
        return self.f(adrs, [_lanes.replicate(word, count, 64) for word in self.sk_seed], count)

    # F with hash address j, for an address made with hash address 0: the low half of the hash
    # word is the top half of message word 5.
    def step(self, adrs, value, count, j):
        return self.f(adrs[:5] + [_lanes.replicate(j << 16, count, 64)], value, count)

    def h(self, adrs, left, right, count):
        if self.wide:
            return self._large(count, adrs[:2] + _lanes.shifted(adrs[2], left + right, 8, 6, count), 22 + 2 * self.n)

        return self._small(count, adrs[:5] + _lanes.shifted(adrs[5], left + right, 4, 2, count), 22 + 2 * self.n)

    def t(self, adrs, values, count):
        length = 22 + len(values) * self.n

        if self.wide:
            words = [word for value in values for word in self.widen(value, count)]

            return self._large(count, adrs[:2] + _lanes.shifted(adrs[2], words, 8, 6, count), length)

        words = [word for value in values for word in value]

        return self._small(count, adrs[:5] + _lanes.shifted(adrs[5], words, 4, 2, count), length)


class _ShakeLanes:
    """F, H, T and PRF of the SHAKE sets on many inputs at once (see _lanes). n is a multiple of
    8, so PK.seed, the address and every value fill whole 64-bit Keccak lanes."""

    def __init__(self, p, pk_seed, sk_seed):
        n = p.n

        self.n = n

        self.width = 64

        self.pk_seed = list(struct.unpack(f"<{n // 8}Q", pk_seed))

        self.sk_seed = list(struct.unpack(f"<{n // 8}Q", sk_seed)) if sk_seed is not None else None

    def address(self, count, layer, tree, kind, word5=0, word6=0, word7=0, wide=False):
        return _address_words(_ADDRESS, "<QQQQ", (64,) * 4, count, (layer, tree, kind, word5, word6, word7))

    def to_bytes(self, value, count, wide=False):
        return _lanes.chunks64(value, count)

    def from_bytes(self, values, wide=False):
        return _lanes.lanes64(values)

    def widen(self, value, count):
        return value

    def _shake(self, count, message):
        seed = [_lanes.replicate(word, count, 64) for word in self.pk_seed]

        return _lanes.shake256(seed + message + [_lanes.replicate(0x1F, count, 64)], count, self.n // 8)

    def f(self, adrs, value, count):
        return self._shake(count, adrs + value)

    def prf(self, adrs, count):
        return self._shake(count, adrs + [_lanes.replicate(word, count, 64) for word in self.sk_seed])

    # F with hash address j, for an address made with hash address 0: the hash word is the high
    # half of the last address lane, in big-endian byte order.
    def step(self, adrs, value, count, j):
        return self._shake(count, adrs[:3] + [adrs[3] | _lanes.replicate(int.from_bytes(j.to_bytes(4, "big"), "little") << 32, count, 64)] + value)

    def h(self, adrs, left, right, count):
        return self._shake(count, adrs + left + right)

    def t(self, adrs, values, count):
        return self._shake(count, adrs + [word for value in values for word in value])


def _hashes(p, pk_seed, sk_seed):
    return (_ShakeLanes if p.shake else _Sha2Lanes)(p, pk_seed, sk_seed)


@lru_cache(maxsize=32)
def _reverse(bits):
    return [int(f"{k:0{bits}b}"[::-1], 2) if bits else 0 for k in range(1 << bits)]


def _select(value, start, count, width):
    return [_lanes.select(word, start, count, width) for word in value]


def _join(parts, counts, width):
    return [_lanes.concatenate(words, counts, width) for words in zip(*parts)]


# The WOTS public keys, compressed by T, of every leaf of the given XMSS trees. Leaf q of tree t
# is lane reverse(q) * len(trees) + t: with the leaf index bit-reversed, the left children of
# every level fill the lower half of the lanes and their right siblings the upper half, in the
# same order, so each Merkle level is one split and one batch of H. The chains of one batch are
# grouped by chain index, which keeps the slice of one chain contiguous.
def wots_leaves(hashes, p, trees):
    count_t = len(trees)

    positions = count_t << p.hp

    reverse = _reverse(p.hp)

    layers = [layer for _ in range(1 << p.hp) for layer, _ in trees]

    tree_addresses = [tree for _ in range(1 << p.hp) for _, tree in trees]

    key_pairs = [reverse[r] for r in range(1 << p.hp) for _ in trees]

    per_batch = max(1, CHUNK // positions)

    values = []

    for first in range(0, p.length, per_batch):
        chains = range(first, min(p.length, first + per_batch))

        count = len(chains) * positions

        layer, tree, key_pair = layers * len(chains), tree_addresses * len(chains), key_pairs * len(chains)

        chain = [i for i in chains for _ in range(positions)]

        value = hashes.prf(hashes.address(count, layer, tree, WOTS_PRF, key_pair, chain), count)

        adrs = hashes.address(count, layer, tree, WOTS_HASH, key_pair, chain)

        for j in range(W - 1):
            value = hashes.step(adrs, value, count, j)

        for c in range(len(chains)):
            values.append(_select(value, c * positions, positions, 64))

    return hashes.t(hashes.address(positions, layers, tree_addresses, WOTS_PK, key_pairs, wide=True), values, positions)


# Every level of trees whose leaves are in the lane order of wots_leaves, from the leaves to the
# roots. adrs(height, indices, trees) gives the addresses of the nodes at that height.
def merkle_levels(hashes, height, count_t, leaves, adrs):
    levels = [leaves]

    for z in range(height):
        half = count_t << (height - z - 1)

        level = levels[-1]

        reverse = _reverse(height - z - 1)

        indices = [reverse[r] for r in range(1 << (height - z - 1)) for _ in range(count_t)]

        trees = list(range(count_t)) * (1 << (height - z - 1))

        left, right = _select(level, 0, half, hashes.width), _select(level, half, half, hashes.width)

        levels.append(hashes.h(adrs(z + 1, indices, trees), left, right, half))

    return levels


def _node(hashes, levels, height, count_t, z, index, t):
    lane = _reverse(height - z)[index] * count_t + t

    return hashes.to_bytes([_lanes.lane(word, lane, hashes.width, M64) for word in levels[z]], 1, wide=True)[0]


def xmss_trees(hashes, p, trees):
    leaves = wots_leaves(hashes, p, trees)

    layers = [layer for layer, _ in trees]

    tree_addresses = [tree for _, tree in trees]

    def adrs(height, indices, which):
        count = len(indices)

        return hashes.address(count, [layers[t] for t in which], [tree_addresses[t] for t in which], TREE, 0, height, indices, wide=True)

    return merkle_levels(hashes, p.hp, len(trees), leaves, adrs)


def root(p, sk_seed, pk_seed):
    hashes = _hashes(p, pk_seed, sk_seed)

    levels = xmss_trees(hashes, p, [(p.d - 1, 0)])

    return _node(hashes, levels, p.hp, 1, p.hp, 0, 0)


def keygen_internal(sk_seed, sk_prf, pk_seed, p):
    pk_root = root(p, sk_seed, pk_seed)

    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


# The WOTS signatures of several layers at once: lane i * len + j is chain j of layer i.
def wots_sign(hashes, p, messages, trees, leaves):
    count = len(messages) * p.length

    digits = [digit for message in messages for digit in wots_digits(p, message)]

    layer = [layer for layer, _ in trees for _ in range(p.length)]

    tree = [tree for _, tree in trees for _ in range(p.length)]

    key_pair = [leaf for leaf in leaves for _ in range(p.length)]

    chain = list(range(p.length)) * len(messages)

    secret = hashes.prf(hashes.address(count, layer, tree, WOTS_PRF, key_pair, chain), count)

    adrs = hashes.address(count, layer, tree, WOTS_HASH, key_pair, chain)

    signature = _lanes.run_to(lambda value, j: hashes.step(adrs, value, count, j), secret, digits)

    values = hashes.to_bytes(signature, count)

    return [b"".join(values[i * p.length : (i + 1) * p.length]) for i in range(len(messages))]


# The hypertree signature builds the XMSS tree of every layer at once: their auth paths and roots
# come from the same levels, and the root of a layer is the message of the layer above.
def ht_sign(hashes, p, message, tree, leaf):
    trees, leaves = [], []

    for _ in range(p.d):
        trees.append((len(trees), tree))

        leaves.append(leaf)

        leaf = tree % (1 << p.hp)

        tree >>= p.hp

    levels = xmss_trees(hashes, p, trees)

    messages = [message] + [_node(hashes, levels, p.hp, p.d, p.hp, 0, layer) for layer in range(p.d - 1)]

    signatures = wots_sign(hashes, p, messages, trees, leaves)

    out = []

    for layer, leaf in enumerate(leaves):
        out.append(signatures[layer])

        out += [_node(hashes, levels, p.hp, p.d, z, (leaf >> z) ^ 1, layer) for z in range(p.hp)]

    return b"".join(out)


# FORS trees go in groups that fill a batch; lane reverse(j) * group + c is leaf j of tree
# first + c. A tree larger than a batch computes its leaves in several batches.
def fors_sign(hashes, p, digest, idx_tree, idx_leaf):
    indices = base_2b(digest, p.a, p.k)

    group = max(1, CHUNK >> p.a)

    reverse = _reverse(p.a)

    out, roots = [], []

    for first in range(0, p.k, group):
        trees = range(first, min(p.k, first + group))

        positions = len(trees) << p.a

        index = [(i << p.a) | reverse[r] for r in range(1 << p.a) for i in trees]

        secrets, leaves, counts = [], [], []

        for start in range(0, positions, CHUNK):
            count = min(CHUNK, positions - start)

            part = index[start : start + count]

            secret = hashes.prf(hashes.address(count, 0, idx_tree, FORS_PRF, idx_leaf, 0, part), count)

            leaves.append(hashes.widen(hashes.f(hashes.address(count, 0, idx_tree, FORS_TREE, idx_leaf, 0, part), secret, count), count))

            secrets.append(secret)

            counts.append(count)

        def adrs(height, nodes, which, first=first):
            count = len(nodes)

            return hashes.address(count, 0, idx_tree, FORS_TREE, idx_leaf, height, [((first + t) << (p.a - height)) | node for node, t in zip(nodes, which)], wide=True)

        levels = merkle_levels(hashes, p.a, len(trees), _join(leaves, counts, hashes.width), adrs)

        for c, i in enumerate(trees):
            lane = reverse[indices[i]] * len(trees) + c

            chunk, offset = divmod(lane, CHUNK)

            out.append(hashes.to_bytes([_lanes.lane(word, offset, 64, M64) for word in secrets[chunk]], 1)[0])

            out += [_node(hashes, levels, p.a, len(trees), z, (indices[i] >> z) ^ 1, c) for z in range(p.a)]

            roots.append(_node(hashes, levels, p.a, len(trees), p.a, 0, c))

    return b"".join(out), roots


def _fors_public(single, idx_tree, idx_leaf, roots):
    return single.t(address(0, idx_tree, FORS_ROOTS, idx_leaf), b"".join(roots))


def sign_internal(message, sk, addrnd, p):
    n = p.n

    sk_seed, sk_prf, pk_seed, pk_root = sk[:n], sk[n : 2 * n], sk[2 * n : 3 * n], sk[3 * n :]

    hashes = _hashes(p, pk_seed, sk_seed)

    r = prf_msg(p, sk_prf, addrnd, message)

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    fors, roots = fors_sign(hashes, p, md, tree, leaf)

    pk_fors = _fors_public(Hashes(p, pk_seed), tree, leaf, roots)

    return r + fors + ht_sign(hashes, p, pk_fors, tree, leaf)


# Verification follows one path per tree: the k FORS trees climb together in k lanes, and the
# chains of one WOTS signature run in len lanes.
def fors_pk_from_sig(hashes, single, p, signature, digest, idx_tree, idx_leaf):
    n, k = p.n, p.k

    indices = base_2b(digest, p.a, k)

    size = (p.a + 1) * n

    index = [(i << p.a) + indices[i] for i in range(k)]

    secrets = hashes.from_bytes([signature[i * size : i * size + n] for i in range(k)])

    node = hashes.widen(hashes.f(hashes.address(k, 0, idx_tree, FORS_TREE, idx_leaf, 0, index), secrets, k), k)

    for z in range(p.a):
        sibling = hashes.from_bytes([signature[i * size + (z + 1) * n : i * size + (z + 2) * n] for i in range(k)], wide=True)

        first = _lanes.mask([(x >> z) & 1 == 0 for x in indices], hashes.width)

        left = [s ^ ((x ^ s) & first) for x, s in zip(node, sibling)]

        right = [x ^ s ^ y for x, s, y in zip(node, sibling, left)]

        index = [x >> 1 for x in index]

        node = hashes.h(hashes.address(k, 0, idx_tree, FORS_TREE, idx_leaf, z + 1, index, wide=True), left, right, k)

    return _fors_public(single, idx_tree, idx_leaf, hashes.to_bytes(node, k, wide=True))


def xmss_pk_from_sig(hashes, single, p, leaf, signature, message, layer, tree):
    n = p.n

    count = p.length

    values = hashes.from_bytes([signature[i * n : (i + 1) * n] for i in range(count)])

    adrs = hashes.address(count, layer, tree, WOTS_HASH, leaf, list(range(count)))

    values = _lanes.run_from(lambda value, j: hashes.step(adrs, value, count, j), values, wots_digits(p, message), W - 1)

    node = single.t(address(layer, tree, WOTS_PK, leaf), b"".join(hashes.to_bytes(values, count)))

    auth = signature[count * n :]

    index = leaf

    for z in range(p.hp):
        sibling = auth[z * n : (z + 1) * n]

        pair = sibling + node if index & 1 else node + sibling

        index >>= 1

        node = single.h(address(layer, tree, TREE, 0, z + 1, index), pair)

    return node


def ht_verify(hashes, single, p, message, signature, tree, leaf, pk_root):
    size = (p.length + p.hp) * p.n

    node = message

    for layer in range(p.d):
        node = xmss_pk_from_sig(hashes, single, p, leaf, signature[layer * size : (layer + 1) * size], node, layer, tree)

        leaf = tree % (1 << p.hp)

        tree >>= p.hp

    return node == pk_root


def verify_internal(message, signature, pk, p):
    n = p.n

    if len(signature) != p.signature_size or len(pk) != p.public_key_size:
        return False

    pk_seed, pk_root = pk[:n], pk[n:]

    hashes = _hashes(p, pk_seed, None)

    single = Hashes(p, pk_seed)

    r = signature[:n]

    fors_end = (1 + p.k * (1 + p.a)) * n

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    pk_fors = fors_pk_from_sig(hashes, single, p, signature[n:fors_end], md, tree, leaf)

    return ht_verify(hashes, single, p, pk_fors, signature[fors_end:], tree, leaf, pk_root)


# FIPS 205, section 11, for single inputs: H and T of the SHA-2 sets reuse the state after the
# block of PK.seed and zeros.
class Hashes:
    def __init__(self, p, pk_seed):
        self.n = p.n

        self.pk_seed = pk_seed

        self.shake = p.shake

        if not p.shake:
            self.base = Sha256(IV_256, 32) if p.n == 16 else Sha512(IV_512, 64)

            self.base.update(pk_seed + bytes(self.base._block - p.n))

    def h(self, adrs, message):
        if self.shake:
            return shake256(self.pk_seed + adrs + message, self.n)

        engine = self.base.copy()

        engine.update(adrs[3:4] + adrs[8:16] + adrs[19:20] + adrs[20:32] + message)

        return engine.digest()[: self.n]

    t = h
