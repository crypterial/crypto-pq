from typing import NamedTuple

from . import _lanes, _primitives
from ._bytes import Output
from ._merkle import MerkleTree

D_PBLC = b"\x80\x80"

D_MESG = b"\x81\x81"

D_LEAF = b"\x82\x82"

D_INTR = b"\x83\x83"

# Pseudorandom values derived from a tree's SEED (RFC 8554, Appendix A, and the convention of
# the hash-sigs reference used by the RFC 8554 and RFC 9858 test cases): the signature
# randomizer C, and the SEED and I of a child tree. Chain indices are below 0xFFFD.
RANDOMIZER = 0xFFFD

CHILD_SEED = 0xFFFE

CHILD_I = 0xFFFF


class OtsType(NamedTuple):
    code: int

    name: str

    shake: bool

    n: int

    w: int

    @property
    def p(self):
        u = -(-8 * self.n // self.w)

        v = -(-(((1 << self.w) - 1) * u).bit_length() // self.w)

        return u + v

    @property
    def ls(self):
        u = -(-8 * self.n // self.w)

        v = -(-(((1 << self.w) - 1) * u).bit_length() // self.w)

        return 16 - v * self.w

    @property
    def signature_size(self):
        return 4 + self.n * (self.p + 1)


class LmsType(NamedTuple):
    code: int

    name: str

    shake: bool

    m: int

    h: int

    @property
    def public_key_size(self):
        return 24 + self.m


FAMILIES = ((False, 32, "SHA256_N32", "SHA256_M32"), (False, 24, "SHA256_N24", "SHA256_M24"), (True, 32, "SHAKE_N32", "SHAKE_M32"), (True, 24, "SHAKE_N24", "SHAKE_M24"))

OTS_TYPES = {}

LMS_TYPES = {}

for _index, (_shake, _n, _ots, _lms) in enumerate(FAMILIES):
    for _j, _w in enumerate((1, 2, 4, 8)):
        _ots_type = OtsType(1 + 4 * _index + _j, f"LMOTS_{_ots}_W{_w}", _shake, _n, _w)

        OTS_TYPES[_ots_type.code] = _ots_type

    for _j, _h in enumerate((5, 10, 15, 20, 25)):
        _lms_type = LmsType(5 + 5 * _index + _j, f"LMS_{_lms}_H{_h}", _shake, _n, _h)

        LMS_TYPES[_lms_type.code] = _lms_type

OTS_BY_NAME = {t.name: t for t in OTS_TYPES.values()}

# The chain indices i as the two bytes that addresses hold, for every chain of every OTS type.
_CHAINS = [i.to_bytes(2, "big") for i in range(max(t.p for t in OTS_TYPES.values()))]

_SECRET = b"\xff"

LMS_BY_NAME = {t.name: t for t in LMS_TYPES.values()}


def u32(value):
    return value.to_bytes(4, "big")


def u16(value):
    return value.to_bytes(2, "big")


def digest(shake, n, data):
    return _primitives.shake_256(data).digest(n) if shake else _primitives.sha256(data).digest()[:n]


# A hash state that takes `data` and then the caller's further data, and its digest.
def hasher(shake, data):
    return _primitives.shake_256(data) if shake else _primitives.sha256(data)


def finish(shake, n, h):
    return h.digest(n) if shake else h.digest()[:n]


def derive(shake, n, i_value, q, index, seed):
    return digest(shake, n, i_value + u32(q) + u16(index) + _SECRET + seed)


def coefficients(t, data, count):
    w = t.w

    mask = (1 << w) - 1

    per_byte = 8 // w

    return [(data[i // per_byte] >> (8 - w * (i % per_byte + 1))) & mask for i in range(count)]


def digits(t, q_hash):
    count = 8 * t.n // t.w

    values = coefficients(t, q_hash, count)

    checksum = sum((1 << t.w) - 1 - x for x in values) << t.ls

    return coefficients(t, q_hash + u16(checksum), t.p)


_STEPS = [bytes([j]) for j in range(256)]

# The leaves whose public keys K, 34 blocks each when n = 32, are hashed together: 8 keys take
# about 17 KB.
_K_GROUP = 8


# The hashes of `messages`, which share one length, computed together (see _lanes).
def digests(shake, n, messages):
    if shake:
        return _lanes.shake_many(136, messages, n)

    return [d[:n] for d in _lanes.sha256_many(messages)]


# The chains of one OTS key under `prefix` (I || q), stepped together: chain i runs H(I || q || i ||
# j || value) for j from firsts[i] to lasts[i] - 1, from values[i].
def run_chains(shake, n, prefix, values, firsts, lasts):
    values = [*values]

    for j in range(min(firsts), max(lasts)):
        active = [i for i in range(len(values)) if firsts[i] <= j < lasts[i]]

        if not active:
            continue

        step = _STEPS[j]

        for i, value in zip(active, digests(shake, n, [prefix + _CHAINS[i] + step + values[i] for i in active])):
            values[i] = value

    return values


# The chain starts x_i of RFC 8554, Appendix A.
def chain_starts(t, prefix, seed):
    return digests(t.shake, t.n, [prefix + _CHAINS[i] + _SECRET + seed for i in range(t.p)])


# The leaves first .. first + count - 1: each the hash of the OTS public key K of its index q,
# whose chains run from their starts x_i to their ends. K and the leaves of a group of leaves are
# hashed together.
def leaves(lms, ots, i_value, seed, first, count):
    shake, n, p, last = ots.shake, ots.n, ots.p, (1 << ots.w) - 1

    out = []

    for start in range(first, first + count, _K_GROUP):
        group = range(start, min(start + _K_GROUP, first + count))

        keys = []

        for q in group:
            prefix = i_value + u32(q)

            keys.append(prefix + D_PBLC + b"".join(run_chains(shake, n, prefix, chain_starts(ots, prefix, seed), [0] * p, [last] * p)))

        out += digests(shake, n, [i_value + u32((1 << lms.h) + q) + D_LEAF + k for q, k in zip(group, digests(shake, n, keys))])

    return out


def combine(lms, i_value, z, first, lefts, rights):
    base = (1 << (lms.h - z - 1)) + first

    return digests(lms.shake, lms.m, [i_value + u32(base + i) + D_INTR + left + right for i, (left, right) in enumerate(zip(lefts, rights))])


# The hash of `message` that leaf q signs, with the randomizer `c`.
def message_hash(t, prefix, c, message):
    h = hasher(t.shake, prefix + D_MESG + c)

    h.update(message)

    return finish(t.shake, t.n, h)


# The OTS signature of `message` with leaf q, written to out[offset:].
def ots_sign(t, i_value, q, seed, message, out, offset):
    shake, n = t.shake, t.n

    c = derive(shake, n, i_value, q, RANDOMIZER, seed)

    prefix = i_value + u32(q)

    out[offset : offset + 4] = u32(t.code)

    out[offset + 4 : offset + 4 + n] = c

    offset += 4 + n

    for i, value in enumerate(run_chains(shake, n, prefix, chain_starts(t, prefix, seed), [0] * t.p, digits(t, message_hash(t, prefix, c, message)))):
        out[offset + i * n : offset + (i + 1) * n] = value


# The candidate OTS public key of the signature at signature[offset:].
def ots_candidate(t, i_value, q, signature, offset, message):
    shake, n, last = t.shake, t.n, (1 << t.w) - 1

    prefix = i_value + u32(q)

    k_value = hasher(shake, prefix + D_PBLC)

    start = offset + 4 + n

    starts = [signature[start + i * n : start + (i + 1) * n] for i in range(t.p)]

    for value in run_chains(shake, n, prefix, starts, digits(t, message_hash(t, prefix, signature[offset + 4 : start], message)), [last] * t.p):
        k_value.update(value)

    return finish(shake, n, k_value)


def lms_signature_size(lms, ots):
    return 8 + ots.signature_size + lms.h * lms.m


def parse_public_key(data):
    if len(data) < 8:
        return None

    lms = LMS_TYPES.get(int.from_bytes(data[:4], "big"))

    ots = OTS_TYPES.get(int.from_bytes(data[4:8], "big"))

    if lms is None or ots is None or lms.shake != ots.shake or lms.m != ots.n or len(data) != lms.public_key_size:
        return None

    return lms, ots, data[8:24], data[24:]


# The LMS signature signature[start:end] of `message`.
def lms_verify(public_key, message, signature, start, end):
    parsed = parse_public_key(public_key)

    if parsed is None or end - start < 8:
        return False

    lms, ots, i_value, root = parsed

    q = int.from_bytes(signature[start : start + 4], "big")

    if int.from_bytes(signature[start + 4 : start + 8], "big") != ots.code or end - start != lms_signature_size(lms, ots):
        return False

    offset = start + 4 + ots.signature_size

    if int.from_bytes(signature[offset : offset + 4], "big") != lms.code or q >= 1 << lms.h:
        return False

    node = 1 << lms.h | q

    candidate = digest(lms.shake, lms.m, i_value + u32(node) + D_LEAF + ots_candidate(ots, i_value, q, signature, start + 4, message))

    for i in range(lms.h):
        sibling = signature[offset + 4 + i * lms.m : offset + 4 + (i + 1) * lms.m]

        pair = sibling + candidate if node & 1 else candidate + sibling

        node >>= 1

        candidate = digest(lms.shake, lms.m, i_value + u32(node) + D_INTR + pair)

    return candidate == root


def check_public_key(data):
    if len(data) < 4 or not 1 <= int.from_bytes(data[:4], "big") <= 8:
        return False

    return parse_public_key(data[4:]) is not None


def hss_verify(public_key, message, signature):
    if not check_public_key(public_key) or len(signature) < 4:
        return False

    levels = int.from_bytes(public_key[:4], "big")

    if int.from_bytes(signature[:4], "big") != levels - 1:
        return False

    key = public_key[4:]

    offset = 4

    for _ in range(levels - 1):
        lms, ots, _, _ = parse_public_key(key)

        end = offset + lms_signature_size(lms, ots)

        if len(signature) < end + 8:
            return False

        child_lms = LMS_TYPES.get(int.from_bytes(signature[end : end + 4], "big"))

        if child_lms is None:
            return False

        child = signature[end : end + child_lms.public_key_size]

        if parse_public_key(child) is None or not lms_verify(key, child, signature, offset, end):
            return False

        key = child

        offset = end + len(child)

    return lms_verify(key, message, signature, offset, len(signature))


# The I and SEED of the child tree that leaf q signs, from the I and SEED of its parent.
def child_keys(lms, i_value, seed, q):
    return derive(lms.shake, lms.m, i_value, q, CHILD_I, seed)[:16], derive(lms.shake, lms.m, i_value, q, CHILD_SEED, seed)


class Tree:
    """One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys, built
    or taken from the levels of a tree cache."""

    __slots__ = ("lms", "ots", "i_value", "seed", "merkle", "public_key")

    def __init__(self, lms, ots, i_value, seed, levels=None):
        self.lms = lms

        self.ots = ots

        self.i_value = i_value

        self.seed = seed

        def tree_leaves(first, count):
            return leaves(lms, ots, i_value, seed, first, count)

        def tree_combine(z, first, lefts, rights):
            return combine(lms, i_value, z, first, lefts, rights)

        self.merkle = MerkleTree(lms.h, tree_leaves, tree_combine, levels)

        self.public_key = u32(lms.code) + u32(ots.code) + i_value + self.merkle.root

    # The LMS signature of `message` with leaf q, written to out[offset:].
    def sign_into(self, q, message, out, offset):
        out[offset : offset + 4] = u32(q)

        ots_sign(self.ots, self.i_value, q, self.seed, message, out, offset + 4)

        offset += 4 + self.ots.signature_size

        out[offset : offset + 4] = u32(self.lms.code)

        offset += 4

        for node in self.merkle.auth_path(q):
            out[offset : offset + len(node)] = node

            offset += len(node)

    def sign(self, q, message):
        signature = Output(lms_signature_size(self.lms, self.ots))

        self.sign_into(q, message, signature.view, 0)

        return signature.finish()

    def child(self, lms, ots, q):
        return Tree(lms, ots, *child_keys(self.lms, self.i_value, self.seed, q))


class Hss:
    """The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the
    index leaves a tree, and each child public key signed by its parent.

    `cached` maps levels to (tree number, levels) for the trees of a verified tree cache that the
    next index signs with. The top one replaces the build; the lower ones wait in `restored` until
    the first signature needs them, and they are checked now, so a bad cache fails the load."""

    def __init__(self, levels, i_value, seed, cached=None):
        cached = cached or {}

        self.levels = levels

        self.heights = [lms.h for lms, _ in levels]

        self.trees = [Tree(*levels[0], i_value, seed, cached.get(0, (0, None))[1])]

        self.signed = []

        self.prefixes = [0]

        self.restored = {level: (prefix, self._path_tree(level, prefix, nodes)) for level, (prefix, nodes) in cached.items() if level}

    @property
    def public_key(self):
        return u32(len(self.levels)) + self.trees[0].public_key

    @property
    def capacity(self):
        return 1 << sum(self.heights)

    def leaf_index(self, index, level):
        below = sum(self.heights[level + 1 :])

        return (index >> below) & ((1 << self.heights[level]) - 1)

    # Tree `prefix` of a lower level: the leaves that sign it on the levels above follow from its
    # number, and with them its I and SEED.
    def _path_tree(self, level, prefix, nodes):
        top = self.trees[0]

        i_value, seed = top.i_value, top.seed

        for upper in range(level):
            q = (prefix >> sum(self.heights[upper + 1 : level])) & ((1 << self.heights[upper]) - 1)

            i_value, seed = child_keys(top.lms, i_value, seed, q)

        return Tree(*self.levels[level], i_value, seed, nodes)

    # Every tree the key holds, top first, as (level, tree number, Merkle tree).
    def cached(self):
        held = [(level, self.prefixes[level], tree.merkle) for level, tree in enumerate(self.trees)]

        return held + [(level, prefix, tree.merkle) for level, (prefix, tree) in sorted(self.restored.items())]

    def sign(self, index, message):
        for level in range(1, len(self.levels)):
            prefix = index >> sum(self.heights[level:])

            if level < len(self.trees) and self.prefixes[level] == prefix:
                continue

            del self.trees[level:], self.signed[level - 1 :], self.prefixes[level:]

            parent = self.trees[level - 1]

            q = self.leaf_index(index, level - 1)

            restored = self.restored.pop(level, None)

            tree = restored[1] if restored is not None and restored[0] == prefix else parent.child(*self.levels[level], q)

            self.trees.append(tree)

            self.signed.append(parent.sign(q, tree.public_key) + tree.public_key)

            self.prefixes.append(prefix)

        bottom = self.trees[-1]

        signature = Output(4 + sum(map(len, self.signed)) + lms_signature_size(bottom.lms, bottom.ots))

        out = signature.view

        out[:4] = u32(len(self.levels) - 1)

        offset = 4

        for part in self.signed:
            out[offset : offset + len(part)] = part

            offset += len(part)

        bottom.sign_into(self.leaf_index(index, len(self.levels) - 1), message, out, offset)

        return signature.finish()
