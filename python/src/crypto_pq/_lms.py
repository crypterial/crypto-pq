from typing import NamedTuple

from ._merkle import MerkleTree
from ._primitives import sha256, shake256

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

LMS_BY_NAME = {t.name: t for t in LMS_TYPES.values()}


def u32(value):
    return value.to_bytes(4, "big")


def u16(value):
    return value.to_bytes(2, "big")


def digest(shake, n, data):
    return shake256(data, n) if shake else sha256(data)[:n]


def derive(shake, n, i_value, q, index, seed):
    return digest(shake, n, i_value + u32(q) + u16(index) + b"\xff" + seed)


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


def chain(t, i_value, q, j, start, end, x):
    for k in range(start, end):
        x = digest(t.shake, t.n, i_value + u32(q) + u16(j) + bytes([k]) + x)

    return x


def ots_public_key(t, i_value, q, seed):
    top = (1 << t.w) - 1

    y = [chain(t, i_value, q, j, 0, top, derive(t.shake, t.n, i_value, q, j, seed)) for j in range(t.p)]

    return digest(t.shake, t.n, i_value + u32(q) + D_PBLC + b"".join(y))


def ots_sign(t, i_value, q, seed, message):
    c = derive(t.shake, t.n, i_value, q, RANDOMIZER, seed)

    q_hash = digest(t.shake, t.n, i_value + u32(q) + D_MESG + c + message)

    y = [chain(t, i_value, q, j, 0, a, derive(t.shake, t.n, i_value, q, j, seed)) for j, a in enumerate(digits(t, q_hash))]

    return u32(t.code) + c + b"".join(y)


def ots_candidate(t, i_value, q, signature, message):
    n = t.n

    c = signature[4 : 4 + n]

    q_hash = digest(t.shake, n, i_value + u32(q) + D_MESG + c + message)

    top = (1 << t.w) - 1

    z = []

    for j, a in enumerate(digits(t, q_hash)):
        y = signature[4 + n * (j + 1) : 4 + n * (j + 2)]

        z.append(chain(t, i_value, q, j, a, top, y))

    return digest(t.shake, n, i_value + u32(q) + D_PBLC + b"".join(z))


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


def lms_verify(public_key, message, signature):
    parsed = parse_public_key(public_key)

    if parsed is None or len(signature) < 8:
        return False

    lms, ots, i_value, root = parsed

    q = int.from_bytes(signature[:4], "big")

    if int.from_bytes(signature[4:8], "big") != ots.code or len(signature) != lms_signature_size(lms, ots):
        return False

    offset = 4 + ots.signature_size

    if int.from_bytes(signature[offset : offset + 4], "big") != lms.code or q >= 1 << lms.h:
        return False

    node = 1 << lms.h | q

    candidate = digest(lms.shake, lms.m, i_value + u32(node) + D_LEAF + ots_candidate(ots, i_value, q, signature[4:offset], message))

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

        if parse_public_key(child) is None or not lms_verify(key, child, signature[offset:end]):
            return False

        key = child

        offset = end + len(child)

    return lms_verify(key, message, signature[offset:])


class Tree:
    """One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys."""

    __slots__ = ("lms", "ots", "i_value", "seed", "merkle", "public_key")

    def __init__(self, lms, ots, i_value, seed):
        self.lms = lms

        self.ots = ots

        self.i_value = i_value

        self.seed = seed

        def leaf(q):
            k = ots_public_key(ots, i_value, q, seed)

            return digest(lms.shake, lms.m, i_value + u32((1 << lms.h) + q) + D_LEAF + k)

        def combine(z, j, left, right):
            return digest(lms.shake, lms.m, i_value + u32((1 << (lms.h - z - 1)) + j) + D_INTR + left + right)

        self.merkle = MerkleTree(lms.h, leaf, combine)

        self.public_key = u32(lms.code) + u32(ots.code) + i_value + self.merkle.root

    def sign(self, q, message):
        ots_signature = ots_sign(self.ots, self.i_value, q, self.seed, message)

        return u32(q) + ots_signature + u32(self.lms.code) + b"".join(self.merkle.auth_path(q))

    def child(self, lms, ots, q):
        seed = derive(self.lms.shake, self.lms.m, self.i_value, q, CHILD_SEED, self.seed)

        i_value = derive(self.lms.shake, self.lms.m, self.i_value, q, CHILD_I, self.seed)[:16]

        return Tree(lms, ots, i_value, seed)


class Hss:
    """The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the
    index leaves a tree, and each child public key signed by its parent."""

    def __init__(self, levels, i_value, seed):
        self.levels = levels

        self.heights = [lms.h for lms, _ in levels]

        self.trees = [Tree(*levels[0], i_value, seed)]

        self.signed = []

        self.prefixes = [0]

    @property
    def public_key(self):
        return u32(len(self.levels)) + self.trees[0].public_key

    @property
    def capacity(self):
        return 1 << sum(self.heights)

    def leaf_index(self, index, level):
        below = sum(self.heights[level + 1 :])

        return (index >> below) & ((1 << self.heights[level]) - 1)

    def sign(self, index, message):
        for level in range(1, len(self.levels)):
            prefix = index >> sum(self.heights[level:])

            if level < len(self.trees) and self.prefixes[level] == prefix:
                continue

            del self.trees[level:], self.signed[level - 1 :], self.prefixes[level:]

            parent = self.trees[level - 1]

            q = self.leaf_index(index, level - 1)

            tree = parent.child(*self.levels[level], q)

            self.trees.append(tree)

            self.signed.append(parent.sign(q, tree.public_key) + tree.public_key)

            self.prefixes.append(prefix)

        bottom = self.trees[-1].sign(self.leaf_index(index, len(self.levels) - 1), message)

        return u32(len(self.levels) - 1) + b"".join(self.signed) + bottom
