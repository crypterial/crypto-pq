import struct
from typing import NamedTuple

from . import _lanes
from ._merkle import MerkleTree
from ._primitives import sha256, shake256
from ._sha2 import IV_256

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

# Lanes per batch (see _slhdsa).
CHUNK = 8192


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


def _swap32(values):
    return list(struct.unpack(f"<{len(values)}I", struct.pack(f">{len(values)}I", *values)))


class Lanes:
    """The hashes of one LMS tree on many inputs at once (see _lanes).

    Every message is I, a 32-bit number q or r, two or three bytes (a tag, or a chain index and a
    step) and n-byte values, which therefore start 2 or 3 bytes into a SHA-256 word, or 6 or 7
    bytes into a Keccak lane. A value is n/4 SHA-256 words in 64-bit fields, or n/8 Keccak lanes.
    """

    def __init__(self, shake, n, i_value, count):
        self.shake = shake

        self.n = n

        self.count = count

        words = struct.unpack("<2Q", i_value) if shake else struct.unpack(">4I", i_value)

        self.i_value = [_lanes.replicate(word, count, 64) for word in words]

    # The words in front of the values for one number per lane, and the bits of the number that
    # share the word or lane of the first value.
    def head(self, numbers):
        numbers = numbers if isinstance(numbers, list) else [numbers] * self.count

        if self.shake:
            return list(self.i_value), _lanes.pack(_swap32(numbers), 64)

        return self.i_value + [_lanes.pack(numbers, 64)], 0

    # The two or three bytes after the number (a tag, or a chain index and a step), given as one
    # big-endian value for every lane or a list of them, placed in the word or lane of the first
    # value.
    def after(self, values, size):
        if isinstance(values, list):
            return _lanes.pack([self._place(value, size) for value in values], 64)

        return _lanes.replicate(self._place(values, size), self.count, 64)

    def _place(self, value, size):
        if self.shake:
            return int.from_bytes(value.to_bytes(size, "big"), "little") << 32

        return value << (32 - 8 * size)

    def hash(self, head, top, values, offset):
        length = 20 + offset + len(values) * (8 if self.shake else 4)

        if self.shake:
            return _lanes.shake256(head + _lanes.shifted_le(top, values, offset + 4, self.count), self.count, self.n // 8)

        return _lanes.sha256(IV_256, head + _lanes.shifted(top, values, 4, offset, self.count), self.count, 8 * length)[: self.n // 4]

    def tagged(self, numbers, tag, values):
        head, top = self.head(numbers)

        return self.hash(head, top | self.after(int.from_bytes(tag, "big"), 2), values, 2)

    def from_bytes(self, values):
        return _lanes.lanes64(values) if self.shake else _lanes.words(values, 4, 64)

    def to_bytes(self, value):
        return _lanes.chunks64(value, self.count) if self.shake else _lanes.chunks(value, self.count, 4, 64)

    def constant(self, data):
        words = struct.unpack(f"<{len(data) // 8}Q", data) if self.shake else struct.unpack(f">{len(data) // 4}I", data)

        return [_lanes.replicate(word, self.count, 64) for word in words]

    # step(value, k) hashes I || q || j || k || value in every lane, for the (q, j) of each lane.
    def chain_step(self, numbers, chains):
        head, top = self.head(numbers)

        top |= self.after([j << 8 for j in chains], 3)

        unit = (1 << 48) if self.shake else (1 << 8)

        def step(value, k):
            return self.hash(head, top | _lanes.replicate(k * unit, self.count, 64), value, 3)

        return step

    # The chain starts x_j = H(I || q || j || 0xFF || SEED) of RFC 8554, Appendix A.
    def chain_start(self, step, seed):
        return step(self.constant(seed), 0xFF)


# Leaves q of one tree: the chains of a batch of leaves run in lane j * count + i (chain j of
# leaf first + i), so that the n-byte results of one chain are a contiguous slice for K.
def leaves(lms, ots, i_value, seed, first, count):
    p = ots.p

    per_batch = max(1, CHUNK // p)

    out = []

    for start in range(first, first + count, per_batch):
        size = min(per_batch, first + count - start)

        numbers = list(range(start, start + size))

        lanes = Lanes(ots.shake, ots.n, i_value, size * p)

        step = lanes.chain_step(numbers * p, [j for j in range(p) for _ in range(size)])

        value = lanes.chain_start(step, seed)

        for k in range((1 << ots.w) - 1):
            value = step(value, k)

        lanes = Lanes(ots.shake, ots.n, i_value, size)

        y = [_lanes.select(word, j * size, size, 64) for j in range(p) for word in value]

        k_value = lanes.tagged(numbers, D_PBLC, y)

        out += lanes.to_bytes(lanes.tagged([(1 << lms.h) + q for q in numbers], D_LEAF, k_value))

    return out


def combine(lms, i_value, z, first, lefts, rights):
    out = []

    for start in range(0, len(lefts), CHUNK):
        size = min(CHUNK, len(lefts) - start)

        lanes = Lanes(lms.shake, lms.m, i_value, size)

        values = lanes.from_bytes(lefts[start : start + size]) + lanes.from_bytes(rights[start : start + size])

        numbers = [(1 << (lms.h - z - 1)) + first + start + i for i in range(size)]

        out += lanes.to_bytes(lanes.tagged(numbers, D_INTR, values))

    return out


def ots_sign(t, i_value, q, seed, message):
    c = derive(t.shake, t.n, i_value, q, RANDOMIZER, seed)

    q_hash = digest(t.shake, t.n, i_value + u32(q) + D_MESG + c + message)

    lanes = Lanes(t.shake, t.n, i_value, t.p)

    step = lanes.chain_step(q, list(range(t.p)))

    y = _lanes.run_to(step, lanes.chain_start(step, seed), digits(t, q_hash))

    return u32(t.code) + c + b"".join(lanes.to_bytes(y))


def ots_candidate(t, i_value, q, signature, message):
    n = t.n

    c = signature[4 : 4 + n]

    q_hash = digest(t.shake, n, i_value + u32(q) + D_MESG + c + message)

    lanes = Lanes(t.shake, n, i_value, t.p)

    step = lanes.chain_step(q, list(range(t.p)))

    y = lanes.from_bytes([signature[4 + n * (j + 1) : 4 + n * (j + 2)] for j in range(t.p)])

    z = _lanes.run_from(step, y, digits(t, q_hash), (1 << t.w) - 1)

    return digest(t.shake, n, i_value + u32(q) + D_PBLC + b"".join(lanes.to_bytes(z)))


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

        def tree_leaves(first, count):
            return leaves(lms, ots, i_value, seed, first, count)

        def tree_combine(z, first, lefts, rights):
            return combine(lms, i_value, z, first, lefts, rights)

        self.merkle = MerkleTree(lms.h, tree_leaves, tree_combine)

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
