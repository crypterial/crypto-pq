import struct
from typing import NamedTuple

from . import _keccak, _lanes, _primitives, _sha2
from ._bytes import Output, wipe
from ._hash import HMAC_SHA_256, HMAC_SHA_512

WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)

W = 16

LG_W = 4

# A FORS tree is built in subtrees of at most 2^6 leaves, each hashed level by level, so that it
# holds one subtree and a node per height above it rather than every node of the tree.
FORS_SUBTREE = 6


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

_PAD = bytes(8)

# The rate of SHAKE256, whose one block holds the input of F, H and PRF.
_RATE = 136

# The bytes of the chain ends of the WOTS+ keys computed together, at most: 8 keys when n = 16, 4
# when n = 24 and 2 when n = 32.
_GROUP_BYTES = 8192


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


# The chains by digit: times[j] lists the chains whose signature value comes after j steps.
def _times(digits):
    times = [[] for _ in range(W)]

    for i, digit in enumerate(digits):
        times[digit].append(i)

    return times


# For the lanes first .. first + count - 1 of a group of WOTS+ keys, `length` chains each: the
# lanes of key `signer`, by the step after which each passes its value to the signature, as (lane
# in the computation, chain) pairs.
def _signer_times(digits, signer, length, first, count):
    times = [[] for _ in range(W)]

    if digits is not None:
        for lane in range(max(first, signer * length), min(first + count, (signer + 1) * length)):
            times[digits[lane - signer * length]].append((lane - first, lane - signer * length))

    return times


class _Sha2Hashes:
    """F, H, T and PRF of the SHA-2 sets for one key (FIPS 205, 11.2): each hash continues the state
    after the block of PK.seed and zeros, and F, PRF and H take one more block. F and PRF use
    SHA-256; H and T use SHA-512 when n > 16. Hashes that do not wait for each other run as the
    lanes of one computation (see _lanes): the chains of a WOTS+ key, FORS leaves, tree levels.

    An address is its head (one byte of the layer, the low eight bytes of the tree and one byte of
    the type: the compressed form ADRSc) and three 32-bit words.
    """

    __slots__ = ("n", "sk_seed", "small", "large", "tail_f", "tail_h", "size_h", "join_h", "last_h", "t")

    def __init__(self, p, pk_seed, sk_seed):
        n = p.n

        self.n = n

        self.sk_seed = sk_seed

        self.small = _sha2.chain256(_sha2.IV_256, pk_seed + bytes(64 - n))

        self.tail_f = _sha2.tail256(22 + n, 86 + n)

        if n > 16:
            self.large = _sha2.chain512(_sha2.IV_512, pk_seed + bytes(128 - n))

            self.tail_h, self.size_h, self.join_h, self.last_h = _sha2.tail512(22 + 2 * n, 150 + 2 * n), 64, _lanes.sha512_join, _sha2.last512

            self.t = _primitives.sha512(pk_seed + bytes(128 - n)).copy
        else:
            self.large = self.small

            self.tail_h, self.size_h, self.join_h, self.last_h = _sha2.tail256(22 + 2 * n, 86 + 2 * n), 32, _lanes.sha256_join, _sha2.last256

            self.t = _primitives.sha256(pk_seed + bytes(64 - n)).copy

    @staticmethod
    def head(layer, tree, kind):
        return bytes([layer]) + tree.to_bytes(8, "big") + bytes([kind])

    def f(self, adrs, value):
        return _sha2.last256(self.small, adrs + value + self.tail_f)[: self.n]

    def prf(self, adrs):
        return _sha2.last256(self.small, adrs + self.sk_seed + self.tail_f)[: self.n]

    # FIPS 205, Algorithm 6 for the WOTS+ keys `keypairs` of one XMSS tree, whose addresses start
    # with `heads` (of WOTS_PRF, WOTS_HASH and WOTS_PK): their public keys. The chains of all the
    # keys step together, a computation's blocks rewritten in place between steps (the hash word's
    # low byte at 21, the value from 22), and T hashes the keys together. With `digits`, chain i of
    # key number `signer` passes its value after digits[i] steps to out[offset + i * n:]: the WOTS+
    # signature (Algorithm 7).
    def wots_pks(self, heads, keypairs, length, digits, signer, out, offset):
        n, small, tail = self.n, self.small, self.tail_f

        prf_head, hash_head, pk_head = heads

        ends = bytearray(len(keypairs) * length * n)

        for first, count in _lanes.chunks(len(keypairs) * length):
            addresses = [_WORDS[keypairs[lane // length]] + _WORDS[lane % length] + _ZERO for lane in range(first, first + count)]

            secrets = bytearray().join([prf_head + address + self.sk_seed + tail for address in addresses])

            values = _lanes.sha256_join(small, secrets, count)

            wipe(secrets)

            blocks = bytearray().join([hash_head + address + bytes(n) + tail for address in addresses])

            del addresses

            times = _signer_times(digits, signer, length, first, count)

            for j in range(W):
                for k, i in times[j]:
                    out[offset + i * n : offset + (i + 1) * n] = values[32 * k : 32 * k + n]

                if j == W - 1:
                    break

                blocks[21::64] = bytes([j]) * count

                for b in range(n):
                    blocks[22 + b :: 64] = values[b::32]

                wipe(values)

                values = _lanes.sha256_join(small, blocks, count)

            for b in range(n):
                ends[n * first + b : n * (first + count) : n] = values[b::32]

            wipe(values)

            wipe(blocks)

        size = length * n

        keys = [digest[:n] for digest in self.t_many([pk_head + _WORDS[keypair] + _PAD + ends[size * g : size * (g + 1)] for g, keypair in enumerate(keypairs)])]

        wipe(ends)

        return keys

    # FIPS 205, Algorithm 8: the WOTS+ public key that the signature at signature[offset:] gives
    # for the message `digits` encode, under the address prefixes of one key. A chain joins the
    # others at the step of its digit.
    def wots_pk_from_sig(self, hash_prefix, pk_adrs, length, digits, signature, offset):
        n, small, tail = self.n, self.small, self.tail_f

        prefixes = [hash_prefix + chain for chain in _WORDS[:length]]

        values = [signature[offset + i * n : offset + (i + 1) * n] for i in range(length)]

        times, active = _times(digits), []

        for j in range(W - 1):
            active += times[j]

            if not active:
                continue

            step = _WORDS[j]

            hashed = _lanes.sha256_join(small, b"".join([prefixes[i] + step + values[i] + tail for i in active]), len(active))

            for k, i in enumerate(active):
                values[i] = hashed[32 * k : 32 * k + n]

        return self.t_bytes(pk_adrs, b"".join(values))

    # The parents of `nodes`, numbered from `first`, after `prefix`: the head, the first word and
    # their height.
    def parents(self, prefix, first, nodes):
        n, size, tail, count = self.n, self.size_h, self.tail_h, len(nodes) // 2

        hashed = self.join_h(self.large, b"".join([prefix + _WORD(first + k) + nodes[2 * k] + nodes[2 * k + 1] + tail for k in range(count)]), count)

        return [hashed[size * k : size * k + n] for k in range(count)]

    # The parent number `index` of `left` and `right`, after `prefix` as for parents.
    def node(self, prefix, index, left, right):
        return self.last_h(self.large, prefix + _WORD(index) + left + right + self.tail_h)[: self.n]

    # The parents at height 1 of the FORS leaves first .. first + count - 1, each leaf F of its
    # PRF value: `prf_prefix` and `leaf_prefix` are the PRF and the tree addresses without the tree
    # index, `prefix` the tree address of the parents without their index.
    def fors_parents(self, prf_prefix, leaf_prefix, prefix, first, count):
        n, small, tail = self.n, self.small, self.tail_f

        addresses = [_WORD(i) for i in range(first, first + count)]

        blocks = bytearray().join([prf_prefix + address + self.sk_seed + tail for address in addresses])

        secrets = _lanes.sha256_join(small, blocks, count)

        wipe(blocks)

        blocks = bytearray().join([leaf_prefix + address + secrets[32 * i : 32 * i + n] + tail for i, address in enumerate(addresses)])

        wipe(secrets)

        leaves = _lanes.sha256_join(small, blocks, count)

        wipe(blocks)

        return self.parents(prefix, first >> 1, [leaves[32 * i : 32 * i + n] for i in range(count)])

    # T of the address `adrs` and of the values that the caller adds in turn: the state that takes
    # them, its function that adds one, and t_end of the state gives the hash.
    def t_start(self, adrs):
        h = self.t()

        h.update(adrs)

        return h, h.update

    def t_end(self, h):
        return h.digest()[: self.n]

    def t_bytes(self, adrs, values):
        h = self.t()

        h.update(adrs + values)

        return h.digest()[: self.n]

    # T of each of `inputs` (address and values), which share one length, together.
    def t_many(self, inputs):
        if self.n > 16:
            return _lanes.sha512_many(inputs, self.large, 128)

        return _lanes.sha256_many(inputs, self.small, 64)


class _ShakeHashes:
    """F, H, T and PRF of the SHAKE sets for one key (FIPS 205, 11.1), with the same interface; an
    address head is the layer, the 12-byte tree and the type. F, PRF and H absorb one block; their
    lanes run as the SHA-2 ones do, a step's block taking the hash word's low byte at n + 31 and
    the value, eight bytes at a time, from n + 32."""

    __slots__ = ("n", "pk_seed", "sk_seed", "tail_f", "tail_h")

    def __init__(self, p, pk_seed, sk_seed):
        n = p.n

        self.n = n

        self.pk_seed = pk_seed

        self.sk_seed = sk_seed

        self.tail_f = _keccak.shake_tail(_RATE, 2 * n + 32)

        self.tail_h = _keccak.shake_tail(_RATE, 3 * n + 32)

    @staticmethod
    def head(layer, tree, kind):
        return layer.to_bytes(4, "big") + tree.to_bytes(12, "big") + kind.to_bytes(4, "big")

    def f(self, adrs, value):
        return _keccak.one_block(self.pk_seed + adrs + value + self.tail_f, _RATE, self.n)

    def prf(self, adrs):
        return _keccak.one_block(self.pk_seed + adrs + self.sk_seed + self.tail_f, _RATE, self.n)

    def wots_pks(self, heads, keypairs, length, digits, signer, out, offset):
        n, pk_seed, tail = self.n, self.pk_seed, self.tail_f

        prf_head, hash_head, pk_head = heads

        ends = bytearray(len(keypairs) * length * n)

        start, per = (n + 32) // 8, n // 8

        for first, count in _lanes.chunks(len(keypairs) * length):
            addresses = [_WORDS[keypairs[lane // length]] + _WORDS[lane % length] + _ZERO for lane in range(first, first + count)]

            secrets = bytearray().join([pk_seed + prf_head + address + self.sk_seed + tail for address in addresses])

            values = _lanes.keccak_join(secrets, count, _RATE, n)

            wipe(secrets)

            blocks = bytearray().join([pk_seed + hash_head + address + bytes(n) + tail for address in addresses])

            del addresses

            words = memoryview(blocks).cast("Q")

            times = _signer_times(digits, signer, length, first, count)

            for j in range(W):
                for k, i in times[j]:
                    out[offset + i * n : offset + (i + 1) * n] = values[n * k : n * (k + 1)]

                if j == W - 1:
                    break

                blocks[n + 31 :: _RATE] = bytes([j]) * count

                source = memoryview(values).cast("Q")

                # PyPy assigns to a memoryview from a C-contiguous source only, so each strided
                # column of words is copied out first.
                for w in range(per):
                    words[start + w :: _RATE // 8] = memoryview(source[w::per].tobytes()).cast("Q")

                source.release()

                wipe(values)

                values = _lanes.keccak_join(blocks, count, _RATE, n)

            words.release()

            ends[n * first : n * (first + count)] = values

            wipe(values)

            wipe(blocks)

        size = length * n

        keys = _lanes.shake_many(_RATE, [pk_seed + pk_head + _WORDS[keypair] + _PAD + ends[size * g : size * (g + 1)] for g, keypair in enumerate(keypairs)], n)

        wipe(ends)

        return keys

    def wots_pk_from_sig(self, hash_prefix, pk_adrs, length, digits, signature, offset):
        n, pk_seed, tail = self.n, self.pk_seed, self.tail_f

        prefixes = [pk_seed + hash_prefix + chain for chain in _WORDS[:length]]

        values = [signature[offset + i * n : offset + (i + 1) * n] for i in range(length)]

        times, active = _times(digits), []

        for j in range(W - 1):
            active += times[j]

            if not active:
                continue

            step = _WORDS[j]

            hashed = _lanes.keccak_join(b"".join([prefixes[i] + step + values[i] + tail for i in active]), len(active), _RATE, n)

            for k, i in enumerate(active):
                values[i] = hashed[n * k : n * (k + 1)]

        return self.t_bytes(pk_adrs, b"".join(values))

    def parents(self, prefix, first, nodes):
        n, pk_seed, tail, count = self.n, self.pk_seed, self.tail_h, len(nodes) // 2

        hashed = _lanes.keccak_join(b"".join([pk_seed + prefix + _WORD(first + k) + nodes[2 * k] + nodes[2 * k + 1] + tail for k in range(count)]), count, _RATE, n)

        return [hashed[n * k : n * (k + 1)] for k in range(count)]

    def node(self, prefix, index, left, right):
        return _keccak.one_block(self.pk_seed + prefix + _WORD(index) + left + right + self.tail_h, _RATE, self.n)

    def fors_parents(self, prf_prefix, leaf_prefix, prefix, first, count):
        n, pk_seed, tail = self.n, self.pk_seed, self.tail_f

        addresses = [_WORD(i) for i in range(first, first + count)]

        blocks = bytearray().join([pk_seed + prf_prefix + address + self.sk_seed + tail for address in addresses])

        secrets = _lanes.keccak_join(blocks, count, _RATE, n)

        wipe(blocks)

        blocks = bytearray().join([pk_seed + leaf_prefix + address + secrets[n * i : n * (i + 1)] + tail for i, address in enumerate(addresses)])

        wipe(secrets)

        leaves = _lanes.keccak_join(blocks, count, _RATE, n)

        wipe(blocks)

        return self.parents(prefix, first >> 1, [leaves[n * i : n * (i + 1)] for i in range(count)])

    def t_start(self, adrs):
        buffer = bytearray(self.pk_seed)

        buffer += adrs

        return buffer, buffer.extend

    def t_end(self, buffer):
        return _primitives.shake_256(buffer).digest(self.n)

    def t_bytes(self, adrs, values):
        return _primitives.shake_256(self.pk_seed + adrs + values).digest(self.n)


def _hashes(p, pk_seed, sk_seed):
    return (_ShakeHashes if p.shake else _Sha2Hashes)(p, pk_seed, sk_seed)


# The leaves of an XMSS tree whose WOTS+ keys are computed together: a power of two whose chain ends,
# kept for T, take at most _GROUP_BYTES.
def _group(p):
    return min(1 << p.hp, 1 << ((_GROUP_BYTES // (p.length * p.n)).bit_length() - 1))


# Treehash: `stack` holds the roots of the complete subtrees that wait for a right sibling, lowest
# last. `node`, at `height` and `index`, merges with them up to height `top` before it waits
# itself. A node that is the sibling of an ancestor of leaf `target` goes to the authentication
# path at out[offset:]; target -1 asks for none.
def push(hashes, prefix, stack, node, height, index, top, target, out, offset):
    n = hashes.n

    while True:
        if index ^ 1 == target >> height:
            out[offset + height * n : offset + (height + 1) * n] = node

        if height == top or not index & 1:
            stack.append(node)

            return

        node = hashes.node(prefix + _WORDS[height + 1], index >> 1, stack.pop(), node)

        index >>= 1

        height += 1


# The root of the XMSS tree `tree` of `layer` (FIPS 205, Algorithm 9) from its leaves in order.
# With a message, the WOTS+ signature of it with leaf `leaf` and that leaf's authentication path
# go to out[offset:] (Algorithm 10).
def xmss_sign(hashes, p, layer, tree, message=None, leaf=-1, out=None, offset=0):
    heads = hashes.head(layer, tree, WOTS_PRF), hashes.head(layer, tree, WOTS_HASH), hashes.head(layer, tree, WOTS_PK)

    prefix = hashes.head(layer, tree, TREE) + _ZERO

    digits = wots_digits(p, message) if message is not None else None

    path = offset + p.length * p.n

    group = _group(p)

    stack = []

    for start in range(0, 1 << p.hp, group):
        keypairs = range(start, start + group)

        for keypair, node in zip(keypairs, hashes.wots_pks(heads, keypairs, p.length, digits, leaf - start, out, offset)):
            push(hashes, prefix, stack, node, 0, keypair, p.hp, leaf, out, path)

    return stack[0]


def root(p, sk_seed, pk_seed):
    return xmss_sign(_hashes(p, pk_seed, sk_seed), p, p.d - 1, 0)


def keygen_internal(sk_seed, sk_prf, pk_seed, p):
    pk_root = root(p, sk_seed, pk_seed)

    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


# FIPS 205, Algorithm 12: each layer signs the root of the one below with the leaf that the tree
# address gives, and its tree gives the authentication path and its own root.
def ht_sign(hashes, p, message, tree, leaf, out, offset):
    size = (p.length + p.hp) * p.n

    for layer in range(p.d):
        message = xmss_sign(hashes, p, layer, tree, message, leaf, out, offset)

        offset += size

        leaf = tree & ((1 << p.hp) - 1)

        tree >>= p.hp


# FIPS 205, Algorithms 14 to 16: every FORS tree in turn, with the secret value of its leaf, the
# authentication path and its root, written to out[offset:]; returns the FORS public key. A tree's
# subtrees of 2^low leaves are hashed level by level, then merge on a treehash stack; the sibling
# of the signed leaf is computed on its own.
def fors_sign(hashes, p, md, tree, leaf, out, offset):
    n, a = p.n, p.a

    low = min(a, FORS_SUBTREE)

    indices = base_2b(md, a, p.k)

    word = _WORDS[leaf]

    prf_head = hashes.head(0, tree, FORS_PRF) + word + _ZERO

    tree_head = hashes.head(0, tree, FORS_TREE) + word

    leaf_head = tree_head + _ZERO

    roots, add = hashes.t_start(hashes.head(0, tree, FORS_ROOTS) + word + _PAD)

    for i in range(p.k):
        first = i << a

        target = first + indices[i]

        out[offset : offset + n] = hashes.prf(prf_head + _WORD(target))

        path = offset + n

        sibling = _WORD(target ^ 1)

        out[path : path + n] = hashes.f(leaf_head + sibling, hashes.prf(prf_head + sibling))

        stack = []

        for start in range(first, first + (1 << a), 1 << low):
            level = hashes.fors_parents(prf_head, leaf_head, tree_head + _WORDS[1], start, 1 << low)

            signed = start >> low == target >> low

            for z in range(1, low):
                if signed:
                    out[path + z * n : path + (z + 1) * n] = level[((target >> z) ^ 1) - (start >> z)]

                level = hashes.parents(tree_head + _WORDS[z + 1], start >> (z + 1), level)

            push(hashes, tree_head, stack, level[0], low, start >> low, a, target, out, path)

        add(stack[0])

        offset = path + a * n

    return hashes.t_end(roots)


def sign_internal(message, sk, addrnd, p):
    n = p.n

    sk_seed, sk_prf, pk_seed, pk_root = sk[:n], sk[n : 2 * n], sk[2 * n : 3 * n], sk[3 * n :]

    hashes = _hashes(p, pk_seed, sk_seed)

    r = prf_msg(p, sk_prf, addrnd, message)

    md, tree, leaf = split_digest(p, h_msg(p, r, pk_seed, pk_root, message))

    signature = Output(p.signature_size)

    out = signature.view

    out[:n] = r

    pk_fors = fors_sign(hashes, p, md, tree, leaf, out, n)

    ht_sign(hashes, p, pk_fors, tree, leaf, out, (1 + p.k * (1 + p.a)) * n)

    return signature.finish()


# Climbs from `node`, at `index` on the lowest level, along the authentication path at
# signature[offset:], under `prefix`: an address head and its first word.
def climb(hashes, p, node, index, signature, offset, prefix, height):
    n = p.n

    for z in range(height):
        sibling = signature[offset + z * n : offset + (z + 1) * n]

        left, right = (sibling, node) if index & 1 else (node, sibling)

        index >>= 1

        node = hashes.node(prefix + _WORDS[z + 1], index, left, right)

    return node


# FIPS 205, Algorithm 17, on the FORS signature at signature[offset:].
def fors_pk_from_sig(hashes, p, signature, offset, md, tree, leaf):
    n, a = p.n, p.a

    indices = base_2b(md, a, p.k)

    word = _WORDS[leaf]

    tree_head = hashes.head(0, tree, FORS_TREE) + word

    roots, add = hashes.t_start(hashes.head(0, tree, FORS_ROOTS) + word + _PAD)

    for i in range(p.k):
        index = (i << a) + indices[i]

        node = hashes.f(tree_head + _ZERO + _WORD(index), signature[offset : offset + n])

        add(climb(hashes, p, node, index, signature, offset + n, tree_head, a))

        offset += (a + 1) * n

    return hashes.t_end(roots)


# FIPS 205, Algorithms 8 and 11, on the XMSS signature at signature[offset:].
def xmss_pk_from_sig(hashes, p, leaf, signature, offset, message, layer, tree):
    word = _WORDS[leaf]

    node = hashes.wots_pk_from_sig(hashes.head(layer, tree, WOTS_HASH) + word, hashes.head(layer, tree, WOTS_PK) + word + _PAD, p.length, wots_digits(p, message), signature, offset)

    return climb(hashes, p, node, leaf, signature, offset + p.length * p.n, hashes.head(layer, tree, TREE) + _ZERO, p.hp)


def ht_verify(hashes, p, message, signature, offset, tree, leaf, pk_root):
    size = (p.length + p.hp) * p.n

    node = message

    for layer in range(p.d):
        node = xmss_pk_from_sig(hashes, p, leaf, signature, offset, node, layer, tree)

        offset += size

        leaf = tree & ((1 << p.hp) - 1)

        tree >>= p.hp

    return node == pk_root


def verify_internal(message, signature, pk, p):
    n = p.n

    if len(signature) != p.signature_size or len(pk) != p.public_key_size:
        return False

    pk_seed, pk_root = pk[:n], pk[n:]

    hashes = _hashes(p, pk_seed, None)

    md, tree, leaf = split_digest(p, h_msg(p, signature[:n], pk_seed, pk_root, message))

    pk_fors = fors_pk_from_sig(hashes, p, signature, n, md, tree, leaf)

    return ht_verify(hashes, p, pk_fors, signature, (1 + p.k * (1 + p.a)) * n, tree, leaf, pk_root)
